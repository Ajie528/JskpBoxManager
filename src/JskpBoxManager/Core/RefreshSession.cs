using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 计划任务触发的静默保活（JskpBoxManager.exe refresh qbN）：冷启动一次，等微信运行时自动授权换新密钥，存进金库后停箱。
/// 和旧版不同：游戏正开着时不再强行重启（正在用的会话本身就是有效的），只存一次凭证。
/// 开启 ProtocolRenew 时先走纯协议续期（不开浏览器），成功即结束。
/// </summary>
public sealed class RefreshSession
{
    readonly string _box;
    public RefreshSession(string box) { _box = box; }
    void L(string m) => Log.Box(_box, m);

    sealed class ColdResult
    {
        public bool SawGame, Renewed, QrFail, SawQr;
        /// <summary>运行时把凭证写成了无效但没出现扫码页：不登记作废，也不拿金库旧凭证覆盖运行时自己的状态。</summary>
        public bool CredCleared;
        /// <summary>凭证被清空且出现扫码页：不能单靠这个确认被顶，不烧密钥。</summary>
        public bool Suspected;
        public DateTime LaunchUtc;
    }

    public int Run()
    {
        var cfg = Keepalive.Load();
        if (!cfg.EnabledFor(_box)) { L("refresh skipped (keepalive disabled in config)"); return 0; }
        if (!EnvDetect.SbieOk || !EnvDetect.QqOk) { L("refresh skipped (Sandboxie or QQBrowser not found)"); return 1; }

        using var global = new Mutex(false, @"Local\JskpBoxManager.Keepalive");
        bool gotGlobal;
        try { gotGlobal = global.WaitOne(TimeSpan.FromMinutes(12)); } catch (AbandonedMutexException) { gotGlobal = true; }
        if (!gotGlobal) { L("refresh skipped (another box is renewing too long)"); return 0; }
        try
        {
            using var boxLock = LaunchSession.TryLock(_box, out bool gotBox);
            if (!gotBox)
            {
                // 沙箱被启动/看门进程占着。常驻态下这是常态：常驻进程要一直留着 ilink 长连接，
                // 不能为了保活把箱停掉。以前这里直接 return，等于开常驻的号「每天一次续期」从来没跑过，
                // 密钥只能靠自然寿命（qb4 就是这样约一天后弹码）。
                // 现在改成给常驻进程留一张续期请求，由它在循环里做一次真实 AutoAuth。
                if (RequestRenewFromWatchdog())
                {
                    L("refresh skipped (box is being watched) -> asked the watchdog to renew the key in place");
                    return 0;
                }
                L("refresh skipped (box is being launched / watched)");
                return 0;
            }
            try
            {
                BoxRuntime.RegisterLauncher(_box, "refresh");
                RepairInterrupted();
                try { File.WriteAllText(AppPaths.BoxRefreshPhase(_box), $"phase=cold-start pid={Environment.ProcessId} {DateTime.Now:o}"); } catch { }
                try { Core(cfg); }
                catch (Exception ex)
                {
                    L("refresh session EXCEPTION: " + ex);
                    try { BoxRuntime.StopForce(_box, false); } catch { }
                    try { VaultSync.PushVaultToLive(_box); } catch { }
                }
            }
            finally
            {
                try { File.Delete(AppPaths.BoxRefreshPhase(_box)); } catch { }
                BoxRuntime.UnregisterLauncher(_box);
                try { boxLock.ReleaseMutex(); } catch { }
            }
        }
        finally { try { global.ReleaseMutex(); } catch { } }
        return 0;
    }

    /// <summary>
    /// 沙箱被看门进程占着时，不能冷启续期，只能让看门进程在它认为安全的时机就地续。
    /// 只有「确实有个看门进程活着、且开了常驻」才值得留续期请求，免得在别人手动玩的时候多写一个文件。
    /// </summary>
    bool RequestRenewFromWatchdog()
    {
        try
        {
            if (!Keepalive.Load().For(_box).ResidentKeepalive) return false;
            var mode = BoxRuntime.LauncherMode(_box);
            if (mode is not ("launch" or "resident")) return false;

            // 游戏正开着时看门循环本身每 30 秒就在存凭证，游戏里的会话是有效的，不必再滚一次。
            // 只有常驻（只剩运行时、没有游戏窗）才需要按请求做真实 AutoAuth，否则密钥会一路放到自然寿命。
            var phase = BoxStatusFile.Read(_box)?.Phase;
            if (phase == BoxPhase.InGame)
            {
                L("refresh: game is running in a watched box -> its session is live, no renew needed");
                return true;
            }
            File.WriteAllText(AppPaths.BoxRenewRequest(_box),
                $"requested {DateTime.Now:o} pid={Environment.ProcessId}\r\n");
            L($"refresh: renew request written to watchdog (keyAge={ProtocolRenew.KeyAgeText(_box)})");
            return true;
        }
        catch { return false; }
    }

    void RepairInterrupted()
    {
        var p = AppPaths.BoxRefreshPhase(_box);
        if (!File.Exists(p)) return;
        L("refresh interrupted last time -> stop box and restore vault");
        try { BoxRuntime.StopForce(_box, false); } catch { }
        BoxRuntime.RegisterLauncher(_box, "refresh");
        try { VaultSync.PushVaultToLive(_box); } catch { }
        try { File.Delete(p); } catch { }
    }

    void Core(KeepConfig cfg)
    {
        L($"refresh session start ({AppInfo.VersionLabel})");
        var before = new BoxView(_box);
        if (before.HasGameWindow)
        {
            // 游戏正在跑：不打断玩家，也不试着在运行中换钥（会断会话，见 6F）。
            // 密钥超龄时只把凭证存好，交给看门进程在「游戏关闭」那一刻续。
            Ilink.Save(_box, "refresh-in-game");
            if (ProtocolRenew.KeyOverdue(_box))
            {
                L($"refresh: game is running with key {ProtocolRenew.KeyAgeText(_box)} old "
                  + $"(limit {ProtocolRenew.KeyMaxAgeHours}h) -> renew deferred until the game closes");
                Ilink.WriteEvent(_box, "refresh", new JsonObject
                {
                    ["result"] = "in-game-overdue-deferred",
                    ["keySha"] = Ilink.Live(_box).KeyHash,
                    ["keyAgeHours"] = ProtocolRenew.KeyAgeHours(_box),
                });
                return;
            }
            L("refresh: game is running -> keep it, credential saved, skip cold start");
            Ilink.WriteEvent(_box, "refresh", new JsonObject
            {
                ["result"] = "in-game", ["keySha"] = Ilink.Live(_box).KeyHash,
                ["keyAgeHours"] = ProtocolRenew.KeyAgeHours(_box),
            });
            return;
        }
        // 常驻轻量运行时：微信还在就别冷启杀进程，只存凭证。
        // 密钥超龄时不能在这里直接协议续期（运行时握着旧 key，会写回并断会话，见 6F）；
        // 交给常驻循环用它自己的「重开游戏滚 key」路径（ResidentRenew），那条不打断玩家。
        if (cfg.For(_box).ResidentKeepalive && before.WeChatRuntimeUp)
        {
            Ilink.Save(_box, "refresh-resident");
            if (ProtocolRenew.KeyOverdue(_box))
            {
                L($"refresh: resident runtime up with key {ProtocolRenew.KeyAgeText(_box)} old "
                  + $"(limit {ProtocolRenew.KeyMaxAgeHours}h) -> resident loop will roll it");
                RequestRenewFromWatchdog();
                Ilink.WriteEvent(_box, "refresh", new JsonObject
                {
                    ["result"] = "resident-overdue-requested",
                    ["keySha"] = Ilink.Live(_box).KeyHash,
                    ["keyAgeHours"] = ProtocolRenew.KeyAgeHours(_box),
                });
                return;
            }
            L("refresh: resident runtime up -> keep it, credential saved, skip cold start");
            Ilink.WriteEvent(_box, "refresh", new JsonObject
            {
                ["result"] = "resident-skip", ["keySha"] = Ilink.Live(_box).KeyHash,
                ["keyAgeHours"] = ProtocolRenew.KeyAgeHours(_box),
            });
            return;
        }
        // 标记可能已经过时（之后又扫过码 / 直接开过沙箱 / 导入过凭证），先按「沙箱里是否已有更新的有效凭证」清一次
        try { NeedScan.ClearIfRenewed(_box); } catch { }

        // live 无效但金库有旧凭证：先试金库，能续上就不用扫码。
        // qb10 / qb12 就是这样被救回来的（金库 10-16 / 10-18 的 key 放了 20 多天仍然有效）。
        if (!before.HasGameWindow && !before.HasQqOrGame)
        {
            var live0 = Ilink.Live(_box);
            var vault0 = Ilink.VaultState(_box);
            if (!live0.Valid && vault0.Valid && !Ilink.IsRevoked(_box, vault0.KeyHash))
            {
                L($"refresh: live invalid, vault has {vault0.KeyHash} at {vault0.WriteLocal} -> trying it first");
                var res0 = Ilink.Restore(_box, "refresh-live-invalid");
                L("refresh: vault restore result: " + res0);
                try { NeedScan.ClearIfRenewed(_box); } catch { }
            }
        }

        if (NeedScan.Pending(_box))
        {
            L("refresh skipped (need QR scan — no cold start until manual login)");
            return;
        }
        if (before.HasQqOrGame)
        {
            L("refresh: leftover processes -> force stop");
            BoxRuntime.StopForce(_box, false);
            BoxRuntime.RegisterLauncher(_box, "refresh");
            Thread.Sleep(3000);
        }
        BoxStatusFile.Write(_box, BoxPhase.Refreshing, "静默保活中…");
        var frozenKey = Ilink.VaultState(_box).KeyHash;

        // ---- 协议续期优先：不用开浏览器，几秒完成，成功就完全跳过冷启动 ----
        // 密钥超过 20 小时硬上限时**强制**走协议续期，不看用户有没有勾选（勾选项只决定「平时是否优先用协议」）。
        bool overdue = ProtocolRenew.KeyOverdue(_box);
        if (overdue) L($"refresh: key is {ProtocolRenew.KeyAgeText(_box)} old (limit {ProtocolRenew.KeyMaxAgeHours}h) -> protocol renew forced");
        if (cfg.For(_box).ProtocolRenew || overdue)
        {
            switch (TryProtocolRenew(frozenKey))
            {
                case ProtocolRenewOutcome.Renewed:
                case ProtocolRenewOutcome.Revoked:
                    return;   // 两种情况都已定论，不必再冷启动
            }
        }

        BoxRuntime.EnsureWxRuntimeInBox(_box);
        VaultSync.PushVaultToLive(_box);

        ColdResult r;
        string usedMode = "Full";

        L("refresh mode=full");
        r = TryCold(frozenKey, BoxRuntime.LaunchMode.Full, timeoutMin: 6, maxAttempts: 2);

        r ??= new ColdResult { LaunchUtc = DateTime.UtcNow };
        bool softRetry = false;
        if (!r.Renewed && !r.SawGame && (r.Suspected || r.CredCleared))
        {
            softRetry = true;
            L(r.Suspected
                ? "refresh: credential cleared + QR -> suspected, keep key; restore vault and retry Full once"
                : "refresh: credential cleared by runtime -> restore vault and retry Full once");
            BoxRuntime.StopForce(_box, false);
            BoxRuntime.RegisterLauncher(_box, "refresh");
            Thread.Sleep(3000);
            BoxRuntime.EnsureWxRuntimeInBox(_box);
            VaultSync.PushVaultToLive(_box);
            r = TryCold(frozenKey, BoxRuntime.LaunchMode.Full, timeoutMin: 6, maxAttempts: 1, suspectHoldSec: 60);
            usedMode += "+retry";
        }
        bool ok = false;
        if (r.SawGame || r.Renewed)
        {
            if (!r.Renewed) r.Renewed = Ilink.WaitRenewed(_box, r.LaunchUtc, 90);
            if (r.Renewed)
            {
                var res = Ilink.Save(_box, "refresh");
                ok = (res is "saved" or "unchanged") && Ilink.VaultState(_box).KeyHash == Ilink.Live(_box).KeyHash;
                if (ok) try { VaultSync.SyncRuntimeFromLive(_box); } catch { }
                else L($"refresh: ilink credential renewed but vault save failed ({res})");
            }
            else L("refresh: ilink credential not rewritten after game window");
        }
        var outcome = ok ? "ok" : r.Suspected ? "suspected" : r.QrFail ? "qr" : r.SawQr ? "qr-seen" : r.SawGame ? "no-rewrite" : "no-game";
        Ilink.WriteEvent(_box, "refresh", new JsonObject
        {
            ["result"] = outcome, ["keySha"] = Ilink.Live(_box).KeyHash, ["frozenKey"] = frozenKey,
            ["mode"] = usedMode, ["credCleared"] = r.CredCleared, ["softRetry"] = softRetry,
        });

        if (ok)
        {
            NeedScan.Clear(_box);
            NeedScan.ClearQrStreak(_box);
            BoxRuntime.StopForce(_box, false);
            BoxStatusFile.Write(_box, BoxPhase.Stopped, $"保活成功 {DateTime.Now:MM-dd HH:mm}");
            L($"refresh session OK mode={usedMode} -> box closed");
        }
        else
        {
            // 冷启动也没续上：再用协议逐把确认历史凭证（每把 0.1 秒），
            // 能救回来就不算失败，也不用标 need-scan。
            // 先停箱：冷启动失败后沙箱里可能还有进程，历史凭证要写 live 必须没有进程占着。
            if (HistoryProbePossible())
            {
                L("refresh FAIL -> try historical credentials via protocol before giving up");
                BoxRuntime.StopForce(_box, false);
                Thread.Sleep(1500);
                if (TryHistoryRecoverByProtocol())
                {
                    NeedScan.Clear(_box);
                    NeedScan.ClearQrStreak(_box);
                    Ilink.WriteEvent(_box, "refresh", new JsonObject
                    {
                        ["result"] = "ok", ["keySha"] = Ilink.Live(_box).KeyHash, ["frozenKey"] = frozenKey,
                        ["mode"] = usedMode + "+history", ["credCleared"] = r.CredCleared, ["softRetry"] = softRetry,
                    });
                    BoxStatusFile.Write(_box, BoxPhase.Stopped, "保活成功（历史凭证协议续期）");
                    L("refresh session OK via historical credential");
                    try { Notifier.CheckAndNotify(Sandboxie.QueryBoxes()); } catch { }
                    return;
                }
                L("refresh: all historical credentials rejected too");
            }

            if (r.Suspected)
            {
                NeedScan.Set(_box, "suspected-revoked");
                L("refresh session FAIL -> QR again after vault retry, mark need-scan (key not burned)");
            }
            else if (r.QrFail) NeedScan.RegisterQrFailure(_box);
            else if (!r.SawGame && r.SawQr)
            {
                NeedScan.Set(_box, "refresh-qr-seen-no-game");
                L("refresh session FAIL -> mark need-scan (QR seen, no game)");
            }
            else L($"refresh session FAIL mode={usedMode} (will retry next schedule)");
            BoxRuntime.StopForce(_box, false);
            if (!r.CredCleared) try { VaultSync.PushVaultToLive(_box); } catch { }
            BoxStatusFile.Write(_box, NeedScan.Pending(_box) ? BoxPhase.Failed : BoxPhase.Stopped,
                NeedScan.Pending(_box) ? "保活失败：需要重新扫码" : $"保活未成功（{outcome}），下次再试");
        }
        L("refresh session end");
        // 保活跑完顺手扫一遍全局：有号超过阈值没续期就推微信（同一把 key 限流，不会刷屏）
        try { Notifier.CheckAndNotify(Sandboxie.QueryBoxes()); } catch (Exception ex) { L("notify check failed: " + ex.Message); }
    }

    /// <summary>
    /// 保活时先走纯协议续期。成功就写事件并直接结束（不开浏览器、不冷启动）；
    /// 失败返回 null 让调用方回退到原有的冷启动流程。
    /// </summary>
    ProtocolRenewOutcome TryProtocolRenew(string frozenKey)
    {
        if (!ProtocolRenew.AttemptPending(_box) && !Ilink.VaultState(_box).Valid)
        {
            // 金库这把已经不可读（被清空/格式坏了）不代表整个号没救：
            // 历史快照里很可能还有能用的（qb10 / qb12 就是这样救回来的）。
            // 直接冷启动会白跑几分钟，这里先用协议逐把确认（0.1 秒/把）。
            L("protocol renew: 金库没有有效凭证 -> 先用协议试历史凭证");
            if (TryHistoryRecoverByProtocol())
            {
                L("refresh OK via historical credential (vault was invalid)");
                Ilink.WriteEvent(_box, "refresh", new JsonObject
                {
                    ["result"] = "ok", ["keySha"] = Ilink.Live(_box).KeyHash, ["frozenKey"] = frozenKey,
                    ["mode"] = "HistoryProbe", ["lean"] = false, ["credCleared"] = true,
                    ["softRetry"] = false,
                });
                NeedScan.Clear(_box);
                NeedScan.ClearQrStreak(_box);
                BoxStatusFile.Write(_box, BoxPhase.Stopped, "保活成功（历史凭证协议续期）");
                return ProtocolRenewOutcome.Renewed;
            }
            L("protocol renew: 历史凭证也不可用 -> 回退冷启动");
            return ProtocolRenewOutcome.Fallback;
        }

        var (renewable, blocked) = ProtocolRenew.CheckRenewable(_box);
        if (!renewable)
        {
            L("protocol renew skipped: " + blocked.Split('\n')[0]);
            return ProtocolRenewOutcome.Fallback;
        }

        L("protocol renew: 开始（不开浏览器）");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = ProtocolRenew.Renew(_box);
        sw.Stop();
        var live = Ilink.Live(_box);
        if (r.Ok)
        {
            CredentialProbe.RecordRotationPublic(_box, r.NewKeyHash, "refresh");
            try { VaultSync.PushVaultToLive(_box); } catch { }
            L($"protocol renew OK in {sw.ElapsedMilliseconds}ms key={r.NewKeyHash}");
            Ilink.WriteEvent(_box, "refresh", new JsonObject
            {
                ["result"] = "ok", ["keySha"] = r.NewKeyHash, ["frozenKey"] = frozenKey,
                ["mode"] = "ProtocolRenew", ["lean"] = false, ["credCleared"] = false,
                ["softRetry"] = false, ["auth"] = null, ["authRet"] = null, ["authMsg"] = null,
                ["elapsedMs"] = sw.ElapsedMilliseconds,
            });
            BoxStatusFile.Write(_box, BoxPhase.Stopped, "保活成功（协议续期）");
            L("refresh session OK via protocol renew");
            return ProtocolRenewOutcome.Renewed;
        }

        // 服务端明确拒绝这把 key：不等于整个号没救——历史快照里可能还有能用的。
        // 先用协议逐把确认（0.1 秒/把，不用停箱也不用开浏览器），
        // 只有全部都被拒才真的标「需要扫码」。
        // （qb4 11-09 03:30 就是这里直接放弃、白白浪费了一整轮历史凭证。）
        if (r.Code is -13 or -14)
        {
            L($"protocol renew rejected ({r.Code}) -> try historical credentials via protocol before giving up");
            BoxStatusFile.Write(_box, BoxPhase.Starting, "当前凭证已失效，正在用协议逐个确认历史凭证…");
            if (TryHistoryRecoverByProtocol())
            {
                L("refresh OK via historical credential (protocol)");
                Ilink.WriteEvent(_box, "refresh", new JsonObject
                {
                    ["result"] = "ok", ["keySha"] = Ilink.Live(_box).KeyHash, ["frozenKey"] = frozenKey,
                    ["mode"] = "HistoryProbe", ["lean"] = false, ["credCleared"] = false,
                    ["softRetry"] = false, ["authRet"] = (int)r.Code, ["authMsg"] = r.Message,
                });
                NeedScan.Clear(_box);
                NeedScan.ClearQrStreak(_box);
                BoxStatusFile.Write(_box, BoxPhase.Stopped, "保活成功（历史凭证协议续期）");
                return ProtocolRenewOutcome.Renewed;
            }

            L($"all historical credentials rejected too -> 需要重新扫码");
            Ilink.WriteEvent(_box, "refresh", new JsonObject
            {
                ["result"] = "revoked", ["keySha"] = frozenKey, ["frozenKey"] = frozenKey,
                ["mode"] = "ProtocolRenew", ["authRet"] = (int)r.Code, ["authMsg"] = r.Message,
            });
            NeedScan.Set(_box, "protocol-renew-revoked");
            BoxStatusFile.Write(_box, BoxPhase.Failed, "保活失败：协议续期被拒，需要重新扫码");
            return ProtocolRenewOutcome.Revoked;
        }

        L($"protocol renew failed ({r.Message}) -> 回退冷启动");
        return ProtocolRenewOutcome.Fallback;
    }

    enum ProtocolRenewOutcome { Renewed, Revoked, Fallback }

    /// <summary>是否值得尝试历史凭证（有非作废、且不同于当前 live 的 key）。</summary>
    bool HistoryProbePossible()
    {
        try
        {
            var live = Ilink.Live(_box);
            return Ilink.CredentialHistory(_box)
                .Any(c => !c.Revoked && (!live.Valid || c.KeyHash != live.KeyHash));
        }
        catch { return false; }
    }

    /// <summary>
    /// 当前这把被判废后，逐把用协议确认历史快照里的 key（每把约 0.1 秒，不停箱不开浏览器）。
    /// 找到第一把能用的就换上并存金库，返回 true。
    ///
    /// 和 RecoverSession.ProbeHistoryKey 的区别：这里**不重复停箱**——保活时沙箱本来就是停的，
    /// 只有探测成功那一刻才需要确保沙箱已停（ProbeHistoryKey 内部会判断）。
    /// </summary>
    bool TryHistoryRecoverByProtocol()
    {
        List<CredCandidate> list;
        try
        {
            var live = Ilink.Live(_box);
            list = Ilink.CredentialHistory(_box)
                .Where(c => !c.Revoked)
                .Where(c => !live.Valid || c.KeyHash != live.KeyHash)
                .ToList();
        }
        catch (Exception ex)
        {
            L("history probe: 读不到历史凭证列表 -> " + ex.Message);
            return false;
        }
        if (list.Count == 0)
        {
            L("history probe: 没有可试的历史凭证");
            return false;
        }

        L($"history probe: 共 {list.Count} 把可试（协议逐把确认，约 0.1 秒/把）");
        var rec = new RecoverSession(_box);
        int i = 0;
        foreach (var c in list)
        {
            i++;
            L($"[{i}/{list.Count}] history probe key {c.KeyShort} ({c.SavedAt:MM-dd HH:mm}{(c.IsVault ? " · vault" : "")})");
            BoxStatusFile.Write(_box, BoxPhase.Refreshing, $"保活中：试历史凭证 {c.KeyShort}（{i}/{list.Count}）");
            try
            {
                var pr = rec.ProbeHistoryKey(c);
                if (pr.Ok)
                {
                    L($"history probe OK with key {c.KeyHash} -> new {pr.NewKeyHash}");
                    // ProbeHistoryKey 内部已完成停箱 + 写 live + 推金库
                    return true;
                }
                if (pr.Rejected)
                {
                    L($"[{i}/{list.Count}] key {c.KeyShort} rejected ({pr.Code}) -> next");
                    continue;
                }
                L($"[{i}/{list.Count}] key {c.KeyShort} probe failed: {pr.Message} -> next");
            }
            catch (Exception ex)
            {
                L($"[{i}/{list.Count}] key {c.KeyShort} error: {ex.Message}");
            }
        }
        L("history probe: 全部历史凭证都被服务端拒绝");
        return false;
    }

    /// <param name="suspectHoldSec">凭证清空且扫码页持续这么久仍没等到服务端 ret=-13，才算疑似失效。</param>
    ColdResult TryCold(string frozenKey, BoxRuntime.LaunchMode mode, int timeoutMin, int maxAttempts, int suspectHoldSec = 15)
    {
        var r = new ColdResult();
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            if (attempt > 1)
            {
                L($"refresh cold retry {attempt}/{maxAttempts} mode={mode}");
                BoxRuntime.StopForce(_box, false);
                BoxRuntime.RegisterLauncher(_box, "refresh");
                Thread.Sleep(4000);
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                if (!r.CredCleared) VaultSync.PushVaultToLive(_box);
            }
            BoxRuntime.Warmup(_box, attempt > 1);
            BoxRuntime.ClearCrashRestore(_box);
            var baseline = Ilink.Baseline(_box);
            r.LaunchUtc = DateTime.UtcNow;
            BoxRuntime.StartBrowser(_box, "refresh", mode);

            var deadline = DateTime.Now.AddMinutes(timeoutMin);
            var started = DateTime.Now;
            bool needRetry = false, sawWx = false, reloadDone = false, nudged = false;
            int mpFail = 0, wxGone = 0;
            var lastTab = DateTime.MinValue;
            DateTime? uiSince = null, clearedQrSince = null;
            while (DateTime.Now < deadline)
            {
                Thread.Sleep(3000);
                if (Ilink.RenewedSince(_box, r.LaunchUtc) && Ilink.Live(_box).KeyHash != frozenKey)
                {
                    r.Renewed = true;
                    L($"refresh: ilink key renewed mode={mode} {Ilink.Live(_box)}");
                    break;
                }
                if (!r.CredCleared && Ilink.RevokedSinceLaunch(_box, baseline))
                {
                    r.CredCleared = true;
                    L("refresh: credential cleared by runtime -> wait; only a QR page confirms the key was revoked");
                }
                var v = new BoxView(_box);
                if (r.CredCleared && v.HasStrictQr)
                {
                    clearedQrSince ??= DateTime.Now;
                    if ((DateTime.Now - clearedQrSince.Value).TotalSeconds >= suspectHoldSec)
                    {
                        r.SawQr = true;
                        r.Suspected = true;
                        L($"refresh: credential cleared + QR {suspectHoldSec}s -> suspected (key kept)");
                        break;
                    }
                    continue;
                }
                clearedQrSince = null;
                v.CloseRestorePage();
                if ((DateTime.Now - lastTab).TotalSeconds >= 8) { Cdp.CloseExtraTabs(_box); lastTab = DateTime.Now; }
                if (v.HasGameWindow) { r.SawGame = true; L("refresh: game window up -> check ilink credential"); break; }
                double wait = (DateTime.Now - started).TotalSeconds;

                if (v.WeChatRuntimeUp)
                {
                    sawWx = true; wxGone = 0;
                    if (!reloadDone && wait >= 35) { reloadDone = true; Cdp.ReloadGameCenter(_box); }
                    if (!nudged && wait >= 50) { nudged = true; BoxRuntime.StartBrowser(_box, "refresh-nudge", BoxRuntime.LaunchMode.Full); }
                    if (wait >= 180) { L("refresh: runtime 180s without game window -> retry"); needRetry = true; break; }
                    continue;
                }
                if (v.HasWeChat) { sawWx = true; wxGone = 0; } else if (sawWx) wxGone++;

                if (v.HasMiniProgramFail(out var pt))
                {
                    if (++mpFail <= 4) v.ClickMiniProgramRetry(pt);
                    else if (mpFail >= 8) { L("refresh: mini-program fail -> cold retry"); needRetry = true; break; }
                    continue;
                }
                mpFail = 0;

                if (v.HasStrictQr)
                {
                    r.SawQr = true;
                    if (wait >= 180) { L("refresh: QR still up after 180s"); r.QrFail = true; break; }
                    if (!v.HasWeChat && wait >= 120) { L("refresh: strict QR 120s without WeChat"); r.QrFail = true; break; }
                    continue;
                }
                if (v.HasWmpfSetup)
                {
                    if (!v.HasWeChat && wait >= 150) { L("refresh: WMPF setup 150s without WeChat -> retry"); needRetry = true; break; }
                    continue;
                }
                if (sawWx && wxGone >= 3 && wait < 120) { L("refresh: WeChatAppEx died (SBIE1231 likely) -> cold retry"); needRetry = true; break; }
                if (v.HasVisibleUi)
                {
                    uiSince ??= DateTime.Now;
                    if ((DateTime.Now - uiSince.Value).TotalSeconds >= 180 && !sawWx) { L("refresh: UI 180s without WeChat -> retry"); needRetry = true; break; }
                    continue;
                }
                if (v.HasQqOrGame) continue;
                if (wait >= 90) { L("refresh: no process 90s -> cold retry"); needRetry = true; break; }
            }
            if (r.SawGame || r.Renewed || r.Suspected || r.QrFail || !needRetry) break;
        }
        return r;
    }
}
