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
    }

    /// <summary>
    /// 保活时先走纯协议续期。成功就写事件并直接结束（不开浏览器、不冷启动）；
    /// 失败返回 null 让调用方回退到原有的冷启动流程。
    /// </summary>
    ProtocolRenewOutcome TryProtocolRenew(string frozenKey)
    {
        if (!ProtocolRenew.AttemptPending(_box) && !Ilink.VaultState(_box).Valid)
        {
            L("protocol renew: 金库没有有效凭证 -> 回退冷启动");
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

        // 服务端明确拒绝：说明这把 key 真不能用了，别再冷启动浪费时间，直接标「需要扫码」
        if (r.Code is -13 or -14)
        {
            L($"protocol renew rejected ({r.Code}) -> 需要重新扫码，跳过冷启动");
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
