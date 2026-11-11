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
        if (!cfg.EnabledFor(_box)) { L("保活已跳过（配置里关掉了保活）"); return 0; }
        if (!EnvDetect.SbieOk || !EnvDetect.QqOk) { L("保活已跳过（找不到 Sandboxie 或 QQ 浏览器）"); return 1; }

        // ★ 第一优先：上次换钥后没落盘。这一步必须排在 DecideWake 之前。
        //   理由：DecideWake 会因为「密钥太新（<5h）」直接返回 skip 而根本不进 Core，
        //   但那时 live 里放的是**服务端已经作废的旧 key**、新 key 只在 pending 文件里——
        //   越新的 key 越会被这条规则挡住，等于崩溃后永远补不上（实测就这么发生了）。
        if (ProtocolRenew.HasPending(_box))
        {
            L("保活：发现未落盘的新 key → 优先补写，再做其它判断");
            if (ProtocolRenew.RecoverPending(_box))
            {
                L("保活：新 key 已补写（沙箱与金库都等于服务端下发的那把）");
                try { NeedScan.ClearIfRenewed(_box); } catch { }
            }
            else
            {
                L("保活：新 key 还没补写成功（沙箱在忙？）→ 稍后重试");
            }
        }

        // v1.5.37：任务现在每小时醒一次，这里先判断「这次到底该不该动上游」。
        // 判断很便宜（只读几个小文件），不通过就直接退出，不抢锁、不停箱。
        var decision = Keepalive.DecideWake(_box, cfg.For(_box), DateTime.Now);
        if (!decision.Run)
        {
            L("保活已跳过：" + decision.Reason);
            return 0;
        }
        L("保活到期：" + decision.Reason);

        using var global = new Mutex(false, @"Local\JskpBoxManager.Keepalive");
        bool gotGlobal;
        try { gotGlobal = global.WaitOne(TimeSpan.FromMinutes(12)); } catch (AbandonedMutexException) { gotGlobal = true; }
        if (!gotGlobal) { L("保活已跳过（另一个沙箱续期太久，占着全局锁）"); return 0; }
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
                    L("保活已跳过（沙箱被看门进程占着）→ 已请它在原地续期");
                    return 0;
                }
                L("保活已跳过（沙箱正在启动/被看门）");
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
                    L("保活会话异常：" + ex);
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
                L("保活：游戏在受看门的沙箱里运行 → 会话有效，无需续期");
                return true;
            }
            File.WriteAllText(AppPaths.BoxRenewRequest(_box),
                $"requested {DateTime.Now:o} pid={Environment.ProcessId}\r\n");
            L($"保活：已向看门进程写入续期请求（密钥年龄={ProtocolRenew.KeyAgeText(_box)})");
            return true;
        }
        catch { return false; }
    }

    void RepairInterrupted()
    {
        var p = AppPaths.BoxRefreshPhase(_box);
        if (!File.Exists(p)) return;
        L("上次保活被中断 → 停箱并从金库还原");
        try { BoxRuntime.StopForce(_box, false); } catch { }
        BoxRuntime.RegisterLauncher(_box, "refresh");
        try { VaultSync.PushVaultToLive(_box); } catch { }
        try { File.Delete(p); } catch { }
    }

    void Core(KeepConfig cfg)
    {
        L($"保活会话开始（{AppInfo.VersionLabel})");
        var before = new BoxView(_box);
        if (before.HasGameWindow)
        {
            // 游戏正在跑：不打断玩家，也不试着在运行中换钥（会断会话，见 6F）。
            // 密钥超龄时只把凭证存好，交给看门进程在「游戏关闭」那一刻续。
            Ilink.Save(_box, "refresh-in-game");
            if (ProtocolRenew.KeyOverdue(_box))
            {
                L($"保活：游戏正在运行，密钥已用 {ProtocolRenew.KeyAgeText(_box)} old "
                  + $"(limit {ProtocolRenew.KeyMaxAgeHours}h) -> renew deferred until the game closes");
                Ilink.WriteEvent(_box, "refresh", new JsonObject
                {
                    ["result"] = "in-game-overdue-deferred",
                    ["keySha"] = Ilink.Live(_box).KeyHash,
                    ["keyAgeHours"] = ProtocolRenew.KeyAgeHours(_box),
                });
                return;
            }
            L("保活：游戏在跑 → 保留会话、已存凭证，跳过冷启动");
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
                L($"保活：常驻运行时在跑，密钥已用 {ProtocolRenew.KeyAgeText(_box)} old "
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
            L("保活：常驻运行时在跑 → 保留它、已存凭证，跳过冷启动");
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
                L($"保活：沙箱凭证无效，金库有 {vault0.KeyHash} at {vault0.WriteLocal} -> trying it first");
                var res0 = Ilink.Restore(_box, "refresh-live-invalid");
                L("保活：金库还原结果：" + res0);
                try { NeedScan.ClearIfRenewed(_box); } catch { }
            }
        }

        if (NeedScan.Pending(_box))
        {
            L("保活已跳过（需要扫码 —— 手动登录前不再冷启动）");
            return;
        }
        if (before.HasQqOrGame)
        {
            L("保活：还有残留进程 → 强制停箱");
            BoxRuntime.StopForce(_box, false);
            BoxRuntime.RegisterLauncher(_box, "refresh");
            Thread.Sleep(3000);
        }
        BoxStatusFile.Write(_box, BoxPhase.Refreshing, "静默保活中…");
        var frozenKey = Ilink.VaultState(_box).KeyHash;

        // ---- 协议续期优先：不用开浏览器，几秒完成，成功就完全跳过冷启动 ----
        // 密钥超过 20 小时硬上限时**强制**走协议续期，不看用户有没有勾选（勾选项只决定「平时是否优先用协议」）。
        bool overdue = ProtocolRenew.KeyOverdue(_box);
        if (overdue) L($"保活：密钥已用 {ProtocolRenew.KeyAgeText(_box)} old (limit {ProtocolRenew.KeyMaxAgeHours}h) -> protocol renew forced");
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

        L("保活模式：完整冷启动");
        r = TryCold(frozenKey, BoxRuntime.LaunchMode.Full, timeoutMin: 6, maxAttempts: 2);

        r ??= new ColdResult { LaunchUtc = DateTime.UtcNow };
        bool softRetry = false;
        if (!r.Renewed && !r.SawGame && (r.Suspected || r.CredCleared))
        {
            softRetry = true;
            L(r.Suspected
                ? "保活：凭证被清空且出现二维码 -> suspected, keep key; restore vault and retry Full once"
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
                else L($"保活：凭证已换新但存金库失败（{res})");
            }
            else L("保活：进游戏后凭证没有被重写");
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
            NeedScan.ClearRetry(_box);   // v1.5.37：成功即解除退避，回到正常节奏
            BoxRuntime.StopForce(_box, false);
            BoxStatusFile.Write(_box, BoxPhase.Stopped, $"保活成功 {DateTime.Now:MM-dd HH:mm}");
            L($"保活成功 模式={usedMode} -> box closed");
        }
        else
        {
            // 冷启动也没续上：再用协议逐把确认历史凭证（每把 0.1 秒），
            // 能救回来就不算失败，也不用标 need-scan。
            // 先停箱：冷启动失败后沙箱里可能还有进程，历史凭证要写 live 必须没有进程占着。
            if (HistoryProbePossible())
            {
                L("保活失败 → 放弃前先用协议试历史凭证");
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
                    L("保活成功（通过历史凭证）");
                    NeedScan.ClearRetry(_box);
                    try { Notifier.CheckAndNotify(Sandboxie.QueryBoxes()); } catch { }
                    return;
                }
                L("保活：历史凭证也全被拒");
            }

            // v1.5.37：失败要登记退避，否则任务每小时醒来都会重跑一遍完整的停箱/冷启动，
            // 既浪费资源，也可能因为反复冷启把密钥状态搅乱。
            // 密钥已过硬上限时必须压缩退避——否则「等待」等于让它过期。
            bool definitive = r.Suspected || r.QrFail;
            bool urgent = ProtocolRenew.KeyOverdue(_box);
            NeedScan.RegisterFailure(_box, outcome, definitive, urgent);

            if (r.Suspected)
            {
                NeedScan.Set(_box, "suspected-revoked");
                L("保活失败：金库重试后仍要扫码 → 标记需要扫码（未烧掉 key）");
            }
            else if (r.QrFail) NeedScan.RegisterQrFailure(_box);
            else if (!r.SawGame && r.SawQr)
            {
                NeedScan.Set(_box, "refresh-qr-seen-no-game");
                L("保活失败：出现二维码但没进游戏 → 标记需要扫码");
            }
            else L($"保活失败 模式={usedMode} (will retry next schedule)");
            BoxRuntime.StopForce(_box, false);
            if (!r.CredCleared) try { VaultSync.PushVaultToLive(_box); } catch { }
            BoxStatusFile.Write(_box, NeedScan.Pending(_box) ? BoxPhase.Failed : BoxPhase.Stopped,
                NeedScan.Pending(_box) ? "保活失败：需要重新扫码" : $"保活未成功（{outcome}），下次再试");
        }
        L("保活会话结束");
        // 保活跑完顺手扫一遍全局：有号超过阈值没续期就推微信（同一把 key 限流，不会刷屏）
        try { Notifier.CheckAndNotify(Sandboxie.QueryBoxes()); } catch (Exception ex) { L("过期提醒检查失败：" + ex.Message); }
    }

    /// <summary>
    /// 保活时先走纯协议续期。成功就写事件并直接结束（不开浏览器、不冷启动）；
    /// 失败返回 null 让调用方回退到原有的冷启动流程。
    /// </summary>
    ProtocolRenewOutcome TryProtocolRenew(string frozenKey)
    {
        // ★ 上次换钥后没落盘：先补写，否则接下来「续期」读到的旧 key 会和 service 端不一致
        if (ProtocolRenew.HasPending(_box))
        {
            L("协议续期：发现上次残留的待写新 key → 优先补写");
            ProtocolRenew.RecoverPending(_box);
        }

        if (!ProtocolRenew.AttemptPending(_box) && !Ilink.VaultState(_box).Valid)
        {
            // 金库这把已经不可读（被清空/格式坏了）不代表整个号没救：
            // 历史快照里很可能还有能用的（qb10 / qb12 就是这样救回来的）。
            // 直接冷启动会白跑几分钟，这里先用协议逐把确认（0.1 秒/把）。
            L("协议续期：金库没有有效凭证 → 先用协议试历史凭证");
            if (TryHistoryRecoverByProtocol())
            {
                L("保活成功（金库无效，走历史凭证）");
                Ilink.WriteEvent(_box, "refresh", new JsonObject
                {
                    ["result"] = "ok", ["keySha"] = Ilink.Live(_box).KeyHash, ["frozenKey"] = frozenKey,
                    ["mode"] = "HistoryProbe", ["lean"] = false, ["credCleared"] = true,
                    ["softRetry"] = false,
                });
                NeedScan.Clear(_box);
                NeedScan.ClearQrStreak(_box);
                NeedScan.ClearRetry(_box);
                BoxStatusFile.Write(_box, BoxPhase.Stopped, "保活成功（历史凭证协议续期）");
                return ProtocolRenewOutcome.Renewed;
            }
            L("协议续期：历史凭证也不可用 → 回退冷启动");
            return ProtocolRenewOutcome.Fallback;
        }

        var (renewable, blocked) = ProtocolRenew.CheckRenewable(_box);
        if (!renewable)
        {
            L("协议续期已跳过：" + blocked.Split('\n')[0]);
            return ProtocolRenewOutcome.Fallback;
        }

        L("协议续期：开始（不开浏览器）");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = ProtocolRenew.Renew(_box);
        sw.Stop();
        var live = Ilink.Live(_box);
        if (r.Ok)
        {
            CredentialProbe.RecordRotationPublic(_box, r.NewKeyHash, "refresh");
            try { VaultSync.PushVaultToLive(_box); } catch { }
            L($"协议续期成功 耗时 {sw.ElapsedMilliseconds}ms key={r.NewKeyHash}");
            Ilink.WriteEvent(_box, "refresh", new JsonObject
            {
                ["result"] = "ok", ["keySha"] = r.NewKeyHash, ["frozenKey"] = frozenKey,
                ["mode"] = "ProtocolRenew", ["lean"] = false, ["credCleared"] = false,
                ["softRetry"] = false, ["auth"] = null, ["authRet"] = null, ["authMsg"] = null,
                ["elapsedMs"] = sw.ElapsedMilliseconds,
            });
            BoxStatusFile.Write(_box, BoxPhase.Stopped, "保活成功（协议续期）");
            L("保活成功（协议续期）");
            NeedScan.ClearRetry(_box);
            return ProtocolRenewOutcome.Renewed;
        }

        // 服务端明确拒绝这把 key：不等于整个号没救——历史快照里可能还有能用的。
        // 先用协议逐把确认（0.1 秒/把，不用停箱也不用开浏览器），
        // 只有全部都被拒才真的标「需要扫码」。
        // （qb4 11-09 03:30 就是这里直接放弃、白白浪费了一整轮历史凭证。）
        if (r.Code is -13 or -14)
        {
            // v1.5.37：先把「被服务端明确拒绝的那一把」登记作废，再去试历史。
            // 不登记的话，下一轮保活/恢复会把这把死 key 再发一遍，纯属多打一次上游。
            Ilink.RegisterRevokedKey(_box, frozenKey, "protocol-renew-" + r.Code);
            HistoryCooldown.Mark(_box, frozenKey, r.Code);
            L($"协议续期被拒（{r.Code})）→ 这把已退役，改试历史凭证");
            BoxStatusFile.Write(_box, BoxPhase.Starting, "当前凭证已失效，正在用协议逐个确认历史凭证…");
            if (TryHistoryRecoverByProtocol())
            {
                L("保活成功（历史凭证 + 协议续期）");
                Ilink.WriteEvent(_box, "refresh", new JsonObject
                {
                    ["result"] = "ok", ["keySha"] = Ilink.Live(_box).KeyHash, ["frozenKey"] = frozenKey,
                    ["mode"] = "HistoryProbe", ["lean"] = false, ["credCleared"] = false,
                    ["softRetry"] = false, ["authRet"] = (int)r.Code, ["authMsg"] = r.Message,
                });
                NeedScan.Clear(_box);
                NeedScan.ClearQrStreak(_box);
                NeedScan.ClearRetry(_box);
                BoxStatusFile.Write(_box, BoxPhase.Stopped, "保活成功（历史凭证协议续期）");
                return ProtocolRenewOutcome.Renewed;
            }

            L("历史凭证也全被服务端拒绝 → 需要重新扫码");
            Ilink.WriteEvent(_box, "refresh", new JsonObject
            {
                ["result"] = "revoked", ["keySha"] = frozenKey, ["frozenKey"] = frozenKey,
                ["mode"] = "ProtocolRenew", ["authRet"] = (int)r.Code, ["authMsg"] = r.Message,
            });
            NeedScan.Set(_box, "protocol-renew-revoked");
            BoxStatusFile.Write(_box, BoxPhase.Failed, "保活失败：协议续期被拒，需要重新扫码");
            return ProtocolRenewOutcome.Revoked;
        }

        L($"协议续期失败（{r.Message})）→ 回退冷启动");
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
            var all = Ilink.CredentialHistory(_box);
            // 冷却期内的不再重试（见 HistoryCooldown：qb4 曾经一轮轮把同样十几把反复发出去）
            list = all
                .Where(c => !c.Revoked && HistoryCooldown.Allowed(_box, c.KeyHash))
                .Where(c => !live.Valid || c.KeyHash != live.KeyHash)
                .ToList();
            int cooling = all.Count(c => !c.Revoked && !HistoryCooldown.Allowed(_box, c.KeyHash));
            if (cooling > 0) L($"历史探测：{cooling} 把仍在被拒冷却期，本轮跳过");
        }
        catch (Exception ex)
        {
            L("历史探测：读不到历史凭证列表 -> " + ex.Message);
            return false;
        }
        if (list.Count == 0)
        {
            L("历史探测：没有可试的历史凭证（都在作废/冷却中）");
            return false;
        }

        L($"历史探测：共 {list.Count} 把可试（协议逐把确认，约 0.1 秒/把）");
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
                    L($"历史探测命中 key {c.KeyHash} -> new {pr.NewKeyHash}");
                    HistoryCooldown.Clear(_box, c.KeyHash);
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
        L("历史探测：全部历史凭证都被服务端拒绝");
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
                L($"保活冷启动重试 {attempt}/{maxAttempts} mode={mode}");
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
                    L($"保活：凭证已换新 模式={mode} {Ilink.Live(_box)}");
                    break;
                }
                if (!r.CredCleared && Ilink.RevokedSinceLaunch(_box, baseline))
                {
                    r.CredCleared = true;
                    L("保活：运行时清空了凭证 → 继续等；只有出现扫码页才说明这把 key 被作废");
                }
                var v = new BoxView(_box);
                if (r.CredCleared && v.HasStrictQr)
                {
                    clearedQrSince ??= DateTime.Now;
                    if ((DateTime.Now - clearedQrSince.Value).TotalSeconds >= suspectHoldSec)
                    {
                        r.SawQr = true;
                        r.Suspected = true;
                        L($"保活：凭证被清空且出现二维码 {suspectHoldSec}s -> suspected (key kept)");
                        break;
                    }
                    continue;
                }
                clearedQrSince = null;
                v.CloseRestorePage();
                if ((DateTime.Now - lastTab).TotalSeconds >= 8) { Cdp.CloseExtraTabs(_box); lastTab = DateTime.Now; }
                if (v.HasGameWindow) { r.SawGame = true; L("保活：游戏窗已出现 → 检查凭证是否换新"); break; }
                double wait = (DateTime.Now - started).TotalSeconds;

                if (v.WeChatRuntimeUp)
                {
                    sawWx = true; wxGone = 0;
                    if (!reloadDone && wait >= 35) { reloadDone = true; Cdp.ReloadGameCenter(_box); }
                    if (!nudged && wait >= 50) { nudged = true; BoxRuntime.StartBrowser(_box, "refresh-nudge", BoxRuntime.LaunchMode.Full); }
                    if (wait >= 180) { L("保活：运行时 180 秒没出游戏窗 → 重试"); needRetry = true; break; }
                    continue;
                }
                if (v.HasWeChat) { sawWx = true; wxGone = 0; } else if (sawWx) wxGone++;

                if (v.HasMiniProgramFail(out var pt))
                {
                    if (++mpFail <= 4) v.ClickMiniProgramRetry(pt);
                    else if (mpFail >= 8) { L("保活：小程序加载失败 → 冷启动重试"); needRetry = true; break; }
                    continue;
                }
                mpFail = 0;

                if (v.HasStrictQr)
                {
                    r.SawQr = true;
                    if (wait >= 180) { L("保活：二维码挂了 180 秒还在"); r.QrFail = true; break; }
                    if (!v.HasWeChat && wait >= 120) { L("保活：出现扫码页 120 秒但微信没起来"); r.QrFail = true; break; }
                    continue;
                }
                if (v.HasWmpfSetup)
                {
                    if (!v.HasWeChat && wait >= 150) { L("保活：WMPF 配置页 150 秒但微信没起来 → 重试"); needRetry = true; break; }
                    continue;
                }
                if (sawWx && wxGone >= 3 && wait < 120) { L("保活：微信运行时挂了（大概率 SBIE1231）→ 冷启动重试"); needRetry = true; break; }
                if (v.HasVisibleUi)
                {
                    uiSince ??= DateTime.Now;
                    if ((DateTime.Now - uiSince.Value).TotalSeconds >= 180 && !sawWx) { L("保活：界面 180 秒但微信没起来 → 重试"); needRetry = true; break; }
                    continue;
                }
                if (v.HasQqOrGame) continue;
                if (wait >= 90) { L("保活：90 秒没有任何进程 → 冷启动重试"); needRetry = true; break; }
            }
            if (r.SawGame || r.Renewed || r.Suspected || r.QrFail || !needRetry) break;
        }
        return r;
    }
}
