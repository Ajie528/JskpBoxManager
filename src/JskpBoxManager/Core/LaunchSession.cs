namespace JskpBoxManager.Core;

/// <summary>
/// 「启动游戏」的后台流程（JskpBoxManager.exe launch qbN）：准备凭证 → 拉起浏览器 → 等游戏或扫码 → 看门。
/// 看门期间定时存凭证；玩家关掉游戏后默认停箱；若开了常驻则藏窗压内存，保留 ilink 长连接。
/// </summary>
public sealed class LaunchSession
{
    readonly string _box;
    DateTime _mpRetryNotBefore = DateTime.MinValue;
    bool _suspectRetried;
    /// <summary>游戏运行中密钥已超龄，等游戏关闭后立刻续期。</summary>
    bool _renewPending;
    /// <summary>历史凭证已全部试过且失败：之后的扫码框要原地等用户扫，不再提前返回。</summary>
    bool _historyExhausted;

    public LaunchSession(string box) { _box = box; }

    void L(string msg) => Log.Box(_box, msg);
    void Phase(BoxPhase p, string text) => BoxStatusFile.Write(_box, p, text);

    public static Mutex TryLock(string box, out bool acquired)
    {
        var m = new Mutex(false, @"Local\JskpBoxManager.Box." + box);
        try { acquired = m.WaitOne(0); }
        catch (AbandonedMutexException) { acquired = true; }
        return m;
    }

    public int Run()
    {
        L($"launch start ({AppInfo.ProductName} {AppInfo.VersionLabel})");
        using var mutex = TryLock(_box, out bool got);
        if (!got)
        {
            // 已有一个启动/看门进程：把已有界面拉到前台；常驻态则复开 GameUrl 让看门进程接上游戏窗
            var v = new BoxView(_box);
            if (v.HasGameWindow) { v.ShowGameWindow(); L("already running -> show game window"); }
            else if (v.HasStrictQr) { v.ShowQrWindow(); L("already running -> show QR window"); }
            else if (v.WeChatRuntimeUp && Keepalive.Load().For(_box).ResidentKeepalive)
            {
                try { BoxRuntime.StartBrowser(_box, "resume-resident-dup"); } catch { }
                L("already running (resident) -> reopen GameUrl");
            }
            else L("already running (launcher busy) -> skip duplicate launch");
            return 0;
        }
        BoxRuntime.RegisterLauncher(_box, "launch");
        try
        {
            // 上一次没被常驻进程取走的续期请求已经没意义了（这次是完整启动，会自己续）
            try { File.Delete(AppPaths.BoxRenewRequest(_box)); } catch { }
            RunLocked();        }
        catch (Exception ex)
        {
            L("launch EXCEPTION: " + ex);
            Phase(BoxPhase.Failed, "启动出错：" + ex.Message);
        }
        finally
        {
            BoxRuntime.UnregisterLauncher(_box);
            try { mutex.ReleaseMutex(); } catch { }
        }
        return 0;
    }

    /// <summary>
    /// live 凭证无效、金库还有有效凭证时，把金库推回 live 并清掉过时的 need-scan。
    ///
    /// 为什么值得做：实测 qb10 / qb12 的 need-scan 挂了 4 天，金库里 10-16 / 10-18 的旧 key
    /// 其实一直有效（协议续期一次就换成新 key）。旧逻辑直接「等扫码」，白白浪费了能用的凭证。
    /// 服务端对真作废的 key 会回 -13，不会因为多试一次造成损害。
    ///
    /// 只在沙箱已停时动手——运行中推金库会覆盖运行时自己的状态。
    /// </summary>
    void TryRestoreVaultWhenLiveInvalid()
    {
        try
        {
            var live = Ilink.Live(_box);
            if (live.Valid) return;                       // live 本来就好，不用管
            var vault = Ilink.VaultState(_box);
            if (!vault.Valid) return;                     // 金库也没有，只能扫
            if (Ilink.IsRevoked(_box, vault.KeyHash))     // 金库这把已登记作废
            {
                L("vault credential is registered revoked -> skip auto restore");
                return;
            }
            if (new BoxView(_box).HasQqOrGame)
            {
                L("live credential invalid but box is running -> skip vault restore (wait for QR)");
                return;
            }

            L($"live credential invalid, vault has {vault.KeyHash} at {vault.WriteLocal} -> trying it first");
            var res = Ilink.Restore(_box, "launch-live-invalid");
            L("vault restore result: " + res);
            if (res is not ("restored" or "same")) return;

            // 推回去之后再清一次标记：新的写入时间已经晚于 need-scan 文件
            try { NeedScan.ClearIfRenewed(_box); } catch { }
        }
        catch (Exception ex) { L("vault restore attempt failed: " + ex.Message); }
    }

    void RunLocked()
    {
        if (!EnvDetect.SbieOk) throw new InvalidOperationException("找不到 Sandboxie-Plus");
        if (!EnvDetect.QqOk) throw new InvalidOperationException("找不到 QQ 浏览器");
        Phase(BoxPhase.Starting, "正在启动…");        // 先看标记是不是过时了：标记之后沙箱里已经出现更新的有效凭证（重新扫码、直接开沙箱、导入凭证）
        // 就不该再拿旧标记降级成「必须扫码」。以前只在进游戏后才清，结果钥匙已经换了还按需扫码处理
        // （qb15 11-04 12:07：钥匙 12:04:44 就换新了，标记停在 11:28:55，启动照样干等扫码框）。
        try { NeedScan.ClearIfRenewed(_box); } catch { }

        // live 里的凭证无效、但金库里还有一把能用的：先推回 live 再判断。
        // 实测 qb10 / qb12：need-scan 挂了 4 天，金库里 10-16 / 10-18 的旧 key 其实一直有效，
        // 协议续期一次就换成了新 key。以前只在「探测」里做，手动启动会直接等扫码。
        TryRestoreVaultWhenLiveInvalid();

        if (NeedScan.Pending(_box))
        {
            L("need-scan pending -> ignore saved login, wait for WeChat QR");
            // 之前已经把所有历史凭证试完并全部被拒：这次不必再花几分钟重试，
            // 直接把扫码框摆给用户。真的换了新 key 时上面 ClearIfRenewed 会清掉标记。
            if (NeedScan.Reason(_box).Contains("history-all-failed", StringComparison.OrdinalIgnoreCase))
            {
                _historyExhausted = true;
                L("history already exhausted last time -> skip retrying, go straight to QR");
            }
        }

        var existing = new BoxView(_box);
        bool attach = false;
        if (existing.HasGameWindow)
        {
            L("game already running -> show + watch");
            existing.ShowGameWindow();
            Watch();
            return;
        }
        if (existing.HasStrictQr)
        {
            L("QR page already up -> show and watch");
            existing.ShowQrWindow();
            Watch();
            return;
        }
        if (existing.WeChatRuntimeUp)
        {
            if (Keepalive.Load().For(_box).ResidentKeepalive)
            {
                L("WeChat runtime only (resident) -> reopen GameUrl + watch");
                try { BoxRuntime.StartBrowser(_box, "resume-resident"); } catch { }
                Watch();
                return;
            }
            L("WeChat runtime only (no game window) -> force stop and relaunch");
            BoxRuntime.StopForce(_box, false);
            BoxRuntime.RegisterLauncher(_box, "launch");
            Thread.Sleep(3000);
        }
        else if (existing.HasQqOrGame)
        {
            if (existing.HasVisibleUi || Cdp.Alive(_box))
            {
                L("browser already up -> wait for game, do not relaunch");
                attach = true;
            }
            else
            {
                L("leftover processes -> force stop");
                BoxRuntime.StopForce(_box, false);
                BoxRuntime.RegisterLauncher(_box, "launch");
                Thread.Sleep(3000);
            }
        }

        if (!attach)
        {
            BoxRuntime.EnsureWxRuntimeInBox(_box);
            VaultSync.PrepareBeforeLaunch(_box);
            // 启动前准备刚把沙箱里更新的凭证收进金库，标记可能就此过时（同上，不能等到进游戏才清）
            try { NeedScan.ClearIfRenewed(_box); } catch { }
        }

    bool opened = false, waitingQrAtEnd = false, didVaultRestore = false, forceFullWarmup = false;
    bool didHistoryRecover = _historyExhausted;
    const int maxAttempts = 3;
        for (int attempt = 1; attempt <= maxAttempts && !opened; attempt++)
        {
            LaunchBaseline baseline = null;
            if (attach && attempt == 1)
            {
                L("attach existing QQBrowser (skip second launch)");
            }
            else
            {
                BoxRuntime.Warmup(_box, attempt > 1 && !forceFullWarmup);
                forceFullWarmup = false;
                BoxRuntime.ClearCrashRestore(_box);
                baseline = Ilink.Baseline(_box);
                L($"launch QQBrowser attempt={attempt} credential {Ilink.Live(_box)}");
                BoxRuntime.StartBrowser(_box, "launch");
            }
            var result = WaitForGame(baseline);
            waitingQrAtEnd = result.WaitingQr;
            if (result.Opened) { opened = true; break; }

            // 扫码框出现且还有历史凭证可试时：先别急着判「必须扫码」。
            // 历史快照里很可能还有一把能用的（qb10 / qb12 就是这样白等了好几天的），
            // 这里逐把走协议续期确认，每把 0.5 秒，比冷启动验证快两个数量级。
            if (!didHistoryRecover && result.WaitingQr && result.SawQr && HistoryCanHelp())
            {
                didHistoryRecover = true;
                L("QR up -> try historical credentials via protocol renew (0.5s each)");
                Phase(BoxPhase.Starting, "扫码框出现了，正在用历史凭证逐个试…");
                if (TryHistoryRecover())
                {
                    L("history recover succeeded -> credential swapped, relaunching game");
                    NeedScan.Clear(_box);
                    NeedScan.ClearQrStreak(_box);
                    // 协议续期只是把 key 换好了，游戏还没起来：重开一次浏览器让新 key 生效
                    if (attempt < maxAttempts)
                    {
                        BoxRuntime.EnsureWxRuntimeInBox(_box);
                        BoxRuntime.Warmup(_box, false);
                        BoxRuntime.ClearCrashRestore(_box);
                        baseline = Ilink.Baseline(_box);
                        L($"relaunch with recovered credential {Ilink.Live(_box)}");
                        BoxRuntime.StartBrowser(_box, "history-recovered");
                        var again = WaitForGame(baseline);
                        waitingQrAtEnd = again.WaitingQr;
                        if (again.Opened)
                        {
                            opened = true;
                            break;
                        }
                        L("relaunch after history recovery did not open game -> continue");
                    }
                    else
                    {
                        // 已经用完次数：凭证是好的，只是这次没等到游戏窗，交给用户点一次启动即可
                        L("history recover OK but no attempts left -> credential ready, user can launch again");
                        opened = true;
                        break;
                    }
                }
                L("history recover failed -> all keys rejected, now present the QR page for manual scan");
                _historyExhausted = true;
                // 记下「历史已试完」：下次启动直接用 need-scan 判定，不必再花两分钟重试一遍。
                // 一旦真的换了新 key（扫码/导入/探测成功），NeedScan.ClearIfRenewed 会自动清掉。
                NeedScan.Set(_box, "history-all-failed");
                // 关键：TryHistoryRecover 内部每把都会停箱，试完这里沙箱是空的。
                // 必须重新拉起浏览器把扫码框摆到用户面前，否则会直接「launch ended without game」，
                // 用户看到的就是「弹扫码框后直接停箱、没机会扫」。
                try
                {
                    BoxRuntime.EnsureWxRuntimeInBox(_box);
                    BoxRuntime.Warmup(_box, false);
                    BoxRuntime.ClearCrashRestore(_box);
                    baseline = Ilink.Baseline(_box);
                    L("relaunch for manual QR scan");
                    BoxRuntime.StartBrowser(_box, "qr-wait");
                    var qrResult = WaitForGame(baseline);
                    waitingQrAtEnd = qrResult.WaitingQr;
                    if (qrResult.Opened)
                    {
                        opened = true;
                        break;
                    }
                }
                catch (Exception ex) { L("relaunch for QR failed: " + ex.Message); }
            }

            if (result.NeedColdRetry && attempt < maxAttempts)
            {
                L($"cold start failed -> retry {attempt}/{maxAttempts}");
                Phase(BoxPhase.Starting, $"启动没成功，正在重试（{attempt}/{maxAttempts}）…");
                BoxRuntime.StopForce(_box, false);
                BoxRuntime.RegisterLauncher(_box, "launch");
                Thread.Sleep(6000);
                BoxRuntime.WaitRpcReady(_box, 90);
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                if (result.Suspected)
                {
                    L("suspected revoke (cleared + QR, no server reject seen) -> restore vault and retry once");
                    VaultSync.PushVaultToLive(_box);
                    didVaultRestore = true;
                }
                else if (result.CredCleared)
                    L("credential was cleared by runtime without QR -> keep runtime state (no vault restore) and retry");
                else if (!didVaultRestore)
                {
                    L("live launch failed -> full restore from vault then retry");
                    VaultSync.PushVaultToLive(_box);
                    didVaultRestore = true;
                }
                forceFullWarmup = true;
                continue;
            }
            if (result.NeedColdRetry)
            {
                L("cold retries exhausted -> leave browser visible (may need scan)");
                if (result.SawQr) NeedScan.Set(_box, "launch-no-game");
                try { new BoxView(_box).ShowQrWindow(); } catch { }
            }
            break;
        }

        if (opened)
        {
            L("game window up -> settle, hide browser, save credential");
            Phase(BoxPhase.InGame, "游戏中");
            try { Cdp.CloseExtraTabs(_box); } catch { }
            for (int i = 0; i < 3; i++)
            {
                new BoxView(_box).HideBrowserKeepGame(true);
                if (i < 2) Thread.Sleep(400);
            }
            try { Ilink.Save(_box, "game-ok"); } catch { }
            try { NeedScan.ClearIfRenewed(_box); } catch { }
            EnsureKeepaliveTask();
            Watch();
        }
        else if (new BoxView(_box).HasQqOrGame)
        {
            L("QQ still running -> watch until scan/game or user closes");
            Watch();
        }
        else
        {
            L("launch ended without game");
            Phase(waitingQrAtEnd ? BoxPhase.Failed : BoxPhase.Stopped, waitingQrAtEnd ? "等待扫码时浏览器被关闭" : "没能进入游戏，请查看日志");
        }
    }

    /// <summary>
    /// 历史快照里是否还有「未作废、且与当前 live 不同」的凭证值得一试。
    /// 注意：不能用 <see cref="Ilink.VaultCanHelp"/> —— 它只比较「金库 vs live」，
    /// 当两边是同一把 key 时返回 false，于是历史里的好 key 永远不会被尝试
    /// （qb15 11-05 00:42 弹码后就是这样被直接判成「必须扫码」，而历史里其实有能用的）。
    /// </summary>
    bool HistoryCanHelp()
    {
        try
        {
            var live = Ilink.Live(_box);
            var list = Ilink.CredentialHistory(_box)
                .Where(c => !c.Revoked)
                .Where(c => !live.Valid || c.KeyHash != live.KeyHash)
                .ToList();
            if (list.Count > 0) L($"history candidates available: {list.Count} ({string.Join(",", list.Take(5).Select(c => c.KeyShort))})");
            return list.Count > 0;
        }
        catch (Exception ex)
        {
            L("HistoryCanHelp error: " + ex.Message);
            return false;
        }
    }

    /// <summary>是否还有可试的历史凭证（不含当前 live 那把）。用于决定「弹扫码框时是否值得提前返回」。</summary>
    bool HistoryCandidatesExist()
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
    /// 逐个试历史凭证恢复免扫。**优先协议续期**（0.5 秒/把，不开浏览器），
    /// 协议明确拒绝就换下一把；只有网络类失败才回退冷启动验证。
    ///
    /// 为什么必须优先协议：弹扫码框时，冷启动验证每把要 1~2 分钟且反复重启沙箱，
    /// 10 把就是十几分钟；协议续期每把 0.5 秒，且能直接确认服务端是否认可这把 key。
    /// </summary>
    bool TryHistoryRecover()
    {
        var live = Ilink.Live(_box);
        var tryList = Ilink.CredentialHistory(_box)
            .Where(c => !c.Revoked)
            .Where(c => !live.Valid || c.KeyHash != live.KeyHash)
            .ToList();
        if (tryList.Count == 0) return false;

        var rec = new RecoverSession(_box);
        int i = 0;
        foreach (var c in tryList)
        {
            i++;
            L($"[{i}/{tryList.Count}] try historical key {c.KeyShort} ({c.SavedAt:MM-dd HH:mm}{(c.IsVault ? " · vault" : "")})");
            Phase(BoxPhase.Starting, $"正在用历史凭证恢复（{i}/{tryList.Count}）：试 {c.KeyShort}");

            // 先协议续期：成功即恢复完成，且已换成新 key
            try
            {
                var pr = rec.TryOneByProtocol(c);
                if (pr.Ok)
                {
                    L($"history recover OK (protocol) with key {c.KeyHash} -> {pr.NewKeyHash}");
                    Phase(BoxPhase.Stopped, "已用历史凭证恢复（协议续期），点「启动游戏」即可进入");
                    return true;
                }
                if (pr.Rejected)
                {
                    L($"[{i}/{tryList.Count}] key {c.KeyShort} rejected by server ({pr.Code}) -> next");
                    continue;
                }
                L($"[{i}/{tryList.Count}] key {c.KeyShort} protocol failed ({pr.Message}) -> try cold start for this key");
            }
            catch (Exception ex)
            {
                L($"history key {c.KeyShort} protocol error: {ex.Message}");
            }

            // 协议说不通（网络等）时才冷启动验证这一把
            try
            {
                if (rec.TryOne(c))
                {
                    L($"history recover OK (cold start) with key {c.KeyHash}");
                    try { Ilink.Save(_box, "history-recover"); } catch { }
                    Phase(BoxPhase.InGame, "已用历史凭证免扫恢复");
                    return true;
                }
            }
            catch (Exception ex)
            {
                L($"history key {c.KeyShort} error: {ex.Message}");
            }
            L($"[{i}/{tryList.Count}] key {c.KeyShort} still needs QR");
        }
        return false;
    }

    /// <param name="CredCleared">启动后运行时把凭证写成了无效，但没出现扫码页（不能算被顶掉）。</param>
    /// <param name="Suspected">凭证被清空且出现扫码页，但启动流程看不到服务端返回，先从金库还原重试一次。</param>
    sealed record WaitResult(bool Opened, bool NeedColdRetry, bool WaitingQr, bool SawQr, bool CredCleared = false, bool Suspected = false);

    WaitResult WaitForGame(LaunchBaseline baseline)
    {
        var deadline = DateTime.Now.AddMinutes(30);
        var coldStartDeadline = DateTime.Now.AddSeconds(180);
        var launchStarted = DateTime.Now;
        var lastLog = DateTime.MinValue;
        var lastCred = DateTime.MinValue;
        var lastTabClean = DateTime.MinValue;
        bool savedLogin = NeedScan.SavedLoginUsable(_box);
        bool revoked = false, credCleared = false, waitingQr = false, qrResumed = false, notedSavedQr = false, sawQr = false;
        bool sawApp = false, sawWx = false, gameUrlNudged = false, pageReloadDone = false;
        int mpFailTicks = 0, wxGoneAfterSeen = 0, missingAfterSeen = 0;
        DateTime? noUiSince = null, gameSince = null;
        // 有可用免扫凭证时，授权扫码层只是加载期过早弹出来的挡板：关掉它让 GameUrl 去自动授权。
        // 以前是原地等 60 秒就判「必须扫码」，但扫码层不下线时 ilink 根本不启动，AutoAuth 永远不会发出，
        // 等于必然失败（qb15 11-04 12:07 就是这样：手动关掉扫码框后 6 秒 AutoAuth ret=0 进游戏）。
        DateTime qrOverlaySince = DateTime.MinValue;
        int qrOverlayRounds = 0;
        const int qrOverlayMaxRounds = 2;
        const int qrOverlayWaitSec = 12;

        bool LogDue(int sec)
        {
            if ((DateTime.Now - lastLog).TotalSeconds < sec) return false;
            lastLog = DateTime.Now;
            return true;
        }

        while (DateTime.Now < deadline)
        {
            try
            {
                Thread.Sleep(2000);
                // 运行时启动后十几秒就会完成自动授权、换掉密钥，不等游戏窗口就先存
                if ((DateTime.Now - lastCred).TotalSeconds >= 15)
                {
                    try { Ilink.Save(_box, "launch"); } catch { }
                    lastCred = DateTime.Now;
                }
                // 运行时把凭证写成无效：只有同时出现扫码页才是真被顶掉 / 过期。
                // 实测（R7000P 10-29 14:12）也会无扫码页地清掉、下次冷启动又自己恢复，那种不能登记作废
                if (!revoked && !credCleared && baseline != null && Ilink.RevokedSinceLaunch(_box, baseline))
                {
                    credCleared = true;
                    L("credential cleared by runtime after launch -> wait; only a QR page confirms the key was revoked");
                }

                var v = new BoxView(_box);
                if (credCleared && !revoked && v.HasStrictQr)
                {
                    // 凭证清空 + 扫码页不足以确认被顶：不登记作废，先用金库同一把再冷启一次
                    if (savedLogin && !_suspectRetried && Ilink.VaultCanHelp(_box))
                    {
                        _suspectRetried = true;
                        return new(false, true, false, true, false, true);
                    }
                    else
                    {
                        revoked = true;
                        savedLogin = false;
                        NeedScan.Set(_box, _suspectRetried ? "suspected-revoked" : "launch-qr-after-clear");
                        Phase(BoxPhase.WaitingScan, "登录已失效，请用微信扫码");
                    }
                }
                if (v.CloseRestorePage()) L("closed 要恢复页面吗 dialog");
                if (!waitingQr && (DateTime.Now - lastTabClean).TotalSeconds >= 6)
                {
                    int n = Cdp.CloseExtraTabs(_box);
                    if (n > 0) L($"closed extra browser tabs via CDP count={n}");
                    lastTabClean = DateTime.Now;
                }

                if (v.HasMiniProgramFail(out var pt))
                {
                    mpFailTicks++;
                    gameSince = null;
                    if (mpFailTicks <= 4 && DateTime.Now >= _mpRetryNotBefore && v.ClickMiniProgramRetry(pt))
                    {
                        L("mini-program open failed -> click 再次尝试");
                        _mpRetryNotBefore = DateTime.Now.AddSeconds(8);
                    }
                    else if (mpFailTicks >= 8)
                    {
                        L("mini-program still failed -> cold relaunch");
                        return new(false, true, waitingQr, sawQr, credCleared && !revoked);
                    }
                    continue;
                }
                mpFailTicks = 0;

                // 加载页标题也是「向僵尸开炮」：标题窗稳定几秒且没出现失败页，或凭证已换新，才算进了游戏
                if (v.HasGameWindow)
                {
                    gameSince ??= DateTime.Now;
                    bool renewed = baseline != null && Ilink.RenewedSince(_box, baseline.LaunchUtc);
                    if (renewed || (DateTime.Now - gameSince.Value).TotalSeconds >= 8)
                    {
                        L($"game window confirmed (credential renewed={renewed})");
                        return new(true, false, false, sawQr, credCleared && !revoked);
                    }
                    continue;
                }
                gameSince = null;

                if (v.HasStrictQr)
                {
                    sawQr = true;
                    if (savedLogin && !waitingQr)
                    {
                        // 有可用免扫凭证时，这层授权页只是加载期过早弹出来的挡板：
                        // 它不下线，ilink 就不会启动，AutoAuth 永远发不出去，原地等必然失败。
                        // 所以先给运行时十几秒自己的机会，仍挡着就主动关掉并重开 GameUrl。
                        if (qrOverlaySince == DateTime.MinValue)
                        {
                            L("saved login: QR overlay ignored briefly, waiting for game window");
                            notedSavedQr = true;
                            qrOverlaySince = DateTime.Now;
                        }
                        else if ((DateTime.Now - qrOverlaySince).TotalSeconds >= qrOverlayWaitSec)
                        {
                            if (qrOverlayRounds < qrOverlayMaxRounds)
                            {
                                qrOverlayRounds++;
                                L($"saved login: QR overlay still up {qrOverlayWaitSec}s -> close it and reopen GameUrl (round {qrOverlayRounds}/{qrOverlayMaxRounds})");
                                // 到这里才算「授权层挡住了免扫」：用户没扫码，程序主动关掉它。
                                // 不必在这里重开 GameUrl——下面「扫码层消失」分支会做，避免重复拉起。
                                ScanHint.MarkOverlay(_box);
                                try { v.CloseQrPage(); } catch (Exception ex) { L("close QR page failed: " + ex.Message); }
                                qrOverlaySince = DateTime.Now;
                                launchStarted = DateTime.Now;
                                qrResumed = false;   // 关掉后由「扫码层消失」分支重开 GameUrl，允许每轮都重开
                                continue;
                            }
                            // 关掉两轮仍回来，才认为这次真的需要扫码
                            if (!revoked && Ilink.VaultCanHelp(_box))
                            {
                                L("saved login: QR overlay came back after dismiss -> cold retry once");
                                return new(false, true, false, sawQr, credCleared && !revoked);
                            }
                            L("saved login stale: QR overlay kept coming back -> hand over to history recovery");
                            savedLogin = false;
                            waitingQr = true;
                            qrResumed = false;
                            NeedScan.Set(_box, "saved-login-stale-qr");
                            ScanHint.MarkQrScan(_box);
                            Phase(BoxPhase.WaitingScan, "需要用微信扫码登录");
                            v.ShowQrWindow();
                            // 有历史凭证可试时提前返回：外层会用协议续期逐把确认（0.5 秒/把），
                            // 比在这里干等用户扫码快得多（qb10/qb12 就是这样白等了好几天的）。
                            // 没有历史凭证就继续等扫码，不打断正常流程。
                            if (HistoryCandidatesExist() && !_historyExhausted) return new(false, false, true, sawQr, credCleared && !revoked);
                        }
                        continue;
                    }
                    if (!waitingQr)
                    {
                        waitingQr = true;
                        qrResumed = false;
                        L("strict QR auth page detected -> wait for WeChat scan | titles=" + v.TitlesSample());
                        v.ShowQrWindow();
                        NeedScan.Set(_box, revoked ? "key-revoked" : "strict-qr-auth-page");
                        ScanHint.MarkQrScan(_box);
                        Phase(BoxPhase.WaitingScan, "需要用微信扫码登录");
                        // 同上：有历史凭证就先让外层试协议续期，不打断「确实需要扫码」的正常流程。
                        if (HistoryCandidatesExist() && !_historyExhausted) return new(false, false, true, sawQr, credCleared && !revoked);
                    }
                    else if (LogDue(60))
                    {
                        L("still waiting for QR scan...");
                        v.ShowQrWindow();
                    }
                    continue;
                }

                // 扫码页消失：通常表示已扫码（或程序刚把加载期授权层关掉），要重新打开游戏页，
                // 否则会卡在授权后的空白页
                if ((waitingQr || notedSavedQr) && !qrResumed)
                {
                    L(waitingQr
                        ? "QR page gone (scanned) -> reopen GameUrl and wait for game (no sandbox restart needed)"
                        : "QR overlay gone -> reopen GameUrl and wait for game");
                    Phase(BoxPhase.Starting, waitingQr ? "已扫码，正在进入游戏…" : "正在进入游戏…");
                    try { BoxRuntime.StartBrowser(_box, "post-scan"); } catch (Exception ex) { L("post-scan reopen failed: " + ex.Message); }
                    qrResumed = true;
                    waitingQr = false;
                    gameUrlNudged = true;
                    launchStarted = DateTime.Now;
                    sawWx = false;
                    wxGoneAfterSeen = 0;
                    continue;
                }

                if (v.WeChatRuntimeUp)
                {
                    sawWx = true;
                    double wxWait = (DateTime.Now - launchStarted).TotalSeconds;
                    if (savedLogin)
                    {
                        if (!gameUrlNudged && wxWait >= 20 && !Cdp.HasGameCenterTab(_box))
                        {
                            L("saved login: game center tab missing -> reopen GameUrl once");
                            BoxRuntime.StartBrowser(_box, "nudge");
                            gameUrlNudged = true;
                            launchStarted = DateTime.Now;
                        }
                        else if (!pageReloadDone && wxWait >= 35)
                        {
                            L("saved login: WeChat up 35s without game -> CDP reload game-center");
                            Cdp.ReloadGameCenter(_box);
                            pageReloadDone = true;
                            launchStarted = DateTime.Now;
                        }
                        else if (!gameUrlNudged && wxWait >= 50)
                        {
                            if (Cdp.HasQrTab(_box) || notedSavedQr)
                            {
                                L("saved login: QR still up with no game -> cold relaunch");
                                return new(false, true, false, sawQr, credCleared && !revoked);
                            }
                            L("saved login: still no game after reload -> reopen GameUrl once");
                            BoxRuntime.StartBrowser(_box, "nudge");
                            gameUrlNudged = true;
                            launchStarted = DateTime.Now;
                        }
                        else if (gameUrlNudged && wxWait >= 50)
                        {
                            L("saved login: still no game after GameUrl nudge -> cold relaunch");
                            return new(false, true, false, sawQr, credCleared && !revoked);
                        }
                        else if (LogDue(20)) L("saved login: WeChat up, waiting for game window...");
                        continue;
                    }
                    if (!waitingQr && !gameUrlNudged && wxWait >= 90)
                    {
                        if (Cdp.HasQrTab(_box)) { waitingQr = true; continue; }
                        L("WeChat up 90s without game -> reopen GameUrl once");
                        BoxRuntime.StartBrowser(_box, "nudge");
                        gameUrlNudged = true;
                        launchStarted = DateTime.Now;
                        continue;
                    }
                    if (!waitingQr && wxWait >= 120)
                    {
                        L("WeChat runtime up without game after GameUrl nudge -> cold relaunch");
                        return new(false, true, false, sawQr, credCleared && !revoked);
                    }
                }

                if (v.HasWeChat) { sawWx = true; wxGoneAfterSeen = 0; }
                else if (sawWx) wxGoneAfterSeen++;

                // 浏览器还在但微信运行时刚起就死 = 典型 SBIE1231
                if (sawApp && sawWx && wxGoneAfterSeen >= 3 && (DateTime.Now - launchStarted).TotalSeconds < 120)
                {
                    L("WeChatAppEx died after start (SBIE1231 likely) -> cold relaunch");
                    return new(false, true, waitingQr, sawQr, credCleared && !revoked);
                }

                if (!v.HasQqOrGame)
                {
                    if (waitingQr)
                    {
                        L("box ended while waiting for QR");
                        return new(false, false, true, sawQr, credCleared && !revoked);
                    }
                    if (!sawApp)
                    {
                        double waitSec = (DateTime.Now - launchStarted).TotalSeconds;
                        if (LogDue(15)) L($"waiting for QQBrowser process... {waitSec:F0}s");
                        if (waitSec >= 45 && !gameUrlNudged)
                        {
                            L("no QQBrowser process 45s after start -> re-issue Start.exe once");
                            BoxRuntime.StartBrowser(_box, "re-issue");
                            gameUrlNudged = true;
                            launchStarted = DateTime.Now;
                            coldStartDeadline = DateTime.Now.AddSeconds(180);
                        }
                        else if (DateTime.Now > coldStartDeadline)
                        {
                            L("cold start timeout (no process)");
                            return new(false, true, false, sawQr, credCleared && !revoked);
                        }
                        continue;
                    }
                    if (++missingAfterSeen >= 4)
                    {
                        L("box died before game (cold start)");
                        return new(false, true, false, sawQr, credCleared && !revoked);
                    }
                    continue;
                }
                sawApp = true;
                missingAfterSeen = 0;

                if (v.HasVisibleUi)
                {
                    noUiSince = null;
                    double uiWait = (DateTime.Now - launchStarted).TotalSeconds;
                    if (LogDue(30)) L("browser UI (not QR) -> wait for game...");
                    if (!sawWx && !waitingQr && !pageReloadDone && uiWait >= 40)
                    {
                        L("UI 40s without WeChat -> CDP reload game-center once");
                        Cdp.ReloadGameCenter(_box);
                        pageReloadDone = true;
                        launchStarted = DateTime.Now;
                        continue;
                    }
                    if (!sawWx && !waitingQr && uiWait >= 90)
                    {
                        L("UI 90s without WeChat runtime -> cold relaunch");
                        return new(false, true, false, sawQr, credCleared && !revoked);
                    }
                    continue;
                }

                noUiSince ??= DateTime.Now;
                double noUi = (DateTime.Now - noUiSince.Value).TotalSeconds;
                if (!gameUrlNudged && noUi >= 20)
                {
                    L("QQ process up but no window 20s -> show browser and reopen GameUrl");
                    v.ShowBrowser();
                    BoxRuntime.StartBrowser(_box, "no-window");
                    gameUrlNudged = true;
                    noUiSince = DateTime.Now;
                    launchStarted = DateTime.Now;
                }
                else if (noUi >= 90)
                {
                    L("QQ process up 90s without a window -> cold relaunch");
                    return new(false, true, false, sawQr, credCleared && !revoked);
                }
                else if (LogDue(30)) L("QQ loading, waiting...");
            }
            catch (Exception ex)
            {
                L("launch wait error: " + ex.Message);
            }
        }
        L("launch wait timeout (30 min)");
        return new(false, false, waitingQr, sawQr, credCleared && !revoked);
    }

    /// <summary>看门：游戏开着时定时存凭证、藏浏览器；玩家关游戏后停箱。</summary>
    /// <summary>新沙箱第一次扫码进游戏后才有可保活的凭证，此时补登记计划任务。</summary>
    void EnsureKeepaliveTask()
    {
        try
        {
            var cfg = Keepalive.Load();
            if (cfg.EnabledFor(_box) && !Keepalive.TaskPointsHere(_box)) Keepalive.SyncTask(_box, cfg);
        }
        catch (Exception ex) { L("keepalive task sync failed: " + ex.Message); }
    }

    void Watch()
    {
        using var cts = new CancellationTokenSource();
        var roles = Task.Run(() => RoleLoop(cts.Token));
        try { WatchLoop(); }
        finally
        {
            cts.Cancel();
            try { roles.Wait(5000); } catch { }
        }
    }

    /// <summary>
    /// 后台读角色名和攻击力：进游戏后每 10 秒试一次，读全了改为每 30 分钟更新一次攻击力；
    /// 20 分钟还没读全就放慢到每 5 分钟（避免一直扫游戏内存）。
    /// </summary>
    void RoleLoop(CancellationToken ct)
    {
        var started = DateTime.MinValue;
        var lastTry = DateTime.MinValue;
        bool name = false, attack = false, gaveUpLogged = false;
        while (!ct.WaitHandle.WaitOne(3000))
        {
            try
            {
                if (!new BoxView(_box).HasGameWindow) continue;
                if (started == DateTime.MinValue) { started = DateTime.Now; lastTry = DateTime.Now.AddSeconds(-5); }
                var interval = name && attack ? TimeSpan.FromMinutes(30)
                    : DateTime.Now - started > TimeSpan.FromMinutes(20) ? TimeSpan.FromMinutes(5)
                    : TimeSpan.FromSeconds(10);
                if (!name || !attack)
                    if (DateTime.Now - started > TimeSpan.FromMinutes(20) && !gaveUpLogged)
                    {
                        gaveUpLogged = true;
                        L($"role read incomplete after 20 min (name={name} attack={attack}) -> retry every 5 min");
                    }
                if (DateTime.Now - lastTry < interval) continue;
                lastTry = DateTime.Now;
                var r = RoleCapture.ReadOnce(_box);
                name |= r.NameFound;
                attack |= r.AttackFound;
            }
            catch (Exception ex) { L("role read error: " + ex.Message); lastTry = DateTime.Now; }
        }
    }

    void WatchLoop()
    {
        L("watch start");
        bool hadGame = false, sawQr = false, qrResumed = false, wxNudged = false;
        int goneTicks = 0, uiGoneTicks = 0;
        var lastCred = DateTime.MinValue;
        var lastKeep = DateTime.MinValue;
        var lastPkg = DateTime.Now;
        var lastOverdueWarn = DateTime.MinValue;
        var lastLog = DateTime.MinValue;
        var updateSince = DateTime.MinValue;
        var waitGameDeadline = DateTime.Now.AddMinutes(30);
        var gameStartedAt = DateTime.MinValue;
        DateTime? wxNoGameSince = null;
        bool updateRestartDone = false;

        while (true)
        {
            Thread.Sleep(2000);
            BoxView v;
            try { v = new BoxView(_box); }
            catch { continue; }
            if (!v.HasQqOrGame)
            {
                L(hadGame ? "box empty after game, watch end" : "box empty (browser closed), watch end");
                try { Ilink.Save(_box, "watch-end"); } catch { }
                Phase(BoxPhase.Stopped, hadGame ? "游戏已关闭" : "浏览器已关闭");
                break;
            }
            if ((DateTime.Now - lastCred).TotalSeconds >= 30)
            {
                try { Ilink.Save(_box, "watch"); } catch { }
                try { NeedScan.ClearIfRenewed(_box); } catch { }
                lastCred = DateTime.Now;
            }

            if (v.HasGameWindow)
            {
                if (!hadGame) { gameStartedAt = DateTime.Now; Phase(BoxPhase.InGame, "游戏中"); }
                hadGame = true;
                goneTicks = 0;
                uiGoneTicks = 0;
                wxNoGameSince = null;

                // 进游戏后的前两分钟仍可能卡在「暂无法打开小程序」
                if ((DateTime.Now - gameStartedAt).TotalMinutes < 2 && DateTime.Now >= _mpRetryNotBefore && v.HasMiniProgramFail(out var pt))
                {
                    if (v.ClickMiniProgramRetry(pt)) L("watch: mini-program fail -> click 再次尝试");
                    _mpRetryNotBefore = DateTime.Now.AddSeconds(10);
                }

                if (v.HasGameUpdateDialog)
                {
                    if (updateSince == DateTime.MinValue) updateSince = DateTime.Now;
                    if (!updateRestartDone && (DateTime.Now - updateSince).TotalSeconds >= 10)
                    {
                        updateRestartDone = true;
                        SoftRestartForUpdate(v);
                        updateSince = DateTime.MinValue;
                        // 重启期间游戏窗会消失，不能当成玩家关了游戏
                        hadGame = false;
                        waitGameDeadline = DateTime.Now.AddMinutes(10);
                    }
                    continue;
                }
                updateSince = DateTime.MinValue;

                if ((DateTime.Now - lastKeep).TotalSeconds >= 30)
                {
                    v.HideBrowserKeepGame(true);
                    lastKeep = DateTime.Now;
                }
                if ((DateTime.Now - lastPkg).TotalMinutes >= 10)
                {
                    lastPkg = DateTime.Now;
                    try { if (VaultSync.LivePackageNewerThanVault(_box)) VaultSync.HarvestGamePackage(_box); } catch { }
                }

                // 密钥到硬上限：游戏正在跑时**不打断玩家**。
                // 运行中不能用协议续期（服务端作废旧 key 后运行时会把旧值写回文件、并断掉游戏会话，见 6F），
                // 也不能只重开 GameUrl（app session 仍有效，运行时不会发 AutoAuth，见 9A.2）。
                // 所以这里只记警告，等游戏关掉的第一时间再续（见下方 goneTicks 分支 / 常驻循环）。
                if (ProtocolRenew.KeyOverdue(_box))
                {
                    _renewPending = true;
                    if ((DateTime.Now - lastOverdueWarn).TotalHours >= 1)
                    {
                        lastOverdueWarn = DateTime.Now;
                        L($"watch: key is {ProtocolRenew.KeyAgeText(_box)} old (limit {ProtocolRenew.KeyMaxAgeHours}h) "
                          + "-> will renew as soon as the game closes (not interrupting play)");
                    }
                }
                TakeRenewRequest();
                continue;
            }

            if (hadGame)
            {
                goneTicks++;
                L($"game window missing tick={goneTicks}");
                if (goneTicks == 1) try { Ilink.Save(_box, "game-closing"); } catch { }
                if (goneTicks >= 3)
                {
                    // 游戏刚关：这是协议续期最安全的时机（运行时已退出，不会再把旧 key 写回文件）。
                    // 密钥超龄或保活留下请求时，先停箱换钥，再按原逻辑决定进常驻还是停箱。
                    if (_renewPending || ProtocolRenew.KeyOverdue(_box) || TakeRenewRequest())
                    {
                        _renewPending = false;
                        L($"watch: game closed with key {ProtocolRenew.KeyAgeText(_box)} old -> protocol renew before stopping");
                        BoxRuntime.StopSoft(_box, true);
                        Thread.Sleep(1500);
                        BoxRuntime.StopForce(_box, false);
                        RenewWhenStopped();
                        // 续完再看要不要进常驻（常驻需要运行时，重开一次让它起来）
                        if (Keepalive.Load().For(_box).ResidentKeepalive)
                        {
                            try { BoxRuntime.StartBrowser(_box, "renew-then-resident"); } catch { }
                            Thread.Sleep(5000);
                            if (EnterResident())
                            {
                                hadGame = true;
                                goneTicks = 0;
                                uiGoneTicks = 0;
                                wxNoGameSince = null;
                                continue;
                            }
                        }
                        break;
                    }
                    if (Keepalive.Load().For(_box).ResidentKeepalive)
                    {
                        if (EnterResident())
                        {
                            hadGame = true;
                            goneTicks = 0;
                            uiGoneTicks = 0;
                            wxNoGameSince = null;
                            continue;
                        }
                        break;
                    }
                    L("game closed -> stop box (save credential)");
                    Phase(BoxPhase.Stopped, "游戏已关闭，正在保存…");
                    BoxRuntime.StopSoft(_box, true);
                    Phase(BoxPhase.Stopped, "游戏已关闭");
                    L("box stopped");
                    break;
                }
                continue;
            }

            if (v.HasStrictQr)
            {
                uiGoneTicks = 0;
                if (!sawQr)
                {
                    sawQr = true;
                    NeedScan.Set(_box, "watch-qr");
                    ScanHint.MarkQrScan(_box);
                    Phase(BoxPhase.WaitingScan, "需要用微信扫码登录");
                }
                if ((DateTime.Now - lastLog).TotalSeconds >= 60)
                {
                    L("watch: waiting for QR scan...");
                    lastLog = DateTime.Now;
                    v.ShowQrWindow();
                }
                continue;
            }
            if (sawQr && !qrResumed)
            {
                L("watch: QR gone after scan -> reopen GameUrl");                Phase(BoxPhase.Starting, "已扫码，正在进入游戏…");
                try { BoxRuntime.StartBrowser(_box, "post-scan"); } catch { }
                qrResumed = true;
                waitGameDeadline = DateTime.Now.AddMinutes(15);
                continue;
            }

            if (v.WeChatRuntimeUp)
            {
                uiGoneTicks = 0;
                wxNoGameSince ??= DateTime.Now;
                if (!wxNudged && (DateTime.Now - wxNoGameSince.Value).TotalSeconds >= 90)
                {
                    L("watch: WeChat 90s without game title -> reopen GameUrl");
                    try { BoxRuntime.StartBrowser(_box, "watch-nudge"); } catch { }
                    wxNudged = true;
                    wxNoGameSince = DateTime.Now;
                }
                continue;
            }
            wxNoGameSince = null;

            if (v.HasVisibleUi) uiGoneTicks = 0;
            else if (++uiGoneTicks >= 4)
            {
                L("browser closed without game -> stop box");
                BoxRuntime.StopSoft(_box, false);
                Phase(BoxPhase.Stopped, "浏览器已关闭");
                break;
            }
            if (DateTime.Now > waitGameDeadline)
            {
                L("watch timeout -> stop box");
                BoxRuntime.StopSoft(_box, false);
                Phase(BoxPhase.Failed, "等了 30 分钟没进游戏，已停止");
                break;
            }
        }
    }

    /// <summary>
    /// 关游戏后常驻：存凭证、藏窗压内存，保留 QQBrowser+WeChatAppEx 上的 ilink。
    /// 返回 true = 游戏窗又回来了，继续 WatchLoop；false = 结束看门。
    /// </summary>
    bool EnterResident()
    {
        L("game closed -> enter resident (hide+trim, keep ilink runtime)");
        Phase(BoxPhase.Resident, "常驻保活中（轻量）");
        try { Ilink.Save(_box, "enter-resident"); } catch { }
        try
        {
            var first = new BoxView(_box);
            first.TrimResident();
        }
        catch { }

        int failStreak = 0;
        int ilinkDownTicks = 0;
        var lastTrim = DateTime.MinValue;
        var lastCred = DateTime.MinValue;
        var lastLog = DateTime.MinValue;
        // 常驻期间要周期性做一次真实 AutoAuth 把密钥往前滚，否则只存 psk、密钥一路放到自然寿命就弹码
        // （qb4 在 1.5.3 上就是这样：11-03 11:23 进常驻，此后从不滚 key，11-04 08:40 弹扫码）。
        // 计时从「密钥实际写入时间」起算：从游戏里滚出来的新钥匙不必刚进常驻就再滚一次。
        var lastRenew = DateTime.Now;
        try
        {
            var st = Ilink.Live(_box);
            if (st.Valid && st.WriteUtc != DateTime.MinValue)
            {
                var age = DateTime.UtcNow - st.WriteUtc;
                if (age > TimeSpan.Zero) lastRenew = DateTime.Now - age;
            }
        }
        catch { }
        bool sawQr = false;

        while (true)
        {
            Thread.Sleep(2000);
            BoxView v;
            try { v = new BoxView(_box); }
            catch { continue; }

            if (!v.HasQqOrGame)
            {
                L("resident: box empty -> end");
                try { Ilink.Save(_box, "resident-end"); } catch { }
                Phase(BoxPhase.Stopped, "常驻已结束");
                return false;
            }

            if (v.HasGameWindow)
            {
                L("resident: game window back -> resume watch");
                Phase(BoxPhase.InGame, "游戏中");
                v.ShowGameWindow();
                return true;
            }

            if (v.HasStrictQr)
            {
                if (!sawQr)
                {
                    sawQr = true;
                    NeedScan.Set(_box, "resident-qr");
                    Phase(BoxPhase.WaitingScan, "需要用微信扫码登录");
                    L("resident: QR appeared");
                }
                if ((DateTime.Now - lastLog).TotalSeconds >= 60)
                {
                    v.ShowQrWindow();
                    lastLog = DateTime.Now;
                }
                continue;
            }
            if (sawQr)
            {
                // 扫完码后复开游戏页，仍留在常驻循环等游戏窗
                L("resident: QR gone after scan -> reopen GameUrl");
                Phase(BoxPhase.Starting, "已扫码，正在进入游戏…");
                try { BoxRuntime.StartBrowser(_box, "resident-post-scan"); } catch { }
                sawQr = false;
                Phase(BoxPhase.Resident, "常驻保活中（轻量）");
                continue;
            }

            if ((DateTime.Now - lastCred).TotalSeconds >= 30)
            {
                try { Ilink.Save(_box, "resident"); } catch { }
                lastCred = DateTime.Now;
            }

            if ((DateTime.Now - lastTrim).TotalSeconds >= 30)
            {
                try { v.TrimResident(); } catch { }
                lastTrim = DateTime.Now;
                Phase(BoxPhase.Resident, "常驻保活中（轻量）");
            }

            var keyAge = LiveKeyAgeHours();
            bool keyAging = keyAge != null && keyAge.Value >= ResidentKeyMaxAgeHours;
            if ((DateTime.Now - lastRenew).TotalHours >= ResidentRenewHours || keyAging || TakeRenewRequest())
            {
                if (keyAging) L($"resident: key is {keyAge:F1}h old (limit {ResidentKeyMaxAgeHours}h) -> renew now");
                lastRenew = DateTime.Now;
                ResidentRenew(); // 出扫码页时不藏窗，主循环下一轮看到扫码页转入 need-scan
                continue;
            }

            // 主进程在、但 ilink 长连接进程没了（关游戏后服务端下发 sessiontimeout 会让它自己退出）。
            // 以前这里只看主进程，于是整段常驻都在「假长连接」空转，密钥一路放到自然寿命就弹码。
            if (!v.IlinkConnected)
            {
                ilinkDownTicks++;
                if (ilinkDownTicks == 1)
                    L("resident: WeChat main is up but ilink long-link process is gone -> reopen game to re-establish it");
                Phase(BoxPhase.Resident, "常驻长连接已断，正在重连…");
                // 重开 GameUrl 会拉起 ILinkServiceHost 并触发一次 AutoAuth，同时顺手把密钥往前滚
                if (ilinkDownTicks >= 2)
                {
                    ilinkDownTicks = 0;
                    try { BoxRuntime.StartBrowser(_box, "resident-relink"); }
                    catch (Exception ex) { L("resident relink: " + ex.Message); }
                    lastRenew = DateTime.Now;
                }
                continue;
            }
            if (ilinkDownTicks > 0)
            {
                L("resident: ilink long-link is back");
                ilinkDownTicks = 0;
            }

            if (v.WeChatRuntimeUp)
            {
                failStreak = 0;
                continue;
            }

            failStreak++;
            L($"resident: WeChat runtime down -> recover (streak={failStreak})");
            Phase(BoxPhase.Resident, "常驻运行时恢复中…");
            try { BoxRuntime.StartBrowser(_box, "resident-recover", BoxRuntime.LaunchMode.RuntimeOnly); }
            catch (Exception ex) { L("resident RuntimeOnly: " + ex.Message); }
            Thread.Sleep(5000);
            v = new BoxView(_box);
            if (!v.WeChatRuntimeUp)
            {
                try { BoxRuntime.StartBrowser(_box, "resident-recover-full", BoxRuntime.LaunchMode.Full); }
                catch (Exception ex) { L("resident Full: " + ex.Message); }
                Thread.Sleep(8000);
                try { new BoxView(_box).TrimResident(); } catch { }
            }

            v = new BoxView(_box);
            if (v.WeChatRuntimeUp)
            {
                failStreak = 0;
                Phase(BoxPhase.Resident, "常驻保活中（轻量）");
                continue;
            }
            if (failStreak >= 3)
            {
                L("resident: recover failed repeatedly -> stop, next launch needs cold start");
                try { Ilink.Save(_box, "resident-give-up"); } catch { }
                BoxRuntime.StopSoft(_box, true);
                Phase(BoxPhase.Stopped, "常驻运行时已挂，下次需冷启动");
                return false;
            }
        }
    }

    /// <summary>
    /// 常驻每隔多少小时主动重开游戏做一次真实 AutoAuth（远小于免扫链约一天的寿命）。
    /// </summary>
    const double ResidentRenewHours = 6;

    /// <summary>
    /// 密钥年龄到这个阈值就必须续期：实测免扫链约一天就撞墙，留 4 小时余量。
    /// 已统一到 <see cref="ProtocolRenew.KeyMaxAgeHours"/>，这里是同一数值的别名。
    /// </summary>
    const double ResidentKeyMaxAgeHours = ProtocolRenew.KeyMaxAgeHours;

    /// <summary>当前这把密钥空闲多久了（小时）；没有有效凭证时返回 null。</summary>
    double? LiveKeyAgeHours() => ProtocolRenew.KeyAgeHours(_box);

    /// <summary>
    /// 取一次保活计划任务留下的续期请求（logs\qbN.renew）：有就删掉并返回 true。
    /// 计划任务拿不到沙箱锁时会写这个文件，让常驻进程代替它做一次真实 AutoAuth。
    /// </summary>
    bool TakeRenewRequest()
    {
        var p = AppPaths.BoxRenewRequest(_box);
        try
        {
            if (!File.Exists(p)) return false;
            File.Delete(p);
            L("resident: keepalive task asked for a renew -> doing it now");
            return true;
        }
        catch { return false; }
    }

    enum ResidentRenewResult { Rolled, NotRolled, NeedScan }

    /// <summary>
    /// 沙箱已经停掉（运行时不在）时的续期：这是协议续期唯一安全的状态，
    /// 因为没有进程会用内存里的旧 key 把文件写回（见 mmtls 研究 6F）。
    /// 成功就换一把新 key；失败保留 attempt 标记，下次保活再试。
    /// </summary>
    void RenewWhenStopped()
    {
        var (renewable, why) = ProtocolRenew.CheckRenewable(_box);
        if (!renewable)
        {
            L("watch renew: still busy after stop -> skip: " + why.Split('\n')[0]);
            return;
        }
        var r = ProtocolRenew.Renew(_box);
        if (r.Ok)
        {
            L($"watch renew: ok, new key {r.NewKeyHash} (key age reset)");
            try { VaultSync.PushVaultToLive(_box); } catch { }
            BoxStatusFile.Write(_box, BoxPhase.Stopped, "已停箱（密钥已续期）");
        }
        else
        {
            L("watch renew: failed -> " + r.Message);
            // 被服务端明确拒绝：这把 key 真不能用了
            if (r.Code is -13 or -14)
            {
                NeedScan.Set(_box, "renew-revoked");
                BoxStatusFile.Write(_box, BoxPhase.Failed, "密钥已被服务端作废，需要重新扫码");
            }
        }
    }

    /// <summary>
    /// 常驻真实续期：重开游戏让运行时发一次 AutoAuth，把 AutoAuthKey 往前滚并存金库，再藏回去。
    /// 关游戏窗时 app 会话本就会超时，真正决定能不能免扫重进的是这把 key 还在不在寿命内——所以常驻必须周期性真滚它，而不是只存 psk。
    /// </summary>
    ResidentRenewResult ResidentRenew()
    {
        L("resident: periodic renew -> reopen game to roll AutoAuthKey");
        Phase(BoxPhase.Resident, "常驻续期中…");
        var frozen = Ilink.Live(_box).KeyHash;
        try { BoxRuntime.StartBrowser(_box, "resident-renew"); }
        catch (Exception ex) { L("resident renew start: " + ex.Message); }

        var deadline = DateTime.Now.AddSeconds(120);
        var result = ResidentRenewResult.NotRolled;
        while (DateTime.Now < deadline)
        {
            Thread.Sleep(3000);
            BoxView v;
            try { v = new BoxView(_box); }
            catch { continue; }
            if (v.HasStrictQr)
            {
                L("resident renew: QR appeared -> key dead, need scan");
                return ResidentRenewResult.NeedScan; // 不藏窗，留着扫码页让主循环接手
            }
            var live = Ilink.Live(_box);
            if (live.Valid && live.KeyHash.Length > 0 && live.KeyHash != frozen)
            {
                Ilink.Save(_box, "resident-renew");
                L($"resident renew: key rolled {frozen} -> {live.KeyHash}");
                result = ResidentRenewResult.Rolled;
                break;
            }
        }
        if (result != ResidentRenewResult.Rolled)
        {
            try { Ilink.Save(_box, "resident-renew-nokeyroll"); } catch { }
            L("resident renew: key not rolled within window (will retry next cycle)");
        }
        try { new BoxView(_box).TrimResident(); } catch { } // 关游戏窗 + 藏壳 + 压 QQ 内存，回到轻量态
        Phase(BoxPhase.Resident, "常驻保活中（轻量）");
        return result;
    }

    /// <summary>游戏弹「版本已经更新，请重启」：确认 → 关微信运行时 → 重新打开游戏。</summary>
    void SoftRestartForUpdate(BoxView v)
    {
        L("game update dialog lingered -> soft-restart once");
        Phase(BoxPhase.Starting, "游戏更新了，正在自动重启游戏…");
        try { VaultSync.HarvestGamePackage(_box); } catch { }
        var upd = v.FindTitle(Titles.IsGameUpdateRestart, true);
        if (upd != IntPtr.Zero)
        {
            Win32.ShowWindow(upd, Win32.SW_RESTORE);
            Win32.SetForegroundWindow(upd);
            Thread.Sleep(250);
            Win32.PressEnter();
            Win32.ClickWindowRatio(upd, 0.5, 0.72);
            Thread.Sleep(1000);
        }
        var game = v.GameHwnd;
        if (game != IntPtr.Zero) Win32.PostMessage(game, Win32.WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
        Thread.Sleep(2000);
        int killed = 0;
        foreach (var pid in Sandboxie.Pids(_box))
            if (ProcessUtil.NameOf(pid) is "WeChatAppEx" or "WeChatAppHost") { ProcessUtil.Kill(pid); killed++; }
        L($"update restart: closed WeChat runtime procs={killed}");
        Thread.Sleep(2000);
        BoxRuntime.StartBrowser(_box, "update-restart");
    }
}
