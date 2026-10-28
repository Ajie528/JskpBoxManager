namespace JskpBoxManager.Core;

/// <summary>
/// 「启动游戏」的后台流程（JskpBoxManager.exe launch qbN）：准备凭证 → 拉起浏览器 → 等游戏或扫码 → 看门。
/// 看门期间定时存凭证；玩家关掉游戏后停箱并做最后一次保存。
/// </summary>
public sealed class LaunchSession
{
    readonly string _box;
    DateTime _mpRetryNotBefore = DateTime.MinValue;

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
            // 已有一个启动/看门进程：把已有界面拉到前台就行
            var v = new BoxView(_box);
            if (v.HasGameWindow) { v.ShowGameWindow(); L("already running -> show game window"); }
            else if (v.HasStrictQr) { v.ShowQrWindow(); L("already running -> show QR window"); }
            else L("already running (launcher busy) -> skip duplicate launch");
            return 0;
        }
        BoxRuntime.RegisterLauncher(_box, "launch");
        try
        {
            RunLocked();
        }
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

    void RunLocked()
    {
        if (!EnvDetect.SbieOk) throw new InvalidOperationException("找不到 Sandboxie-Plus");
        if (!EnvDetect.QqOk) throw new InvalidOperationException("找不到 QQ 浏览器");
        Phase(BoxPhase.Starting, "正在启动…");
        if (NeedScan.Pending(_box)) L("need-scan pending -> ignore saved login, wait for WeChat QR");

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
        }

        bool opened = false, waitingQrAtEnd = false, didVaultRestore = false, forceFullWarmup = false;
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
            if (result.NeedColdRetry && attempt < maxAttempts)
            {
                L($"cold start failed -> retry {attempt}/{maxAttempts}");
                Phase(BoxPhase.Starting, $"启动没成功，正在重试（{attempt}/{maxAttempts}）…");
                BoxRuntime.StopForce(_box, false);
                BoxRuntime.RegisterLauncher(_box, "launch");
                Thread.Sleep(6000);
                BoxRuntime.WaitRpcReady(_box, 90);
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                if (!didVaultRestore)
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

    sealed record WaitResult(bool Opened, bool NeedColdRetry, bool WaitingQr, bool SawQr);

    WaitResult WaitForGame(LaunchBaseline baseline)
    {
        var deadline = DateTime.Now.AddMinutes(30);
        var coldStartDeadline = DateTime.Now.AddSeconds(180);
        var launchStarted = DateTime.Now;
        var lastLog = DateTime.MinValue;
        var lastCred = DateTime.MinValue;
        var lastTabClean = DateTime.MinValue;
        bool savedLogin = NeedScan.SavedLoginUsable(_box);
        bool revoked = false, waitingQr = false, qrResumed = false, notedSavedQr = false, sawQr = false;
        bool sawApp = false, sawWx = false, gameUrlNudged = false, pageReloadDone = false;
        int mpFailTicks = 0, wxGoneAfterSeen = 0, missingAfterSeen = 0;
        DateTime? noUiSince = null, gameSince = null;

        bool LogDue(int sec)
        {
            if ((DateTime.Now - lastLog).TotalSeconds < sec) return false;
            lastLog = DateTime.Now;
            return true;
        }

        while (DateTime.Now < deadline)
        {
            Thread.Sleep(2000);
            try
            {
                // 运行时启动后十几秒就会完成自动授权、换掉密钥，不等游戏窗口就先存
                if ((DateTime.Now - lastCred).TotalSeconds >= 15)
                {
                    try { Ilink.Save(_box, "launch"); } catch { }
                    lastCred = DateTime.Now;
                }
                // 服务端拒绝了这次自动授权（被别的设备扫码顶掉，或过期）：金库同一把也没用，直接等扫码
                if (!revoked && baseline != null && Ilink.RevokedSinceLaunch(_box, baseline))
                {
                    revoked = true;
                    Ilink.RegisterRevoked(_box, baseline, "launch");
                    savedLogin = false;
                    NeedScan.Set(_box, "key-revoked");
                    Phase(BoxPhase.WaitingScan, "登录已失效（可能在别的设备扫码登录过），请用微信扫码");
                }

                var v = new BoxView(_box);
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
                        return new(false, true, waitingQr, sawQr);
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
                        return new(true, false, false, sawQr);
                    }
                    continue;
                }
                gameSince = null;

                if (v.HasStrictQr)
                {
                    sawQr = true;
                    if (savedLogin && !waitingQr)
                    {
                        // 有可用备份时扫码层先忽略一会儿（真能免扫会自己进游戏）
                        if (!notedSavedQr)
                        {
                            L("saved login: QR overlay ignored briefly, waiting for game window");
                            notedSavedQr = true;
                            launchStarted = DateTime.Now;
                        }
                        else if ((DateTime.Now - launchStarted).TotalSeconds >= 60)
                        {
                            if (!revoked && Ilink.VaultCanHelp(_box))
                            {
                                L("QR still up 60s -> restore vault login and cold retry");
                                return new(false, true, false, sawQr);
                            }
                            L("saved login stale: QR still up 60s with no game -> require WeChat scan");
                            savedLogin = false;
                            waitingQr = true;
                            qrResumed = false;
                            NeedScan.Set(_box, "saved-login-stale-qr");
                            Phase(BoxPhase.WaitingScan, "需要用微信扫码登录");
                            v.ShowQrWindow();
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
                        Phase(BoxPhase.WaitingScan, "需要用微信扫码登录");
                    }
                    else if (LogDue(60))
                    {
                        L("still waiting for QR scan...");
                        v.ShowQrWindow();
                    }
                    continue;
                }

                // 扫码页消失：通常表示已扫码，要重新打开游戏页，否则会卡在授权后的空白页
                if ((waitingQr || notedSavedQr) && !qrResumed)
                {
                    L("QR page gone (scanned) -> reopen GameUrl and wait for game (no sandbox restart needed)");
                    Phase(BoxPhase.Starting, "已扫码，正在进入游戏…");
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
                                return new(false, true, false, sawQr);
                            }
                            L("saved login: still no game after reload -> reopen GameUrl once");
                            BoxRuntime.StartBrowser(_box, "nudge");
                            gameUrlNudged = true;
                            launchStarted = DateTime.Now;
                        }
                        else if (gameUrlNudged && wxWait >= 50)
                        {
                            L("saved login: still no game after GameUrl nudge -> cold relaunch");
                            return new(false, true, false, sawQr);
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
                        return new(false, true, false, sawQr);
                    }
                }

                if (v.HasWeChat) { sawWx = true; wxGoneAfterSeen = 0; }
                else if (sawWx) wxGoneAfterSeen++;

                // 浏览器还在但微信运行时刚起就死 = 典型 SBIE1231
                if (sawApp && sawWx && wxGoneAfterSeen >= 3 && (DateTime.Now - launchStarted).TotalSeconds < 120)
                {
                    L("WeChatAppEx died after start (SBIE1231 likely) -> cold relaunch");
                    return new(false, true, waitingQr, sawQr);
                }

                if (!v.HasQqOrGame)
                {
                    if (waitingQr)
                    {
                        L("box ended while waiting for QR");
                        return new(false, false, true, sawQr);
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
                            return new(false, true, false, sawQr);
                        }
                        continue;
                    }
                    if (++missingAfterSeen >= 4)
                    {
                        L("box died before game (cold start)");
                        return new(false, true, false, sawQr);
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
                        return new(false, true, false, sawQr);
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
                    return new(false, true, false, sawQr);
                }
                else if (LogDue(30)) L("QQ loading, waiting...");
            }
            catch (Exception ex)
            {
                L("launch wait error: " + ex.Message);
            }
        }
        L("launch wait timeout (30 min)");
        return new(false, false, waitingQr, sawQr);
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
        L("watch start");
        bool hadGame = false, sawQr = false, qrResumed = false, wxNudged = false;
        int goneTicks = 0, uiGoneTicks = 0;
        var lastCred = DateTime.MinValue;
        var lastKeep = DateTime.MinValue;
        var lastPkg = DateTime.Now;
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
                continue;
            }

            if (hadGame)
            {
                goneTicks++;
                L($"game window missing tick={goneTicks}");
                if (goneTicks == 1) try { Ilink.Save(_box, "game-closing"); } catch { }
                if (goneTicks >= 3)
                {
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
                L("watch: QR gone after scan -> reopen GameUrl");
                Phase(BoxPhase.Starting, "已扫码，正在进入游戏…");
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
