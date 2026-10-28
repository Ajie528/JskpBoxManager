using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 计划任务触发的静默保活（JskpBoxManager.exe refresh qbN）：冷启动一次，等微信运行时自动授权换新密钥，存进金库后停箱。
/// 和旧版不同：游戏正开着时不再强行重启（正在用的会话本身就是有效的），只存一次凭证。
/// </summary>
public sealed class RefreshSession
{
    readonly string _box;
    public RefreshSession(string box) { _box = box; }
    void L(string m) => Log.Box(_box, m);

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
            if (!gotBox) { L("refresh skipped (box is being launched / watched)"); return 0; }
            try
            {
                BoxRuntime.RegisterLauncher(_box, "refresh");
                RepairInterrupted();
                try { File.WriteAllText(AppPaths.BoxRefreshPhase(_box), $"phase=cold-start pid={Environment.ProcessId} {DateTime.Now:o}"); } catch { }
                try { Core(); }
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

    void Core()
    {
        L($"refresh session start ({AppInfo.VersionLabel})");
        var before = new BoxView(_box);
        if (before.HasGameWindow)
        {
            Ilink.Save(_box, "refresh-in-game");
            L("refresh: game is running -> keep it, credential saved, skip cold start");
            Ilink.WriteEvent(_box, "refresh", new JsonObject { ["result"] = "in-game", ["keySha"] = Ilink.Live(_box).KeyHash });
            return;
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
        BoxRuntime.EnsureWxRuntimeInBox(_box);
        VaultSync.PushVaultToLive(_box);

        bool sawGame = false, renewed = false, revoked = false, qrFail = false, sawQr = false;
        var launchUtc = DateTime.UtcNow;
        for (int attempt = 1; attempt <= 2; attempt++)
        {
            if (attempt > 1)
            {
                L($"refresh cold retry {attempt}/2");
                BoxRuntime.StopForce(_box, false);
                BoxRuntime.RegisterLauncher(_box, "refresh");
                Thread.Sleep(4000);
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                VaultSync.PushVaultToLive(_box);
            }
            BoxRuntime.Warmup(_box, false);
            BoxRuntime.ClearCrashRestore(_box);
            var baseline = Ilink.Baseline(_box);
            launchUtc = DateTime.UtcNow;
            BoxRuntime.StartBrowser(_box, "refresh");

            var deadline = DateTime.Now.AddMinutes(6);
            var started = DateTime.Now;
            bool needRetry = false, sawWx = false, reloadDone = false, nudged = false;
            int mpFail = 0, wxGone = 0;
            var lastTab = DateTime.MinValue;
            DateTime? uiSince = null;
            while (DateTime.Now < deadline)
            {
                Thread.Sleep(3000);
                // 运行时完成自动授权会重写 tdi_account.txt；密钥换新即续期成功，不必等游戏窗
                if (Ilink.RenewedSince(_box, launchUtc) && Ilink.Live(_box).KeyHash != frozenKey)
                {
                    renewed = true;
                    L($"refresh: ilink key renewed {Ilink.Live(_box)}");
                    break;
                }
                if (Ilink.RevokedSinceLaunch(_box, baseline))
                {
                    Ilink.RegisterRevoked(_box, baseline, "refresh");
                    revoked = true;
                    break;
                }
                var v = new BoxView(_box);
                v.CloseRestorePage();
                if ((DateTime.Now - lastTab).TotalSeconds >= 8) { Cdp.CloseExtraTabs(_box); lastTab = DateTime.Now; }
                if (v.HasGameWindow) { sawGame = true; L("refresh: game window up -> check ilink credential"); break; }
                double wait = (DateTime.Now - started).TotalSeconds;

                if (v.WeChatRuntimeUp)
                {
                    sawWx = true; wxGone = 0;
                    if (!reloadDone && wait >= 35) { reloadDone = true; Cdp.ReloadGameCenter(_box); }
                    if (!nudged && wait >= 50) { nudged = true; BoxRuntime.StartBrowser(_box, "refresh-nudge"); }
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
                    sawQr = true;
                    if (wait >= 180) { L("refresh: QR still up after 180s"); qrFail = true; break; }
                    if (!v.HasWeChat && wait >= 120) { L("refresh: strict QR 120s without WeChat"); qrFail = true; break; }
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
            if (sawGame || renewed || revoked || qrFail || !needRetry) break;
        }

        bool ok = false;
        if (sawGame || renewed)
        {
            if (!renewed) renewed = Ilink.WaitRenewed(_box, launchUtc, 90);
            if (renewed)
            {
                var res = Ilink.Save(_box, "refresh");
                ok = (res is "saved" or "unchanged") && Ilink.VaultState(_box).KeyHash == Ilink.Live(_box).KeyHash;
                if (ok) try { VaultSync.SyncRuntimeFromLive(_box); } catch { }
                else L($"refresh: ilink credential renewed but vault save failed ({res})");
            }
            else L("refresh: ilink credential not rewritten after game window");
        }
        var outcome = ok ? "ok" : revoked ? "revoked" : qrFail ? "qr" : sawQr ? "qr-seen" : sawGame ? "no-rewrite" : "no-game";
        Ilink.WriteEvent(_box, "refresh", new JsonObject { ["result"] = outcome, ["keySha"] = Ilink.Live(_box).KeyHash, ["frozenKey"] = frozenKey });

        if (ok)
        {
            NeedScan.Clear(_box);
            NeedScan.ClearQrStreak(_box);
            BoxRuntime.StopForce(_box, false);
            BoxStatusFile.Write(_box, BoxPhase.Stopped, $"保活成功 {DateTime.Now:MM-dd HH:mm}");
            L("refresh session OK -> box closed");
        }
        else
        {
            if (revoked)
            {
                NeedScan.Set(_box, "key-revoked");
                L("refresh session FAIL -> key revoked by server, mark need-scan");
            }
            else if (qrFail) NeedScan.RegisterQrFailure(_box);
            else if (!sawGame && sawQr)
            {
                NeedScan.Set(_box, "refresh-qr-seen-no-game");
                L("refresh session FAIL -> mark need-scan (QR seen, no game)");
            }
            else L("refresh session FAIL (will retry next schedule)");
            BoxRuntime.StopForce(_box, false);
            if (!revoked) try { VaultSync.PushVaultToLive(_box); } catch { }
            BoxStatusFile.Write(_box, NeedScan.Pending(_box) ? BoxPhase.Failed : BoxPhase.Stopped,
                NeedScan.Pending(_box) ? "保活失败：需要重新扫码" : $"保活未成功（{outcome}），下次再试");
        }
        L("refresh session end");
    }
}
