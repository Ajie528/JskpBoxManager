using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 计划任务触发的静默保活（JskpBoxManager.exe refresh qbN）：冷启动一次，等微信运行时自动授权换新密钥，存进金库后停箱。
/// 和旧版不同：游戏正开着时不再强行重启（正在用的会话本身就是有效的），只存一次凭证。
/// LeanRefresh=true 时先试精简启动（Blank/NoUrl/RuntimeOnly），失败再回退 Full。
/// </summary>
public sealed class RefreshSession
{
    readonly string _box;
    AuthProbe.Env _probeEnv;
    public RefreshSession(string box) { _box = box; }
    void L(string m) => Log.Box(_box, m);

    sealed class ColdResult
    {
        /// <summary>Revoked 只在服务端明确拒绝（AutoAuth ret=-13）时为 true，此时密钥登记作废。</summary>
        public bool SawGame, Renewed, Revoked, QrFail, SawQr;
        /// <summary>运行时把凭证写成了无效但没出现扫码页：不登记作废，也不拿金库旧凭证覆盖运行时自己的状态。</summary>
        public bool CredCleared;
        /// <summary>凭证被清空且出现扫码页，但没拿到服务端 ret=-13：不能确认被顶，不烧密钥。</summary>
        public bool Suspected;
        /// <summary>收到过 AutoAuth ret=-13。单独不足以判作废（关游戏秒重启等瞬态拒绝，运行时能 ManualAuth 免扫自愈）；只有再出现二维码才确认真被顶。</summary>
        public bool HardReject;
        public DateTime LaunchUtc;
        public AuthProbe.AuthResult Auth;
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
    /// 沙箱被看门进程占着时，不能冷启续期。只有「确实有个看门进程活着、且开了常驻」才值得留续期请求，
    /// 免得在别人手动玩的时候多写一个文件。
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
            File.WriteAllText(AppPaths.BoxRenewRequest(_box), $"requested {DateTime.Now:o} pid={Environment.ProcessId}\r\n");
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
            Ilink.Save(_box, "refresh-in-game");
            L("refresh: game is running -> keep it, credential saved, skip cold start");
            Ilink.WriteEvent(_box, "refresh", new JsonObject { ["result"] = "in-game", ["keySha"] = Ilink.Live(_box).KeyHash });
            return;
        }
        // 常驻轻量运行时：微信还在就别冷启杀进程，只存凭证
        if (cfg.For(_box).ResidentKeepalive && before.WeChatRuntimeUp)
        {
            Ilink.Save(_box, "refresh-resident");
            L("refresh: resident runtime up -> keep it, credential saved, skip cold start");
            Ilink.WriteEvent(_box, "refresh", new JsonObject { ["result"] = "resident-skip", ["keySha"] = Ilink.Live(_box).KeyHash });
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
        BoxRuntime.EnsureWxRuntimeInBox(_box);
        VaultSync.PushVaultToLive(_box);

        bool lean = cfg.For(_box).LeanRefresh;
        if (cfg.For(_box).ProbeAuth)
        {
            _probeEnv = AuthProbe.Resolve(false);
            L(_probeEnv.Ok ? $"refresh: auth probe on (frida {_probeEnv.Frida})" : "refresh: auth probe off -> " + _probeEnv.Error);
            if (!_probeEnv.Ok) _probeEnv = null;
        }
        ColdResult r = null;
        string usedMode = "Full";

        if (lean)
        {
            L("refresh mode=lean (Blank -> NoUrl -> RuntimeOnly; fallback Full)");
            foreach (var mode in new[] { BoxRuntime.LaunchMode.Blank, BoxRuntime.LaunchMode.NoUrl, BoxRuntime.LaunchMode.RuntimeOnly })
            {
                r = TryCold(frozenKey, mode, leanNudge: false, timeoutMin: 2, maxAttempts: 1);
                usedMode = mode.ToString();
                if (r.Renewed || r.Revoked || r.QrFail || r.Suspected) break;
                if (r.CredCleared) { L($"refresh lean {mode}: credential cleared -> stop lean chain"); break; }
                L($"refresh lean {mode} no renew -> next candidate");
                BoxRuntime.StopForce(_box, false);
                BoxRuntime.RegisterLauncher(_box, "refresh");
                Thread.Sleep(3000);
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                VaultSync.PushVaultToLive(_box);
            }
            if (r != null && !r.Renewed && !r.Revoked && !r.QrFail && !r.Suspected && !r.CredCleared)
            {
                L("refresh lean exhausted -> fallback Full");
                BoxRuntime.StopForce(_box, false);
                BoxRuntime.RegisterLauncher(_box, "refresh");
                Thread.Sleep(3000);
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                VaultSync.PushVaultToLive(_box);
                r = TryCold(frozenKey, BoxRuntime.LaunchMode.Full, leanNudge: true, timeoutMin: 6, maxAttempts: 2);
                usedMode = "Full(fallback)";
            }
        }
        else
        {
            L("refresh mode=full");
            r = TryCold(frozenKey, BoxRuntime.LaunchMode.Full, leanNudge: true, timeoutMin: 6, maxAttempts: 2);
            usedMode = "Full";
        }

        r ??= new ColdResult { LaunchUtc = DateTime.UtcNow };
        bool softRetry = false;
        if (!r.Renewed && !r.Revoked && !r.SawGame && (r.Suspected || r.CredCleared))
        {
            softRetry = true;
            // 收到过 ret=-13（HardReject）时，不把金库旧凭证推回去——那把 key 刚被拒，重放只会再 ret=-13；
            // 让运行时保留自己清空后的状态，用 ManualAuth 免扫自愈（与启动流程一致）。
            bool keepRuntimeState = r.HardReject;
            L(r.Suspected
                ? "refresh: credential cleared + QR without server ret=-13 -> suspected, keep key; restore vault and retry Full once"
                : keepRuntimeState
                    ? "refresh: autoauth ret=-13 -> 保留运行时状态（不还原金库）冷重试一次，等 ManualAuth 自愈"
                    : "refresh: credential cleared by runtime -> restore vault and retry Full once");
            BoxRuntime.StopForce(_box, false);
            BoxRuntime.RegisterLauncher(_box, "refresh");
            Thread.Sleep(3000);
            BoxRuntime.EnsureWxRuntimeInBox(_box);
            if (!keepRuntimeState) VaultSync.PushVaultToLive(_box);
            r = TryCold(frozenKey, BoxRuntime.LaunchMode.Full, leanNudge: true, timeoutMin: 6, maxAttempts: 1, suspectHoldSec: 60);
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
        var outcome = ok ? "ok" : r.Revoked ? "revoked" : r.Suspected ? "suspected" : r.QrFail ? "qr" : r.SawQr ? "qr-seen" : r.SawGame ? "no-rewrite" : "no-game";
        Ilink.WriteEvent(_box, "refresh", new JsonObject
        {
            ["result"] = outcome, ["keySha"] = Ilink.Live(_box).KeyHash, ["frozenKey"] = frozenKey,
            ["mode"] = usedMode, ["lean"] = lean, ["credCleared"] = r.CredCleared, ["softRetry"] = softRetry,
            ["auth"] = r.Auth?.Text, ["authRet"] = r.Auth?.Ret, ["authMsg"] = r.Auth?.Msg,
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
            if (r.Revoked)
            {
                NeedScan.Set(_box, "key-revoked");
                L("refresh session FAIL -> key revoked by server, mark need-scan");
            }
            else if (r.Suspected)
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
            if (!r.Revoked && !r.CredCleared) try { VaultSync.PushVaultToLive(_box); } catch { }
            BoxStatusFile.Write(_box, NeedScan.Pending(_box) ? BoxPhase.Failed : BoxPhase.Stopped,
                NeedScan.Pending(_box) ? "保活失败：需要重新扫码" : $"保活未成功（{outcome}），下次再试");
        }
        L("refresh session end");
    }

    /// <param name="leanNudge">Full 模式才做 CDP reload / GameUrl nudge；精简模式只等密钥换新。</param>
    /// <param name="suspectHoldSec">凭证清空且扫码页持续这么久仍没等到服务端 ret=-13，才算疑似失效。</param>
    ColdResult TryCold(string frozenKey, BoxRuntime.LaunchMode mode, bool leanNudge, int timeoutMin, int maxAttempts, int suspectHoldSec = 15)
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
            AuthProbe probe = null;
            if (_probeEnv != null)
            {
                probe = AuthProbe.Start(_box, _probeEnv, timeoutMin * 60 + 180, out var probeErr,
                    Keepalive.Load().For(_box).BlockSessionTimeout);
                if (probe == null) L("refresh: auth probe not started -> " + probeErr);
            }
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
                PollAuth(probe, r);
                if (IsHardReject(r.Auth))
                {
                    // ret=-13 不等于真被顶：关游戏秒重启等瞬态拒绝后，运行时常能用 ManualAuth 免扫自愈。
                    // 当「凭证被清空」处理，继续等自愈（游戏窗/换新）或二维码；只有再出现二维码才确认作废。
                    if (!r.HardReject) L($"refresh: autoauth {r.Auth.Text} -> 先当凭证清空，等自愈/二维码确认");
                    r.HardReject = true;
                    r.CredCleared = true;
                }
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
                        if (r.HardReject)
                        {
                            // ret=-13 + 二维码 = 确认真被顶：登记作废
                            Ilink.RegisterRevoked(_box, baseline, "refresh");
                            r.Revoked = true;
                            L($"refresh: autoauth ret=-13 + 二维码 {suspectHoldSec}s -> 确认被顶，登记作废");
                        }
                        else
                        {
                            r.Suspected = true;
                            L($"refresh: credential cleared + QR {suspectHoldSec}s, no server ret=-13 -> suspected (key kept)");
                        }
                        break;
                    }
                    continue;
                }
                clearedQrSince = null;
                v.CloseRestorePage();
                if (leanNudge && (DateTime.Now - lastTab).TotalSeconds >= 8) { Cdp.CloseExtraTabs(_box); lastTab = DateTime.Now; }
                if (v.HasGameWindow) { r.SawGame = true; L("refresh: game window up -> check ilink credential"); break; }
                double wait = (DateTime.Now - started).TotalSeconds;

                if (v.WeChatRuntimeUp)
                {
                    sawWx = true; wxGone = 0;
                    if (leanNudge)
                    {
                        if (!reloadDone && wait >= 35) { reloadDone = true; Cdp.ReloadGameCenter(_box); }
                        if (!nudged && wait >= 50) { nudged = true; BoxRuntime.StartBrowser(_box, "refresh-nudge", BoxRuntime.LaunchMode.Full); }
                    }
                    // 精简模式：有运行时就耐心等密钥；Full 仍按 180s 无游戏窗重试
                    if (leanNudge && wait >= 180) { L("refresh: runtime 180s without game window -> retry"); needRetry = true; break; }
                    continue;
                }
                if (v.HasWeChat) { sawWx = true; wxGone = 0; } else if (sawWx) wxGone++;
                // 精简候选：1 分钟内完全看不到微信运行时 → 早退换下一个 / 回退 Full
                if (!leanNudge && !sawWx && wait >= 60)
                {
                    L($"refresh lean {mode}: no WeChat in 60s -> abandon candidate");
                    break;
                }

                if (leanNudge && v.HasMiniProgramFail(out var pt))
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
            PollAuth(probe, r);
            if (!r.Revoked && IsHardReject(r.Auth))
            {
                // 收尾时才看到 ret=-13：不立刻烧 key，当凭证清空，交给冷重试自愈 / 二维码确认
                r.HardReject = true;
                r.CredCleared = true;
                L($"refresh: late autoauth {r.Auth.Text} -> 先当凭证清空（重试/二维码确认）");
            }
            if (r.SawGame || r.Renewed || r.Revoked || r.Suspected || r.QrFail || !needRetry) break;
        }
        return r;
    }

    static bool IsHardReject(AuthProbe.AuthResult a) =>
        a != null && a.Ret == -13 && a.Cgi.Contains("AutoAuth", StringComparison.OrdinalIgnoreCase);

    void PollAuth(AuthProbe probe, ColdResult r)
    {
        if (probe == null) return;
        foreach (var a in probe.Poll(t =>
                 {
                     if (t.Contains("ManualAuth", StringComparison.OrdinalIgnoreCase))
                     {
                         L("refresh: 抓到 ManualAuth（手机扫码登录）");
                         ScanHint.MarkManualAuth(_box);
                     }
                 }))
        {
            L($"refresh: 授权返回 {a.Text}");
            if (!a.Cgi.Contains("Auth", StringComparison.OrdinalIgnoreCase)) continue;
            if (a.Cgi.Contains("ManualAuth", StringComparison.OrdinalIgnoreCase)) ScanHint.MarkManualAuth(_box);
            if (a.Cgi.Contains("AutoAuth", StringComparison.OrdinalIgnoreCase) && a.Ok) ScanHint.MarkAutoAuthOk(_box);
            r.Auth = a;
        }
    }
}
