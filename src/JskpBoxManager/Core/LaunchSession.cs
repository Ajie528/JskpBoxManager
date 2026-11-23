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
        L($"启动开始（{AppInfo.ProductName} {AppInfo.VersionLabel})");
        using var mutex = TryLock(_box, out bool got);
        if (!got)
        {
            // 已有一个启动/看门进程：把已有界面拉到前台；常驻态则复开 GameUrl 让看门进程接上游戏窗
            var v = new BoxView(_box);
            if (v.HasGameWindow) { v.ShowGameWindow(); L("已在运行 → 显示游戏窗"); }
            else if (v.HasStrictQr) { v.ShowQrWindow(); L("已在运行 → 显示扫码窗"); }
            else if (v.WeChatRuntimeUp && Keepalive.Load().For(_box).ResidentKeepalive)
            {
                try { BoxRuntime.StartBrowser(_box, "resume-resident-dup"); } catch { }
                L("已在运行（常驻）→ 重开游戏页");
            }
            else L("已在运行（启动进程占着锁）→ 跳过重复启动");
            return 0;
        }
        BoxRuntime.RegisterLauncher(_box, "launch");
        try
        {
            // 上一次没被常驻进程取走的续期请求已经没意义了（这次是完整启动，会自己续）
            try { File.Delete(AppPaths.BoxRenewRequest(_box)); } catch { }

            // ★ 必须在 PrepareBeforeLaunch / 预检之前：那些步骤会把金库推回 live，
            //   而金库这时还是**服务端已作废的旧 key**，一旦先跑就会把待写的新 key 盖掉。
            if (ProtocolRenew.HasPending(_box))
            {
                L("启动：发现未落盘的新 key → 优先补写，再做其它事");
                if (ProtocolRenew.RecoverPending(_box))
                {
                    L("启动：新 key 已补写，沙箱与金库都等于服务端下发的那把");
                    try { NeedScan.ClearIfRenewed(_box); } catch { }
                }
                else L("启动：新 key 暂时没补写成功（沙箱在忙？）→ 预检时会再试");
            }

            RunLocked();        }
        catch (Exception ex)
        {
            L("启动异常：" + ex);
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
                L("金库凭证已登记作废 → 跳过自动还原");
                return;
            }
            if (new BoxView(_box).HasQqOrGame)
            {
                L("沙箱凭证无效但沙箱在运行 → 跳过金库还原（等扫码）");
                return;
            }

            L($"沙箱凭证无效，金库有 {vault.KeyHash} at {vault.WriteLocal} → 先试它");
            var res = Ilink.Restore(_box, "launch-live-invalid");
            L("金库还原结果：" + res);
            if (res is not ("restored" or "same")) return;

            // 推回去之后再清一次标记：新的写入时间已经晚于 need-scan 文件
            try { NeedScan.ClearIfRenewed(_box); } catch { }
        }
        catch (Exception ex) { L("金库还原尝试失败：" + ex.Message); }
    }

    /// <summary>
    /// 启动前预检：用协议确认 live 这把 key 服务端还认不认（纯网络 0.1 秒，不动文件）。
    ///
    /// 目的：避免「启动 → 等 34 秒 → 凭证被清空 → 再等 106 秒」这种白跑。
    ///   · 认可   → 服务端会顺带回一把新 key，直接写入（停箱状态），然后正常启动
    ///   · -13    → 这把废了，用历史凭证逐把协议探测，找到一个能用的就换上去
    ///   · 网络错 → 不折腾，照常启动（可能只是临时连不上）
    ///
    /// 只在沙箱已停、且 live 凭证有效时执行。开关由 notify.json 的 probeEnabled 控制，
    /// 关掉就不预检（有些人不希望启动时多一次网络请求）。
    /// </summary>
    void PreflightCheckLiveKey()
    {
        try
        {
            // ★ 最优先：上次换钥后没落盘的凭证先补写。
            //   那种情况下服务端已经是新 key 了，而本地还是旧的——直接启动必然失败。
            if (ProtocolRenew.HasPending(_box))
            {
                L("启动预检：发现上次残留的待写新 key → 优先补写");
                if (ProtocolRenew.RecoverPending(_box))
                    L("启动预检：新 key 已补写，沙箱与金库都等于服务端下发的那把");
                else
                    L("启动预检：暂时没法补写新 key（沙箱在忙？）→ 停箱后再试");
            }

            var cfg = NotifyConfig.Load();
            if (!cfg.ProbeEnabled) return;
            if (Sandboxie.Pids(_box).Count > 0) return;

            var live = Ilink.Live(_box);
            if (!live.Valid)
            {
                L("启动预检：沙箱凭证无效 → 跳过（交给金库/历史凭证流程）");
                return;
            }
            if (ProtocolRenew.AttemptPending(_box))
            {
                L("启动预检：上次续期结果未知 → 跳过");
                return;
            }
            // 预检会真实换一把 key，别把每天的额度用在频繁启动上
            int today = CredentialProbe.RotationsToday(_box);
            if (today >= CredentialProbe.MaxRotationsPerDay)
            {
                L($"启动预检：今天已换 {today} 次 → 跳过预检，按原样启动");
                return;
            }

            // ★ 按密钥年龄决定要不要预检。
            //
            // 预检的用途是「避免启动后等 34 秒发现凭证被清空、再白等 106 秒」。
            // 但 AutoAuth 是轮换语义——预检成功就消耗一次换钥额度，而密钥还新的时候
            // 它几乎必然有效，这次换钥纯属白送。实测 qb1 一天开关两次游戏就白烧
            // 2 次 preflight 额度（7/10 里有 2 次是这么来的），逼近风控上限。
            //
            // 所以：密钥还新于 minAge（默认 5 小时）就跳过预检，直接用它启动。
            // 万一这把 key 其实已经被别处顶掉，运行时启动后会立刻清空凭证，
            // 上层 `credential cleared` 分支会自动接手走历史凭证恢复——那条路本来就在，
            // 只是晚几十秒，比每天白烧额度划算。
            //
            // 密钥超过 forceHours（默认 20 小时）属于硬上限，不管门槛一律预检。
            var pol = Keepalive.Load().For(_box);
            double minAge = pol.EffectiveMinKeyAgeHours;
            var keyAge = ProtocolRenew.KeyAgeHours(_box);
            bool overdue = ProtocolRenew.KeyOverdue(_box);
            if (!overdue && keyAge is double young && young < minAge)
            {
                L($"启动预检：密钥才 {young:F1} 小时（门槛 {minAge:F0} 小时）→ 跳过预检，直接用这把启动"
                    + "（省一次换钥额度）");
                return;
            }
            if (keyAge is double aged)
                L($"启动预检：密钥已 {aged:F1} 小时（门槛 {minAge:F0} 小时）→ 值得确认一次"
                    + (overdue ? "，且已过硬上限" : ""));

            L($"启动预检：问服务端这把 key 还能不能用 {live.KeyHash}");
            var r = ProtocolRenew.Renew(_box);
            if (r.Ok)
            {
                CredentialProbe.RecordRotationPublic(_box, r.NewKeyHash, "preflight");
                try { VaultSync.PushVaultToLive(_box); } catch { }
                L($"启动预检：key 有效并已换新 → {r.NewKeyHash}（将用它启动）");
                return;
            }
            if (r.Rejected)
            {
                L($"启动预检：key {live.KeyHash} 被拒（{r.Code}）→ 用协议逐个探测历史凭证");
                Phase(BoxPhase.Starting, "凭证已失效，正在用协议找可用的历史凭证…");
                if (TryHistoryRecover())
                {
                    L("启动预检：找到可用的历史 key → 用它启动");
                    NeedScan.Clear(_box);
                    NeedScan.ClearQrStreak(_box);
                    return;
                }
                L("启动预检：历史 key 都不可用 → 照常启动（会停在扫码页）");
                return;
            }
            L($"启动预检：探测失败（{r.Message}）→ 照常启动");
        }
        catch (Exception ex) { L("启动预检出错：" + ex.Message); }
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
            L("待扫码标记存在 → 忽略已保存的登录，等微信二维码");
            // 之前已经把所有历史凭证试完并全部被拒：这次不必再花几分钟重试，
            // 直接把扫码框摆给用户。真的换了新 key 时上面 ClearIfRenewed 会清掉标记。
            if (NeedScan.Reason(_box).Contains("history-all-failed", StringComparison.OrdinalIgnoreCase))
            {
                _historyExhausted = true;
                L("上次历史凭证已试完 → 不再重试，直接摆扫码框");
            }
        }

        var existing = new BoxView(_box);
        bool attach = false;
        if (existing.HasGameWindow)
        {
            L("游戏已在运行 → 显示并看门");
            existing.ShowGameWindow();
            Watch();
            return;
        }
        if (existing.HasStrictQr)
        {
            L("扫码页已出现 → 显示并看门");
            existing.ShowQrWindow();
            Watch();
            return;
        }
        if (existing.WeChatRuntimeUp)
        {
            if (Keepalive.Load().For(_box).ResidentKeepalive)
            {
                L("只有微信运行时（常驻）→ 重开游戏页并看门");
                try { BoxRuntime.StartBrowser(_box, "resume-resident"); } catch { }
                Watch();
                return;
            }
            L("只有微信运行时（没有游戏窗）→ 强制停箱后重开");
            BoxRuntime.StopForce(_box, false);
            BoxRuntime.RegisterLauncher(_box, "launch");
            Thread.Sleep(3000);
        }
        else if (existing.HasQqOrGame)
        {
            if (existing.HasVisibleUi || Cdp.Alive(_box))
            {
                L("浏览器已启动 → 等游戏，不重复启动");
                attach = true;
            }
            else
            {
                L("还有残留进程 → 强制停箱");
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

            // 启动前预检：用协议快速问一下服务器「live 这把 key 还能不能用」（0.1 秒）。
            // 能用就直接启动，省掉「启动 34 秒 → 被清空 → 再等 106 秒」的白跑。
            // 不能用就先在停箱状态下换好 key，再启动一次成功。
            PreflightCheckLiveKey();
        }

    bool opened = false, waitingQrAtEnd = false, didVaultRestore = false, forceFullWarmup = false;
    bool didHistoryRecover = _historyExhausted;
    const int maxAttempts = 3;
        for (int attempt = 1; attempt <= maxAttempts && !opened; attempt++)
        {
            LaunchBaseline baseline = null;
            if (attach && attempt == 1)
            {
                L("接上已有的 QQ 浏览器（不重复启动）");
            }
            else
            {
                BoxRuntime.Warmup(_box, attempt > 1 && !forceFullWarmup);
                forceFullWarmup = false;
                BoxRuntime.ClearCrashRestore(_box);
                baseline = Ilink.Baseline(_box);
                L($"启动 QQ 浏览器 第 {attempt} credential {Ilink.Live(_box)}");
                BoxRuntime.StartBrowser(_box, "launch");
            }
            var result = WaitForGame(baseline);
            waitingQrAtEnd = result.WaitingQr;
            if (result.Opened) { opened = true; break; }

            // 凭证被运行时清空（服务端不认这把 key）：立刻用协议逐把确认历史凭证，
            // 不要再走「reload / nudge / 傻等」那 100 多秒。
            if (result.CredCleared && !didHistoryRecover && HistoryCanHelp())
            {
                didHistoryRecover = true;
                L("运行时清空了凭证 → 用协议逐个探测历史凭证");
                Phase(BoxPhase.Starting, "凭证失效了，正在用协议逐个确认历史凭证…");
                if (TryHistoryRecover())
                {
                    L("历史凭证恢复成功 → 用新凭证重新进游戏");
                    NeedScan.Clear(_box);
                    NeedScan.ClearQrStreak(_box);
                    if (attempt < maxAttempts)
                    {
                        BoxRuntime.EnsureWxRuntimeInBox(_box);
                        BoxRuntime.ClearCrashRestore(_box);
                        baseline = Ilink.Baseline(_box);
                        L($"用恢复出来的凭证重开 {Ilink.Live(_box)}");
                        BoxRuntime.StartBrowser(_box, "recovered");
                        var again = WaitForGame(baseline);
                        waitingQrAtEnd = again.WaitingQr;
                        if (again.Opened) { opened = true; break; }
                        L("恢复后重开没进游戏 → 继续");
                    }
                    else { opened = true; break; }
                }
                L("历史凭证恢复失败 → 走冷启动重试流程");
            }

            // 扫码框出现且还有历史凭证可试时：先别急着判「必须扫码」。
            // 历史快照里很可能还有一把能用的（qb10 / qb12 就是这样白等了好几天的），
            // 这里逐把走协议续期确认，每把 0.5 秒，比冷启动验证快两个数量级。
            if (!didHistoryRecover && result.WaitingQr && result.SawQr && HistoryCanHelp())
            {
                didHistoryRecover = true;
                L("出现二维码 → 用协议逐把试历史凭证（每把约 0.5 秒）");
                Phase(BoxPhase.Starting, "扫码框出现了，正在用历史凭证逐个试…");
                if (TryHistoryRecover())
                {
                    L("历史凭证恢复成功 → 已换凭证，重新进游戏");
                    NeedScan.Clear(_box);
                    NeedScan.ClearQrStreak(_box);
                    // 协议续期只是把 key 换好了，游戏还没起来：重开一次浏览器让新 key 生效
                    if (attempt < maxAttempts)
                    {
                        BoxRuntime.EnsureWxRuntimeInBox(_box);
                        BoxRuntime.Warmup(_box, false);
                        BoxRuntime.ClearCrashRestore(_box);
                        baseline = Ilink.Baseline(_box);
                        L($"用恢复出来的凭证重开 {Ilink.Live(_box)}");
                        BoxRuntime.StartBrowser(_box, "history-recovered");
                        var again = WaitForGame(baseline);
                        waitingQrAtEnd = again.WaitingQr;
                        if (again.Opened)
                        {
                            opened = true;
                            break;
                        }
                        L("历史凭证恢复后重开没进游戏 → 继续");
                    }
                    else
                    {
                        // 已经用完次数：凭证是好的，只是这次没等到游戏窗，交给用户点一次启动即可
                        L("历史凭证恢复成功但启动次数已用完 → 凭证已就绪，可再点启动");
                        opened = true;
                        break;
                    }
                }
                L("历史凭证恢复失败 → 全部被拒，摆出扫码页等人工扫");
                _historyExhausted = true;
                // 记下「历史已试完」：下次启动直接用 need-scan 判定，不必再花两分钟重试一遍。
                // 一旦真的换了新 key（扫码/导入/探测成功），NeedScan.ClearIfRenewed 会自动清掉。
                NeedScan.Set(_box, "history-all-failed");
                // 关键：TryHistoryRecover 内部每把都会停箱，试完这里沙箱是空的。
                // 必须重新拉起浏览器把扫码框摆到用户面前，否则会直接「启动结束但没进游戏」，
                // 用户看到的就是「弹扫码框后直接停箱、没机会扫」。
                try
                {
                    BoxRuntime.EnsureWxRuntimeInBox(_box);
                    BoxRuntime.Warmup(_box, false);
                    BoxRuntime.ClearCrashRestore(_box);
                    baseline = Ilink.Baseline(_box);
                    L("重开以显示手动扫码页");
                    BoxRuntime.StartBrowser(_box, "qr-wait");
                    var qrResult = WaitForGame(baseline);
                    waitingQrAtEnd = qrResult.WaitingQr;
                    if (qrResult.Opened)
                    {
                        opened = true;
                        break;
                    }
                }
                catch (Exception ex) { L("为显示扫码页而重开失败：" + ex.Message); }
            }

            if (result.NeedColdRetry && attempt < maxAttempts)
            {
                L($"冷启动失败 → 重试 {attempt}/{maxAttempts}");
                Phase(BoxPhase.Starting, $"启动没成功，正在重试（{attempt}/{maxAttempts}）…");
                BoxRuntime.StopForce(_box, false);
                BoxRuntime.RegisterLauncher(_box, "launch");
                Thread.Sleep(6000);
                BoxRuntime.WaitRpcReady(_box, 90);
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                if (result.Suspected)
                {
                    L("疑似被顶（凭证被清 + 出现二维码，但没看到服务端拒绝）→ 还原金库后重试一次");
                    VaultSync.PushVaultToLive(_box);
                    didVaultRestore = true;
                }
                else if (result.CredCleared)
                    L("运行时清空了凭证但没出现二维码 → 保留运行时状态（不还原金库）后重试");
                else if (!didVaultRestore)
                {
                    L("直接启动失败 → 从金库完整还原后重试");
                    VaultSync.PushVaultToLive(_box);
                    didVaultRestore = true;
                }
                forceFullWarmup = true;
                continue;
            }
            if (result.NeedColdRetry)
            {
                L("冷启动重试次数用完 → 浏览器留在前台（可能需要扫码）");
                if (result.SawQr) NeedScan.Set(_box, "launch-no-game");
                try { new BoxView(_box).ShowQrWindow(); } catch { }
            }
            break;
        }

        if (opened)
        {
            L("游戏窗已出现 → 稍等稳定、隐藏浏览器、保存凭证");
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
            L("QQ 还在运行 → 看门直到扫码/进游戏或用户关闭");
            Watch();
        }
        else
        {
            L("启动结束但没进游戏");
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
            var all = Ilink.CredentialHistory(_box);
            var list = all
                .Where(c => !c.Revoked)
                .Where(c => HistoryCooldown.Allowed(_box, c.KeyHash))
                .Where(c => !live.Valid || c.KeyHash != live.KeyHash)
                .ToList();
            int cooling = all.Count(c => !c.Revoked && !HistoryCooldown.Allowed(_box, c.KeyHash));
            if (list.Count > 0) L($"可试的历史凭证：{list.Count} ({string.Join(",", list.Take(5).Select(c => c.KeyShort))})"
                + (cooling > 0 ? $" | {cooling} 把在冷却期" : ""));
            else if (cooling > 0) L($"历史凭证全在冷却期：{cooling} 把被拒过，先不重试");
            return list.Count > 0;
        }
        catch (Exception ex)
        {
            L("判断历史凭证可用性出错：" + ex.Message);
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
        var all = Ilink.CredentialHistory(_box)
            .Where(c => !c.Revoked)
            .Where(c => HistoryCooldown.Allowed(_box, c.KeyHash))
            .Where(c => !live.Valid || c.KeyHash != live.KeyHash)
            .ToList();
        // 最多只打前 N 把。见 HistoryCooldown.MaxProbesPerRound 的说明：
        // qb4 在 11-13 09:27 于 5 秒内连打 22 次 AutoAuth（全 -13），
        // 这种突发密度本身就是风控特征，也是这个号反复被顶的推手之一。
        var tryList = all.Take(HistoryCooldown.MaxProbesPerRound).ToList();
        if (tryList.Count == 0) return false;
        if (all.Count > tryList.Count)
            L($"历史凭证共 {all.Count} 把，本轮只试最近 {tryList.Count} 把"
              + $"（防止连续 AutoAuth 触发风控，其余下次轮换后再试）");

        var rec = new RecoverSession(_box);
        int i = 0;
        foreach (var c in tryList)
        {
            i++;
            if (i > 1) Thread.Sleep(HistoryCooldown.ProbeSpacingMs);
            L($"[{i}/{tryList.Count}] try historical key {c.KeyShort} ({c.SavedAt:MM-dd HH:mm}{(c.IsVault ? " · vault" : "")})");
            Phase(BoxPhase.Starting, $"正在用历史凭证恢复（{i}/{tryList.Count}）：试 {c.KeyShort}");

            // 先协议探测：**不停箱**直接拿快照里的 key 问服务器（纯网络，零成本）。
            // 只有服务端认可（返回 0）时才停箱落盘——这就是「先不停箱判断，成功了才停」。
            try
            {
                var pr = rec.ProbeHistoryKey(c);
                if (pr.Ok)
                {
                    L($"历史凭证恢复成功（协议）key {c.KeyHash} -> {pr.NewKeyHash}");
                    HistoryCooldown.Clear(_box, c.KeyHash);
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
                L($"历史 key {c.KeyShort} 协议出错：{ex.Message}");
            }

            // 协议说不通（网络等）时才冷启动验证这一把
            try
            {
                if (rec.TryOne(c))
                {
                    L($"历史凭证恢复成功（冷启动）key {c.KeyHash}");
                    HistoryCooldown.Clear(_box, c.KeyHash);
                    try { Ilink.Save(_box, "history-recover"); } catch { }
                    Phase(BoxPhase.InGame, "已用历史凭证免扫恢复");
                    return true;
                }
            }
            catch (Exception ex)
            {
                L($"历史 key {c.KeyShort} 出错：{ex.Message}");
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

        // 页面假死探测（见 HasVisibleUi 分支里的说明）：没有进展多久算卡住、重开过几次。
        var lastPageProbe = DateTime.MinValue;
        DateTime pageStallSince = DateTime.MinValue;
        Cdp.PageState lastPage = null;
        int pageProbeFails = 0, pageReopens = 0;
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
                    L("启动后运行时清空了凭证 → 提前交给协议探测");
                    // 凭证被清空说明这把 key 服务端不认了：继续等游戏窗毫无意义
                    // （qb4 11-08 15:34 就是这样白等了 106 秒）。
                    // 立刻返回，交给外层用协议续期确认「是这把废了」还是「换一把就行」。
                    if (!_historyExhausted && HistoryCandidatesExist())
                        return new(false, false, false, sawQr, true);
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
                if (v.CloseRestorePage()) L("已关闭「要恢复页面吗」对话框");
                if (!waitingQr && (DateTime.Now - lastTabClean).TotalSeconds >= 6)
                {
                    int n = Cdp.CloseExtraTabs(_box);
                    if (n > 0) L($"已通过 CDP 关闭多余标签页 数量={n}");
                    lastTabClean = DateTime.Now;
                }

                if (v.HasMiniProgramFail(out var pt))
                {
                    mpFailTicks++;
                    gameSince = null;
                    if (mpFailTicks <= 4 && DateTime.Now >= _mpRetryNotBefore && v.ClickMiniProgramRetry(pt))
                    {
                        L("小程序打开失败 → 点「再次尝试」");
                        _mpRetryNotBefore = DateTime.Now.AddSeconds(8);
                    }
                    else if (mpFailTicks >= 8)
                    {
                        L("小程序仍然失败 → 冷启动重开");
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
                        L($"游戏窗已确认（凭证已换新={renewed})");
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
                            L("免扫登录：扫码浮层先忽略一下，等游戏窗");
                            notedSavedQr = true;
                            qrOverlaySince = DateTime.Now;
                        }
                        else if ((DateTime.Now - qrOverlaySince).TotalSeconds >= qrOverlayWaitSec)
                        {
                            if (qrOverlayRounds < qrOverlayMaxRounds)
                            {
                                qrOverlayRounds++;
                                L($"免扫登录：扫码浮层挂了 {qrOverlayWaitSec} 秒 → 关掉它并重开游戏页（第 {qrOverlayRounds}/{qrOverlayMaxRounds})");
                                // 到这里才算「授权层挡住了免扫」：用户没扫码，程序主动关掉它。
                                // 不必在这里重开 GameUrl——下面「扫码层消失」分支会做，避免重复拉起。
                                ScanHint.MarkOverlay(_box);
                                try { v.CloseQrPage(); } catch (Exception ex) { L("关闭扫码页失败：" + ex.Message); }
                                qrOverlaySince = DateTime.Now;
                                launchStarted = DateTime.Now;
                                qrResumed = false;   // 关掉后由「扫码层消失」分支重开 GameUrl，允许每轮都重开
                                continue;
                            }
                            // 关掉两轮仍回来，才认为这次真的需要扫码
                            if (!revoked && Ilink.VaultCanHelp(_box))
                            {
                                L("免扫登录：关掉后扫码浮层又回来了 → 冷启动重试一次");
                                return new(false, true, false, sawQr, credCleared && !revoked);
                            }
                            L("免扫登录已失效：扫码浮层反复出现 → 交给历史凭证恢复");
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
                        L("检测到强制扫码页 → 等微信扫码 | 窗口标题=" + v.TitlesSample());
                        v.ShowQrWindow();
                        NeedScan.Set(_box, revoked ? "key-revoked" : "strict-qr-auth-page");
                        ScanHint.MarkQrScan(_box);
                        Phase(BoxPhase.WaitingScan, "需要用微信扫码登录");
                        // 同上：有历史凭证就先让外层试协议续期，不打断「确实需要扫码」的正常流程。
                        if (HistoryCandidatesExist() && !_historyExhausted) return new(false, false, true, sawQr, credCleared && !revoked);
                    }
                    else if (LogDue(60))
                    {
                        L("仍在等扫码...");
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
                    try { BoxRuntime.StartBrowser(_box, "post-scan"); } catch (Exception ex) { L("扫码后重开失败：" + ex.Message); }
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
                            L("免扫登录：游戏中心标签页不见了 → 重开一次游戏页");
                            BoxRuntime.StartBrowser(_box, "nudge");
                            gameUrlNudged = true;
                            launchStarted = DateTime.Now;
                        }
                        else if (!pageReloadDone && wxWait >= 35)
                        {
                            L("免扫登录：微信起来了 35 秒没进游戏 → CDP 刷新游戏中心");
                            Cdp.ReloadGameCenter(_box);
                            pageReloadDone = true;
                            launchStarted = DateTime.Now;
                        }
                        else if (!gameUrlNudged && wxWait >= 50)
                        {
                            if (Cdp.HasQrTab(_box) || notedSavedQr)
                            {
                                L("免扫登录：二维码还在且没进游戏 → 冷启动重开");
                                return new(false, true, false, sawQr, credCleared && !revoked);
                            }
                            L("免扫登录：刷新后仍没进游戏 → 重开一次游戏页");
                            BoxRuntime.StartBrowser(_box, "nudge");
                            gameUrlNudged = true;
                            launchStarted = DateTime.Now;
                        }
                        else if (gameUrlNudged && wxWait >= 50)
                        {
                            L("免扫登录：重开游戏页后仍没进游戏 → 冷启动重开");
                            return new(false, true, false, sawQr, credCleared && !revoked);
                        }
                        else if (LogDue(20)) L("免扫登录：微信已起来，等游戏窗...");
                        continue;
                    }
                    if (!waitingQr && !gameUrlNudged && wxWait >= 90)
                    {
                        if (Cdp.HasQrTab(_box)) { waitingQr = true; continue; }
                        L("微信起来 90 秒没进游戏 → 重开一次游戏页");
                        BoxRuntime.StartBrowser(_box, "nudge");
                        gameUrlNudged = true;
                        launchStarted = DateTime.Now;
                        continue;
                    }
                    if (!waitingQr && wxWait >= 120)
                    {
                        L("重开游戏页后微信在跑但没进游戏 → 冷启动重开");
                        return new(false, true, false, sawQr, credCleared && !revoked);
                    }
                }

                if (v.HasWeChat) { sawWx = true; wxGoneAfterSeen = 0; }
                else if (sawWx) wxGoneAfterSeen++;

                // 浏览器还在但微信运行时刚起就死 = 典型 SBIE1231
                if (sawApp && sawWx && wxGoneAfterSeen >= 3 && (DateTime.Now - launchStarted).TotalSeconds < 120)
                {
                    L("微信运行时启动后就挂了（大概率 SBIE1231）→ 冷启动重开");
                    return new(false, true, waitingQr, sawQr, credCleared && !revoked);
                }

                if (!v.HasQqOrGame)
                {
                    if (waitingQr)
                    {
                        L("等扫码期间沙箱结束了");
                        return new(false, false, true, sawQr, credCleared && !revoked);
                    }
                    if (!sawApp)
                    {
                        double waitSec = (DateTime.Now - launchStarted).TotalSeconds;
                        if (LogDue(15)) L($"等 QQ 浏览器进程... {waitSec:F0}s");
                        if (waitSec >= 45 && !gameUrlNudged)
                        {
                            L("启动后 45 秒没有 QQ 浏览器进程 → 再拉一次 Start.exe");
                            BoxRuntime.StartBrowser(_box, "re-issue");
                            gameUrlNudged = true;
                            launchStarted = DateTime.Now;
                            coldStartDeadline = DateTime.Now.AddSeconds(180);
                        }
                        else if (DateTime.Now > coldStartDeadline)
                        {
                            L("冷启动超时（没有进程）");
                            return new(false, true, false, sawQr, credCleared && !revoked);
                        }
                        continue;
                    }
                    if (++missingAfterSeen >= 4)
                    {
                        L("还没进游戏沙箱就结束了（冷启动）");
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
                    if (LogDue(30)) L("浏览器界面（不是扫码页）→ 等游戏...");

                    // ★ 页面就绪探测：窗口标题叫「游戏中心」不代表页面真的跑起来了。
                    //   实测 qb1 2026-11-23 09:02：readyState 永远是 interactive、load 事件从不触发、
                    //   49 张图里 36 张 complete 永远为 false，而同一页面里 fetch 同一张 CDN 图只要 162ms
                    //   —— 网络没慢，是这个渲染/网络服务假死了。这种页面永远不会去拉起小程序，
                    //   以前只能干等到 90 秒判「没等到微信运行时」再冷启动，白烧一次尝试。
                    //   现在：页面卡住（资源数/图片进度十几秒零增长）就关标签重开，比清缓存重刷快得多。
                    if (!sawWx && !waitingQr)
                    {
                        if (uiWait >= 15 && (DateTime.Now - lastPageProbe).TotalSeconds >= 6)
                        {
                            lastPageProbe = DateTime.Now;
                            var st = Cdp.ProbeGameCenter(_box);
                            if (st == null)
                            {
                                // 探测不到**不算**卡死：标签页被切到后台时，CDP eval 会直接超时
                                // （实测游戏窗顶到前台后对游戏中心页执行 JS，10 秒都不回），
                                // 那种情况下页面本身可能是好的。这里只记一笔，交给下面 40/90 秒的老路径兜底。
                                pageProbeFails++;
                                if (pageProbeFails == 1 || pageProbeFails % 5 == 0)
                                    L($"页面探测无响应（连续 {pageProbeFails} 次，标签页可能在后台被节流）→ 先按老流程等");
                            }
                            else
                            {
                                pageProbeFails = 0;
                                bool progressed = lastPage != null
                                    && (st.ResourceCount > lastPage.ResourceCount || st.ImagesUnloaded < lastPage.ImagesUnloaded);
                                if (st.Loaded) pageStallSince = DateTime.MinValue;
                                else if (progressed || pageStallSince == DateTime.MinValue) pageStallSince = DateTime.Now;
                                lastPage = st;
                            }
                        }

                        double stalledSec = pageStallSince == DateTime.MinValue ? 0 : (DateTime.Now - pageStallSince).TotalSeconds;
                        if (stalledSec >= 14)
                        {
                            var stuck = lastPage?.Describe() ?? "探测不到页面状态";
                            if (pageReopens < 2)
                            {
                                pageReopens++;
                                L($"页面卡住 {stalledSec:F0} 秒没有进展（{stuck}）→ 关掉标签页重开游戏中心（第 {pageReopens}/2 次）");
                                int closedStuck = 0;
                                try { closedStuck = Cdp.CloseGameCenterTabs(_box); } catch { }
                                L($"假死页已关闭 标签数={closedStuck}");
                                pageStallSince = DateTime.MinValue;
                                lastPage = null;
                                pageReloadDone = true;   // 重开比 40 秒那次 CDP 刷新更强，别重复做
                                gameUrlNudged = true;    // 也免掉 20 秒没窗口时的再次拉起
                                launchStarted = DateTime.Now;
                                try { BoxRuntime.StartBrowser(_box, "page-stuck"); }
                                catch (Exception ex) { L("重开游戏中心失败：" + ex.Message); }
                                continue;
                            }
                            L($"页面重开后依旧卡住（{stuck}）→ 冷启动重开");
                            return new(false, true, false, sawQr, credCleared && !revoked);
                        }
                    }

                    if (!sawWx && !waitingQr && !pageReloadDone && uiWait >= 40)
                    {
                        L("界面 40 秒没等到微信 → CDP 刷新一次游戏中心");
                        Cdp.ReloadGameCenter(_box);
                        pageReloadDone = true;
                        launchStarted = DateTime.Now;
                        continue;
                    }
                    if (!sawWx && !waitingQr && uiWait >= 90)
                    {
                        L("界面 90 秒没等到微信运行时 → 冷启动重开");
                        return new(false, true, false, sawQr, credCleared && !revoked);
                    }
                    continue;
                }

                noUiSince ??= DateTime.Now;
                double noUi = (DateTime.Now - noUiSince.Value).TotalSeconds;
                if (!gameUrlNudged && noUi >= 20)
                {
                    L("QQ 进程起来了但 20 秒没窗口 → 显示浏览器并重开游戏页");
                    v.ShowBrowser();
                    BoxRuntime.StartBrowser(_box, "no-window");
                    gameUrlNudged = true;
                    noUiSince = DateTime.Now;
                    launchStarted = DateTime.Now;
                }
                else if (noUi >= 90)
                {
                    L("QQ 进程 90 秒没窗口 → 冷启动重开");
                    return new(false, true, false, sawQr, credCleared && !revoked);
                }
                else if (LogDue(30)) L("QQ 加载中，继续等...");
            }
            catch (Exception ex)
            {
                L("启动等待出错：" + ex.Message);
            }
        }
        L("启动等待超时（30 分钟）");
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
        catch (Exception ex) { L("保活计划任务同步失败：" + ex.Message); }
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
                        L($"20 分钟还没读全角色信息（名字={name} attack={attack}) -> retry every 5 min");
                    }
                if (DateTime.Now - lastTry < interval) continue;
                lastTry = DateTime.Now;
                var r = RoleCapture.ReadOnce(_box);
                name |= r.NameFound;
                attack |= r.AttackFound;
            }
            catch (Exception ex) { L("读角色出错：" + ex.Message); lastTry = DateTime.Now; }
        }
    }

    void WatchLoop()
    {
        L("看门开始");
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
        var lastTabClean = DateTime.MinValue;

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

            // 扫码后 post-scan 又开了一次游戏页，浏览器里会同时留着「扫码页」和「游戏页」两个标签。
            // 两个标签都跑游戏 = 同一个微信号在同一设备上开了两条游戏会话，
            // 服务端会按「重复登录」处理，把较早那条的授权顶掉（-13）。
            // 启动路径（Run 里）一直有这个定时清理，看门路径以前漏了：
            // qb4 在 2026-11-16 21:01 扫码后日志里完全没有「关闭多余标签页」，
            // 两个游戏页并存，1 分 26 秒后游戏窗就自己消失了。
            if (!v.HasStrictQr && (DateTime.Now - lastTabClean).TotalSeconds >= 6)
            {
                int n = 0;
                try { n = Cdp.CloseExtraTabs(_box); } catch { }
                if (n > 0) L($"看门：已关闭多余标签页 数量={n}");
                lastTabClean = DateTime.Now;
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
                    if (v.ClickMiniProgramRetry(pt)) L("看门：小程序失败 → 点「再次尝试」");
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
                //
                // ★ 但「等游戏关掉」不能无限等。qb4 是 24 小时挂机的号，
                //   2026-11-21 就从 17h 一路放到 23.9h，中间七次保活全部跳过，
                //   最后运行时自己判失效、清空凭证、游戏掉线。
                //   所以超过「该号实测寿命」整整一倍还没等到游戏关，就必须主动重启一次续期。
                //   牺牲几分钟游戏时间，换链条不断——这比直接掉线代价小得多。
                if (ProtocolRenew.KeyOverdue(_box))
                {
                    _renewPending = true;
                    double hardLimit = ProtocolRenew.EffectiveMaxAgeHours(_box);
                    double ageNow = ProtocolRenew.KeyAgeHours(_box) ?? 0;
                    double lifeLine = ProtocolRenew.ShortestObservedLifeHours(_box);
                    bool hasHistory = lifeLine < ProtocolRenew.KeyMaxAgeHours;

                    // 「最晚必须动手」的时刻：
                    //   · 有实测历史 → 该号实测最短寿命 × 0.85（赶在死亡线之前）
                    //   · 无历史（普通号）→ 全局硬上限 20h 的 0.85
                    //
                    // 为什么不能等「hardLimit × 2」：hardLimit 已经是「该动手」的时刻了
                    // （扣过 30% 余量 + 一个唤醒周期），再往上翻倍必然越过死亡线。
                    // qb4 实测最短 4.96h、hardLimit 3.0h —— 若按 3.0×2=6h 才动，
                    // 6 小时早就死了（这正是 11-21 密钥被放到 23.9h 的同一个错误）。
                    double restartAt = hasHistory ? lifeLine * 0.85 : ProtocolRenew.KeyMaxAgeHours * 0.85;
                    bool mustRestart = ageNow >= restartAt;

                    if (mustRestart)
                    {
                        L($"看门：密钥已用 {ageNow:F1}h，已到该号必须续期的时刻 {restartAt:F1}h"
                          + $"（实测最短寿命 {lifeLine:F1}h，主动续期点 {hardLimit:F1}h 已过，等不到游戏关闭）"
                          + " → 主动重启续期（约 1 分钟，之后自动重进游戏）");
                        Phase(BoxPhase.Starting, "密钥快到期，正在自动续期…");
                        BoxRuntime.StopSoft(_box, true);
                        Thread.Sleep(1500);
                        BoxRuntime.StopForce(_box, false);
                        RenewWhenStopped();
                        // 续完把游戏重新拉起来，玩家视角只是闪了一下
                        try
                        {
                            BoxRuntime.EnsureWxRuntimeInBox(_box);
                            BoxRuntime.Warmup(_box, false);
                            BoxRuntime.ClearCrashRestore(_box);
                            BoxRuntime.StartBrowser(_box, "auto-renew-reopen");
                        }
                        catch (Exception ex) { L("自动续期后重开失败：" + ex.Message); }
                        _renewPending = false;
                        // 请求已由这次重启消化掉了，必须清掉：
                        // 不清的话，重开之后 TakeRenewRequest 立刻又返回 true，会陷入「不停重启」。
                        try { TakeRenewRequest(); } catch { }
                        hadGame = false;
                        goneTicks = 0;
                        uiGoneTicks = 0;
                        gameStartedAt = DateTime.MinValue;
                        waitGameDeadline = DateTime.Now.AddMinutes(15);
                        lastOverdueWarn = DateTime.MinValue;
                        continue;
                    }

                    if ((DateTime.Now - lastOverdueWarn).TotalHours >= 1)
                    {
                        lastOverdueWarn = DateTime.Now;
                        L($"看门：密钥已用 {ProtocolRenew.KeyAgeText(_box)}（该号上限 {hardLimit:F1}h）"
                          + " → 游戏一关闭就立即续期（不打断游戏）");
                    }
                }
                // 注意：**不能**在这里 TakeRenewRequest()。
                // 那个方法会把请求文件删掉，而现在游戏正跑着、根本没法真续期，
                // 请求就等于被白白吃掉了（等于保活白提醒一次）。
                // 让请求留在文件里，等游戏关闭那一支（goneTicks >= 3）自然会消费它。
                continue;
            }

            if (hadGame)
            {
                goneTicks++;
                L($"游戏窗消失 第 {goneTicks}");
                if (goneTicks == 1) try { Ilink.Save(_box, "game-closing"); } catch { }
                if (goneTicks >= 3)
                {
                    // 游戏刚关：这是协议续期最安全的时机（运行时已退出，不会再把旧 key 写回文件）。
                    // 密钥超龄或保活留下请求时，先停箱换钥，再按原逻辑决定进常驻还是停箱。
                    if (_renewPending || ProtocolRenew.KeyOverdue(_box) || TakeRenewRequest())
                    {
                        _renewPending = false;
                        L($"看门：游戏已关闭，密钥已用 {ProtocolRenew.KeyAgeText(_box)} → 停箱前先做协议续期");
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
                    L("游戏已关闭 → 停箱（保存凭证）");
                    Phase(BoxPhase.Stopped, "游戏已关闭，正在保存…");
                    BoxRuntime.StopSoft(_box, true);
                    Phase(BoxPhase.Stopped, "游戏已关闭");
                    L("沙箱已停止");
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
                    L("看门：等扫码...");
                    lastLog = DateTime.Now;
                    v.ShowQrWindow();
                }
                continue;
            }
            if (sawQr && !qrResumed)
            {
                L("看门：扫码后二维码消失 → 重开游戏页");
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
                    L("看门：微信起来 90 秒没游戏窗 → 重开游戏页");
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
                L("浏览器关了但没进游戏 → 停箱");
                BoxRuntime.StopSoft(_box, false);
                Phase(BoxPhase.Stopped, "浏览器已关闭");
                break;
            }
            if (DateTime.Now > waitGameDeadline)
            {
                L("看门超时 → 停箱");
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
        L("游戏已关闭 → 进入常驻（藏窗+压内存，保留 ilink 运行时）");
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
        int renewFailStreak = 0;              // 续期连续失败次数（用于指数退避）
        var renewSkipUntil = DateTime.MinValue; // 退避到什么时候
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
                L("常驻：沙箱空了 → 结束");
                try { Ilink.Save(_box, "resident-end"); } catch { }
                Phase(BoxPhase.Stopped, "常驻已结束");
                return false;
            }

            if (v.HasGameWindow)
            {
                L("常驻：游戏窗回来了 → 恢复看门");
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
                    L("常驻：出现二维码");
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
                L("常驻：扫码后二维码消失 → 重开游戏页");
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
            bool renewBackingOff = DateTime.Now < renewSkipUntil;
            if (!renewBackingOff
                && ((DateTime.Now - lastRenew).TotalHours >= ResidentRenewHours || keyAging || TakeRenewRequest()))
            {
                if (keyAging) L($"常驻：密钥已用 {keyAge:F1}h old (limit {ResidentKeyMaxAgeHours}h) -> renew now");
                lastRenew = DateTime.Now;
                var rr = ResidentRenew(); // 出扫码页时不藏窗，主循环下一轮看到扫码页转入 need-scan

                // ★ 续期失败必须退避，否则会死循环。
                //
                // 原来这里无条件 continue：ResidentRenew 失败后密钥年龄没变化
                // （还是 20.5h），下一轮 keyAging 依旧为 true，立刻再触发一次续期，
                // 又失败、又重试……2026-11-22 从 01:27 到 19:38 就这样
                // **连续 18 小时每 2 分钟重启一次游戏**，把 qb4 彻底折腾死。
                //
                // 现在：失败后按指数退避（5 分钟起，最长 2 小时），
                // 期间不再重试。真的需要扫码时会由 NeedScan 标记接管。
                if (rr == ResidentRenewResult.Rolled)
                {
                    renewFailStreak = 0;
                }
                else if (rr == ResidentRenewResult.NeedScan)
                {
                    L("常驻：出现二维码 → 停止自动续期，等待人工扫码");
                    break;      // 交给外层 need-scan 流程
                }
                else
                {
                    renewFailStreak++;
                    double backoffMin = Math.Min(120, 5 * Math.Pow(2, Math.Min(renewFailStreak - 1, 5)));
                    renewSkipUntil = DateTime.Now.AddMinutes(backoffMin);
                    L($"常驻：续期未成功（连续 {renewFailStreak} 次）→ 退避 {backoffMin:F0} 分钟后再试");
                }
                continue;
            }

            // 主进程在、但 ilink 长连接进程没了（关游戏后服务端下发 sessiontimeout 会让它自己退出）。
            // 以前这里只看主进程，于是整段常驻都在「假长连接」空转，密钥一路放到自然寿命就弹码。
            if (!v.IlinkConnected)
            {
                ilinkDownTicks++;
                if (ilinkDownTicks == 1)
                    L("常驻：微信主进程在但 ilink 长连接进程没了 → 重开游戏重新拉起");
                Phase(BoxPhase.Resident, "常驻长连接已断，正在重连…");
                // 重开 GameUrl 会拉起 ILinkServiceHost 并触发一次 AutoAuth，同时顺手把密钥往前滚
                if (ilinkDownTicks >= 2)
                {
                    ilinkDownTicks = 0;
                    try { BoxRuntime.StartBrowser(_box, "resident-relink"); }
                    catch (Exception ex) { L("常驻重连：" + ex.Message); }
                    lastRenew = DateTime.Now;
                }
                continue;
            }
            if (ilinkDownTicks > 0)
            {
                L("常驻：ilink 长连接已恢复");
                ilinkDownTicks = 0;
            }

            if (v.WeChatRuntimeUp)
            {
                failStreak = 0;
                continue;
            }

            failStreak++;
            L($"常驻：微信运行时挂了 → 恢复（连续失败={failStreak})");
            Phase(BoxPhase.Resident, "常驻运行时恢复中…");
            try { BoxRuntime.StartBrowser(_box, "resident-recover", BoxRuntime.LaunchMode.RuntimeOnly); }
            catch (Exception ex) { L("常驻（仅运行时）出错：" + ex.Message); }
            Thread.Sleep(5000);
            v = new BoxView(_box);
            if (!v.WeChatRuntimeUp)
            {
                try { BoxRuntime.StartBrowser(_box, "resident-recover-full", BoxRuntime.LaunchMode.Full); }
                catch (Exception ex) { L("常驻（完整）出错：" + ex.Message); }
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
                L("常驻：反复恢复失败 → 停箱，下次启动需要冷启动");
                try { Ilink.Save(_box, "resident-give-up"); } catch { }
                BoxRuntime.StopSoft(_box, true);
                Phase(BoxPhase.Stopped, "常驻运行时已挂，下次需冷启动");
                return false;
            }
        }
        // 只有 break 跳出（例如「出现二维码 → 停止自动续期」）才会走到这里。
        // 返回 false 表示「结束看门」，交给外层流程处理 need-scan。
        L("常驻：已退出常驻循环");
        return false;
    }

    /// <summary>
    /// 常驻每隔多少小时主动重开游戏做一次真实 AutoAuth（远小于免扫链约一天的寿命）。
    ///
    /// 与 <see cref="ResidentKeyMaxAgeHours"/> 一样要按该号实测寿命自适应：
    /// qb4 的 key 最短只活 4.96 小时，固定等 6 小时的话，每轮都会在续期前先死掉。
    /// 取「6 小时」与「该号上限 × 1.2」的较小值，保证总在寿命终点之前动手。
    /// </summary>
    double ResidentRenewHours => Math.Min(6.0, ProtocolRenew.EffectiveMaxAgeHours(_box) * 1.2);

    /// <summary>
    /// 常驻模式下，密钥年龄到这个阈值就必须续期。
    ///
    /// <para>
    /// 这里**不能**用固定的 <see cref="ProtocolRenew.KeyMaxAgeHours"/>（20 小时）：
    /// 有的号实测寿命远低于它。qb4 最短一把 key 只活 4.96 小时，
    /// 用 20 小时等于永远等它自然死——2026-11-21 就是这样把密钥放到 23.9 小时、
    /// 最后运行时判失效、清空凭证、整条链断掉。
    /// </para>
    /// <para>
    /// 改为「全局上限与该号实测寿命取较小值」，也就是走
    /// <see cref="ProtocolRenew.EffectiveMaxAgeHours"/>。没有 -13 历史的号行为不变。
    /// </para>
    /// </summary>
    double ResidentKeyMaxAgeHours => ProtocolRenew.EffectiveMaxAgeHours(_box);

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
            L("常驻：保活任务请求续期 → 现在就做");
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
            L("看门续期：停箱后仍忙 → 跳过：" + why.Split('\n')[0]);
            return;
        }
        var r = ProtocolRenew.Renew(_box);
        if (r.Ok)
        {
            L($"看门续期成功，新 key {r.NewKeyHash}（密钥年龄已重置）");
            try { VaultSync.PushVaultToLive(_box); } catch { }
            BoxStatusFile.Write(_box, BoxPhase.Stopped, "已停箱（密钥已续期）");
        }
        else
        {
            L("看门续期失败 → " + r.Message);
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
        L("常驻：周期性续期 → 重开游戏以滚动 AutoAuthKey");
        Phase(BoxPhase.Resident, "常驻续期中…");
        var frozen = Ilink.Live(_box).KeyHash;
        try { BoxRuntime.StartBrowser(_box, "resident-renew"); }
        catch (Exception ex) { L("常驻续期启动失败：" + ex.Message); }

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
                L("常驻续期：出现二维码 → key 已死，需要扫码");
                return ResidentRenewResult.NeedScan; // 不藏窗，留着扫码页让主循环接手
            }
            var live = Ilink.Live(_box);
            if (live.Valid && live.KeyHash.Length > 0 && live.KeyHash != frozen)
            {
                Ilink.Save(_box, "resident-renew");
                L($"常驻续期：key 已滚动 {frozen} -> {live.KeyHash}");
                result = ResidentRenewResult.Rolled;
                break;
            }
        }
        if (result != ResidentRenewResult.Rolled)
        {
            try { Ilink.Save(_box, "resident-renew-nokeyroll"); } catch { }
            L("常驻续期：窗口内没滚成（下个周期再试）");
        }
        try { new BoxView(_box).TrimResident(); } catch { } // 关游戏窗 + 藏壳 + 压 QQ 内存，回到轻量态
        Phase(BoxPhase.Resident, "常驻保活中（轻量）");
        return result;
    }

    /// <summary>游戏弹「版本已经更新，请重启」：确认 → 关微信运行时 → 重新打开游戏。</summary>
    void SoftRestartForUpdate(BoxView v)
    {
        L("游戏更新弹窗一直不走 → 软重启一次");
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
        L($"更新重启：已结束微信运行时进程 数量={killed}");
        Thread.Sleep(2000);
        BoxRuntime.StartBrowser(_box, "update-restart");
    }
}
