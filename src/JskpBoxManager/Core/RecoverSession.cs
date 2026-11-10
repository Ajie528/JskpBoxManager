namespace JskpBoxManager.Core;

/// <summary>
/// 自动用历史凭证逐个试恢复免扫：JskpBoxManager.exe recover qbN。
/// 按「当前金库 → 历史从新到旧」，跳过已登记作废的，逐把冷启验证；第一把能免扫进游戏就停并存回金库。
/// 只能救「本地坏/坏换新」——真被顶（服务端 ret=-13）整条链都会被拒，最后提示必须重新扫码。
/// </summary>
public sealed class RecoverSession
{
    readonly string _box;
    public RecoverSession(string box) { _box = box; }

    void L(string m) => Log.Box(_box, m);
    static void Out(string m) => System.Console.WriteLine(m);

    public int Run()
    {
        L("recover start");
        Out($"开始用历史凭证恢复 {_box} 的免扫登录…");

        var cands = Ilink.CredentialHistory(_box);
        var tryList = cands.Where(c => !c.Revoked && HistoryCooldown.Allowed(_box, c.KeyHash)).ToList();
        if (tryList.Count == 0)
        {
            var cooling = cands.Count(c => !c.Revoked && !HistoryCooldown.Allowed(_box, c.KeyHash));
            Out(cooling > 0
                ? $"还剩 {cooling} 把历史凭证在被拒冷却期里（默认 {HistoryCooldown.DefaultHours:0} 小时），暂不重试；这次只能重新扫码。"
                : "没有可用的历史凭证（都已作废或没有备份），只能重新扫码。");
            return 1;
        }
        Out($"共 {tryList.Count} 把可试（跳过 {cands.Count - tryList.Count} 把已作废/冷却中）。每把约 1~2 分钟。");

        BoxRuntime.RegisterLauncher(_box, "recover");
        try
        {
            int i = 0;
            foreach (var c in tryList)
            {
                i++;
                Out($"[{i}/{tryList.Count}] 试 key {c.KeyShort}（{c.SavedAt:MM-dd HH:mm}{(c.IsVault ? " · 当前金库" : "")}）…");
                BoxStatusFile.Write(_box, BoxPhase.Starting, $"恢复中：试 {c.KeyShort}（{i}/{tryList.Count}）");

                // 先用协议探测（0.1 秒，不开浏览器、不停箱）：服务端认可就一步到位换新 key。
                // 这才是当初救回 qb10 / qb12 的方式；冷启动只作为「协议说不通」时的兜底。
                var pr = ProbeHistoryKey(c);
                if (pr.Ok)
                {
                    Out($"✓ 成功：key {c.KeyShort} 协议续期通过，已换新 key {pr.NewKeyHash}。");
                    HistoryCooldown.Clear(_box, c.KeyHash);
                    L($"recover OK (protocol) with key {c.KeyHash} -> {pr.NewKeyHash}");
                    Out("提示：这个号已恢复免扫，直接点「启动游戏」即可进入；不需要再扫码。");
                    return 0;
                }
                if (pr.Rejected)
                {
                    Out($"  ✗ key {c.KeyShort} 服务端明确拒绝（{pr.Code}），换下一把。");
                    continue;
                }
                Out($"  · key {c.KeyShort} 协议续期未成功（{pr.Message}），回退冷启动验证…");

                if (TryOne(c))
                {
                    Out($"✓ 成功：key {c.KeyShort} 能免扫，已进入游戏并存回金库。");
                    L($"recover OK with key {c.KeyHash}");
                    HistoryCooldown.Clear(_box, c.KeyHash);
                    NeedScan.Clear(_box);
                    NeedScan.ClearQrStreak(_box);
                    BoxStatusFile.Write(_box, BoxPhase.InGame, "已用历史凭证免扫恢复");
                    Out("提示：如需后台保活/藏窗，点一次「启动游戏」接管即可。");
                    return 0;
                }
                Out($"  ✗ key {c.KeyShort} 仍要扫码，换下一把。");
            }

            Out("所有历史 key 都试过了，都要扫码——这次是真被顶 / 过期，只能重新扫码。");
            L("recover: all candidates failed -> need scan");
            try { VaultSync.PushVaultToLive(_box); } catch { }
            NeedScan.Set(_box, "recover-all-failed");
            BoxRuntime.StopForce(_box, false);
            BoxStatusFile.Write(_box, BoxPhase.Failed, "历史凭证都恢复不了，需要重新扫码");
            return 2;
        }
        finally
        {
            BoxRuntime.UnregisterLauncher(_box);
            L("recover end");
        }
    }

    /// <summary>
    /// 单把凭证的快速验证，**不需要停箱**。
    ///
    /// 思路（用户提出的）：协议续期是纯网络操作，不碰任何沙箱文件。
    /// 所以可以拿着历史快照里的 tdi_account.txt 直接发 AutoAuth：
    ///   · 返回 -13/-14 → 这把废了，换下一把（全程零成本，不用停箱、不用起浏览器）
    ///   · 返回 0      → 服务端已换新 key，**这时才停箱**，把新 key 写进 live 并推金库
    ///
    /// 关键约束：服务端一旦接受就会作废旧 key，所以成功后必须立即落盘，
    /// 否则旧 key 已作废、新 key 又丢了。这个由 CommitToFile 保证。
    /// </summary>
    internal ProtocolRenew.Result ProbeHistoryKey(CredCandidate c)
    {
        // 找到这份快照里的 tdi_account.txt（不依赖沙箱结构）
        var acct = Ilink.AccountFile(c.Dir);
        if (acct == null || !acct.Exists)
            return new ProtocolRenew.Result(false, "这份备份里没有 tdi_account.txt", "", long.MaxValue);

        // 纯网络探测：不停箱、不写文件、不开浏览器
        var r = ProtocolRenew.ProbeFile(acct.FullName, _box);

        // 被拒的历史 key 进冷却，不再每轮重试。
        // 这里**不能**登记成永久作废：实测 -13 会自己恢复——qb4 的 c21a5cc3
        // 在 11-07 15:27 探测时是 -13，11-09 10:38 再用它却被服务端接受了。
        // 但也不能什么都不记：qb4 在 11-10 的 04:15 与 08:42 把同样 16 把全试了两遍，
        // 多打出去的 32 次 AutoAuth 本身就是风控要看的异常特征。
        if (!r.Ok && r.Rejected) HistoryCooldown.Mark(_box, c.KeyHash, r.Code);

        if (!r.Ok) return r;

        // 服务端已认可并换新：现在才停箱落盘
        L($"recover: key {c.KeyShort} accepted by server -> stopping box to write new credential");
        BoxRuntime.StopForce(_box, false);
        BoxRuntime.RegisterLauncher(_box, "recover-commit");
        Thread.Sleep(1500);

        // 把候选写进 live + 金库，再把探测拿到的新 key 覆盖上去
        if (!Ilink.RestoreCredentialSet(_box, c.Dir))
        {
            // 写不进 live 也没关系：至少把新 key 写进快照目录
            L($"recover: cannot restore {c.KeyShort} to live, writing new key to snapshot only");
        }
        SyncCandidateToVault(c);

        // 关键：新 key 必须写进 **live + 金库**，不能只写历史快照。
        // 服务端在探测成功那一刻已经轮换过了，本地若还留着被轮换掉的旧 key，
        // 重新启动时运行时会再发一次 AutoAuth，同一号上就出现两条有效分支，
        // 之后一起被判 -13（qb4 11-09 10:38 的 a4d97938 / 3d0a2ead 就是这样来的）。
        if (!ProtocolRenew.CommitToBox(_box, r, out var err))
        {
            L("recover: commit new key to box failed: " + err + " -> fall back to snapshot write");
            if (!ProtocolRenew.CommitToFile(r, out var err2))
            {
                L("recover: commit new key failed: " + err2);
                return new ProtocolRenew.Result(false, "拿到新 key 但写入失败：" + err2, "", long.MaxValue);
            }
        }
        else
        {
            // live/金库写成功后再把历史快照也更新一份，避免下次从这份快照恢复时
            // 又拿出一把早被轮换掉的 key。
            if (!ProtocolRenew.CommitToFile(r, out var snapErr))
                L("recover: update snapshot failed (not fatal): " + snapErr);
        }

        CredentialProbe.RecordRotationPublic(_box, r.NewKeyHash, "recover-probe");
        try { VaultSync.PushVaultToLive(_box); } catch { }
        try { Ilink.Save(_box, "recover-probe"); } catch { }
        NeedScan.Clear(_box);
        NeedScan.ClearQrStreak(_box);
        L($"recover: protocol OK with key {c.KeyShort} -> new {r.NewKeyHash}");
        BoxStatusFile.Write(_box, BoxPhase.Stopped, "已用历史凭证恢复（协议续期）");
        return r;
    }

    /// <summary>
    /// 单把凭证的快速验证：写入这套凭证 → **协议续期**（0.1 秒，不开浏览器）。
    /// 成功即说明服务端认可这把 key，且顺带换成了新 key（等于恢复 + 续期一步到位）。
    /// 失败返回它的失败码，由调用方决定是否回退到冷启动验证。
    ///
    /// 这就是当初救回 qb10 / qb12 的方式：它们的金库旧 key（10-16 / 10-18）放了 20 多天
    /// 仍然有效，协议续期一次就换成了新 key，根本不需要拉起浏览器。
    ///
    /// **关于停箱**：只有沙箱里还有进程时才需要停（运行时会锁住 tdi_account.txt 并把旧 key 写回）。
    /// 连续试多把时，第一把停完后续都停着，后面的每把能省掉约 6 秒的停箱等待。
    /// </summary>
    internal ProtocolRenew.Result TryOneByProtocol(CredCandidate c)
    {
        // 只在确实有进程时才停箱；已经停着就直接写，省掉 6 秒/把
        if (Sandboxie.Pids(_box).Count > 0)
        {
            BoxRuntime.StopForce(_box, false);
            BoxRuntime.RegisterLauncher(_box, "recover-protocol");
            Thread.Sleep(2000);
        }
        else
        {
            // 仍然登记 launcher，避免同时被别的保活流程抢走
            BoxRuntime.RegisterLauncher(_box, "recover-protocol");
        }

        NeedScan.Clear(_box);
        Ilink.ClearRevokedKey(_box, c.KeyHash);
        if (!Ilink.RestoreCredentialSet(_box, c.Dir))
            return new ProtocolRenew.Result(false, "这份备份读不出有效凭证", "", long.MaxValue);

        // 关键：ProtocolRenew.ReadCredential 会取 live 与金库中**较新**那份。
        // 历史快照写进 live 后时间通常比金库旧，会被金库的 key 顶掉——那样测的就不是这把了。
        // 所以必须把这一份同时写进金库，让两者一致。
        SyncCandidateToVault(c);

        var (renewable, blocked) = ProtocolRenew.CheckRenewable(_box);
        if (!renewable)
            return new ProtocolRenew.Result(false, "沙箱没停干净：" + blocked.Split('\n')[0], "", long.MaxValue);

        // 再确认一次：现在读到的确实是这把 key
        var live = Ilink.Live(_box);
        if (!live.Valid || live.KeyHash != c.KeyHash)
            L($"recover: warning, live key {live.KeyHash} differs from candidate {c.KeyHash}");

        var r = ProtocolRenew.Renew(_box);
        if (r.Ok)
        {
            CredentialProbe.RecordRotationPublic(_box, r.NewKeyHash, "recover-protocol");
            try { VaultSync.PushVaultToLive(_box); } catch { }
            try { Ilink.Save(_box, "recover-protocol"); } catch { }
            NeedScan.Clear(_box);
            NeedScan.ClearQrStreak(_box);
            L($"recover: protocol renew OK with key {c.KeyShort} -> new {r.NewKeyHash}");
            BoxStatusFile.Write(_box, BoxPhase.Stopped, "已用历史凭证恢复（协议续期）");
        }
        return r;
    }

    /// <summary>把候选凭证同时写进金库，避免「金库更新 → 协议续期读到金库那把」的错位。</summary>
    void SyncCandidateToVault(CredCandidate c)
    {
        try
        {
            var vaultRoot = BoxPaths.WmpfVault(_box);
            var src = c.Dir;
            var acct = Ilink.AccountFile(src);
            if (acct == null) return;
            var rel = acct.FullName[src.TrimEnd('\\').Length..].TrimStart('\\');
            var dst = Path.Combine(vaultRoot, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
            File.Copy(acct.FullName, dst, true);
            // 保持时间戳一致，让「较新」判定落在这一份上
            File.SetLastWriteTimeUtc(dst, File.GetLastWriteTimeUtc(acct.FullName));
            var pskSrc = Path.Combine(src, @"ilink\default\psk.key");
            var pskDst = Path.Combine(vaultRoot, @"ilink\default\psk.key");
            if (File.Exists(pskSrc))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(pskDst)!);
                File.Copy(pskSrc, pskDst, true);
                File.SetLastWriteTimeUtc(pskDst, File.GetLastWriteTimeUtc(pskSrc));
            }
            L($"recover: candidate {c.KeyShort} synced to vault so protocol renew uses the right key");
        }
        catch (Exception ex) { L("recover: sync candidate to vault failed " + ex.Message); }
    }

    /// <summary>写入这把 key 冷启一次，2 分钟内进游戏或换新密钥算成功；凭证被清空且扫码页持续约 20s 算这把被拒。</summary>
    internal bool TryOne(CredCandidate c)
    {
        BoxRuntime.StopForce(_box, false);
        BoxRuntime.RegisterLauncher(_box, "recover");
        Thread.Sleep(2500);
        BoxRuntime.ClearCrashRestore(_box);

        if (!Ilink.RestoreCredentialSet(_box, c.Dir))
        {
            Out("  （这份备份读不出凭证，跳过）");
            return false;
        }
        NeedScan.Clear(_box);
        Ilink.ClearRevokedKey(_box, c.KeyHash);
        BoxRuntime.EnsureWxRuntimeInBox(_box);
        BoxRuntime.Warmup(_box, false);

        var baseline = Ilink.Baseline(_box);
        var launchUtc = DateTime.UtcNow;
        BoxRuntime.StartBrowser(_box, "recover", BoxRuntime.LaunchMode.Full);

        var deadline = DateTime.Now.AddMinutes(2);
        bool credCleared = false;
        DateTime? qrSince = null;
        while (DateTime.Now < deadline)
        {
            Thread.Sleep(3000);

            if (Ilink.RenewedSince(_box, launchUtc) && Ilink.Live(_box).KeyHash != c.KeyHash)
            {
                Ilink.Save(_box, "recover");
                return true;
            }
            if (!credCleared && Ilink.RevokedSinceLaunch(_box, baseline)) credCleared = true;

            BoxView v;
            try { v = new BoxView(_box); }
            catch { continue; }

            if (v.HasGameWindow)
            {
                try { Ilink.Save(_box, "recover-game"); } catch { }
                return true;
            }
            if (credCleared && v.HasStrictQr)
            {
                qrSince ??= DateTime.Now;
                if ((DateTime.Now - qrSince.Value).TotalSeconds >= 20) return false;
                continue;
            }
            qrSince = null;
            try { v.CloseRestorePage(); } catch { }
            try { Cdp.CloseExtraTabs(_box); } catch { }
        }
        return false;
    }
}
