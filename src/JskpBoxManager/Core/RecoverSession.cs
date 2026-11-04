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
        var tryList = cands.Where(c => !c.Revoked).ToList();
        if (tryList.Count == 0)
        {
            Out("没有可用的历史凭证（都已作废或没有备份），只能重新扫码。");
            return 1;
        }
        Out($"共 {tryList.Count} 把可试（跳过 {cands.Count - tryList.Count} 把已作废）。每把约 1~2 分钟。");

        BoxRuntime.RegisterLauncher(_box, "recover");
        try
        {
            int i = 0;
            foreach (var c in tryList)
            {
                i++;
                Out($"[{i}/{tryList.Count}] 试 key {c.KeyShort}（{c.SavedAt:MM-dd HH:mm}{(c.IsVault ? " · 当前金库" : "")}）…");
                BoxStatusFile.Write(_box, BoxPhase.Starting, $"恢复中：试 {c.KeyShort}（{i}/{tryList.Count}）");
                if (TryOne(c))
                {
                    Out($"✓ 成功：key {c.KeyShort} 能免扫，已进入游戏并存回金库。");
                    L($"recover OK with key {c.KeyHash}");
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

    /// <summary>写入这把 key 冷启一次，2 分钟内进游戏或换新密钥算成功；凭证被清空且扫码页持续约 20s 算这把被拒。</summary>
    bool TryOne(CredCandidate c)
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
