using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 凭证主动探测：每隔一段时间直接连服务器发一次 AutoAuth，用返回码判断这把 key 还能不能用。
///
/// 为什么用 AutoAuth 当探针：它是唯一「不需要启动浏览器、又能让服务器明确回答凭证是否有效」的请求。
///   · 返回 0   → 凭证有效（顺带把 key 换成新的，等于续期一次）
///   · 返回 -13 / -14 / -2 → 凭证已作废或过期，立刻标「需要扫码」并推送提醒
///
/// 前提：**沙箱必须已停**。运行中的 WeChatAppEx 内存里握着旧 key，服务端作废旧 key 后
/// 它会把旧值写回文件并断掉游戏会话（见 mmtls 研究 6F）。所以探测遇到运行中的沙箱直接跳过。
/// </summary>
public static class CredentialProbe
{
    static readonly object Gate = new();
    static Thread _thread;
    static volatile bool _stop;

    public static bool Running => _thread is { IsAlive: true };

    /// <summary>最近一次探测结果，供界面显示。</summary>
    public static volatile string LastSummary = "";

    static string StatePath(string box) => Path.Combine(AppPaths.Logs, box + ".probe.json");

    public sealed record ProbeResult(string Box, bool Ok, string Message, long Code, bool Skipped)
    {
        public bool Rejected => Code is -2 or -13 or -14;
    }

    /// <summary>后台循环：按配置的间隔反复探测。重复调用是安全的（已在跑就忽略）。</summary>
    public static void Start()
    {
        lock (Gate)
        {
            if (Running) return;
            _stop = false;
            _thread = new Thread(Loop) { IsBackground = true, Name = "credential-probe" };
            _thread.Start();
        }
    }

    public static void Stop()
    {
        lock (Gate)
        {
            _stop = true;
            _thread = null;
        }
    }

    static void Loop()
    {
        // 启动后先等一会儿，避开程序刚起来时正在做的冷启动/保活
        for (int i = 0; i < 20 && !_stop; i++) Thread.Sleep(1000);

        while (!_stop)
        {
            var cfg = NotifyConfig.Load();
            if (!cfg.ProbeEnabled)
            {
                Thread.Sleep(30_000);
                continue;
            }
            int minutes = Math.Clamp(cfg.ProbeMinutes, 1, 720);
            try
            {
                var boxes = Sandboxie.QueryBoxes();
                int ok = 0, bad = 0, skipped = 0;
                foreach (var box in boxes)
                {
                    if (_stop) break;
                    var r = Probe(box, cfg);
                    if (r.Skipped) skipped++;
                    else if (r.Ok) ok++;
                    else if (r.Rejected) bad++;
                }
                LastSummary = bad > 0
                    ? $"{DateTime.Now:HH:mm} 探测：{ok} 正常，{bad} 已失效，{skipped} 跳过"
                    : $"{DateTime.Now:HH:mm} 探测：{ok} 正常，{skipped} 跳过";
                if (bad > 0)
                {
                    // 立刻把失效的号推给用户，不等 20 小时阈值
                    try { Notifier.Check(Sandboxie.QueryBoxes(), cfg); } catch { }
                }
            }
            catch (Exception ex) { Log.App("probe loop: " + ex.Message); }

            // 分片睡眠，方便 Stop 快速生效
            int total = minutes * 60;
            for (int i = 0; i < total && !_stop; i += 5) Thread.Sleep(5000);
        }
    }

    /// <summary>
    /// 探测一个沙箱。会真实发 AutoAuth，成功即等于续期一次。
    /// </summary>
    public static ProbeResult Probe(string box, NotifyConfig cfg = null)
    {
        cfg ??= NotifyConfig.Load();

        // 运行中绝对不碰：会断掉游戏会话（6F 实测游戏窗 2 秒后消失）
        var (renewable, why) = ProtocolRenew.CheckRenewable(box);
        if (!renewable)
            return new ProbeResult(box, false, why.Split('\n')[0], 0, true);

        var vault = Ilink.VaultState(box);
        var live = Ilink.Live(box);
        if (!vault.Valid && !live.Valid)
        {
            var noScan = NeedScan.Pending(box);
            return new ProbeResult(box, false, noScan ? "未登录（待扫码），跳过" : "没有有效凭证，跳过", 0, true);
        }

        // live 坏了但金库还有一把：先把金库推回 live 再探，否则 Renew 会读到无效文件。
        if (!live.Valid && vault.Valid)
        {
            Log.Box(box, $"probe: live invalid but vault has {vault.KeyHash} -> push vault to live first");
            try { VaultSync.PushVaultToLive(box); } catch (Exception ex) { Log.Box(box, "probe: push vault failed " + ex.Message); }
        }

        if (ProtocolRenew.AttemptPending(box))
        {
            // 上一次请求结果未知：不盲目重放，等人工确认
            return new ProbeResult(box, false, "上次续期结果未知（attempt 标记还在），跳过", 0, true);
        }

        var r = ProtocolRenew.Renew(box);
        var rec = new JsonObject
        {
            ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            ["ok"] = r.Ok,
            ["code"] = r.Code,
            ["message"] = r.Message,
            ["keySha"] = r.NewKeyHash,
        };
        try { JsonFile.WriteObject(StatePath(box), rec); } catch { }

        if (r.Ok)
        {
            Log.Box(box, $"probe: 服务器确认凭证有效并已换新 key={r.NewKeyHash}");
            try { VaultSync.PushVaultToLive(box); } catch { }
            return new ProbeResult(box, true, r.Message, 0, false);
        }

        if (r.Rejected)
        {
            Log.Box(box, $"probe: 服务器判定凭证已失效（{r.Code}）-> 标需要扫码");
            NeedScan.Set(box, "probe-revoked");
            BoxStatusFile.Write(box, BoxPhase.Failed, "凭证已被服务器作废，需要重新扫码");
            Ilink.WriteEvent(box, "probe-rejected", new JsonObject
            {
                ["code"] = r.Code, ["message"] = r.Message,
            });
            return new ProbeResult(box, false, r.Message, r.Code, false);
        }

        // 网络等临时错误：不标 need-scan，下一轮再试
        Log.Box(box, "probe: 探测失败（非拒绝）-> " + r.Message);
        return new ProbeResult(box, false, r.Message, r.Code, false);
    }

    /// <summary>读某个沙箱最近一次探测结果（界面上展示用）。</summary>
    public static JsonObject LastState(string box) => JsonFile.ReadObject(StatePath(box));
}
