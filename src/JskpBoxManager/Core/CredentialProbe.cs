using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 凭证主动探测：每隔一段时间直接连服务器发一次 AutoAuth，用返回码判断这把 key 还能不能用。
///
/// 为什么用 AutoAuth 当探针：它是唯一「不需要启动浏览器、又能让服务器明确回答凭证是否有效」的请求。
///   · 返回 0   → 凭证有效（顺带把 key 换成新的）
///   · 返回 -13 / -14 / -2 → 凭证已作废或过期，立刻标「需要扫码」并推送提醒
///
/// **重要限制：AutoAuth 是轮换语义，探一次就换一把 key，协议层做不到「只验证不换」。**
/// 所以探测频率不能太高：qb4 在 2026-11-07 凌晨被每 2 分钟的探测连滚 4 次 key，
/// 当天下午整条授权链被服务端作废（连 10-31 的历史 key 都失效了）。
/// 现在有双重保护：最短 30 分钟一次 + 每号每天最多换 MaxRotationsPerDay 次。
///
/// 前提：**沙箱必须已停**。运行中的 WeChatAppEx 内存里握着旧 key，服务端作废旧 key 后
/// 它会把旧值写回文件并断掉游戏会话（见 mmtls 研究 6F）。所以探测遇到运行中的沙箱直接跳过。
/// </summary>
public static class CredentialProbe
{
    /// <summary>探测的最短间隔（分钟）。再密就会变成「每几分钟滚一次 key」，服务端会当异常。</summary>
    public const int MinProbeMinutes = 30;

    /// <summary>单个号每天最多换几次 key。超过就跳过，等明天。</summary>
    public const int MaxRotationsPerDay = 8;

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
            // 探测会真实换 key（AutoAuth 是轮换语义，协议层做不到「只验证不换」）。
            // 每 2 分钟探一次 = 每 2 分钟滚一次 key，服务端会判定异常并作废整条链
            // （qb4 11-07 凌晨 4 分钟换 4 次，当天下午整条链报废，连 10-31 的历史 key 都失效）。
            // 所以给一个安全下限：最快 30 分钟一次；每号每天最多换 8 次 key。
            int minutes = Math.Clamp(cfg.ProbeMinutes, MinProbeMinutes, 720);
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

        // 今天换够了就别再换：频繁轮换会让服务端把整条授权链判定为异常并全部作废
        int today = RotationsToday(box);
        if (today >= MaxRotationsPerDay)
        {
            Log.Box(box, $"probe: already rotated {today} times today (limit {MaxRotationsPerDay}) -> skip");
            return new ProbeResult(box, false, $"今天已换过 {today} 次 key，跳过（防触发风控）", 0, true);
        }

        var r = ProtocolRenew.Renew(box);
        if (r.Ok) RecordRotation(box, r.NewKeyHash, "probe");
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

    // ---------------- 每日换 key 计数（防把整条链滚废） ----------------

    static string RotateLogPath(string box) => Path.Combine(AppPaths.Logs, box + ".rotate-log");

    /// <summary>今天已经换过几次 key。</summary>
    public static int RotationsToday(string box)
    {
        try
        {
            var p = RotateLogPath(box);
            if (!File.Exists(p)) return 0;
            var today = DateTime.Today.ToString("yyyy-MM-dd");
            return File.ReadAllLines(p).Count(l => l.StartsWith(today, StringComparison.Ordinal));
        }
        catch { return 0; }
    }

    static void RecordRotation(string box, string newKey, string why)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.Logs);
            File.AppendAllText(RotateLogPath(box),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {newKey} {why}\r\n", new UTF8Encoding(false));
        }
        catch { }
    }

    /// <summary>保活等其它路径换 key 后也要记账，否则「每日上限」统计不到。</summary>
    public static void RecordRotationPublic(string box, string newKey, string why) => RecordRotation(box, newKey, why);

    /// <summary>今天是否已经换够了（到上限就不再探，避免服务端把整条链当异常）。</summary>
    public static bool RotationBudgetExhausted(string box) => RotationsToday(box) >= MaxRotationsPerDay;
}
