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
/// **重要限制 1：AutoAuth 是轮换语义，探一次就换一把 key，协议层做不到「只验证不换」。**
/// 所以探测频率不能太高：qb4 在 2026-11-07 凌晨被每 2 分钟的探测连滚 4 次 key，
/// 当天下午整条授权链被服务端作废（连 10-31 的历史 key 都失效了）。
/// 保护：最短 30 分钟一次 + 每号每天最多换 MaxRotationsPerDay 次。
///
/// **重要限制 2：不能所有号在同一时刻同时发。** 同一个公网 IP 在几秒内连续
/// 对十几个不同 uin 发 AutoAuth，本身就是异常特征。所以：
///   · 每个号有自己的到期时间，互相错开；
///   · 每次到期时间带随机抖动（±35%），不会周期性踩点；
///   · 同一轮里也逐个探、中间隔随机 20~70 秒，绝不并发。
///
/// 前提：**沙箱必须已停**。运行中的 WeChatAppEx 内存里握着旧 key，服务端作废旧 key 后
/// 它会把旧值写回文件并断掉游戏会话（见 mmtls 研究 6F）。所以探测遇到运行中的沙箱直接跳过。
/// </summary>
public static class CredentialProbe
{
    /// <summary>探测的最短间隔（分钟）。再密就会变成「每几分钟滚一次 key」，服务端会当异常。</summary>
    public const int MinProbeMinutes = 30;

    /// <summary>单个号每天最多换几次 key。超过就跳过，等明天。可在界面按沙箱覆盖。</summary>
    public const int MaxRotationsPerDay = 8;

    // 「密钥还新就别为探测滚一次」的门槛已改到 Keepalive.DefaultMinKeyAgeHours（可按沙箱配置），
    // 这里不再保留第二个常量，避免两处默认值各说各话。

    /// <summary>到期时间的随机抖动比例：±35%，避免每天踩同一个时间点。</summary>
    const double JitterFraction = 0.35;

    /// <summary>同一轮里两个号之间的随机间隔（秒）。</summary>
    const int MinGapSeconds = 20, MaxGapSeconds = 70;

    /// <summary>调度循环的检查粒度（秒）。</summary>
    const int TickSeconds = 20;

    static readonly object Gate = new();
    static Thread _thread;
    static volatile bool _stop;
    static readonly Random Rng = new();

    public static bool Running => _thread is { IsAlive: true };

    /// <summary>最近一次探测结果，供界面显示。</summary>
    public static volatile string LastSummary = "";

    static string StatePath(string box) => Path.Combine(AppPaths.Logs, box + ".probe.json");

    public sealed record ProbeResult(string Box, bool Ok, string Message, long Code, bool Skipped)
    {
        public bool Rejected => Code is -2 or -13 or -14;
    }

    // ---------------- 每号独立到期时间（错开 + 抖动） ----------------

    static string SchedulePath => Path.Combine(AppPaths.Logs, "probe-schedule.json");

    static Dictionary<string, DateTime> LoadSchedule()
    {
        var d = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        var o = JsonFile.ReadObject(SchedulePath);
        if (o == null) return d;
        foreach (var kv in o)
        {
            var s = JsonFile.Str(o, kv.Key);
            if (DateTime.TryParse(s, out var t)) d[kv.Key] = t;
        }
        return d;
    }

    static void SaveSchedule(Dictionary<string, DateTime> d)
    {
        var o = new JsonObject();
        foreach (var kv in d.OrderBy(x => Sandboxie.BoxNumber(x.Key), Comparer<int>.Default))
            o[kv.Key] = kv.Value.ToString("yyyy-MM-dd HH:mm:ss");
        try { JsonFile.WriteObject(SchedulePath, o); } catch { }
    }

    /// <summary>
    /// 算下一次到期时间 = 现在 + 间隔 + 随机抖动。
    /// 抖动是双向的（±35%），长期看不会漂移，也不会每天固定同一时刻。
    /// </summary>
    static DateTime NextDue(int minutes)
    {
        double baseSec = minutes * 60.0;
        double jitter = baseSec * JitterFraction * (Rng.NextDouble() * 2 - 1);   // ±35%
        var span = TimeSpan.FromSeconds(Math.Max(60, baseSec + jitter));
        return DateTime.Now + span;
    }

    /// <summary>
    /// 首次见到某个号时，把它的到期时间按箱号错开。
    /// 这样即使所有号同时被启用，也不会挤在同一分钟。
    /// </summary>
    static DateTime InitialDue(string box, int minutes)
    {
        int n = Math.Max(1, Sandboxie.BoxNumber(box));
        double spreadSec = Math.Min(minutes * 60.0, n * 97.0 + Rng.Next(0, 180));   // 每号错开约 1.6 分钟
        return DateTime.Now + TimeSpan.FromSeconds(spreadSec);
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
        // 给还没登记过的号排上错开的初次探测时间（已登记的不动，保留原有节奏）
        try { ReseedSchedule(); } catch { }
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

        var schedule = LoadSchedule();

        while (!_stop)
        {
            var cfg = NotifyConfig.Load();
            if (!cfg.ProbeEnabled)
            {
                Thread.Sleep(30_000);
                continue;
            }

            int minutes = Math.Clamp(cfg.ProbeMinutes, MinProbeMinutes, 720);
            var now = DateTime.Now;
            var due = schedule.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList();
            if (due.Count == 0)
            {
                // 还没到任何号的到期时间：睡一小段再看
                for (int i = 0; i < TickSeconds && !_stop; i++) Thread.Sleep(1000);
                continue;
            }

            // 同一轮里有多个号到期：逐个探、中间隔随机 20~70 秒，绝不并发。
            // 同一个公网 IP 几秒内连发十几个 AutoAuth 是明显的异常特征。
            int ok = 0, bad = 0, skipped = 0;
            for (int idx = 0; idx < due.Count && !_stop; idx++)
            {
                var box = due[idx];
                var r = Probe(box, cfg);
                if (r.Skipped) skipped++;
                else if (r.Ok) ok++;
                else if (r.Rejected) bad++;

                // 每个号探完就排下一次（无论成功失败），带抖动避免踩点
                schedule[box] = NextDue(minutes);

                if (idx < due.Count - 1 && !_stop)
                {
                    int gap = Rng.Next(MinGapSeconds, MaxGapSeconds + 1);
                    Log.App($"主动探测：下一个号等 {gap} 秒（错峰，避免同一时刻连发）");
                    for (int s = 0; s < gap && !_stop; s++) Thread.Sleep(1000);
                }
            }

            SaveSchedule(schedule);
            LastSummary = bad > 0
                ? $"{DateTime.Now:HH:mm} 探测：{ok} 正常，{bad} 已失效，{skipped} 跳过"
                : $"{DateTime.Now:HH:mm} 探测：{ok} 正常，{skipped} 跳过";
            if (bad > 0)
            {
                // 立刻把失效的号推给用户，不等 20 小时阈值
                try { Notifier.Check(Sandboxie.QueryBoxes(), cfg); } catch { }
            }

            for (int i = 0; i < TickSeconds && !_stop; i++) Thread.Sleep(1000);
        }
    }

    /// <summary>
    /// 把新出现的号登记进调度表（错开初次探测时间），并清掉已删除的号。
    /// 界面/命令行启动时调用一次即可。</summary>
    public static void ReseedSchedule(IEnumerable<string> boxes = null, NotifyConfig cfg = null)
    {
        cfg ??= NotifyConfig.Load();
        int minutes = Math.Clamp(cfg.ProbeMinutes, MinProbeMinutes, 720);
        var schedule = LoadSchedule();
        var list = (boxes ?? Sandboxie.QueryBoxes()).ToList();
        // 空列表多半是「界面还没加载完」而不是「沙箱都没了」：直接返回，别把计划清空
        if (list.Count == 0 && boxes != null) return;
        var set = new HashSet<string>(list, StringComparer.OrdinalIgnoreCase);
        foreach (var kv in schedule.Keys.Where(k => !set.Contains(k)).ToList()) schedule.Remove(kv);
        foreach (var b in list)
            if (!schedule.ContainsKey(b)) schedule[b] = InitialDue(b, minutes);
        SaveSchedule(schedule);
    }

    /// <summary>某个号下一次探测时间（界面展示用）。</summary>
    public static DateTime? NextProbeAt(string box)
    {
        var s = LoadSchedule();
        return s.TryGetValue(box, out var t) ? t : null;
    }

    /// <summary>所有号的探测计划（界面展示用）。</summary>
    public static (string Box, DateTime Due)[] Schedule()
        => LoadSchedule().OrderBy(kv => kv.Value).Select(kv => (kv.Key, kv.Value)).ToArray();

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
            Log.Box(box, $"主动探测：沙箱凭证无效，但金库有 {vault.KeyHash} → 先把金库推回沙箱");
            try { VaultSync.PushVaultToLive(box); } catch (Exception ex) { Log.Box(box, "主动探测：推金库到沙箱失败 " + ex.Message); }
        }

        if (ProtocolRenew.AttemptPending(box))
        {
            // 上一次请求结果未知：不盲目重放，等人工确认
            return new ProbeResult(box, false, "上次续期结果未知（attempt 标记还在），跳过", 0, true);
        }

        // 密钥还新就别为了「确认一下」去滚它：AutoAuth 是轮换语义，探一次换一把，
        // 白白消耗服务端容忍额度。真要确认，等密钥老化到门槛之后。
        var pol = Keepalive.Load().For(box);
        double minAge = pol.EffectiveMinKeyAgeHours;
        var keyAge = ProtocolRenew.KeyAgeHours(box);
        if (keyAge is double age && age < minAge)
        {
            Log.Box(box, $"主动探测：密钥才 {age:F1} 小时（门槛 {minAge} 小时）→ 不值得为探测滚一次");
            return new ProbeResult(box, false, $"密钥才 {age:F1} 小时，不值得为探测滚一次", 0, true);
        }

        // 今天换够了就别再换：频繁轮换会让服务端把整条授权链判定为异常并全部作废
        int quota = pol.EffectiveMaxRotations;
        int today = RotationsToday(box);
        if (today >= quota)
        {
            Log.Box(box, $"主动探测：今天已换 {today} 次（上限 {quota} 次）→ 跳过");
            return new ProbeResult(box, false, $"今天已换过 {today} 次 key，跳过（防触发风控）", 0, true);
        }

        // ★ 今天已经换过（探测/预检/保活/运行时自己滚）就不再为了「确认一下」再滚一次。
        //
        // 探测的唯一价值是「在密钥自然过期前发现问题」。但密钥一旦今天换过，它顶多
        // 几小时大——此时再探一次，纯粹是拿一次换钥额度换一个「确实没问题」的答案，
        // 而这恰恰是风控最在意的行为（qb4 就是被高频探测把整条链滚废的）。
        // 真要确认，等它老过 minAge 之后那一轮自然会探。
        if (today > 0 && keyAge is double haveAge && haveAge < 12)
        {
            Log.Box(box, $"主动探测：今天已换 {today} 次、密钥才 {haveAge:F1} 小时 → 不再为确认滚一次");
            return new ProbeResult(box, false, $"今天已换过 {today} 次 key，不重复探测", 0, true);
        }

        // 当天已真正跑过保活（refresh）也不必再单独探测：保活本身就是一次完整续期，
        // 已经起过「确认凭证可用」的作用。重复探测只是多烧一次额度。
        if (Keepalive.RefreshServedToday(box) && keyAge is double servedAge && servedAge < 12)
        {
            Log.Box(box, $"主动探测：今天已跑过保活、密钥才 {servedAge:F1} 小时 → 无需再探");
            return new ProbeResult(box, false, "今天已保活过，无需重复探测", 0, true);
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
            Log.Box(box, $"主动探测：服务器确认凭证有效并已换新 key={r.NewKeyHash}");
            try { VaultSync.PushVaultToLive(box); } catch { }
            return new ProbeResult(box, true, r.Message, 0, false);
        }

        if (r.Rejected)
        {
            Log.Box(box, $"主动探测：服务器判定凭证已失效（{r.Code}）→ 标记需要扫码");
            // v1.5.37：登记这把已死，避免历史探测反复重试同一把
            try
            {
                var cur = Ilink.Live(box);
                if (cur.Valid) Ilink.RegisterRevokedKey(box, cur.KeyHash, "probe-" + r.Code);
            }
            catch { }
            NeedScan.Set(box, "probe-revoked");
            BoxStatusFile.Write(box, BoxPhase.Failed, "凭证已被服务器作废，需要重新扫码");
            Ilink.WriteEvent(box, "probe-rejected", new JsonObject
            {
                ["code"] = r.Code, ["message"] = r.Message,
            });
            return new ProbeResult(box, false, r.Message, r.Code, false);
        }

        // 网络等临时错误：不标 need-scan，下一轮再试
        Log.Box(box, "主动探测：探测失败（非拒绝）→ " + r.Message);
        return new ProbeResult(box, false, r.Message, r.Code, false);
    }

    /// <summary>读某个沙箱最近一次探测结果（界面上展示用）。</summary>
    public static JsonObject LastState(string box) => JsonFile.ReadObject(StatePath(box));

    // ---------------- 每日换 key 计数（防把整条链滚废） ----------------

    static string RotateLogPath(string box) => Path.Combine(AppPaths.Logs, box + ".rotate-log");

    /// <summary>今天已经换过几次 key（按 key 哈希去重，同一把重复保存只算一次）。</summary>
    public static int RotationsToday(string box)
    {
        try
        {
            var p = RotateLogPath(box);
            if (!File.Exists(p)) return 0;
            var today = DateTime.Today.ToString("yyyy-MM-dd") + " ";
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadLines(p))
            {
                if (!line.StartsWith(today, StringComparison.Ordinal)) continue;
                // 行格式：「yyyy-MM-dd HH:mm:ss <keySha> <why>」
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 3) seen.Add(parts[2]);
                else seen.Add(line);
            }
            return seen.Count;
        }
        catch { return 0; }
    }

    /// <summary>今天最后一次换 key 的时间；没有记录返回 null。用于「密钥太新就别再滚」的判断。</summary>
    public static DateTime? LastRotationAt(string box)
    {
        try
        {
            var p = RotateLogPath(box);
            if (!File.Exists(p)) return null;
            foreach (var line in File.ReadLines(p).Reverse())
            {
                if (line.Length < 19) continue;
                if (DateTime.TryParseExact(line[..19], "yyyy-MM-dd HH:mm:ss",
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeLocal, out var t))
                    return t;
            }
        }
        catch { }
        return null;
    }

    static void RecordRotation(string box, string newKey, string why)
    {
        try
        {
            // 同一把 key 不重复记账：Ilink.Save 会在每次保活/看门循环里被调用，
            // 若不去重，一次轮换会被记几十次，「每日上限」立刻被虚假耗尽。
            if (newKey.Length > 0)
            {
                var p0 = RotateLogPath(box);
                var todayPrefix = DateTime.Today.ToString("yyyy-MM-dd") + " ";
                if (File.Exists(p0))
                    foreach (var line in File.ReadLines(p0))
                        if (line.StartsWith(todayPrefix, StringComparison.Ordinal)
                            && line.Contains(" " + newKey + " ", StringComparison.OrdinalIgnoreCase))
                            return;
            }
            Directory.CreateDirectory(AppPaths.Logs);
            File.AppendAllText(RotateLogPath(box),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {newKey} {why}\r\n", new UTF8Encoding(false));
        }
        catch { }
    }

    /// <summary>
    /// 保活等其它路径换 key 后也要记账，否则「每日上限」统计不到。
    /// <para>
    /// 这是 v1.5.37 补的：以前只有 <see cref="ProtocolRenew"/> 那条协议路径记账，
    /// 冷启动和手动开游戏滚出来的新 key 只写 <c>key-rotated</c> 事件，不进 rotate-log，
    /// 于是「今天已换 8 次」这条风控判据对最常见的轮换方式完全失效。
    /// </para>
    /// </summary>
    public static void RecordRotationPublic(string box, string newKey, string why) => RecordRotation(box, newKey, why);

    /// <summary>今天还能换几次 key（到 0 表示该停了，避免把整条授权链滚废）。</summary>
    public static int RotationsLeftToday(string box) => Math.Max(0, MaxRotationsPerDay - RotationsToday(box));

    /// <summary>今天是否已经换够了（到上限就不再探，避免服务端把整条链当异常）。</summary>
    public static bool RotationBudgetExhausted(string box) => RotationsToday(box) >= MaxRotationsPerDay;
}
