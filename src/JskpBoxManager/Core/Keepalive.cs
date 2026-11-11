using System.Security;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

public sealed class KeepPolicy
{
    public bool Enabled = true;
    public string Schedule = "daily"; // daily | interval（默认每天一次，少滚密钥）
    public int IntervalHours = 4;
    public string DailyTime = "04:00";
    /// <summary>关游戏窗后不整箱停，藏窗压内存，保留 QQBrowser+WeChatAppEx 上的 ilink 长连接。默认关。</summary>
    public bool ResidentKeepalive = false;
    /// <summary>
    /// 保活时先走纯协议续期（直接连微信服务器发 AutoAuth，不开浏览器、不冷启动）。
    /// 成功就整个跳过冷启动；被服务端明确拒绝(-13/-14)则直接标「需要扫码」；
    /// 其它失败自动回退到原来的冷启动流程。默认关，确认稳定后再开。
    /// </summary>
    public bool ProtocolRenew = false;

    /// <summary>
    /// 每个号每天最多换几次 key（风控上限）。超过就不再滚——频繁轮换会让服务端把整条授权链判成异常并全部作废。
    /// 0 表示用默认值 <see cref="CredentialProbe.MaxRotationsPerDay"/>。
    /// </summary>
    public int MaxRotationsPerDay = 0;

    /// <summary>密钥超过这么多小时必须强制续期（不管计划时刻）。0 = 用默认 20h。</summary>
    public double ForceRenewHours = 0;

    /// <summary>密钥还新于这么多小时时，日常计划也先不动它（少滚一次 = 少一次风险）。0 = 用默认 6h。</summary>
    public double MinKeyAgeHours = 0;

    /// <summary>有效值：没填就用全局默认（先看 notify.json 的全局设置，其次硬编码默认）。</summary>
    public int EffectiveMaxRotations
    {
        get
        {
            if (MaxRotationsPerDay > 0) return MaxRotationsPerDay;
            var g = NotifyConfig.Load().MaxRotationsPerDay;
            return g > 0 ? g : CredentialProbe.MaxRotationsPerDay;
        }
    }

    public double EffectiveForceRenewHours => ForceRenewHours > 0 ? ForceRenewHours : Keepalive.DefaultForceRenewHours;

    public double EffectiveMinKeyAgeHours
    {
        get
        {
            if (MinKeyAgeHours > 0) return MinKeyAgeHours;
            var g = NotifyConfig.Load().ProbeMinKeyAgeHours;
            return g > 0 ? g : Keepalive.DefaultMinKeyAgeHours;
        }
    }

    public KeepPolicy Clone() => (KeepPolicy)MemberwiseClone();

    public string Describe(string box)
    {
        var baseDesc = Schedule == "daily"
            ? $"每天 {Keepalive.RunAt(box, this):HH:mm}"
            : $"每 {IntervalHours} 小时";
        if (ResidentKeepalive) baseDesc += "·常驻";
        if (ProtocolRenew) baseDesc += "·协议";
        return baseDesc;
    }
}

public sealed class KeepConfig
{
    public bool Enabled = true;
    public KeepPolicy Defaults = new();
    public Dictionary<string, KeepPolicy> Boxes = new();

    public KeepPolicy For(string box) => Boxes.TryGetValue(box, out var p) ? p : Defaults.Clone();
    public bool EnabledFor(string box) => Enabled && For(box).Enabled;
}

/// <summary>
/// 静默保活：到点冷启动一次，微信运行时自动授权换新密钥并存进金库后就关掉。
/// 配置文件 keepalive.json 与旧版格式相同；计划任务名 jskp-keepalive-qbN 也相同（导入后会被改指向本程序）。
/// </summary>
public static class Keepalive
{
    public static string TaskName(string box) => "jskp-keepalive-" + box;

    public static string NormalizeClock(string text, string fallback = "04:00")
    {
        var raw = (text ?? "").Trim().Replace('：', ':');
        var m = Regex.Match(raw, @"(\d{1,2})\D+(\d{2})");
        if (m.Success)
        {
            int h = int.Parse(m.Groups[1].Value), mi = int.Parse(m.Groups[2].Value);
            if (h is >= 0 and <= 23 && mi is >= 0 and <= 59) return $"{h:D2}:{mi:D2}";
        }
        return fallback;
    }

    static KeepPolicy ParsePolicy(JsonNode node, KeepPolicy defaults)
    {
        var p = defaults.Clone();
        p.Enabled = true;
        if (node is JsonValue jv)
        {
            if (jv.TryGetValue<bool>(out var b)) p.Enabled = b;
            else if (jv.TryGetValue<int>(out var i)) p.Enabled = i != 0;
            return p;
        }
        if (node is JsonObject o)
        {
            p.Enabled = JsonFile.Bool(o, "enabled") ?? true;
            var s = JsonFile.Str(o, "schedule");
            if (s is "daily" or "interval") p.Schedule = s;
            var h = JsonFile.Int(o, "intervalHours");
            if (h != null) p.IntervalHours = Math.Clamp(h.Value, 1, 24);
            var d = JsonFile.Str(o, "dailyTime");
            if (d.Length > 0) p.DailyTime = NormalizeClock(d, p.DailyTime);
            p.ResidentKeepalive = JsonFile.Bool(o, "residentKeepalive") ?? false;
            // probeAuth / probeAuthLive / invokeAutoAuth 是已移除的 Frida 记录开关，旧配置里的键忽略。
            // leanRefresh 是已移除的「精简保活」，同样忽略旧键。
            p.ProtocolRenew = JsonFile.Bool(o, "protocolRenew") ?? false;
            // 轮换额度（v1.5.37 起可配）：缺键就沿用 defaults（从而回落到全局默认）
            p.MaxRotationsPerDay = Math.Clamp(JsonFile.Int(o, "maxRotationsPerDay") ?? p.MaxRotationsPerDay, 0, 50);
            p.ForceRenewHours = Math.Clamp(JsonFile.Double(o, "forceRenewHours") ?? p.ForceRenewHours, 0, 168);
            p.MinKeyAgeHours = Math.Clamp(JsonFile.Double(o, "minKeyAgeHours") ?? p.MinKeyAgeHours, 0, 168);
        }
        return p;
    }

    public static KeepConfig Load()
    {
        var cfg = new KeepConfig();
        var raw = JsonFile.ReadObject(AppPaths.KeepaliveJson);
        if (raw == null) return cfg;
        cfg.Enabled = JsonFile.Bool(raw, "enabled") ?? true;
        // 显式写 interval 才保留；缺省/其它值走每天（新默认）
        cfg.Defaults.Schedule = JsonFile.Str(raw, "schedule") == "interval" ? "interval" : "daily";
        cfg.Defaults.IntervalHours = Math.Clamp(JsonFile.Int(raw, "intervalHours") ?? 4, 1, 24);
        cfg.Defaults.DailyTime = NormalizeClock(JsonFile.Str(raw, "dailyTime"));
        if (raw["boxes"] is JsonObject boxes)
            foreach (var kv in boxes)
                cfg.Boxes[kv.Key] = ParsePolicy(kv.Value, cfg.Defaults);
        return cfg;
    }

    public static void Save(KeepConfig cfg)
    {
        var boxes = new JsonObject();
        foreach (var kv in cfg.Boxes.OrderBy(k => Sandboxie.BoxNumber(k.Key)))
            boxes[kv.Key] = new JsonObject
            {
                ["enabled"] = kv.Value.Enabled,
                ["schedule"] = kv.Value.Schedule,
                ["intervalHours"] = kv.Value.IntervalHours,
                ["dailyTime"] = kv.Value.DailyTime,
                ["residentKeepalive"] = kv.Value.ResidentKeepalive,
                ["protocolRenew"] = kv.Value.ProtocolRenew,
                ["maxRotationsPerDay"] = kv.Value.MaxRotationsPerDay,
                ["forceRenewHours"] = kv.Value.ForceRenewHours,
                ["minKeyAgeHours"] = kv.Value.MinKeyAgeHours,
            };
        JsonFile.WriteObject(AppPaths.KeepaliveJson, new JsonObject
        {
            ["enabled"] = cfg.Enabled,
            ["schedule"] = cfg.Defaults.Schedule,
            ["intervalHours"] = cfg.Defaults.IntervalHours,
            ["dailyTime"] = cfg.Defaults.DailyTime,
            ["boxes"] = boxes,
        });
    }

    /// <summary>每天模式各号错开 10 分钟，避免同时冷启动把 Sandboxie 挤爆。</summary>
    public static int StaggerMinutes(string box) => (Math.Max(1, Sandboxie.BoxNumber(box)) - 1) * 10;

    public static DateTime RunAt(string box, KeepPolicy p)
    {
        var at = DateTime.Today.AddHours(4);
        var m = Regex.Match(p.DailyTime ?? "", @"^(\d{1,2}):(\d{2})$");
        if (m.Success) at = DateTime.Today.AddHours(int.Parse(m.Groups[1].Value)).AddMinutes(int.Parse(m.Groups[2].Value));
        return at.AddMinutes(StaggerMinutes(box));
    }

    // ---------- 「这次该不该续」的判断（v1.5.37）----------
    //
    // 以前是计划任务只在固定时刻喊一次，喊那次失败了就等明天——一次网络抖动
    // 等于浪费一整天窗口。现在改成「每小时醒一次 + 沙箱自己判断该不该动」：
    // 任务变频繁了，但真正会去碰上游的条件没变松，反而更严（加了退避与密钥年龄）。

    /// <summary>密钥超过这个年龄，即使没到日常计划时间也应尽快续。可在界面按沙箱覆盖。</summary>
    public const double DefaultForceRenewHours = 20;

    /// <summary>密钥还新于这个年龄时，日常计划也先不动它（少滚一次 = 少一次风险）。可在界面按沙箱覆盖。</summary>
    public const double DefaultMinKeyAgeHours = 6;

    public sealed record WakeDecision(bool Run, string Reason)
    {
        public static WakeDecision No(string why) => new(false, why);
        public static WakeDecision Yes(string why) => new(true, why);
    }

    /// <summary>
    /// 计划任务唤醒后，决定这次是否真的执行保活。
    /// 顺序即优先级：已明确需要扫码 > 失败退避 > 密钥超龄强制 > 密钥太新跳过 > 今天是否已到计划时刻。
    /// </summary>
    public static WakeDecision DecideWake(string box, KeepPolicy p, DateTime now)
    {
        // 1) 已经判定要重扫：别再空跑冷启动（旧逻辑也是在 Core 开头 return，这里提前省掉整个进程开销）
        if (NeedScan.Pending(box))
            return WakeDecision.No("need-scan pending");

        // 2) 上次失败还在退避期。但如果密钥已经过硬上限（20h），退避不能让路——
        //    等 6 小时基本等于让它自然过期，这时候必须继续试。
        bool keyOverdue = false;
        try { keyOverdue = ProtocolRenew.KeyOverdue(box); } catch { }
        if (!keyOverdue && NeedScan.RetryPending(box))
        {
            var r = NeedScan.Retry(box);
            return WakeDecision.No($"backoff {r?.MinutesLeft:0} min left after {r?.Failures} failure(s)");
        }

        double? keyAge = null;
        try { keyAge = ProtocolRenew.KeyAgeHours(box); } catch { }

        // 2.5) 完全没有可用凭证（也没历史快照可救）：自动保活救不了它，只会每小时拉起浏览器停在二维码页。
        //      这种情况需要人工扫码，直接跳过。注意必须保留「历史里有可用 key」这条恢复路径（qb10/qb12 就是那样救回来的）。
        if (keyAge is null)
        {
            bool anyHistory = false;
            try { anyHistory = Ilink.CredentialHistory(box).Any(c => !c.Revoked); } catch { }
            if (!anyHistory) return WakeDecision.No("no credential and no history snapshot -> needs manual scan");
        }

        // 3) 密钥超龄：不管计划时刻，立刻续（宁可多滚一次，也不能等它自己过期）
        double forceHours = p.EffectiveForceRenewHours;
        int quota = p.EffectiveMaxRotations;
        if (keyAge is double aged && aged >= forceHours)
        {
            // 但连「今天已经换到上限」都超了的话，继续滚只会把整条链判成异常。
            // 这里不再续，改为告警——这种情况多半是密钥已经被顶，靠滚是救不回来的。
            if (CredentialProbe.RotationsToday(box) >= quota)
                return WakeDecision.No($"key is {aged:F1}h old but already rotated {quota}x today -> stop, needs manual check");
            return WakeDecision.Yes($"key is {aged:F1}h old (>= {forceHours}h) -> renew now");
        }

        // 4) 密钥太新：日常计划也让路，避免「每天固定滚一次」变成无意义的消耗
        double minAge = p.EffectiveMinKeyAgeHours;
        if (keyAge is double young && young < minAge)
            return WakeDecision.No($"key is only {young:F1}h old (< {minAge}h) -> leave it alone");

        // 5) 日常计划时刻：interval 模式看「距上次成功续期是否够久」，daily 模式按当天时刻 + 错峰
        var last = LastSuccessUtc(box);
        if (p.Schedule == "interval")
        {
            var due = (last ?? DateTime.UtcNow.AddHours(-p.IntervalHours)).AddHours(p.IntervalHours);
            if (now.ToUniversalTime() < due)
                return WakeDecision.No($"interval {p.IntervalHours}h not elapsed yet");
            // 每小时唤醒会让 interval 模式一天跑很多轮：必须受每日轮换上限约束，
            // 否则「每 4 小时一次」= 一天 6 次 × 各路径 = 远超风控上限。
            if (CredentialProbe.RotationsToday(box) >= quota)
                return WakeDecision.No($"rotated {quota}x today -> hold until tomorrow");
            return WakeDecision.Yes($"interval {p.IntervalHours}h elapsed");
        }
        var at = RunAt(box, p);
        // 当天计划时刻已过，且今天还没成功续过 → 该跑
        bool passedToday = now >= at;
        bool doneToday = last is DateTime l && l.ToLocalTime().Date == now.Date;
        if (passedToday && !doneToday)
        {
            // 同上：每小时唤醒后，「今天已到点」这个条件整天都成立，
            // 必须靠轮换额度兜住，避免补跑变成整天反复滚 key。
            if (CredentialProbe.RotationsToday(box) >= quota)
                return WakeDecision.No($"rotated {quota}x today -> hold until tomorrow");
            return WakeDecision.Yes($"daily {at:HH:mm} slot");
        }

        // 6) 「今天已续过」不能让密钥就此放到老死。
        //    `doneToday` 只看密钥写入时间，而用户手动开一次游戏时运行时会自己换一把 key——
        //    这被当成了「今天的保活已完成」，于是整天都跳过。
        //    qb4 在 2026-11-11 就是这样：10:14 登录换钥 → 一整天 `already renewed today`
        //    → 密钥一路放到 9.4 小时无人过问 → 19:38 被判 -13。
        //    更早的坑：11-11 凌晨 03:30 的计划时刻真正到来时，密钥才 3 小时（< 5h 门槛）被跳过；
        //    等它老过 5 小时，`doneToday` 又已经是真了——那天的保活就这么整体丢失了。
        //
        //    所以：当天计划时刻已过、密钥也已老过 minAge、但**今天没有任何一次真正的 refresh**
        //    （登录/探测/预检换的 key 不算），就补跑一次。用 rotate-log 里的 reason 判断，
        //    因此补跑成功后当天不会再触发，最多一天一次，不会变成每 5 小时滚一次。
        if (doneToday && keyAge is double stale && stale >= minAge && !RefreshServedToday(box))
        {
            if (CredentialProbe.RotationsToday(box) >= quota)
                return WakeDecision.No($"rotated {quota}x today -> hold until tomorrow");
            return WakeDecision.Yes($"daily {at:HH:mm} slot still owed (key {stale:F1}h old, no refresh run today)");
        }

        return WakeDecision.No(doneToday ? "already renewed today" : $"daily slot {at:HH:mm} not reached");
    }

    /// <summary>
    /// 今天有没有真正跑过一次「保活」（refresh）——只看 rotate-log 里的原因。
    /// 「refresh」是协议续期路径记的，「runtime:refresh」是冷启动路径记的；
    /// probe / preflight / runtime:game-ok 都不算，它们只是顺带换钥，不代表保活执行过。
    /// </summary>
    internal static bool RefreshServedToday(string box)
    {
        try
        {
            var p = Path.Combine(AppPaths.Logs, box + ".rotate-log");
            if (!File.Exists(p)) return false;
            var today = DateTime.Today.ToString("yyyy-MM-dd") + " ";
            foreach (var line in File.ReadLines(p))
            {
                if (!line.StartsWith(today, StringComparison.Ordinal)) continue;
                // 行格式：「yyyy-MM-dd HH:mm:ss <keySha> <why>」
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;
                var why = parts[3].Trim();
                if (why == "refresh" || why == "runtime:refresh") return true;
            }
            return false;
        }
        catch { return false; }
    }

    /// <summary>最近一次成功续期（以金库里最新那把密钥的写入时间为准）。</summary>
    public static DateTime? LastSuccessUtc(string box)
    {
        try
        {
            var live = Ilink.Live(box);
            var vault = Ilink.VaultState(box);
            DateTime best = DateTime.MinValue;
            if (live.Valid && live.WriteUtc > best) best = live.WriteUtc;
            if (vault.Valid && vault.WriteUtc > best) best = vault.WriteUtc;
            return best == DateTime.MinValue ? null : best;
        }
        catch { return null; }
    }

    // ---------- 计划任务 ----------

    static string Schtasks => ProcessUtil.System32("schtasks.exe");

    public static void RemoveTask(string box)
    {
        var (code, _) = ProcessUtil.Run(Schtasks, new[] { "/Delete", "/TN", TaskName(box), "/F" }, 20000);
        if (code == 0) Log.Box(box, "keepalive task removed: " + TaskName(box));
    }

    /// <summary>读计划任务当前指向的程序（用于发现程序目录被挪走、或仍指向旧版 PowerShell）。</summary>
    public static string TaskCommand(string box)
    {
        var (code, output) = ProcessUtil.Run(Schtasks, new[] { "/Query", "/TN", TaskName(box), "/XML" }, 20000);
        if (code != 0) return null;
        var m = Regex.Match(output, @"<Command>(.*?)</Command>", RegexOptions.Singleline);
        return m.Success ? SecurityElement.FromString("<x>" + m.Groups[1].Value + "</x>")?.Text ?? m.Groups[1].Value : "";
    }

    public static bool TaskPointsHere(string box)
    {
        var cmd = TaskCommand(box);
        return cmd != null && string.Equals(cmd.Trim('"'), AppInfo.ExePath, StringComparison.OrdinalIgnoreCase);
    }

    public static string SyncTask(string box, KeepConfig cfg)
    {
        if (!cfg.EnabledFor(box))
        {
            RemoveTask(box);
            return "removed";
        }
        var p = cfg.For(box);
        var user = SecurityElement.Escape(Environment.UserDomainName + "\\" + Environment.UserName);
        // v1.5.37：一律改成「每小时唤醒一次」，由 DecideWake 在沙箱侧判断该不该真续。
        // 这样一次临时失败可以在退避后几小时内补上，而不是等到明天；
        // 真正的上游请求频次没有变松（受退避、密钥年龄、计划时刻三重约束）。
        var start = DateTime.Now.AddMinutes(StaggerMinutes(box) % 60);
        var trigger = $@"<TimeTrigger><Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{start:yyyy-MM-ddTHH:mm:ss}</StartBoundary><Enabled>true</Enabled></TimeTrigger>";
        var xml = $@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo><Description>{SecurityElement.Escape(AppInfo.ProductName)} 静默保活 {box}</Description></RegistrationInfo>
  <Triggers>{trigger}</Triggers>
  <Principals><Principal id=""Author""><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT20M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context=""Author""><Exec><Command>{SecurityElement.Escape(AppInfo.ExePath)}</Command><Arguments>refresh {box}</Arguments><WorkingDirectory>{SecurityElement.Escape(AppPaths.AppDir)}</WorkingDirectory></Exec></Actions>
</Task>";
        var tmp = Path.Combine(Path.GetTempPath(), $"jskp-task-{box}-{Environment.ProcessId}.xml");
        try
        {
            File.WriteAllText(tmp, xml, Encoding.Unicode);
            var (code, output) = ProcessUtil.Run(Schtasks, new[] { "/Create", "/TN", TaskName(box), "/XML", tmp, "/F" }, 30000);
            if (code != 0) throw new InvalidOperationException($"创建计划任务失败：{output.Trim()}");
            Log.Box(box, $"keepalive task registered {p.Describe(box)}: {TaskName(box)}");
            return "registered";
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    public static List<string> SyncAll(IEnumerable<string> boxes)
    {
        var cfg = Load();
        var errors = new List<string>();
        foreach (var b in boxes)
        {
            try { SyncTask(b, cfg); }
            catch (Exception ex) { errors.Add(b + "：" + ex.Message); }
        }
        return errors;
    }
}
