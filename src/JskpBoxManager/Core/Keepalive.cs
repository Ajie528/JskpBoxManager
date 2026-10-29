using System.Security;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

public sealed class KeepPolicy
{
    public bool Enabled = true;
    public string Schedule = "interval"; // interval | daily
    public int IntervalHours = 4;
    public string DailyTime = "04:00";
    /// <summary>精简保活：不打开游戏中心页，优先 Blank/NoUrl/RuntimeOnly；失败回退 Full。默认关。</summary>
    public bool LeanRefresh = false;

    public KeepPolicy Clone() => (KeepPolicy)MemberwiseClone();

    public string Describe(string box)
    {
        var baseDesc = Schedule == "daily"
            ? $"每天 {Keepalive.RunAt(box, this):HH:mm}"
            : $"每 {IntervalHours} 小时";
        return LeanRefresh ? baseDesc + "·精简" : baseDesc;
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
            p.LeanRefresh = JsonFile.Bool(o, "leanRefresh") ?? false;
        }
        return p;
    }

    public static KeepConfig Load()
    {
        var cfg = new KeepConfig();
        var raw = JsonFile.ReadObject(AppPaths.KeepaliveJson);
        if (raw == null) return cfg;
        cfg.Enabled = JsonFile.Bool(raw, "enabled") ?? true;
        cfg.Defaults.Schedule = JsonFile.Str(raw, "schedule") == "daily" ? "daily" : "interval";
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
                ["leanRefresh"] = kv.Value.LeanRefresh,
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
        string trigger;
        if (p.Schedule == "daily")
        {
            var at = RunAt(box, p);
            if (at < DateTime.Now) at = at.AddDays(1);
            trigger = $@"<CalendarTrigger><StartBoundary>{at:yyyy-MM-ddTHH:mm:ss}</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>";
        }
        else
        {
            var at = DateTime.Now.AddHours(p.IntervalHours).AddMinutes(StaggerMinutes(box) % 60);
            trigger = $@"<TimeTrigger><Repetition><Interval>PT{p.IntervalHours}H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{at:yyyy-MM-ddTHH:mm:ss}</StartBoundary><Enabled>true</Enabled></TimeTrigger>";
        }
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
