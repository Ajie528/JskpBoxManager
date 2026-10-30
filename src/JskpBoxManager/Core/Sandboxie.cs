using System.Diagnostics;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

public static class Sandboxie
{
    public static bool IsBoxName(string box) => Regex.IsMatch(box ?? "", @"^qb\d+$");

    public static int BoxNumber(string box)
    {
        var m = Regex.Match(box ?? "", @"(\d+)$");
        return m.Success ? int.Parse(m.Groups[1].Value) : 0;
    }

    static List<string> Ini(params string[] args)
    {
        if (!EnvDetect.SbieOk) return new List<string>();
        var (_, output) = ProcessUtil.Run(EnvDetect.SbieIni, args, 30000);
        return output.Split('\n').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
    }

    public static List<string> QueryBoxes()
    {
        return Ini("query", "*").Where(IsBoxName).Distinct().OrderBy(BoxNumber).ToList();
    }

    public static List<string> Query(string section, string key) => Ini("query", section, key);
    public static void Set(string section, string key, string value) => Ini("set", section, key, value);
    public static void Clear(string section, string key) => Ini("set", section, key);
    public static void Append(string section, string key, string value) => Ini("append", section, key, value);

    public static void AppendMissing(string section, string key, IEnumerable<string> values)
    {
        var have = Query(section, key);
        foreach (var v in values)
            if (!have.Contains(v, StringComparer.OrdinalIgnoreCase)) Append(section, key, v);
    }

    public static void Reload()
    {
        if (!EnvDetect.SbieOk) return;
        ProcessUtil.Run(EnvDetect.SbieStart, new[] { "/reload" }, 30000);
    }

    /// <summary>删除整段配置（例如整个沙箱的 [qbN] 段）。</summary>
    public static void DeleteSection(string section) => Ini("delete", section);

    /// <summary>沙箱内进程。Start.exe /listpids 先输出个数，再逐行输出 PID。</summary>
    public static List<int> Pids(string box)
    {
        if (!EnvDetect.SbieOk) return new List<int>();
        var (_, output) = ProcessUtil.Run(EnvDetect.SbieStart, new[] { "/box:" + box, "/listpids" }, 15000);
        var lines = output.Split('\n').Select(s => s.Trim()).Where(s => Regex.IsMatch(s, @"^\d+$")).Select(int.Parse).ToList();
        if (lines.Count >= 1 && lines.Count == lines[0] + 1)
            return lines[0] <= 0 ? new List<int>() : lines.Skip(1).ToList();
        return lines.Where(x => x > 0).ToList();
    }

    /// <summary>listpids 本身的耗时：开机后 SbieSvc RPC 没就绪时会很慢。</summary>
    public static long ProbeListPidsMs(string box)
    {
        var sw = Stopwatch.StartNew();
        Pids(box);
        return sw.ElapsedMilliseconds;
    }

    public static void Terminate(string box)
    {
        if (!EnvDetect.SbieOk) return;
        ProcessUtil.Run(EnvDetect.SbieStart, new[] { "/box:" + box, "/terminate" }, 30000);
    }

    public static void DeleteContentsSilent(string box)
    {
        if (!EnvDetect.SbieOk) return;
        ProcessUtil.Run(EnvDetect.SbieStart, new[] { "/box:" + box, "delete_sandbox_silent" }, 120000);
    }

    /// <summary>在沙箱里启动程序（不等待）。</summary>
    public static void StartInBox(string box, IEnumerable<string> commandAndArgs, bool hidden = false)
    {
        var args = new List<string> { "/box:" + box };
        args.AddRange(commandAndArgs);
        ProcessUtil.StartDetached(EnvDetect.SbieStart, args, hidden);
    }

    public static bool ServiceRunning()
    {
        var (_, output) = ProcessUtil.Run(ProcessUtil.System32("sc.exe"), new[] { "query", "SbieSvc" }, 10000);
        return output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
    }

    public static bool EnsureService()
    {
        if (ServiceRunning()) return true;
        ProcessUtil.Run(ProcessUtil.System32("sc.exe"), new[] { "start", "SbieSvc" }, 15000);
        Thread.Sleep(2000);
        return ServiceRunning();
    }
}
