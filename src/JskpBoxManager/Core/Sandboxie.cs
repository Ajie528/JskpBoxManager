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

    static (int Exit, List<string> Lines) IniEx(params string[] args)
    {
        if (!EnvDetect.SbieOk) return (-1, new List<string>());
        var (exit, output) = ProcessUtil.Run(EnvDetect.SbieIni, args, 30000);
        return (exit, output.Split('\n').Select(s => s.Trim()).Where(s => s.Length > 0).ToList());
    }

    static List<string> Ini(params string[] args) => IniEx(args).Lines;

    /// <summary>
    /// 列出本机沙箱。
    /// 用 <c>query *</c> 取全量段名（保持旧行为：禁用的沙箱也显示），
    /// 但要跳过「段头还在 ini 里、键已经全被删掉」的空段——
    /// 历史版本删除沙箱失败会留下这种残骸，导致界面上删不掉、重启又冒出来。
    /// </summary>
    public static List<string> QueryBoxes()
    {
        return Ini("query", "*").Where(IsBoxName).Distinct()
            .Where(SectionHasContent)
            .OrderBy(BoxNumber).ToList();
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

    /// <summary>
    /// 删除整个沙箱配置段。
    /// <para>
    /// Sandboxie 没有专门的「删段」命令，官方做法是 <c>set &lt;段&gt; * ""</c>
    /// （见 sandboxie-plus/Sandboxie#2620）。注意 <c>delete</c> 只能删某键的某一行值，
    /// 旧代码写的 <c>delete &lt;段&gt;</c> 是无效命令、静默返回失败，
    /// 这才是「在界面里删了沙箱、重启后又冒出来」的根因。
    /// </para>
    /// </summary>
    public static bool DeleteSection(string section)
    {
        if (!IsBoxName(section) || !EnvDetect.SbieOk) return false;
        Ini("set", section, "*", "");           // 整个段一次性删除
        if (Ini("query", section).Count == 0) return true;

        // 个别版本上通配段名不生效，退回逐键删除（段头会成为空段，QueryBoxes 会跳过）
        for (int pass = 0; pass < 5; pass++)
        {
            var keys = Ini("query", section);
            if (keys.Count == 0) return true;
            foreach (var k in keys) Ini("set", section, k);
        }
        return Ini("query", section).Count == 0;
    }

    /// <summary>判断这个段是否还有配置（空段 = 已被清空但段头仍在 ini 里）。</summary>
    public static bool SectionHasContent(string section) => Ini("query", section).Count > 0;

    /// <summary>
    /// 沙箱在 Sandboxie 里是否真实存在（段存在且不是空段）。
    /// 所有会拉起 Start.exe 的动作都要先过这一关：向不存在的沙箱名调用 Start.exe
    /// 会弹出「无效的沙盒名参数」模态框，把无人值守的流程卡死。
    /// </summary>
    public static bool BoxExists(string box)
    {
        if (!IsBoxName(box) || !EnvDetect.SbieOk) return false;
        return Ini("query", box).Count > 0;
    }

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
        if (!EnvDetect.SbieOk || !BoxExists(box)) return;
        ProcessUtil.Run(EnvDetect.SbieStart, new[] { "/box:" + box, "/terminate" }, 30000);
    }

    public static void DeleteContentsSilent(string box)
    {
        if (!EnvDetect.SbieOk || !BoxExists(box)) return;
        ProcessUtil.Run(EnvDetect.SbieStart, new[] { "/box:" + box, "delete_sandbox_silent" }, 120000);
    }

    /// <summary>在沙箱里启动程序（不等待）。沙箱不存在时直接返回 false，不去触发 Sandboxie 的错误弹窗。</summary>
    public static bool StartInBox(string box, IEnumerable<string> commandAndArgs, bool hidden = false)
    {
        if (!EnvDetect.SbieOk || !BoxExists(box)) return false;
        var args = new List<string> { "/box:" + box };
        args.AddRange(commandAndArgs);
        ProcessUtil.StartDetached(EnvDetect.SbieStart, args, hidden);
        return true;
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
