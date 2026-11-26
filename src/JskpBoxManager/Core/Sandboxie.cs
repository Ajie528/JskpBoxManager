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
    /// <summary>沙箱内进程。Start.exe /listpids 先输出个数，再逐行输出 PID（末尾可能多一行 0）。</summary>
    public static List<int> Pids(string box)
    {
        if (!EnvDetect.SbieOk) return new List<int>();
        var (_, output) = ProcessUtil.Run(EnvDetect.SbieStart, new[] { "/box:" + box, "/listpids" }, 15000);
        var nums = output.Split('\n').Select(s => s.Trim())
            .Where(s => Regex.IsMatch(s, @"^\d+$")).Select(int.Parse).ToList();
        if (nums.Count == 0) return new List<int>();      // 空沙箱：绝不能返回别的东西

        // 第一条是进程数。注意末尾可能带一个 0（Start.exe 收尾行），所以允许 count 或 count+1。
        int declared = nums[0];
        var rest = nums.Skip(1).Where(x => x > 0).ToList();
        if (declared <= 0) return new List<int>();
        if (rest.Count == declared) return rest;
        // 数量对不上（可能是别的版本格式）：只在「没有明显收尾 0」时才信任剩余列表，
        // 否则宁可返回空，也绝不把别的沙箱的 PID 当成自己的。
        if (nums.Last() == 0 && rest.Count == declared + 1) return rest.Take(declared).ToList();
        if (rest.Count > declared) return rest.Take(declared).ToList();
        return rest;
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

    /// <summary>
    /// 重启 SbieSvc 服务，把它的内存占用降回基线。
    ///
    /// <para>
    /// **为什么需要它**：SbieSvc 的内存是「已分配且不主动归还」的。实测把 16 个沙箱
    /// 全部停掉（进程数 0）之后静置 30 秒，它的 WorkingSet 仍是 177MB 不动。
    /// 而涨到 170MB 以上时，沙箱内进程创建子进程会因 RpcSs 超时失败
    /// （Chromium 建不出 renderer → 卡在游戏中心 + 刷 SBIE2203），
    /// 普通用户既杀不掉它（LocalSystem 跨会话）、也释放不了它的内存
    /// （`OpenProcess` 拿不到 PROCESS_SET_QUOTA，错误码 5）。
    /// </para>
    /// <para>
    /// **前提：必须以管理员身份运行**。服务 ACL 里 Interactive Users 只有
    /// `CCLCSWLOCRRC`，没有启动(RP)/停止(WP)权限，所以普通权限调 `sc stop` 会
    /// 返回 Access is denied (5)。
    /// </para>
    /// <para>
    /// 调用前应先确认没有沙箱在跑——停服务会杀掉所有沙箱内进程。
    /// </para>
    /// </summary>
    /// <returns>成功返回 null，失败返回原因。</returns>
    public static string RestartService(int waitStopSec = 20, int waitStartSec = 30)
    {
        if (!IsElevated)
            return "需要管理员权限（服务 ACL 不给 Interactive Users 启停权限）";

        var sc = ProcessUtil.System32("sc.exe");

        var (stopCode, stopOut) = ProcessUtil.Run(sc, new[] { "stop", "SbieSvc" }, 30000);
        // 1062 = 服务本来就没在跑，不算失败
        if (stopCode != 0 && !stopOut.Contains("1062"))
        {
            // 有时候 sc stop 会因为依赖服务而失败，但服务其实已经开始停了；
            // 以「最终是否真的停了」为准，别被返回码误导。
            Log.App($"重启 SbieSvc：sc stop 返回 {stopCode}，继续观察状态");
        }

        // 等它真的停掉（SbieSvc 会等沙箱内进程退出，可能要几秒）
        var deadline = DateTime.Now.AddSeconds(waitStopSec);
        while (DateTime.Now < deadline)
        {
            if (!ServiceRunning()) break;
            Thread.Sleep(500);
        }
        if (ServiceRunning())
            return $"SbieSvc 在 {waitStopSec} 秒内没有停下来（是不是还有沙箱进程在跑）";

        Thread.Sleep(1000);

        var (startCode, startOut) = ProcessUtil.Run(sc, new[] { "start", "SbieSvc" }, 30000);
        if (startCode != 0)
            return $"sc start 失败（{startCode}）：{startOut.Trim()}";

        deadline = DateTime.Now.AddSeconds(waitStartSec);
        while (DateTime.Now < deadline)
        {
            if (ServiceRunning()) return null;
            Thread.Sleep(500);
        }
        return $"SbieSvc 在 {waitStartSec} 秒内没有启动起来";
    }

    /// <summary>
    /// 当前进程是否有管理员权限。
    ///
    /// 用 <c>WindowsIdentity</c> + <c>WindowsPrincipal</c> 判断，不依赖 manifest——
    /// 因为同一个 exe 可能被用户手动「以管理员身份运行」，也可能被计划任务以普通权限拉起。
    /// </summary>
    public static bool IsElevated
    {
        get
        {
            try
            {
                using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                var p = new System.Security.Principal.WindowsPrincipal(id);
                return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    /// <summary>当前 SbieSvc 主进程的内存占用（MB）；取不到返回 0。</summary>
    public static long ServiceMemoryMb()
    {
        try
        {
            var p = Process.GetProcessesByName("SbieSvc")
                .OrderByDescending(x => x.WorkingSet64)
                .FirstOrDefault();
            return p == null ? 0 : p.WorkingSet64 / 1048576;
        }
        catch { return 0; }
    }

    /// <summary>
    /// 找出「实际在沙箱里、但 listpids 看不见」的僵尸进程。
    ///
    /// <para>
    /// **为什么会有这种进程**（2026-11-26 实测）：反复 `Start.exe /terminate` 时，
    /// 如果有子进程没来得及退出，它们会变成孤儿并卡在 <c>SbieDrv</c> 里——
    /// 加载着 <c>SbieDll.dll</c>、进程还活着，但 Sandboxie 的进程跟踪表已经不认它们了。
    /// 实测一次累积到 **22 个 QQBrowser + 4 个孤儿 SandboxieCrypto**，
    /// 之后所有新启动的沙箱进程都刷 `SBIE2203 RPCSS_SXS`，
    /// 浏览器主线程拿不到 RPC 响应 → 页面卡死 → 游戏中心永远进不去。
    /// </para>
    /// <para>
    /// **判据**：加载了 <c>SbieDll.dll</c>（说明是沙箱进程），且不在 <see cref="Pids"/>
    /// 返回的列表里（说明 Sandboxie 已经不认它）。
    /// </para>
    /// <para>
    /// **只检查本沙箱能识别的**：跨沙箱判断归属不可靠（子进程命令行常常不带沙箱名），
    /// 所以这里只在「<paramref name="box"/> 的 listpids 为空、但机器上确实有加载 SbieDll
    /// 的浏览器进程」时才报告——那种情况一定是出问题了，具体属于哪个沙箱不重要。
    /// </para>
    /// </summary>
    /// <param name="box">要检查的沙箱名。</param>
    /// <param name="knownPids">该沙箱已知的 PID（通常传 <see cref="Pids"/> 的结果）。</param>
    /// <returns>僵尸进程 PID 列表（可能为空）。</returns>
    public static List<int> FindZombies(string box, IEnumerable<int> knownPids)
    {
        var result = new List<int>();
        try
        {
            var known = new HashSet<int>(knownPids ?? Enumerable.Empty<int>());
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (known.Contains(p.Id)) continue;
                    // 只看游戏/浏览器相关的进程，避免误伤用户自己的其它沙箱程序
                    if (p.ProcessName is not ("QQBrowser" or "WeChatAppEx" or "WeChatAppHost" or "SandboxieCrypto" or "Start"))
                        continue;
                    bool inBox = false;
                    try { inBox = p.Modules.Cast<ProcessModule>().Any(m =>
                        m.ModuleName.Equals("SbieDll.dll", StringComparison.OrdinalIgnoreCase)); }
                    catch { continue; }   // 拿不到模块列表（权限/已退出）就跳过
                    if (inBox) result.Add(p.Id);
                }
                catch { }
                finally { }
            }
        }
        catch { }
        return result;
    }

    /// <summary>
    /// 杀掉僵尸进程。
    ///
    /// <para>
    /// 这些进程卡在 <c>SbieDrv</c> 里，`Start.exe /terminate` 对它们无效（实测），
    /// 只能 `TerminateProcess` 强杀。杀之前必须确认**没有任何沙箱在运行**——
    /// 否则会把正常运行的沙箱进程一起干掉。
    /// </para>
    /// </summary>
    /// <returns>实际杀掉的个数。</returns>
    public static int KillZombies(IEnumerable<int> pids)
    {
        int killed = 0;
        foreach (var id in pids ?? Enumerable.Empty<int>())
        {
            try { Process.GetProcessById(id).Kill(); killed++; }
            catch { }
        }
        return killed;
    }
}
