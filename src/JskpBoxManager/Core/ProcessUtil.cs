using System.Diagnostics;
using System.Management;
using System.Text;

namespace JskpBoxManager.Core;

public static class ProcessUtil
{
    public static string System32(string exe) => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), exe);

    /// <summary>运行并等待，返回退出码和标准输出。超时会杀掉进程并返回 -1。</summary>
    public static (int Exit, string Output) Run(string exe, IEnumerable<string> args, int timeoutMs = 60000, Encoding encoding = null)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        if (encoding != null) psi.StandardOutputEncoding = encoding;
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi);
            if (p == null) return (-1, "");
            var sb = new StringBuilder();
            p.OutputDataReceived += (_, e) => { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
            p.ErrorDataReceived += (_, _) => { };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                return (-1, sb.ToString());
            }
            p.WaitForExit();
            return (p.ExitCode, sb.ToString());
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }

    /// <summary>不等待地启动（沙箱里拉浏览器用）。</summary>
    public static Process StartDetached(string exe, IEnumerable<string> args, bool hidden = false)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = hidden,
            WindowStyle = hidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        return Process.Start(psi);
    }

    public static string NameOf(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return p.ProcessName; } catch { return ""; }
    }

    public static bool IsAlive(int pid)
    {
        if (pid <= 0) return false;
        try { using var p = Process.GetProcessById(pid); return !p.HasExited; } catch { return false; }
    }

    public static void Kill(int pid)
    {
        try { using var p = Process.GetProcessById(pid); p.Kill(); } catch { }
    }

    /// <summary>按 PID 取进程名和命令行（WMI）。</summary>
    public static Dictionary<int, (string Name, string Cmd)> CommandLines(IEnumerable<int> pids)
    {
        var set = new HashSet<int>(pids);
        var result = new Dictionary<int, (string, string)>();
        if (set.Count == 0) return result;
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, Name, CommandLine FROM Win32_Process");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    int id = Convert.ToInt32(mo["ProcessId"]);
                    if (!set.Contains(id)) continue;
                    result[id] = ((string)mo["Name"] ?? "", (string)mo["CommandLine"] ?? "");
                }
            }
        }
        catch { }
        return result;
    }

    public static Dictionary<int, int> ParentPids(IEnumerable<int> pids)
    {
        var set = new HashSet<int>(pids);
        var result = new Dictionary<int, int>();
        if (set.Count == 0) return result;
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId FROM Win32_Process");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    int id = Convert.ToInt32(mo["ProcessId"]);
                    if (set.Contains(id)) result[id] = Convert.ToInt32(mo["ParentProcessId"]);
                }
            }
        }
        catch { }
        return result;
    }

    /// <summary>找命令行匹配的进程（用于清理旧版 PowerShell 启动脚本）。</summary>
    public static List<(int Pid, string Cmd)> FindByCommandLine(string processName, Func<string, bool> match)
    {
        var list = new List<(int, string)>();
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name='{processName}'");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    var cmd = (string)mo["CommandLine"] ?? "";
                    if (match(cmd)) list.Add((Convert.ToInt32(mo["ProcessId"]), cmd));
                }
            }
        }
        catch { }
        return list;
    }
}
