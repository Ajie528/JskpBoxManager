using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// Frida 只读观测：JskpBoxManager.exe hook qb1 [--mode Full] [--seconds 240] [--no-launch] [--no-stop]
///
/// Sandboxie 拒绝主机往箱内注入 frida-agent，所以 tools/lean-refresh/hook_watch.py 在沙箱里运行，
/// 并且在启动浏览器之前就开始盯：微信运行时一出生就被挂上，ilink 子进程（ILinkServiceHost）启动后
/// 几百毫秒内发出的 ilinkapp_autoauth 请求和服务端返回都能截到。不改包、不改参数。
/// </summary>
public sealed class HookObserveSession
{
    const string OutName = "jskp-frida-qb1";
    static readonly Regex KeyLine = new(
        @"TdiCheckCgiResponse|autoauth_key|require manual|SessionTimeout|session timeout|Logout|kick|get_login_qrcode|svr\(.*cmdid:3198",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    readonly string _box;
    readonly List<string> _args;
    string _logJsonl = "", _logTxt = "";
    static bool _consoleReady;

    public HookObserveSession(string box, IEnumerable<string> args)
    {
        _box = box;
        _args = args?.ToList() ?? new List<string>();
    }

    public int Run()
    {
        if (!string.Equals(_box, "qb1", StringComparison.OrdinalIgnoreCase))
        {
            Out("hook 只允许 qb1");
            return 2;
        }
        if (!EnvDetect.SbieOk) { Out("Sandboxie 未就绪"); return 1; }

        bool launch = !_args.Contains("--no-launch", StringComparer.OrdinalIgnoreCase);
        bool noStop = _args.Contains("--no-stop", StringComparer.OrdinalIgnoreCase);
        int seconds = ArgInt("--seconds", 240, 30, 7200);
        var mode = BoxRuntime.LaunchMode.Full;
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals("--mode", StringComparison.OrdinalIgnoreCase)
                && Enum.TryParse(_args[i + 1], true, out BoxRuntime.LaunchMode m))
                mode = m;

        var tools = FindToolsDir();
        Directory.CreateDirectory(AppPaths.Logs);
        _logJsonl = Path.Combine(AppPaths.Logs, "frida-ilink-qb1.jsonl");
        _logTxt = Path.Combine(AppPaths.Logs, "frida-ilink-qb1.txt");

        var python = FindPython();
        if (python.Length == 0) { Out("找不到 Python 3。先安装 Python 3，再执行：py -3 -m pip install frida psutil pefile"); return 1; }
        var deps = PyDeps(python);
        if (deps.Length == 0)
        {
            Out("安装 Python 包 frida / psutil / pefile ...");
            ProcessUtil.Run(python, new[] { "-m", "pip", "install", "--upgrade", "frida", "psutil", "pefile" }, 300000);
            deps = PyDeps(python);
        }
        if (deps.Length == 0) { Out($"Python 包不可用。手动执行：\"{python}\" -m pip install frida psutil pefile"); return 1; }
        Out($"python={python} frida={deps}");
        Out($"appdir={AppPaths.AppDir}");

        // 箱内 python 写到用户目录下（虚拟路径），主机按沙箱真实路径去读
        var outVirtual = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), OutName + ".jsonl");
        var outReal = Path.Combine(EnvDetect.SandboxRoot, _box, "user", "current", OutName + ".jsonl");
        var txtReal = Path.ChangeExtension(outReal, ".txt");
        var errReal = Path.ChangeExtension(outReal, ".err");
        foreach (var p in new[] { outReal, txtReal, errReal }) try { File.Delete(p); } catch { }

        var startUtc = DateTime.UtcNow;
        Emit(new JsonObject { ["ev"] = "start", ["mode"] = mode.ToString(), ["launch"] = launch, ["seconds"] = seconds, ["frida"] = deps });
        AppendTxt($"===== {DateTime.Now:yyyy-MM-dd HH:mm:ss} hook {_box} mode={mode} launch={launch} seconds={seconds} =====");

        if (launch)
        {
            if (NeedScan.Pending(_box)) Out("提示：qb1 标记了需要扫码，这次大概率只会看到扫码流程");
            Out("停箱后冷启动...");
            BoxRuntime.StopForce(_box, true);
            BoxRuntime.EnsureWxRuntimeInBox(_box);
            try { VaultSync.PushVaultToLive(_box); } catch (Exception ex) { Out("推金库失败：" + ex.Message); }
            BoxRuntime.Warmup(_box, false);
            BoxRuntime.ClearCrashRestore(_box);
        }

        // 用 CreateNoWindow 拉 Start.exe 时，箱内实例常被结束（0x40010004）；Start.exe 本身是窗口程序，正常方式启动即可。
        // 控制台版 python.exe 同理会失败，用 pythonw.exe。
        var pythonw = Path.Combine(Path.GetDirectoryName(python)!, "pythonw.exe");
        var watchArgs = new List<string>
        {
            "/box:" + _box, "/hide_window", File.Exists(pythonw) ? pythonw : python, Path.Combine(tools, "hook_watch.py"),
            "--box", _box, "--out", outVirtual, "--seconds", (seconds + 60).ToString(),
            "--sbie-dir", EnvDetect.SbieDir,
        };
        Log.Box(_box, "hook watcher: " + string.Join(" ", watchArgs));
        bool ready = false;
        for (int attempt = 1; attempt <= 3 && !ready; attempt++)
        {
            using (var starter = ProcessUtil.StartDetached(EnvDetect.SbieStart, watchArgs, false))
                if (starter != null && starter.WaitForExit(10000) && starter.ExitCode != 0)
                    Out($"拉起观测器：Start.exe 退出码 0x{starter.ExitCode:X}（第 {attempt} 次）");
            ready = WaitWatchStart(outReal, 10);
        }
        long jPos = 0, tPos = 0;
        if (!ready)
        {
            string err = "";
            try { if (File.Exists(errReal)) err = File.ReadAllText(errReal).Trim(); } catch { }
            Out("沙箱内的 hook_watch.py 没有启动。" + (err.Length > 0 ? "Python 报错：\n" + err : "没有任何报错输出（Python 可能没被拉起）"));
            if (launch && !noStop) BoxRuntime.StopForce(_box, true);
            return 1;
        }
        if (launch)
        {
            startUtc = DateTime.UtcNow;
            BoxRuntime.StartBrowser(_box, "hook", mode);
            Emit(new JsonObject { ["ev"] = "launched", ["mode"] = mode.ToString() });
        }
        Out(launch ? $"观测器已就绪，已启动 mode={mode}，观测 {seconds} 秒..." : $"观测器已就绪，不重启，直接观测当前 qb1 {seconds} 秒...");

        var deadline = DateTime.Now.AddSeconds(seconds);
        DateTime lastAcct = DateTime.MinValue;
        while (DateTime.Now < deadline)
        {
            Thread.Sleep(2000);
            Mirror(outReal, _logJsonl, ref jPos, null);
            Mirror(txtReal, _logTxt, ref tPos, PrintKeyLine);
            var st = Ilink.Live(_box);
            if (st.WriteUtc > startUtc && st.WriteUtc > lastAcct.AddMilliseconds(50))
            {
                lastAcct = st.WriteUtc;
                Emit(new JsonObject { ["ev"] = "file-watch", ["valid"] = st.Valid, ["keySha"] = st.KeyHash, ["writeLocal"] = st.WriteLocal });
                Out($"[凭证] tdi_account.txt 重写 valid={st.Valid} key={st.KeyHash}");
            }
        }
        Mirror(outReal, _logJsonl, ref jPos, null);
        Mirror(txtReal, _logTxt, ref tPos, PrintKeyLine);

        if (launch && !noStop)
        {
            Out("观测结束，保存凭证并停箱");
            BoxRuntime.StopForce(_box, true);
        }
        Summary(outReal);
        Out("明文日志：" + _logTxt);
        Out("完整记录：" + _logJsonl);
        return 0;
    }

    void PrintKeyLine(string line)
    {
        if (line.Contains("[attach") || line.Contains("[已挂上") || line.Contains("[警告]") || line.Contains("[脚本错误]")
            || line.Contains("tdi_account") || KeyLine.IsMatch(line))
            Out(line.Length > 300 ? line[..300] : line);
    }

    /// <summary>从 jsonl 里挑出 AutoAuth/ManualAuth 的结果，给出一句结论。</summary>
    void Summary(string jsonl)
    {
        var results = new List<string>();
        try
        {
            using var fs = new FileStream(jsonl, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8);
            string line;
            while ((line = sr.ReadLine()) != null)
            {
                if (!line.Contains("TdiCheckCgiResponse") && !line.Contains("autoauth_key is empty")) continue;
                var o = JsonNode.Parse(line);
                results.Add($"{o?["t"]} {o?["msg"]}");
            }
        }
        catch { }
        Out("===== 授权结果 =====");
        if (results.Count == 0) Out("没有截到 AutoAuth/ManualAuth 的返回（可能运行时没起来，或 --no-launch 时授权早已完成）");
        foreach (var r in results)
        {
            var m = Regex.Match(r, @"cgi = (\w+), error = (-?\d+).*?ret = (-?\d+), error_msg = ?(.*)$");
            if (m.Success)
            {
                var ok = m.Groups[2].Value == "0" && m.Groups[3].Value == "0";
                Out($"{(ok ? "成功" : "失败")} {m.Groups[1].Value} error={m.Groups[2].Value} ret={m.Groups[3].Value} msg={m.Groups[4].Value.Trim()}");
            }
            else Out(r);
            Emit(new JsonObject { ["ev"] = "auth-result", ["line"] = r });
        }
    }

    static bool WaitWatchStart(string outReal, int seconds)
    {
        var deadline = DateTime.Now.AddSeconds(seconds);
        while (DateTime.Now < deadline)
        {
            try
            {
                if (File.Exists(outReal))
                {
                    using var fs = new FileStream(outReal, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    if (fs.Length > 0) return true;
                }
            }
            catch { }
            Thread.Sleep(500);
        }
        return false;
    }

    /// <summary>把箱内文件新增的部分追加到程序 logs 目录；按整行处理。</summary>
    static void Mirror(string src, string dst, ref long pos, Action<string> onLine)
    {
        try
        {
            if (!File.Exists(src)) return;
            using var fs = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length <= pos) return;
            fs.Position = pos;
            var buf = new byte[fs.Length - pos];
            int n = fs.Read(buf, 0, buf.Length);
            int end = Array.LastIndexOf(buf, (byte)'\n', n - 1);
            if (end < 0) return;
            pos += end + 1;
            var text = Encoding.UTF8.GetString(buf, 0, end + 1);
            File.AppendAllText(dst, text, new UTF8Encoding(false));
            if (onLine != null)
                foreach (var l in text.Split('\n'))
                    if (l.Length > 0) onLine(l.TrimEnd('\r'));
        }
        catch { }
    }

    void AppendTxt(string line)
    {
        try { File.AppendAllText(_logTxt, line + "\r\n", new UTF8Encoding(false)); } catch { }
    }

    void Emit(JsonObject o)
    {
        o["at"] ??= DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        o["box"] = _box;
        o["src"] = "host";
        try { File.AppendAllText(_logJsonl, o.ToJsonString(JsonFile.Compact) + "\r\n", new UTF8Encoding(false)); }
        catch { }
    }

    void Out(string m)
    {
        Log.Box(_box, "hook " + m);
        try
        {
            if (!_consoleReady)
            {
                if (!System.Console.IsOutputRedirected) Win32.AttachConsole(-1);
                System.Console.OutputEncoding = Encoding.UTF8;
                _consoleReady = true;
            }
            System.Console.WriteLine(m);
        }
        catch { }
    }

    int ArgInt(string name, int def, int min, int max)
    {
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals(name, StringComparison.OrdinalIgnoreCase) && int.TryParse(_args[i + 1], out var n))
                return Math.Clamp(n, min, max);
        return def;
    }

    static string FindToolsDir()
    {
        var starts = new[] { AppContext.BaseDirectory, Environment.CurrentDirectory, AppPaths.AppDir, Path.GetDirectoryName(Environment.ProcessPath) ?? "" };
        foreach (var s in starts)
        {
            if (string.IsNullOrEmpty(s)) continue;
            var dir = new DirectoryInfo(s);
            for (int i = 0; dir != null && i < 8; i++, dir = dir.Parent)
            {
                var py = Path.Combine(dir.FullName, "tools", "lean-refresh", "hook_watch.py");
                if (File.Exists(py)) return Path.GetDirectoryName(py)!;
            }
        }
        throw new FileNotFoundException("找不到 tools\\lean-refresh\\hook_watch.py（把仓库的 tools 目录放在 exe 旁边或上级目录）");
    }

    /// <summary>真正的 python.exe 路径（箱内要直接启动它，不经过 py.exe 启动器）。</summary>
    static string FindPython()
    {
        foreach (var (exe, args) in new[] { ("py.exe", new[] { "-3" }), ("python.exe", Array.Empty<string>()) })
        {
            var a = args.Concat(new[] { "-c", "import sys; print(sys.executable)" });
            var (code, output) = ProcessUtil.Run(exe, a, 20000);
            var path = (output ?? "").Trim().Split('\n').LastOrDefault()?.Trim() ?? "";
            if (code == 0 && File.Exists(path)) return path;
        }
        return "";
    }

    static string PyDeps(string python)
    {
        var (code, output) = ProcessUtil.Run(python, new[] { "-c", "import frida, psutil, pefile; print(frida.__version__)" }, 30000);
        if (code != 0) return "";
        return (output ?? "").Trim().Split('\n').LastOrDefault()?.Trim() ?? "";
    }
}
