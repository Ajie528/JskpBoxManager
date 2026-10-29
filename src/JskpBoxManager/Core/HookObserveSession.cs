using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// Frida 只读观测（原 tools/lean-refresh/hook-observe-qb1.ps1）。
/// JskpBoxManager.exe hook qb1 [--mode Full] [--seconds 180] [--no-launch] [--no-stop] [--pid N]
/// 用 <see cref="BoxView"/> 等「向僵尸开炮」窗口，再把 hook_ilink.js attach 上去。不改包。
/// </summary>
public sealed class HookObserveSession
{
    readonly string _box;
    readonly List<string> _args;
    string _logPath = "";
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
        int seconds = ArgInt("--seconds", 180, 10, 3600);
        int givenPid = ArgInt("--pid", 0, 0, int.MaxValue);
        var mode = BoxRuntime.LaunchMode.Full;
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals("--mode", StringComparison.OrdinalIgnoreCase)
                && Enum.TryParse(_args[i + 1], true, out BoxRuntime.LaunchMode m))
                mode = m;

        var tools = FindToolsDir();
        var hookJs = Path.Combine(tools, "hook_ilink.js");
        var attachPy = Path.Combine(tools, "hook_attach.py");
        Directory.CreateDirectory(AppPaths.Logs);
        _logPath = Path.Combine(AppPaths.Logs, "frida-ilink-qb1.jsonl");

        var py = FindPython();
        var fridaVer = FridaVersion(py);
        if (fridaVer.Length == 0)
        {
            Out("安装 frida（Python 包）...");
            var pipArgs = PyArgs(py, "-m", "pip", "install", "--upgrade", "frida");
            ProcessUtil.Run(py.Exe, pipArgs, 180000);
            fridaVer = FridaVersion(py);
        }
        if (fridaVer.Length == 0) { Out("Frida Python 包不可用。可手动：py -3 -m pip install frida"); return 1; }
        Out($"frida python {fridaVer}");
        Out($"appdir={AppPaths.AppDir}");
        Out($"tools={tools}");

        var launchUtc = DateTime.UtcNow;
        Emit(new JsonObject { ["ev"] = "start", ["mode"] = mode.ToString(), ["launch"] = launch, ["seconds"] = seconds, ["frida"] = fridaVer });

        if (launch)
        {
            if (NeedScan.Pending(_box))
                Out("警告：need-scan 未清，观测可能只看到扫码路径");
            Out("停箱后冷启动...");
            StopBox();
            Thread.Sleep(2000);
            BoxRuntime.EnsureWxRuntimeInBox(_box);
            try { VaultSync.PushVaultToLive(_box); } catch (Exception ex) { Out("推金库失败：" + ex.Message); }
            BoxRuntime.Warmup(_box, false);
            BoxRuntime.ClearCrashRestore(_box);
            launchUtc = DateTime.UtcNow;
            BoxRuntime.StartBrowser(_box, "hook", mode);
            Out($"launched mode={mode}; waiting 向僵尸开炮 / WeChatAppEx...");
            Emit(new JsonObject { ["ev"] = "launched", ["mode"] = mode.ToString() });
        }

        int wxPid = givenPid;
        string why = givenPid > 0 ? "given" : "";
        if (wxPid <= 0)
        {
            var deadline = DateTime.Now.AddSeconds(90);
            int fallback = 0;
            while (DateTime.Now < deadline)
            {
                var v = new BoxView(_box);
                if (v.HasGameWindow)
                {
                    var hwnd = v.GameHwnd;
                    wxPid = Win32.PidOf(hwnd);
                    why = "game-window";
                    Emit(new JsonObject
                    {
                        ["ev"] = "game-window",
                        ["hwnd"] = $"0x{hwnd.ToInt64():X}",
                        ["pid"] = wxPid,
                        ["title"] = Win32.Title(hwnd),
                        ["proc"] = ProcessUtil.NameOf(wxPid),
                    });
                    Out($"game-window pid={wxPid} title={Win32.Title(hwnd)}");
                    break;
                }
                int main = MainWeChatPid(v);
                if (main > 0) fallback = main;
                Thread.Sleep(1000);
            }
            if (wxPid <= 0 && fallback > 0)
            {
                wxPid = fallback;
                why = "main-no-game-window";
                Out($"90 秒内没有游戏窗，改为 attach 主进程 pid={wxPid}");
            }
        }

        if (wxPid <= 0)
        {
            Out("没有 WeChatAppEx / 游戏窗，仅做文件监视");
            Emit(new JsonObject { ["ev"] = "no-wechat-process", ["mode"] = mode.ToString() });
            WatchFiles(launchUtc, seconds);
            if (launch && !noStop) StopBox();
            Out("done; log=" + _logPath);
            return 1;
        }

        var order = CandidatePids(wxPid, why);
        Process proc = null;
        int attachedPid = 0;
        foreach (var (pid, w) in order)
        {
            Out($"attach pid={pid} via {w}");
            Emit(new JsonObject { ["ev"] = "attach", ["pid"] = pid, ["why"] = w, ["where"] = "host", ["mode"] = mode.ToString() });
            proc = StartAttach(py, attachPy, pid, hookJs, seconds);
            if (!proc.WaitForExit(8000))
            {
                attachedPid = pid;
                break;
            }
            Out($"主机 attach pid={pid} 失败");
            proc.Dispose();
            proc = null;
        }

        if (proc == null)
        {
            var inbox = order.Count > 0 ? order[0] : (wxPid, why);
            Out($"主机注入被拒绝，改为在沙箱内 attach pid={inbox.Item1}");
            Emit(new JsonObject { ["ev"] = "attach", ["pid"] = inbox.Item1, ["why"] = inbox.Item2, ["where"] = "inbox" });
            if (TryAttachInBox(py, attachPy, inbox.Item1, hookJs, seconds))
                attachedPid = inbox.Item1;
            else
                Out("沙箱内 attach 也失败，继续文件监视");
        }

        WatchFiles(launchUtc, seconds);
        if (proc != null && !proc.HasExited)
        {
            try { proc.Kill(true); } catch { }
        }
        try { proc?.WaitForExit(5000); } catch { }
        proc?.Dispose();
        if (attachedPid > 0) Out($"hook 目标 pid={attachedPid}");

        if (launch && !noStop)
        {
            Out("观测结束，停箱");
            StopBox();
        }
        Out("done; log=" + _logPath);
        return 0;
    }

    Process StartAttach(Py py, string attachPy, int pid, string hookJs, int seconds)
    {
        var psi = new ProcessStartInfo(py.Exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in PyArgs(py, attachPy, pid.ToString(), hookJs, _logPath, seconds.ToString()))
            psi.ArgumentList.Add(a);
        var proc = Process.Start(psi);
        if (proc == null) throw new InvalidOperationException("无法启动 hook_attach.py");
        proc.OutputDataReceived += (_, e) =>
        {
            if (string.IsNullOrWhiteSpace(e.Data)) return;
            Out("frida " + e.Data);
            Emit(new JsonObject { ["ev"] = "frida-out", ["line"] = e.Data });
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (string.IsNullOrWhiteSpace(e.Data)) return;
            Out("frida! " + e.Data);
            Emit(new JsonObject { ["ev"] = "frida-err", ["line"] = e.Data });
        };
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        return proc;
    }

    void WatchFiles(DateTime sinceUtc, int seconds)
    {
        var deadline = DateTime.Now.AddSeconds(seconds);
        DateTime lastAcct = DateTime.MinValue, lastPsk = DateTime.MinValue;
        var pskPath = Path.Combine(BoxPaths.WmpfLive(_box), @"ilink\default\psk.key");
        var inboxLog = Path.Combine(BoxPaths.UserData(_box), "frida-ilink-inbox.jsonl");
        long inboxPos = 0;
        while (DateTime.Now < deadline)
        {
            MirrorInbox(inboxLog, ref inboxPos);
            var st = Ilink.Live(_box);
            if (st.WriteUtc > sinceUtc && st.WriteUtc > lastAcct.AddMilliseconds(50))
            {
                lastAcct = st.WriteUtc;
                Emit(new JsonObject
                {
                    ["ev"] = "file-watch",
                    ["path"] = st.Path,
                    ["valid"] = st.Valid,
                    ["keySha"] = st.KeyHash,
                    ["writeLocal"] = st.WriteLocal,
                    ["uin"] = st.Uin,
                });
                Out($"file-watch acct valid={st.Valid} key={st.KeyHash}");
            }
            var pskWrite = FileWriteUtc(pskPath);
            if (pskWrite > sinceUtc && pskWrite > lastPsk.AddMilliseconds(50))
            {
                lastPsk = pskWrite;
                var live = Ilink.Live(_box);
                Emit(new JsonObject
                {
                    ["ev"] = "file-watch",
                    ["path"] = pskPath,
                    ["pskSha"] = live.PskHash,
                    ["writeLocal"] = pskWrite.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                });
                Out($"file-watch psk sha={live.PskHash}");
            }
            Thread.Sleep(2000);
        }
        MirrorInbox(inboxLog, ref inboxPos);
    }

    void MirrorInbox(string inboxLog, ref long pos)
    {
        try
        {
            if (!File.Exists(inboxLog)) return;
            using var fs = new FileStream(inboxLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length <= pos) return;
            fs.Position = pos;
            var buf = new byte[fs.Length - pos];
            int n = fs.Read(buf, 0, buf.Length);
            pos += n;
            if (n > 0) File.AppendAllText(_logPath, Encoding.UTF8.GetString(buf, 0, n), new UTF8Encoding(false));
        }
        catch { }
    }

    List<(int Pid, string Why)> CandidatePids(int preferred, string why)
    {
        var list = new List<(int, string)>();
        var seen = new HashSet<int>();
        void Add(int pid, string w)
        {
            if (pid <= 0 || !seen.Add(pid)) return;
            list.Add((pid, w));
        }
        Add(preferred, why);
        var v = new BoxView(_box);
        Add(MainWeChatPid(v), "main");
        foreach (var pid in v.Pids)
            if (v.NameOf(pid) is "WeChatAppEx" or "WeChatAppHost")
                Add(pid, "wechat");
        return list;
    }

    bool TryAttachInBox(Py py, string attachPy, int pid, string hookJs, int seconds)
    {
        var inboxLog = Path.Combine(BoxPaths.UserData(_box), "frida-ilink-inbox.jsonl");
        try { if (File.Exists(inboxLog)) File.Delete(inboxLog); } catch { }
        var args = new List<string>();
        if (py.Launcher) args.Add("-3");
        args.Add(attachPy);
        args.Add(pid.ToString());
        args.Add(hookJs);
        args.Add(inboxLog);
        args.Add(seconds.ToString());
        var cmd = new List<string> { py.Exe };
        cmd.AddRange(args);
        Sandboxie.StartInBox(_box, cmd, true);

        var deadline = DateTime.Now.AddSeconds(20);
        while (DateTime.Now < deadline)
        {
            Thread.Sleep(1000);
            string text = "";
            try { if (File.Exists(inboxLog)) text = File.ReadAllText(inboxLog); } catch { }
            if (text.Contains("frida-attached", StringComparison.Ordinal))
            {
                Out("沙箱内 attach 成功");
                try { File.AppendAllText(_logPath, text, new UTF8Encoding(false)); } catch { }
                return true;
            }
            if (text.Contains("frida-err", StringComparison.Ordinal))
            {
                Out("沙箱内 attach 失败");
                try { File.AppendAllText(_logPath, text, new UTF8Encoding(false)); } catch { }
                return false;
            }
        }
        Out("沙箱内 attach 无回执（20 秒）");
        return false;
    }

    static int MainWeChatPid(BoxView v)
    {
        var cmds = ProcessUtil.CommandLines(v.Pids);
        int best = 0;
        long bestWs = -1;
        foreach (var pid in v.Pids)
        {
            var name = v.NameOf(pid);
            if (name is not ("WeChatAppEx" or "WeChatAppHost")) continue;
            cmds.TryGetValue(pid, out var info);
            if ((info.Cmd ?? "").Contains("--type=", StringComparison.OrdinalIgnoreCase)) continue;
            if (!name.Equals("WeChatAppEx", StringComparison.OrdinalIgnoreCase)
                && !name.Equals("WeChatAppHost", StringComparison.OrdinalIgnoreCase))
                continue;
            long ws = WorkingSet(pid);
            if (ws >= bestWs) { bestWs = ws; best = pid; }
        }
        if (best > 0) return best;
        foreach (var pid in v.Pids)
        {
            if (v.NameOf(pid) is not ("WeChatAppEx" or "WeChatAppHost")) continue;
            long ws = WorkingSet(pid);
            if (ws >= bestWs) { bestWs = ws; best = pid; }
        }
        return best;
    }

    static long WorkingSet(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return p.WorkingSet64; }
        catch { return 0; }
    }

    static void StopBox()
    {
        Sandboxie.Terminate("qb1");
        var deadline = DateTime.Now.AddSeconds(20);
        while (DateTime.Now < deadline && Sandboxie.Pids("qb1").Count > 0)
            Thread.Sleep(500);
    }

    static DateTime FileWriteUtc(string path)
    {
        try { return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue; }
        catch { return DateTime.MinValue; }
    }

    void Emit(JsonObject o)
    {
        o["at"] ??= DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        o["box"] = _box;
        try
        {
            File.AppendAllText(_logPath, o.ToJsonString(JsonFile.Compact) + "\r\n", new UTF8Encoding(false));
        }
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
        var starts = new[] { AppContext.BaseDirectory, Environment.CurrentDirectory, AppPaths.AppDir };
        foreach (var s in starts)
        {
            var dir = new DirectoryInfo(s);
            for (int i = 0; dir != null && i < 8; i++, dir = dir.Parent)
            {
                var js = Path.Combine(dir.FullName, "tools", "lean-refresh", "hook_ilink.js");
                if (File.Exists(js)) return Path.GetDirectoryName(js)!;
            }
        }
        throw new FileNotFoundException("找不到 tools/lean-refresh/hook_ilink.js");
    }

    readonly record struct Py(string Exe, bool Launcher);

    static Py FindPython()
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var py = Path.Combine(dir.Trim(), "py.exe");
            if (File.Exists(py)) return new Py(py, true);
        }
        foreach (var hard in new[]
        {
            @"C:\Windows\py.exe",
            @"D:\Programs\Python\Python313\python.exe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Python\Python313\python.exe"),
        })
        {
            if (!File.Exists(hard)) continue;
            return new Py(hard, Path.GetFileName(hard).Equals("py.exe", StringComparison.OrdinalIgnoreCase));
        }
        throw new FileNotFoundException("找不到 Python（py.exe / python.exe）");
    }

    static string[] PyArgs(Py py, params string[] rest)
    {
        if (!py.Launcher) return rest;
        var list = new List<string> { "-3" };
        list.AddRange(rest);
        return list.ToArray();
    }

    static string FridaVersion(Py py)
    {
        var (code, output) = ProcessUtil.Run(py.Exe, PyArgs(py, "-c", "import frida; print(frida.__version__)"), 30000);
        if (code != 0) return "";
        return (output ?? "").Trim().Split('\n').LastOrDefault()?.Trim() ?? "";
    }
}
