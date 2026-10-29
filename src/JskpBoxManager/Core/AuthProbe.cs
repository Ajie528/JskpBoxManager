using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// 在沙箱内跑 tools/lean-refresh/hook_watch.py（Frida，只读），截 ilink 明文日志里的授权返回。
/// Sandboxie 拒绝主机往箱内注入，所以观测程序必须在箱内启动，而且要在浏览器之前启动：
/// ILinkServiceHost 启动后几毫秒内就发出 ilinkapp_autoauth。箱内进程随停箱一起结束。
/// </summary>
public sealed class AuthProbe
{
    public sealed record AuthResult(string Time, string Cgi, int Error, int Ret, string Msg)
    {
        public bool Ok => Error == 0 && Ret == 0;
        public string Text => $"{(Ok ? "成功" : "失败")} {Cgi} error={Error} ret={Ret}" + (Msg.Length > 0 ? $" msg={Msg}" : "");
    }

    /// <summary>Python 和脚本目录；找不到时 Error 说明原因。</summary>
    public sealed record Env(string Python, string Tools, string Frida, string Error)
    {
        public bool Ok => Error.Length == 0;
    }

    static readonly Regex AuthLine = new(@"cgi = (\w+), error = (-?\d+).*?ret = (-?\d+), error_msg = ?(.*)$", RegexOptions.Singleline);

    readonly string _box;
    readonly string _outReal, _txtReal;
    long _jPos, _tPos;
    public readonly string LogJsonl, LogTxt;
    public readonly List<AuthResult> Results = new();
    /// <summary>autoauth_key 为空等没有 cgi 返回、但同样说明授权没做成的行。</summary>
    public readonly List<string> Notes = new();

    AuthProbe(string box)
    {
        _box = box;
        _outReal = Path.Combine(EnvDetect.SandboxRoot, box, "user", "current", OutName(box) + ".jsonl");
        _txtReal = Path.ChangeExtension(_outReal, ".txt");
        Directory.CreateDirectory(AppPaths.Logs);
        LogJsonl = Path.Combine(AppPaths.Logs, $"frida-ilink-{box}.jsonl");
        LogTxt = Path.Combine(AppPaths.Logs, $"frida-ilink-{box}.txt");
    }

    static string OutName(string box) => "jskp-frida-" + box;

    public static Env Resolve(bool install, Action<string> say = null)
    {
        var tools = ToolsDir();
        if (tools.Length == 0) return new Env("", "", "", "找不到 tools\\lean-refresh\\hook_watch.py（把仓库的 tools 目录放在 exe 旁边或上级目录）");
        var python = FindPython();
        if (python.Length == 0) return new Env("", tools, "", "找不到 Python 3。先安装 Python 3，再执行：py -3 -m pip install frida psutil pefile");
        var frida = PyDeps(python);
        if (frida.Length == 0 && install)
        {
            say?.Invoke("安装 Python 包 frida / psutil / pefile ...");
            ProcessUtil.Run(python, new[] { "-m", "pip", "install", "--upgrade", "frida", "psutil", "pefile" }, 300000);
            frida = PyDeps(python);
        }
        if (frida.Length == 0) return new Env(python, tools, "", $"Python 包不可用。手动执行：\"{python}\" -m pip install frida psutil pefile");
        return new Env(python, tools, frida, "");
    }

    /// <summary>箱内拉起观测程序并等它就绪（最多 3 次）。失败返回 null，error 里带 Python 的报错。</summary>
    public static AuthProbe Start(string box, Env env, int seconds, out string error)
    {
        var p = new AuthProbe(box);
        var errReal = Path.ChangeExtension(p._outReal, ".err");
        foreach (var f in new[] { p._outReal, p._txtReal, errReal }) try { File.Delete(f); } catch { }

        // 箱内 python 写到用户目录下（虚拟路径），主机按沙箱真实路径去读。
        // 用 CreateNoWindow 拉 Start.exe 时箱内实例常被结束（0x40010004）；控制台版 python.exe 同理，用 pythonw.exe。
        var outVirtual = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), OutName(box) + ".jsonl");
        var pythonw = Path.Combine(Path.GetDirectoryName(env.Python)!, "pythonw.exe");
        var args = new List<string>
        {
            "/box:" + box, "/hide_window", File.Exists(pythonw) ? pythonw : env.Python, Path.Combine(env.Tools, "hook_watch.py"),
            "--box", box, "--out", outVirtual, "--seconds", seconds.ToString(), "--sbie-dir", EnvDetect.SbieDir,
        };
        Log.Box(box, "auth probe watcher: " + string.Join(" ", args));
        var codes = new List<string>();
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            using (var starter = ProcessUtil.StartDetached(EnvDetect.SbieStart, args, false))
                if (starter != null && starter.WaitForExit(10000) && starter.ExitCode != 0)
                    codes.Add($"0x{starter.ExitCode:X}");
            if (WaitReady(p._outReal, 10)) { error = ""; return p; }
        }
        string err = "";
        try { if (File.Exists(errReal)) err = File.ReadAllText(errReal).Trim(); } catch { }
        error = "沙箱内的 hook_watch.py 没有启动"
                + (codes.Count > 0 ? $"（Start.exe 退出码 {string.Join(",", codes)}）" : "")
                + (err.Length > 0 ? "。Python 报错：\n" + err : "");
        return null;
    }

    /// <summary>把箱内新写的整行同步到 logs 目录，并解析授权返回。返回本次新增的授权结果。</summary>
    public List<AuthResult> Poll(Action<string> onTxtLine = null)
    {
        int before = Results.Count;
        Mirror(_outReal, LogJsonl, ref _jPos, ParseJson);
        Mirror(_txtReal, LogTxt, ref _tPos, onTxtLine);
        return Results.Skip(before).ToList();
    }

    public AuthResult LastAuth => Results.LastOrDefault(r => r.Cgi.Contains("Auth", StringComparison.OrdinalIgnoreCase));

    void ParseJson(string line)
    {
        if (!line.Contains("TdiCheckCgiResponse") && !line.Contains("autoauth_key is empty")) return;
        try
        {
            var o = JsonNode.Parse(line);
            var msg = o?["msg"]?.ToString() ?? "";
            var t = o?["t"]?.ToString() ?? "";
            var m = AuthLine.Match(msg);
            if (m.Success)
                Results.Add(new AuthResult(t, m.Groups[1].Value, int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value), m.Groups[4].Value.Trim()));
            else
                Notes.Add($"{t} {msg}");
        }
        catch { }
    }

    static bool WaitReady(string outReal, int seconds)
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

    static string ToolsDir()
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
        return "";
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
