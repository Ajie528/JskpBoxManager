using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// Frida 只读观测：JskpBoxManager.exe hook qb1 [--mode Full] [--seconds 240] [--no-launch] [--no-stop]
///
/// 观测程序（AuthProbe → tools/lean-refresh/hook_watch.py）在沙箱里运行，并且在启动浏览器之前就开始盯：
/// 授权进程 ILinkServiceHost 一出生就被挂上，ilinkapp_autoauth 的请求和服务端返回都能截到。不改包、不改参数。
/// </summary>
public sealed class HookObserveSession
{
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

        // 两个 hook 同时跑会各起一个箱内观测程序，日志每行重复，后启动的还会把前一个的输出文件删掉
        using var single = new Mutex(false, $@"Local\JskpBoxManager.Hook.{_box}");
        bool gotSingle;
        try { gotSingle = single.WaitOne(0); } catch (AbandonedMutexException) { gotSingle = true; }
        if (!gotSingle) { Out($"{_box} 已经有一个 hook 在运行，先关掉那个窗口再开"); return 1; }
        try { return RunLocked(); }
        finally { try { single.ReleaseMutex(); } catch { } }
    }

    int RunLocked()
    {
        bool launch = !_args.Contains("--no-launch", StringComparer.OrdinalIgnoreCase);
        bool noStop = _args.Contains("--no-stop", StringComparer.OrdinalIgnoreCase);
        int seconds = ArgInt("--seconds", 240, 30, 7200);
        var mode = BoxRuntime.LaunchMode.Full;
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals("--mode", StringComparison.OrdinalIgnoreCase)
                && Enum.TryParse(_args[i + 1], true, out BoxRuntime.LaunchMode m))
                mode = m;

        Directory.CreateDirectory(AppPaths.Logs);
        _logJsonl = Path.Combine(AppPaths.Logs, $"frida-ilink-{_box}.jsonl");
        _logTxt = Path.Combine(AppPaths.Logs, $"frida-ilink-{_box}.txt");

        var env = AuthProbe.Resolve(true, Out);
        if (!env.Ok) { Out(env.Error); return 1; }
        Out($"python={env.Python} frida={env.Frida}");
        Out($"appdir={AppPaths.AppDir}");

        var startUtc = DateTime.UtcNow;
        Emit(new JsonObject { ["ev"] = "start", ["mode"] = mode.ToString(), ["launch"] = launch, ["seconds"] = seconds, ["frida"] = env.Frida });
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

        var probe = AuthProbe.Start(_box, env, seconds + 60, out var startErr);
        if (probe == null)
        {
            Out(startErr);
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
        int emptyTicks = 0;
        while (DateTime.Now < deadline)
        {
            Thread.Sleep(2000);
            probe.Poll(PrintKeyLine);
            // 观测程序本身也在箱内：箱里一个进程都没有，说明沙箱被停了（游戏关闭 / 别的命令停箱），没有再看的必要
            emptyTicks = Sandboxie.Pids(_box).Count == 0 ? emptyTicks + 1 : 0;
            if (emptyTicks >= 2) { Out($"{_box} 已经停止，观测提前结束"); break; }
            var st = Ilink.Live(_box);
            if (st.WriteUtc > startUtc && st.WriteUtc > lastAcct.AddMilliseconds(50))
            {
                lastAcct = st.WriteUtc;
                Emit(new JsonObject { ["ev"] = "file-watch", ["valid"] = st.Valid, ["keySha"] = st.KeyHash, ["writeLocal"] = st.WriteLocal });
                Out($"[凭证] tdi_account.txt 重写 valid={st.Valid} key={st.KeyHash}");
            }
        }
        probe.Poll(PrintKeyLine);

        if (launch && !noStop)
        {
            Out("观测结束，保存凭证并停箱");
            BoxRuntime.StopForce(_box, true);
        }
        Out("===== 授权结果 =====");
        if (probe.Results.Count == 0 && probe.Notes.Count == 0)
            Out("没有截到 AutoAuth/ManualAuth 的返回（可能运行时没起来，或 --no-launch 时授权早已完成）");
        foreach (var r in probe.Results)
        {
            Out(r.Text);
            Emit(new JsonObject { ["ev"] = "auth-result", ["t"] = r.Time, ["cgi"] = r.Cgi, ["error"] = r.Error, ["ret"] = r.Ret, ["msg"] = r.Msg });
        }
        foreach (var n in probe.Notes)
        {
            Out(n);
            Emit(new JsonObject { ["ev"] = "auth-result", ["line"] = n });
        }
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
}
