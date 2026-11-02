using System.Net;
using System.Text;

namespace JskpBoxManager.Core;

/// <summary>
/// 带 SSLKEYLOGFILE 冷启动一次，把游戏 TLS 会话密钥导出来（供 Wireshark/tshark 解密业务 HTTPS）。
/// 原理：Chromium（flue.dll）读环境变量 SSLKEYLOGFILE，写 NSS 格式密钥；env 经 Sandboxie 传进箱内。
/// 用法：JskpBoxManager.exe keylog qbN [--seconds 120] [--no-stop]
/// </summary>
public sealed class SslKeylogSession
{
    readonly string _box;
    readonly List<string> _args;
    static bool _consoleReady;

    public SslKeylogSession(string box, IEnumerable<string> args)
    {
        _box = box;
        _args = args?.ToList() ?? new List<string>();
    }

    void Out(string m)
    {
        Log.Box(_box, "keylog " + m);
        try
        {
            if (!_consoleReady) { Win32.EnsureCliConsole(); _consoleReady = true; }
            System.Console.WriteLine(m);
        }
        catch { }
    }

    /// <summary>箱内看到的路径（env 设这个），以及主机侧沙箱重定向后的真实落盘路径。</summary>
    string GuestKeyPath => $@"C:\jskp-sslkeys\{_box}.log";
    string OverlayKeyPath => Path.Combine(BoxPaths.SandboxBoxRoot(_box), "drive", "C", "jskp-sslkeys", _box + ".log");
    string OutKeyPath => Path.Combine(AppPaths.Logs, $"sslkeys-{_box}.log");

    public int Run()
    {
        if (!Sandboxie.IsBoxName(_box)) { Out("无效沙箱名"); return 2; }
        if (!EnvDetect.SbieOk || !EnvDetect.QqOk) { Out("Sandboxie 或 QQ 浏览器未找到"); return 1; }
        int seconds = Math.Clamp(ArgInt("seconds", 120), 30, 1200);
        bool noStop = Has("no-stop");

        Directory.CreateDirectory(AppPaths.Logs);
        // 让 env 对本进程后续 spawn 的沙箱进程生效
        Environment.SetEnvironmentVariable("SSLKEYLOGFILE", GuestKeyPath);
        Out($"SSLKEYLOGFILE={GuestKeyPath}（箱内写入会落到 {OverlayKeyPath}）");

        // 清掉上次的密钥文件，确保这次是新登录的
        try { if (File.Exists(OverlayKeyPath)) File.Delete(OverlayKeyPath); } catch { }

        if (NeedScan.Pending(_box))
            Out("注意：该沙箱标记为需要扫码，冷启动可能要扫码才能进游戏。");

        if (new BoxView(_box).HasQqOrGame)
        {
            Out("先停箱再冷启（Chromium 只在启动时读 SSLKEYLOGFILE）");
            BoxRuntime.StopForce(_box, false);
            Thread.Sleep(2000);
        }

        // 复用正式启动流程（带重试/催促/扫码处理）；它作为子进程继承本进程设好的 SSLKEYLOGFILE
        var exe = Environment.ProcessPath ?? AppInfo.ExePath;
        var launchArgs = new List<string> { "launch", _box, "--appdir", AppPaths.AppDir };
        Out("冷启动游戏（走正式 launch，免扫进入即会发登录请求）…");
        var child = ProcessUtil.StartDetached(exe, launchArgs, true);

        var deadline = DateTime.Now.AddSeconds(seconds);
        bool sawGame = false;
        long lastSize = -1;
        while (DateTime.Now < deadline)
        {
            Thread.Sleep(3000);
            var v = new BoxView(_box);
            if (v.HasGameWindow && !sawGame) { sawGame = true; Out("游戏窗口出现，等待 TLS 密钥写入…"); }
            long sz = KeyFileSize();
            if (sz > 0 && sz != lastSize)
            {
                lastSize = sz;
                Out($"已捕获密钥 {sz} 字节（{CountLines()} 行）");
            }
            // 进了游戏且密钥稳定几秒后可以早停
            if (sawGame && sz > 0) { Thread.Sleep(5000); if (KeyFileSize() == sz) break; }
        }
        try { if (child != null && !child.HasExited) { } } catch { }

        var found = ResolveKeyFile();
        if (found == null || KeyFileSize() <= 0)
        {
            Out("没有捕获到密钥文件。可能是没进游戏（要扫码？），或这版 Chromium 未写 keylog。");
            if (!noStop) { BoxRuntime.StopForce(_box, true); Out("已停箱"); }
            return 1;
        }

        int lines = CountLines();
        try
        {
            var bytes = Ilink.ReadShared(found);
            if (bytes != null) File.WriteAllBytes(OutKeyPath, bytes);
            else File.Copy(found, OutKeyPath, true);
            Out($"密钥已导出：{OutKeyPath}（{lines} 行）");
        }
        catch (Exception ex) { Out("复制密钥失败：" + ex.Message + "，原始在 " + found); }

        PrintRecipe();

        if (!noStop) { BoxRuntime.StopForce(_box, true); Out("已停箱"); }
        else Out("游戏保持运行（--no-stop）。");
        return 0;
    }

    void PrintRecipe()
    {
        var ips = new List<string>();
        foreach (var host in new[] { "h5api.scgame.com.cn", "web-t5game2.scgame.com.cn", "cdn-t5game1.scgame.com.cn", "tunnel-dga.scgame.com.cn" })
        {
            try { foreach (var a in Dns.GetHostAddresses(host)) ips.Add($"{host} -> {a}"); }
            catch { }
        }
        Out("");
        Out("===== 用 Wireshark / tshark 解密业务 HTTPS =====");
        Out("1) 抓包（登录发生时）。相关域名/IP：");
        foreach (var ip in ips) Out("     " + ip);
        Out("   capture 过滤器示例：host h5api.scgame.com.cn");
        Out("2) 用导出的密钥解密（需要装 Wireshark，tshark 在其安装目录）：");
        Out($"   tshark -r 抓到的.pcapng -o tls.keylog_file:\"{OutKeyPath}\" \\");
        Out("     -Y \"http.request || http.response\" -T fields -e http.request.full_uri -e http.file_data");
        Out("   登录接口是 GET /login/login_wxmg.php?...js_code=...，返回 JSON 含 token。");
        Out("提示：抓包要在冷启动登录那一刻进行；可先开 Wireshark 再跑本命令。");
    }

    string ResolveKeyFile()
    {
        if (File.Exists(OverlayKeyPath)) return OverlayKeyPath;
        // 兜底：在箱 drive 目录里找同名文件（盘符/路径可能不同）
        try
        {
            var driveRoot = Path.Combine(BoxPaths.SandboxBoxRoot(_box), "drive");
            if (Directory.Exists(driveRoot))
                return new DirectoryInfo(driveRoot)
                    .EnumerateFiles(_box + ".log", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
                    .OrderByDescending(f => f.LastWriteTimeUtc)
                    .FirstOrDefault()?.FullName;
        }
        catch { }
        return null;
    }

    long KeyFileSize()
    {
        var f = ResolveKeyFile();
        try { return f != null && File.Exists(f) ? new FileInfo(f).Length : 0; }
        catch { return 0; }
    }

    int CountLines()
    {
        var f = ResolveKeyFile();
        if (f == null) return 0;
        var bytes = Ilink.ReadShared(f); // 共享读：运行时正占着文件也能读
        if (bytes == null || bytes.Length == 0) return 0;
        int n = 0;
        foreach (var b in bytes) if (b == (byte)'\n') n++;
        return n;
    }

    bool Has(string name) => _args.Any(a => a.Equals("--" + name, StringComparison.OrdinalIgnoreCase));

    int ArgInt(string name, int fallback)
    {
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals("--" + name, StringComparison.OrdinalIgnoreCase) && int.TryParse(_args[i + 1], out int v))
                return v;
        return fallback;
    }
}
