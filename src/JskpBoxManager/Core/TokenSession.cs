using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// 一条龙取业务 token：tshark 定时抓包 + keylog 冷启动免扫登录 + 解密提取。
/// 需要本机装有 Wireshark（tshark）。用法：
///   JskpBoxManager.exe token qbN [--seconds 130] [--iface \Device\NPF_{...}] [--keep]
/// 输出：stdout 一行 JSON {token,uin,open_id,js_code,appid}；日志/进度到 stderr。
/// </summary>
public sealed class TokenSession
{
    readonly string _box;
    readonly List<string> _args;
    static bool _consoleReady;

    /// <summary>true 时只写日志、不碰控制台（协议服务在 GUI 进程内调用时用，避免弹黑窗）。</summary>
    public bool Quiet { get; init; }

    public TokenSession(string box, IEnumerable<string> args)
    {
        _box = box;
        _args = args?.ToList() ?? new List<string>();
    }

    void Info(string m)
    {
        Log.Box(_box, "token " + m);
        if (Quiet) return;
        try
        {
            if (!_consoleReady) { Win32.EnsureCliConsole(); _consoleReady = true; }
            System.Console.Error.WriteLine(m);
        }
        catch { }
    }

    static readonly string[] LoginHosts =
    {
        "h5api.scgame.com.cn", "web-t5game2.scgame.com.cn", "ws82-t5game2.scgame.com.cn",
    };

    string GuestKeyPath => $@"C:\jskp-sslkeys\{_box}.log";
    string OverlayKeyPath => Path.Combine(BoxPaths.SandboxBoxRoot(_box), "drive", "C", "jskp-sslkeys", _box + ".log");
    string OutKeyPath => Path.Combine(AppPaths.Logs, $"sslkeys-{_box}.log");
    string PcapPath => Path.Combine(AppPaths.Logs, $"token-{_box}.pcapng");

    /// <summary>单飞锁：冷启动抓包很重，全局串行，避免并发抢同一个箱/网卡。</summary>
    static readonly SemaphoreSlim Gate = new(1, 1);

    public int Run()
    {
        var r = Capture(out var error);
        if (r == null) { Info("失败：" + error); return 1; }
        System.Console.WriteLine(r.ToJsonString(JsonFile.Compact));
        Info("成功：token/uin/open_id 已提取（上面一行 JSON）。");
        return 0;
    }

    /// <summary>
    /// 跑完整「抓包 + keylog 冷启动登录 + 解密提取」，返回结果 JSON（含 token/uin/open_id/js_code）；
    /// 失败返回 null 并给出 error。供 CLI 和协议服务 /token 共用。
    /// </summary>
    public JsonObject Capture(out string error)
    {
        error = "";
        if (!Sandboxie.IsBoxName(_box)) { error = "无效沙箱名"; return null; }
        if (!EnvDetect.SbieOk || !EnvDetect.QqOk) { error = "Sandboxie 或 QQ 浏览器未找到"; return null; }

        var tshark = FindTshark();
        if (tshark == null) { error = "找不到 tshark（请安装 Wireshark，抓包需勾选 Npcap）"; return null; }
        Info("tshark: " + tshark);

        int seconds = Math.Clamp(ArgInt("seconds", 130), 60, 600);
        bool keep = Has("keep");

        var device = ArgStr("iface");
        if (device.Length == 0) device = PickCaptureDevice();
        if (device.Length == 0) { error = "找不到可抓包的网卡，请用 --iface 指定"; return null; }
        Info("抓包网卡: " + device);

        var ips = ResolveLoginIps();
        if (ips.Count == 0) { error = "无法解析 scgame 域名 IP（断网？）"; return null; }
        var filter = string.Join(" or ", ips.Select(ip => "host " + ip));
        Info("抓包过滤: " + filter);

        if (!Gate.Wait(TimeSpan.FromSeconds(2))) { error = "已有一个取 token 任务在跑，请稍后再试"; return null; }
        try
        {
            Directory.CreateDirectory(AppPaths.Logs);
            foreach (var p in new[] { PcapPath, OverlayKeyPath }) try { if (File.Exists(p)) File.Delete(p); } catch { }
            Environment.SetEnvironmentVariable("SSLKEYLOGFILE", GuestKeyPath);
            try
            {
                if (new BoxView(_box).HasQqOrGame) { Info("先停箱…"); BoxRuntime.StopForce(_box, false); Thread.Sleep(2000); }

                Info($"开始抓包 {seconds}s → {PcapPath}");
                var capPsi = new ProcessStartInfo(tshark) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true };
                foreach (var a in new[] { "-i", device, "-a", "duration:" + seconds, "-f", filter, "-w", PcapPath }) capPsi.ArgumentList.Add(a);
                Process cap;
                try { cap = Process.Start(capPsi); }
                catch (Exception ex) { error = "启动抓包失败（需要 Npcap/管理员权限）：" + ex.Message; return null; }
                Thread.Sleep(2500);

                var exe = Environment.ProcessPath ?? AppInfo.ExePath;
                Info("冷启动游戏（免扫登录，写 TLS 密钥）…");
                ProcessUtil.StartDetached(exe, new[] { "launch", _box, "--appdir", AppPaths.AppDir }, true);

                var sawGame = false;
                var deadline = DateTime.Now.AddSeconds(seconds + 20);
                while (!cap.HasExited && DateTime.Now < deadline)
                {
                    Thread.Sleep(3000);
                    if (!sawGame && new BoxView(_box).HasGameWindow) { sawGame = true; Info("游戏窗口出现。"); }
                }
                try { if (!cap.HasExited) cap.WaitForExit(15000); } catch { }
                Info("抓包结束。");

                var keyFile = ResolveKeyFile();
                if (keyFile != null) { try { File.WriteAllBytes(OutKeyPath, Ilink.ReadShared(keyFile) ?? Array.Empty<byte>()); } catch { } }
                if (keyFile == null || new FileInfo(OutKeyPath).Length == 0)
                {
                    error = "没拿到 TLS 密钥（可能没进游戏 / 需要扫码）";
                    if (!Has("no-stop")) BoxRuntime.StopForce(_box, true);
                    return null;
                }

                var result = Extract(tshark, PcapPath, OutKeyPath);
                if (!keep) try { File.Delete(PcapPath); } catch { }
                if (!Has("no-stop")) { BoxRuntime.StopForce(_box, true); Info("已停箱。"); }

                if (result == null) { error = "解密后未找到 login_wxmg/auth 请求，可加大 --seconds 重试"; return null; }

                Ilink.WriteEvent(_box, "token-captured", new JsonObject
                {
                    ["uin"] = JsonFile.Str(result, "uin"), ["hasToken"] = JsonFile.Str(result, "token").Length > 0,
                });
                return result;
            }
            finally { Environment.SetEnvironmentVariable("SSLKEYLOGFILE", null); }
        }
        finally { Gate.Release(); }
    }

    /// <summary>解密 pcap，提取 login_wxmg 的 js_code 和 auth.php 的 token/uin/open_id。</summary>
    JsonObject Extract(string tshark, string pcap, string keys)
    {
        var paths = new List<string>();
        foreach (var filt in new[] { "http2.headers.path", "http.request.full_uri" })
        {
            var (_, o) = ProcessUtil.Run(tshark, new[]
            {
                "-r", pcap, "-o", "tls.keylog_file:" + keys, "-Y", filt.StartsWith("http2") ? "http2.headers.path" : "http.request",
                "-T", "fields", "-e", "http2.headers.authority", "-e", filt,
            }, 60000);
            foreach (var line in (o ?? "").Split('\n'))
                if (line.Contains("scgame", StringComparison.OrdinalIgnoreCase) || line.Contains("login_wxmg") || line.Contains("auth.php"))
                    paths.Add(line.Trim());
        }

        string jsCode = "", token = "", uin = "", openId = "";
        foreach (var p in paths)
        {
            var m = Regex.Match(p, @"js_code=([^&\s]+)");
            if (m.Success && jsCode.Length == 0) jsCode = m.Groups[1].Value;
            if (p.Contains("auth.php") || p.Contains("token="))
            {
                var mt = Regex.Match(p, @"[?&]token=([^&\s]+)");
                if (mt.Success && token.Length == 0) token = Uri.UnescapeDataString(mt.Groups[1].Value);
                var mu = Regex.Match(p, @"[?&]uin=(\d+)");
                if (mu.Success && uin.Length == 0) uin = mu.Groups[1].Value;
                var mo = Regex.Match(p, @"[?&]open_id=([^&\s]+)");
                if (mo.Success && openId.Length == 0) openId = Uri.UnescapeDataString(mo.Groups[1].Value);
            }
        }
        if (jsCode.Length == 0 && token.Length == 0) return null;
        return new JsonObject
        {
            ["ok"] = true, ["appid"] = "1048", ["wx_appid"] = AppInfo.GameAppId,
            ["js_code"] = jsCode, ["token"] = token, ["uin"] = uin, ["open_id"] = openId,
        };
    }

    string ResolveKeyFile()
    {
        if (File.Exists(OverlayKeyPath)) return OverlayKeyPath;
        try
        {
            var driveRoot = Path.Combine(BoxPaths.SandboxBoxRoot(_box), "drive");
            if (Directory.Exists(driveRoot))
                return new DirectoryInfo(driveRoot)
                    .EnumerateFiles(_box + ".log", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
                    .OrderByDescending(f => f.LastWriteTimeUtc).FirstOrDefault()?.FullName;
        }
        catch { }
        return null;
    }

    List<string> ResolveLoginIps()
    {
        var ips = new List<string>();
        foreach (var h in LoginHosts)
            try { foreach (var a in Dns.GetHostAddresses(h)) if (a.AddressFamily == AddressFamily.InterNetwork) ips.Add(a.ToString()); }
            catch { }
        return ips.Distinct().ToList();
    }

    /// <summary>选活动网卡（有网关、非虚拟/回环），返回 tshark 设备名 \Device\NPF_{GUID}。</summary>
    static string PickCaptureDevice()
    {
        NetworkInterface best = null;
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            var desc = (ni.Description + " " + ni.Name).ToLowerInvariant();
            if (desc.Contains("vmware") || desc.Contains("virtual") || desc.Contains("hyper-v") || desc.Contains("loopback") || desc.Contains("bluetooth")) continue;
            var props = ni.GetIPProperties();
            bool hasGw = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
            bool hasV4 = props.UnicastAddresses.Any(u => u.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(u.Address));
            if (hasGw && hasV4) { best = ni; break; }
        }
        return best == null ? "" : $@"\Device\NPF_{best.Id}";
    }

    static string FindTshark()
    {
        var cands = new List<string>
        {
            @"C:\Program Files\Wireshark\tshark.exe", @"C:\Program Files (x86)\Wireshark\tshark.exe",
            @"D:\Program Files\Wireshark\tshark.exe", @"E:\Program Files\Wireshark\tshark.exe",
        };
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe");
            if (k?.GetValue(null) is string ws && ws.Length > 0)
            {
                var dir = Path.GetDirectoryName(ws);
                if (dir != null) cands.Insert(0, Path.Combine(dir, "tshark.exe"));
            }
        }
        catch { }
        return cands.FirstOrDefault(File.Exists);
    }

    bool Has(string name) => _args.Any(a => a.Equals("--" + name, StringComparison.OrdinalIgnoreCase));

    string ArgStr(string name)
    {
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals("--" + name, StringComparison.OrdinalIgnoreCase)) return _args[i + 1];
        return "";
    }

    int ArgInt(string name, int fallback) => int.TryParse(ArgStr(name), out var v) ? v : fallback;
}
