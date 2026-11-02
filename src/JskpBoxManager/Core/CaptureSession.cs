using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// CDP 抓小游戏 wx.request / wx.login：只读包一层，原样放行。
/// 用法：JskpBoxManager.exe capture qbN [--seconds 120] [--no-launch] [--no-stop]
/// 日志：logs\wxapi-qbN.jsonl（每条请求/响应一行）与控制台摘要。
/// </summary>
public sealed class CaptureSession
{
    readonly string _box;
    readonly List<string> _args;
    static bool _consoleReady;

    public CaptureSession(string box, IEnumerable<string> args)
    {
        _box = box;
        _args = args?.ToList() ?? new List<string>();
    }

    static string LogPath(string box) => Path.Combine(AppPaths.Logs, $"wxapi-{box}.jsonl");

    void Out(string m)
    {
        Log.Box(_box, "capture " + m);
        try
        {
            if (!_consoleReady)
            {
                Win32.EnsureCliConsole();
                _consoleReady = true;
            }
            System.Console.WriteLine(m);
        }
        catch { }
    }

    public int Run()
    {
        if (!Sandboxie.IsBoxName(_box)) { Out("无效沙箱名"); return 2; }
        int seconds = ArgInt("seconds", 120);
        seconds = Math.Clamp(seconds, 20, 3600);
        bool noLaunch = Has("no-launch");
        bool noStop = Has("no-stop");

        Directory.CreateDirectory(AppPaths.Logs);
        Out($"开始抓 wx.request / wx.login  seconds={seconds} noLaunch={noLaunch}");
        Out("数据目录 " + AppPaths.AppDir);
        Out("日志 → " + LogPath(_box));
        if (!Ilink.VaultState(_box).Valid && !Ilink.Live(_box).Valid)
            Out($"注意：本目录没有 {_box} 的登录金库，沙箱里也没有有效凭证，冷启后可能要扫码");

        var clients = new List<Cdp.CdpClient>();
        var seenIds = new HashSet<string>();
        int writes = 0;
        try
        {
            if (!noLaunch)
            {
                if (new BoxView(_box).HasQqOrGame)
                {
                    Out("先停箱再冷启，保证能挂到开局登录请求");
                    BoxRuntime.StopForce(_box, false);
                    Thread.Sleep(2000);
                }
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                try { VaultSync.PushVaultToLive(_box); } catch { }
                BoxRuntime.ClearCrashRestore(_box);
                BoxRuntime.Warmup(_box, false);
                BoxRuntime.StartBrowser(_box, "capture", BoxRuntime.LaunchMode.Full);
            }
            else if (!new BoxView(_box).HasQqOrGame)
            {
                Out("沙箱没在跑，且指定了 --no-launch");
                return 1;
            }

            var deadline = DateTime.Now.AddSeconds(seconds);
            var lastInstall = DateTime.MinValue;
            bool sawGame = false;

            while (DateTime.Now < deadline)
            {
                if ((DateTime.Now - lastInstall).TotalSeconds >= 4)
                {
                    lastInstall = DateTime.Now;
                    // 关掉已断的连接
                    for (int i = clients.Count - 1; i >= 0; i--)
                        if (!clients[i].Connected) { clients[i].Dispose(); clients.RemoveAt(i); }

                    var more = Cdp.InstallWxCaptureAll(_box, out int tried);
                    foreach (var c in more)
                    {
                        if (clients.Any(x => x.Url == c.Url)) { c.Dispose(); continue; }
                        clients.Add(c);
                    }
                    // 已有连接再补一次 Install（页面晚加载出 wx）
                    foreach (var c in clients.Where(x => x.Connected))
                        try { c.InstallWxCapture(); } catch { }
                    if (tried > 0) Out($"本轮探测 targets={tried} 已挂连接={clients.Count}");
                }

                var view = new BoxView(_box);
                if (view.HasGameWindow && !sawGame)
                {
                    sawGame = true;
                    Out("游戏窗口已出现，继续抓请求…");
                }

                foreach (var c in clients.ToList())
                {
                    if (!c.Connected) continue;
                    JsonArray arr;
                    try { arr = c.DrainWxCapture(); }
                    catch { continue; }
                    foreach (var n in arr.OfType<JsonObject>())
                    {
                        var id = JsonFile.Str(n, "id");
                        var ev = JsonFile.Str(n, "ev");
                        // login 没有 id；request/response 用 id 去重 response 仍要写
                        var key = ev + "|" + id + "|" + JsonFile.Str(n, "url") + "|" + (n["ts"]?.ToString() ?? "");
                        if (!seenIds.Add(key)) continue;

                        var line = new JsonObject
                        {
                            ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                            ["box"] = _box,
                            ["app"] = AppInfo.Version,
                            ["via"] = c.Url,
                        };
                        foreach (var kv in n.ToList())
                        {
                            n.Remove(kv.Key);
                            line[kv.Key] = kv.Value;
                        }
                        try
                        {
                            File.AppendAllText(LogPath(_box), line.ToJsonString(JsonFile.Compact) + "\r\n", new UTF8Encoding(false));
                            writes++;
                        }
                        catch { }

                        Out(Summarize(line));
                    }
                }

                Thread.Sleep(800);
            }

            Out($"结束：写入 {writes} 条 → {LogPath(_box)}");
            if (writes == 0)
                Out("提示：若一直 0 条，多半是调试 Target 里没有 wx（WeChatAppEx 未暴露 CDP）。可再试 unpack 看包内登录逻辑。");
            return writes > 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            Out("EXCEPTION: " + ex);
            return 1;
        }
        finally
        {
            foreach (var c in clients) try { c.Dispose(); } catch { }
            if (!noStop && !noLaunch)
            {
                try { BoxRuntime.StopForce(_box, true); } catch { }
                Out("已停箱");
            }
        }
    }

    static string Summarize(JsonObject o)
    {
        var ev = JsonFile.Str(o, "ev");
        return ev switch
        {
            "login" => $"[login] code={(JsonFile.Str(o, "code").Length > 0 ? JsonFile.Str(o, "code")[..Math.Min(12, JsonFile.Str(o, "code").Length)] + "…" : "")} {JsonFile.Str(o, "errMsg")}",
            "request" => $"[req] {JsonFile.Str(o, "method")} {ShortUrl(JsonFile.Str(o, "url"))}",
            "response" => $"[res] {o["statusCode"]} {ShortUrl(JsonFile.Str(o, "url"))}",
            "fail" => $"[fail] {ShortUrl(JsonFile.Str(o, "url"))} {o["err"]}",
            _ => $"[{ev}] {ShortUrl(JsonFile.Str(o, "url"))}",
        };
    }

    static string ShortUrl(string u)
    {
        if (string.IsNullOrEmpty(u)) return "";
        try
        {
            var uri = new Uri(u);
            var path = uri.AbsolutePath;
            if (path.Length > 60) path = path[..57] + "...";
            return uri.Host + path;
        }
        catch { return u.Length > 70 ? u[..67] + "..." : u; }
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
