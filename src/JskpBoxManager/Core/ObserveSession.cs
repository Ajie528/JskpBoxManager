using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 命令行观测：JskpBoxManager.exe observe qbN [--launch] [--mode Full] [--seconds 180] [--no-stop]
/// 用与正式启动/保活相同的 <see cref="BoxView"/> 识别 WeChatAppEx /「向僵尸开炮」窗口，并记录凭证文件变化。
/// 不依赖 PowerShell / Frida；只读观测、不改包。
/// </summary>
public sealed class ObserveSession
{
    readonly string _box;
    readonly List<string> _args;

    public ObserveSession(string box, IEnumerable<string> args)
    {
        _box = box;
        _args = args?.ToList() ?? new List<string>();
    }

    static bool _consoleReady;

    void Out(string m)
    {
        Log.Box(_box, "observe " + m);
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

    static string LogPath(string box) => Path.Combine(AppPaths.Logs, $"observe-{box}.jsonl");

    void Emit(JsonObject o)
    {
        o["at"] ??= DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        o["box"] = _box;
        o["app"] = AppInfo.Version;
        try
        {
            Directory.CreateDirectory(AppPaths.Logs);
            File.AppendAllText(LogPath(_box), o.ToJsonString(JsonFile.Compact) + "\r\n", new UTF8Encoding(false));
        }
        catch { }
        var ev = JsonFile.Str(o, "ev");
        var extra = new List<string>();
        if (o["title"] != null) extra.Add("title=" + o["title"]);
        if (o["pid"] != null) extra.Add("pid=" + o["pid"]);
        if (o["keySha"] != null) extra.Add("key=" + o["keySha"]);
        if (o["valid"] != null) extra.Add("valid=" + o["valid"]);
        Out($"{ev}{(extra.Count > 0 ? "  " + string.Join("  ", extra) : "")}");
    }

    public int Run()
    {
        if (!EnvDetect.SbieOk) { Out("Sandboxie 未就绪"); return 1; }
        bool launch = _args.Contains("--launch", StringComparer.OrdinalIgnoreCase);
        bool noStop = _args.Contains("--no-stop", StringComparer.OrdinalIgnoreCase);
        int seconds = 180;
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals("--seconds", StringComparison.OrdinalIgnoreCase) && int.TryParse(_args[i + 1], out var s))
                seconds = Math.Clamp(s, 10, 3600);
        var mode = BoxRuntime.LaunchMode.Full;
        for (int i = 0; i < _args.Count - 1; i++)
        {
            if (!_args[i].Equals("--mode", StringComparison.OrdinalIgnoreCase)) continue;
            if (Enum.TryParse(_args[i + 1], true, out BoxRuntime.LaunchMode m)) mode = m;
        }

        Out($"start seconds={seconds} launch={launch} mode={mode} noStop={noStop} log={LogPath(_box)}");
        Emit(new JsonObject { ["ev"] = "start", ["seconds"] = seconds, ["launch"] = launch, ["mode"] = mode.ToString() });

        var frozen = Ilink.VaultState(_box);
        Emit(new JsonObject
        {
            ["ev"] = "vault",
            ["valid"] = frozen.Valid,
            ["keySha"] = frozen.KeyHash,
            ["uin"] = frozen.Uin,
            ["atFile"] = frozen.WriteLocal,
        });

        if (launch)
        {
            if (NeedScan.Pending(_box))
                Out("警告：need-scan 未清，启动后可能仍要扫码");
            try
            {
                var before = new BoxView(_box);
                if (before.HasQqOrGame)
                {
                    Out("箱内已有进程 -> 先停箱再冷启动");
                    BoxRuntime.StopForce(_box, false);
                    Thread.Sleep(2000);
                }
                BoxRuntime.EnsureWxRuntimeInBox(_box);
                VaultSync.PushVaultToLive(_box);
                BoxRuntime.Warmup(_box, false);
                BoxRuntime.ClearCrashRestore(_box);
                BoxRuntime.StartBrowser(_box, "observe", mode);
                Emit(new JsonObject { ["ev"] = "launched", ["mode"] = mode.ToString() });
            }
            catch (Exception ex)
            {
                Emit(new JsonObject { ["ev"] = "launch-fail", ["error"] = ex.Message });
                return 1;
            }
        }

        var baselineLive = Ilink.Live(_box);
        var launchUtc = DateTime.UtcNow;
        bool sawWx = false, sawGame = false, sawRenew = false, sawRevoked = false;
        string lastKey = baselineLive.Valid ? baselineLive.KeyHash : "";
        bool lastValid = baselineLive.Valid;
        DateTime lastAcctWrite = baselineLive.WriteUtc;
        DateTime lastPskWrite = FileWriteUtc(Path.Combine(BoxPaths.WmpfLive(_box), @"ilink\default\psk.key"));
        var deadline = DateTime.Now.AddSeconds(seconds);
        var nextHeartbeat = DateTime.MinValue; // 立刻打一条快照

        void SampleOnce()
        {
            var v = new BoxView(_box);
            var live = Ilink.Live(_box);
            var pskWrite = FileWriteUtc(Path.Combine(BoxPaths.WmpfLive(_box), @"ilink\default\psk.key"));

            if (v.HasWeChat && !sawWx)
            {
                sawWx = true;
                var wx = SnapshotWeChat(v);
                Emit(new JsonObject
                {
                    ["ev"] = "wechat-up",
                    ["pids"] = string.Join(",", wx.Pids),
                    ["count"] = wx.Pids.Count,
                    ["sampleCmd"] = wx.SampleCmd,
                });
            }

            if (v.HasGameWindow && !sawGame)
            {
                sawGame = true;
                var hwnd = v.GameHwnd;
                int pid = hwnd != IntPtr.Zero ? Win32.PidOf(hwnd) : 0;
                Emit(new JsonObject
                {
                    ["ev"] = "game-window",
                    ["hwnd"] = $"0x{hwnd.ToInt64():X}",
                    ["pid"] = pid,
                    ["title"] = hwnd != IntPtr.Zero ? Win32.Title(hwnd) : "",
                    ["proc"] = pid > 0 ? ProcessUtil.NameOf(pid) : "",
                });
            }

            if (live.WriteUtc > lastAcctWrite.AddMilliseconds(50) || live.KeyHash != lastKey || live.Valid != lastValid)
            {
                bool renewed = live.Valid && live.WriteUtc > launchUtc && live.KeyHash.Length > 0
                    && live.KeyHash != (frozen.Valid ? frozen.KeyHash : lastKey);
                if (!live.Valid && lastValid) sawRevoked = true;
                if (renewed) sawRenew = true;
                Emit(new JsonObject
                {
                    ["ev"] = !live.Valid && lastValid ? "credential-invalidated"
                        : renewed ? "credential-renewed"
                        : "credential-write",
                    ["valid"] = live.Valid,
                    ["keySha"] = live.KeyHash,
                    ["prevKeySha"] = lastKey,
                    ["pskSha"] = live.PskHash,
                    ["writeLocal"] = live.WriteLocal,
                    ["uin"] = live.Uin,
                });
                lastAcctWrite = live.WriteUtc;
                lastKey = live.KeyHash;
                lastValid = live.Valid;
            }

            if (pskWrite > lastPskWrite.AddMilliseconds(50))
            {
                Emit(new JsonObject
                {
                    ["ev"] = "psk-write",
                    ["pskSha"] = live.PskHash,
                    ["writeUtc"] = pskWrite.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                });
                lastPskWrite = pskWrite;
            }

            if (DateTime.Now >= nextHeartbeat)
            {
                nextHeartbeat = DateTime.Now.AddSeconds(15);
                Emit(new JsonObject
                {
                    ["ev"] = "heartbeat",
                    ["hasWeChat"] = v.HasWeChat,
                    ["hasGame"] = v.HasGameWindow,
                    ["runtimeUp"] = v.WeChatRuntimeUp,
                    ["liveValid"] = live.Valid,
                    ["keySha"] = live.KeyHash,
                    ["boxPids"] = v.Pids.Count,
                    ["wxPids"] = string.Join(",", SnapshotWeChat(v).Pids),
                    ["gameTitle"] = v.HasGameWindow ? Win32.Title(v.GameHwnd) : "",
                });
            }
        }

        while (DateTime.Now < deadline)
        {
            SampleOnce();
            Thread.Sleep(1000);
        }
        SampleOnce();

        Emit(new JsonObject
        {
            ["ev"] = "end",
            ["sawWeChat"] = sawWx,
            ["sawGame"] = sawGame,
            ["sawRenew"] = sawRenew,
            ["sawRevoked"] = sawRevoked,
        });

        if (launch && !noStop)
        {
            Out("观测结束，停箱");
            try { BoxRuntime.StopForce(_box, false); } catch { }
        }

        Out($"完成 sawWeChat={sawWx} sawGame={sawGame} renewed={sawRenew} revoked={sawRevoked}");
        Out($"日志 {LogPath(_box)}");
        return sawGame || sawWx || sawRenew ? 0 : 1;
    }

    static DateTime FileWriteUtc(string path)
    {
        try { return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue; }
        catch { return DateTime.MinValue; }
    }

    sealed record WxSnap(List<int> Pids, string SampleCmd);

    static WxSnap SnapshotWeChat(BoxView v)
    {
        var pids = new List<int>();
        string sample = "";
        var cmds = ProcessUtil.CommandLines(v.Pids);
        foreach (var (pid, (name, cmd)) in cmds)
        {
            if (!name.Equals("WeChatAppEx", StringComparison.OrdinalIgnoreCase)
                && !name.Equals("WeChatAppEx.exe", StringComparison.OrdinalIgnoreCase)
                && !name.Equals("WeChatAppHost", StringComparison.OrdinalIgnoreCase))
                continue;
            pids.Add(pid);
            if (sample.Length == 0 && !string.IsNullOrEmpty(cmd))
                sample = cmd.Length > 160 ? cmd[..160] + "…" : cmd;
        }
        // 回退：仅按进程名（命令行查询失败时）
        if (pids.Count == 0)
        {
            foreach (var pid in v.Pids)
            {
                var n = v.NameOf(pid);
                if (n is "WeChatAppEx" or "WeChatAppHost") pids.Add(pid);
            }
        }
        return new WxSnap(pids, sample);
    }
}
