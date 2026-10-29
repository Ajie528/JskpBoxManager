using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 精简启动候选实验（原 tools/lean-refresh/lean-refresh-qb1.ps1）。
/// JskpBoxManager.exe lean qb1 [--modes Blank,NoUrl,RuntimeOnly] [--seconds 240] [--allow-need-scan] [--skip-stop]
/// 进程是否起来用 <see cref="BoxView"/>，不再用 PowerShell CIM。
/// </summary>
public sealed class LeanProbeSession
{
    readonly string _box;
    readonly List<string> _args;
    string _logPath = "";
    static bool _consoleReady;

    public LeanProbeSession(string box, IEnumerable<string> args)
    {
        _box = box;
        _args = args?.ToList() ?? new List<string>();
    }

    public int Run()
    {
        if (!string.Equals(_box, "qb1", StringComparison.OrdinalIgnoreCase))
        {
            Out("lean 只允许 qb1");
            return 2;
        }
        if (!EnvDetect.SbieOk) { Out("Sandboxie 未就绪"); return 1; }

        var modes = ParseModes();
        int seconds = 240;
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals("--seconds", StringComparison.OrdinalIgnoreCase) && int.TryParse(_args[i + 1], out var s))
                seconds = Math.Clamp(s, 30, 3600);
        bool allowNeed = _args.Contains("--allow-need-scan", StringComparer.OrdinalIgnoreCase);
        bool skipStop = _args.Contains("--skip-stop", StringComparer.OrdinalIgnoreCase);

        Directory.CreateDirectory(AppPaths.Logs);
        _logPath = Path.Combine(AppPaths.Logs, "lean-refresh-qb1.jsonl");
        Out($"appdir={AppPaths.AppDir}");
        Out($"modes={string.Join(",", modes)} seconds={seconds}");

        if (NeedScan.Pending(_box) && !allowNeed)
        {
            Out("qb1 处于 need-scan，先扫码再测。强行试可加 --allow-need-scan");
            return 2;
        }

        var vault = Ilink.VaultState(_box);
        if (!vault.Valid) { Out("金库凭证无效：" + BoxPaths.WmpfVault(_box)); return 1; }
        if (Ilink.IsRevoked(_box, vault.KeyHash))
        {
            Out($"金库密钥 {vault.KeyHash} 已作废，先扫码换新再测");
            return 1;
        }
        Out($"vault key={vault.KeyHash} uin={vault.Uin} at={vault.WriteLocal}");

        string passMode = "";
        foreach (var mode in modes)
        {
            Out("");
            Out($"==== candidate {mode} ====");
            if (!skipStop)
            {
                Out("stop box...");
                StopBox();
                Thread.Sleep(2000);
            }
            BoxRuntime.EnsureWxRuntimeInBox(_box);
            try { VaultSync.PushVaultToLive(_box); } catch (Exception ex) { Out("推金库：" + ex.Message); }
            BoxRuntime.Warmup(_box, false);
            BoxRuntime.ClearCrashRestore(_box);

            var baseline = Ilink.Live(_box);
            var frozenKey = baseline.Valid ? baseline.KeyHash : vault.KeyHash;
            if (!baseline.Valid) Out("WARN live 推金库后仍无效，继续");
            var launchUtc = DateTime.UtcNow;
            var sw = Stopwatch.StartNew();
            try
            {
                BoxRuntime.StartBrowser(_box, "lean", mode);
            }
            catch (Exception ex)
            {
                Emit(Result(mode, "start-fail", frozenKey, null, 0, sw, vault.KeyHash, ex.Message));
                Out("START FAIL: " + ex.Message);
                continue;
            }
            Out($"started; watch key renew (frozen={frozenKey}) up to {seconds}s...");

            string result = "timeout";
            IlinkState live = null;
            int wxPid = 0;
            bool sawWx = false, sawGame = false;
            var deadline = DateTime.Now.AddSeconds(seconds);
            while (DateTime.Now < deadline)
            {
                Thread.Sleep(3000);
                var v = new BoxView(_box);
                if (v.HasWeChat && wxPid <= 0)
                {
                    wxPid = FirstWeChat(v);
                    sawWx = wxPid > 0;
                }
                if (v.HasGameWindow) sawGame = true;
                live = Ilink.Live(_box);
                if (live.Valid && live.WriteUtc > launchUtc && live.KeyHash.Length > 0 && live.KeyHash != frozenKey)
                {
                    result = "renewed";
                    break;
                }
                if (!live.Valid && sw.Elapsed.TotalSeconds >= 12 && live.WriteUtc > launchUtc)
                {
                    result = "revoked";
                    break;
                }
                if (mode != BoxRuntime.LaunchMode.Full && !sawWx && !sawGame && sw.Elapsed.TotalSeconds >= 60)
                {
                    result = "no-wechat";
                    break;
                }
                int sec = (int)sw.Elapsed.TotalSeconds;
                if (sec % 15 < 4)
                {
                    var key = live.Valid ? live.KeyHash : "invalid";
                    Out($"  {sec,3}s  live={key}  wxPid={wxPid}  game={sawGame}  boxPids={v.Pids.Count}");
                }
            }

            var rec = Result(mode, result, frozenKey, live, wxPid, sw, vault.KeyHash, "");
            rec["sawGame"] = sawGame;
            Emit(rec);
            Out($"RESULT {mode} => {result}  liveKey={(live?.KeyHash ?? "")}  {sw.Elapsed.TotalSeconds:0.0}s  game={sawGame}");
            StopBox();
            Thread.Sleep(2000);
            if (result == "renewed")
            {
                passMode = mode.ToString();
                Out($"成功：候选 {mode} 换新了密钥。");
                break;
            }
        }

        Out(passMode.Length > 0 ? $"PASS mode={passMode}" : "FAIL: 没有候选完成密钥换新");
        Out("log=" + _logPath);
        return passMode.Length > 0 ? 0 : 1;
    }

    List<BoxRuntime.LaunchMode> ParseModes()
    {
        string raw = "Blank,NoUrl,RuntimeOnly";
        for (int i = 0; i < _args.Count - 1; i++)
            if (_args[i].Equals("--modes", StringComparison.OrdinalIgnoreCase)) raw = _args[i + 1];
        var list = new List<BoxRuntime.LaunchMode>();
        foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!Enum.TryParse(part, true, out BoxRuntime.LaunchMode m))
                throw new ArgumentException("未知模式 " + part);
            list.Add(m);
        }
        if (list.Count == 0) throw new ArgumentException("至少指定一个 --modes");
        return list;
    }

    static int FirstWeChat(BoxView v)
    {
        foreach (var pid in v.Pids)
            if (v.NameOf(pid) is "WeChatAppEx" or "WeChatAppHost") return pid;
        return 0;
    }

    static JsonObject Result(BoxRuntime.LaunchMode mode, string result, string frozenKey, IlinkState live, int wxPid, Stopwatch sw, string vaultKey, string error)
    {
        var o = new JsonObject
        {
            ["mode"] = mode.ToString(),
            ["result"] = result,
            ["frozenKey"] = frozenKey,
            ["liveKey"] = live?.KeyHash ?? "",
            ["liveValid"] = live?.Valid ?? false,
            ["liveAt"] = live?.WriteLocal ?? "",
            ["wxPid"] = wxPid,
            ["elapsedSec"] = Math.Round(sw.Elapsed.TotalSeconds, 1),
            ["vaultKeyBefore"] = vaultKey,
        };
        if (error.Length > 0) o["error"] = error;
        return o;
    }

    static void StopBox()
    {
        Sandboxie.Terminate("qb1");
        var deadline = DateTime.Now.AddSeconds(20);
        while (DateTime.Now < deadline && Sandboxie.Pids("qb1").Count > 0)
            Thread.Sleep(500);
    }

    void Emit(JsonObject o)
    {
        o["at"] ??= DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        o["box"] = _box;
        try { File.AppendAllText(_logPath, o.ToJsonString(JsonFile.Compact) + "\r\n", new UTF8Encoding(false)); }
        catch { }
    }

    void Out(string m)
    {
        Log.Box(_box, "lean " + m);
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
}
