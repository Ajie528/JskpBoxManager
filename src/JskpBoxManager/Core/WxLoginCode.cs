using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// 通过 CDP 在沙箱内真实微信运行时调用 wx.login，取本游戏的一次性 code。
/// 不实现原生 ilink 发包；要求目标沙箱已有有效免扫凭证，且游戏进程在跑（或允许 ensureRunning 拉起）。
/// </summary>
public static class WxLoginCode
{
    static readonly ConcurrentDictionary<string, object> BoxLocks = new();

    public sealed record Result(bool Ok, string Code, string Box, string AppId, string Uin, string Error, string Via)
    {
        public JsonObject ToJson() => new()
        {
            ["ok"] = Ok,
            ["code"] = Code,
            ["box"] = Box,
            ["app_id"] = AppId,
            ["uin"] = Uin,
            ["error"] = Error,
            ["via"] = Via,
        };
    }

    /// <summary>把脚本里的 ref（qb1 / 1 / uin）解析成沙箱名。</summary>
    public static string ResolveBox(string reference)
    {
        var refRaw = (reference ?? "").Trim();
        if (refRaw.Length == 0) return "";
        if (Sandboxie.IsBoxName(refRaw)) return refRaw;
        if (Regex.IsMatch(refRaw, @"^\d+$")) return "qb" + refRaw;

        foreach (var box in Sandboxie.QueryBoxes())
        {
            var live = Ilink.Live(box);
            if (live.Valid && (live.Uin == refRaw || live.Username.Equals(refRaw, StringComparison.OrdinalIgnoreCase)))
                return box;
            var vault = Ilink.VaultState(box);
            if (vault.Valid && (vault.Uin == refRaw || vault.Username.Equals(refRaw, StringComparison.OrdinalIgnoreCase)))
                return box;
        }
        return "";
    }

    public static Result Get(string reference, string appId, bool ensureRunning = true, int timeoutSec = 45)
    {
        appId = (appId ?? "").Trim();
        if (appId.Length == 0) appId = AppInfo.GameAppId;
        if (!string.Equals(appId, AppInfo.GameAppId, StringComparison.OrdinalIgnoreCase))
            return Fail("", appId, "", $"只允许本游戏 APPID（{AppInfo.GameAppId}）");

        var box = ResolveBox(reference);
        if (box.Length == 0)
            return Fail("", appId, "", "找不到账号：ref 请用 qbN、数字 N，或该沙箱的 ilink uin");

        var gate = BoxLocks.GetOrAdd(box, _ => new object());
        lock (gate)
        {
            try { return GetLocked(box, appId, ensureRunning, timeoutSec); }
            catch (Exception ex)
            {
                Log.Box(box, "wx.login 取 code 异常：" + ex.Message);
                return Fail(box, appId, "", ex.Message);
            }
        }
    }

    static Result GetLocked(string box, string appId, bool ensureRunning, int timeoutSec)
    {
        if (NeedScan.Pending(box))
            return Fail(box, appId, "", "该沙箱需要重新扫码，无法取 code");

        var vault = Ilink.VaultState(box);
        var live = Ilink.Live(box);
        var uin = live.Valid ? live.Uin : vault.Uin;
        if (!vault.Valid && !live.Valid)
            return Fail(box, appId, uin, "没有有效登录凭证，请先扫码登录");

        var view = new BoxView(box);
        if (!view.HasGameWindow)
        {
            if (!ensureRunning)
                return Fail(box, appId, uin, "游戏未在运行；请先启动，或传 ensure_running=true");
            Log.Box(box, "wx.login：游戏没起来 → 先确保它运行");
            if (!EnsureGameUp(box, Math.Min(timeoutSec, 90)))
                return Fail(box, appId, uin, "未能拉起游戏窗口，无法注入 wx.login");
            view = new BoxView(box);
            if (!view.HasGameWindow)
                return Fail(box, appId, uin, "游戏窗口仍未出现");
        }

        var ports = Cdp.DiscoverDebugPorts(box);
        if (ports.Count == 0)
            return Fail(box, appId, uin, "找不到调试端口（QQ 浏览器 remote-debugging 或 WeChatAppEx）");

        var deadline = DateTime.Now.AddSeconds(Math.Clamp(timeoutSec, 10, 120));
        string lastErr = "未找到可执行 wx.login 的页面";
        while (DateTime.Now < deadline)
        {
            foreach (var port in ports.ToList())
            {
                var tabs = Cdp.TabsOnPort(port);
                var ordered = tabs
                    .Where(t => t.Ws.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(t => ScoreTab(t, appId))
                    .ToList();
                foreach (var tab in ordered)
                {
                    if (ScoreTab(tab, appId) < 0) continue;
                    var (ok, code, err) = Cdp.TryWxLogin(tab.Ws, 12);
                    if (ok && !string.IsNullOrEmpty(code))
                    {
                        Log.Box(box, $"wx.login 取 code 成功：端口={port} 标签页={Short(tab.Url)}/{Short(tab.Title)} 长度={code.Length}");
                        Ilink.WriteEvent(box, "wx-login-code", new JsonObject
                        {
                            ["appId"] = appId, ["uin"] = uin, ["via"] = $"cdp:{port}", ["codeLen"] = code.Length,
                        });
                        return new Result(true, code, box, appId, uin, "", $"cdp:{port}");
                    }
                    if (!string.IsNullOrEmpty(err) && !err.Contains("no wx.login", StringComparison.OrdinalIgnoreCase))
                        lastErr = err;
                }
            }
            // 进程命令行上的调试端口可能晚于游戏窗出现
            foreach (var p in Cdp.DiscoverDebugPorts(box))
                if (!ports.Contains(p)) ports.Add(p);
            Thread.Sleep(1500);
        }

        Log.Box(box, "wx.login 取 code 失败：" + lastErr);
        return Fail(box, appId, uin, lastErr);
    }

    /// <summary>游戏已在跑就不碰；常驻态复开 GameUrl；否则走一次 launch 看门进程。</summary>
    static bool EnsureGameUp(string box, int timeoutSec)
    {
        var view = new BoxView(box);
        if (view.HasGameWindow) return true;

        if (view.WeChatRuntimeUp)
        {
            BoxRuntime.StartBrowser(box, "wx-login-nudge", BoxRuntime.LaunchMode.Full);
        }
        else if (BoxRuntime.LauncherPid(box) == 0)
        {
            // 不阻塞整次请求在 LaunchSession 里；只拉起浏览器，由本方法短等游戏窗
            try { VaultSync.PushVaultToLive(box); } catch { }
            BoxRuntime.EnsureWxRuntimeInBox(box);
            BoxRuntime.ClearCrashRestore(box);
            BoxRuntime.StartBrowser(box, "wx-login-ensure", BoxRuntime.LaunchMode.Full);
        }
        else
        {
            BoxRuntime.StartBrowser(box, "wx-login-nudge-existing", BoxRuntime.LaunchMode.Full);
        }

        var deadline = DateTime.Now.AddSeconds(timeoutSec);
        while (DateTime.Now < deadline)
        {
            if (new BoxView(box).HasGameWindow) return true;
            if (NeedScan.Pending(box) || Cdp.HasQrTab(box) || new BoxView(box).HasStrictQr)
                return false;
            Thread.Sleep(2000);
        }
        return new BoxView(box).HasGameWindow;
    }

    static int ScoreTab(Cdp.Tab t, string appId)
    {
        var url = t.Url ?? "";
        var title = t.Title ?? "";
        int score = 0;
        if (url.Contains(appId, StringComparison.OrdinalIgnoreCase)) score += 100;
        if (title.Contains(AppInfo.GameTitle)) score += 80;
        if (url.Contains("servicewechat.com", StringComparison.OrdinalIgnoreCase)) score += 60;
        if (url.Contains("openGameId", StringComparison.OrdinalIgnoreCase)) score += 20;
        if (t.Type is "page" or "iframe" or "worker" or "service_worker" or "") score += 5;
        // 明显无关的标签
        if (Cdp.IsQrTab(url, title)) return -1;
        if (url.Contains("chrome://") || url.Contains("about:blank")) return -1;
        if (url.Contains("pcgame.qqbrowser") && !url.Contains(appId, StringComparison.OrdinalIgnoreCase) && score < 80)
            return 1; // 游戏中心页通常没有 wx，但仍可试
        return score;
    }

    static Result Fail(string box, string appId, string uin, string err) =>
        new(false, "", box, appId, uin ?? "", err ?? "", "");

    static string Short(string s) => string.IsNullOrEmpty(s) ? "" : (s.Length <= 48 ? s : s[..45] + "...");
}
