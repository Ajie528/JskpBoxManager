using System.Net.WebSockets;
using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>QQ 浏览器远程调试端口（9300+N）：列标签、关标签、刷新游戏中心页。</summary>
public static class Cdp
{
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(3) };

    public sealed record Tab(string Id, string Type, string Url, string Title, string Ws);

    public static List<Tab> Tabs(string box)
    {
        var list = new List<Tab>();
        try
        {
            var text = Http.GetStringAsync($"http://127.0.0.1:{BoxPaths.DebugPort(box)}/json").GetAwaiter().GetResult();
            if (JsonNode.Parse(text) is JsonArray arr)
                foreach (var n in arr.OfType<JsonObject>())
                    list.Add(new Tab(JsonFile.Str(n, "id"), JsonFile.Str(n, "type"), JsonFile.Str(n, "url"), JsonFile.Str(n, "title"), JsonFile.Str(n, "webSocketDebuggerUrl")));
        }
        catch { }
        return list;
    }

    public static bool Alive(string box)
    {
        try
        {
            Http.GetStringAsync($"http://127.0.0.1:{BoxPaths.DebugPort(box)}/json/version").GetAwaiter().GetResult();
            return true;
        }
        catch { return false; }
    }

    static bool Close(string box, string id)
    {
        try
        {
            Http.GetStringAsync($"http://127.0.0.1:{BoxPaths.DebugPort(box)}/json/close/{id}").GetAwaiter().GetResult();
            return true;
        }
        catch { return false; }
    }

    public static bool IsQrTab(string url, string title) =>
        (url ?? "").Contains("wx_login", StringComparison.OrdinalIgnoreCase) || Titles.IsStrictQr(title);

    static bool IsGameCenter(Tab t) => t.Url.Contains("pcgame.qqbrowser", StringComparison.OrdinalIgnoreCase) || t.Title.Contains("游戏中心");

    static bool IsExtraTab(string url, string title)
    {
        if (url.Contains("WXRuntime_Log") || title.Contains("WXRuntime_Log")) return true;
        if (url.StartsWith("http://data/") || title.Contains("http://data/")) return true;
        if (url.Contains("chrome://newtab") || url.Contains("about:blank")) return true;
        if (title is "新标签页" or "New Tab") return true;
        return url.Contains("sogou.com/tx") || title.Contains("搜狗");
    }

    public static bool HasGameCenterTab(string box) => Tabs(box).Any(IsGameCenter);
    public static bool HasQrTab(string box) => Tabs(box).Any(t => IsQrTab(t.Url, t.Title));

    /// <summary>关掉 WXRuntime_Log / 新标签 等多余标签；游戏中心只留一个。游戏中心还没打开时不关（那往往是唯一的窗口）。</summary>
    public static int CloseExtraTabs(string box)
    {
        var tabs = Tabs(box).Where(t => t.Type is "" or "page").Where(t => t.Id.Length > 0).ToList();
        var game = new List<Tab>();
        var extra = new List<Tab>();
        foreach (var t in tabs)
        {
            if (IsQrTab(t.Url, t.Title)) continue;
            if (IsGameCenter(t)) { game.Add(t); continue; }
            if (IsExtraTab(t.Url, t.Title)) extra.Add(t);
        }
        if (game.Count == 0) return 0;
        int closed = extra.Count(t => Close(box, t.Id));
        closed += game.Skip(1).Count(t => Close(box, t.Id));
        return closed;
    }

    /// <summary>游戏已经起来时，扫码授权页是多余弹层。</summary>
    public static int CloseQrTabs(string box) =>
        Tabs(box).Where(t => t.Type is "" or "page" or "iframe").Where(t => t.Id.Length > 0 && IsQrTab(t.Url, t.Title)).Count(t => Close(box, t.Id));

    /// <summary>游戏中心页空白/不注入微信时，Page.reload 比整箱冷启快得多。</summary>
    public static bool ReloadGameCenter(string box)
    {
        var tab = Tabs(box).FirstOrDefault(t => t.Type == "page" && (t.Url.Contains("openGameId") || t.Url.Contains("pcgame.qqbrowser.qq.com")) && t.Ws.StartsWith("ws://"));
        if (tab == null) return false;
        try
        {
            using var ws = new ClientWebSocket();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            ws.ConnectAsync(new Uri(tab.Ws), cts.Token).GetAwaiter().GetResult();
            var payload = Encoding.UTF8.GetBytes("{\"id\":1,\"method\":\"Page.reload\",\"params\":{\"ignoreCache\":true}}");
            ws.SendAsync(payload, WebSocketMessageType.Text, true, cts.Token).GetAwaiter().GetResult();
            var buf = new byte[4096];
            try { ws.ReceiveAsync(buf, cts.Token).GetAwaiter().GetResult(); } catch { }
            Log.Box(box, "CDP Page.reload game-center (ignoreCache)");
            return true;
        }
        catch (Exception ex)
        {
            Log.Box(box, "CDP Page.reload failed: " + ex.Message);
            return false;
        }
    }
}
