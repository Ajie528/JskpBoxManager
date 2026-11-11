using System.Net.WebSockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>QQ 浏览器远程调试端口（9300+N）：列标签、关标签、刷新游戏中心页；协议服务用 CDP 调 wx.login。</summary>
public static class Cdp
{
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(3) };
    static int _evalId = 100;

    public sealed record Tab(string Id, string Type, string Url, string Title, string Ws);

    public static List<Tab> Tabs(string box) => TabsOnPort(BoxPaths.DebugPort(box));

    public static List<Tab> TabsOnPort(int port)
    {
        var list = new List<Tab>();
        try
        {
            var text = Http.GetStringAsync($"http://127.0.0.1:{port}/json").GetAwaiter().GetResult();
            if (JsonNode.Parse(text) is JsonArray arr)
                foreach (var n in arr.OfType<JsonObject>())
                    list.Add(new Tab(JsonFile.Str(n, "id"), JsonFile.Str(n, "type"), JsonFile.Str(n, "url"), JsonFile.Str(n, "title"), JsonFile.Str(n, "webSocketDebuggerUrl")));
            // 部分 Chromium 还要把 /json/list 合进来
            try
            {
                var text2 = Http.GetStringAsync($"http://127.0.0.1:{port}/json/list").GetAwaiter().GetResult();
                if (JsonNode.Parse(text2) is JsonArray arr2)
                    foreach (var n in arr2.OfType<JsonObject>())
                    {
                        var id = JsonFile.Str(n, "id");
                        if (list.Any(t => t.Id == id)) continue;
                        list.Add(new Tab(id, JsonFile.Str(n, "type"), JsonFile.Str(n, "url"), JsonFile.Str(n, "title"), JsonFile.Str(n, "webSocketDebuggerUrl")));
                    }
            }
            catch { }
        }
        catch { }
        return list;
    }

    /// <summary>本沙箱可能挂着的调试端口：QQ 浏览器固定口 + WeChatAppEx 命令行里的 --remote-debugging-port。</summary>
    public static List<int> DiscoverDebugPorts(string box)
    {
        var ports = new List<int>();
        int qq = BoxPaths.DebugPort(box);
        ports.Add(qq);
        try
        {
            var cmds = ProcessUtil.CommandLines(new BoxView(box).Pids);
            foreach (var (_, (name, cmd)) in cmds)
            {
                if (!name.Contains("WeChatAppEx", StringComparison.OrdinalIgnoreCase)
                    && !name.Contains("QQBrowser", StringComparison.OrdinalIgnoreCase)
                    && !name.Contains("chrome", StringComparison.OrdinalIgnoreCase))
                    continue;
                foreach (Match m in Regex.Matches(cmd ?? "", @"--remote-debugging-port=(\d+)"))
                {
                    if (int.TryParse(m.Groups[1].Value, out int p) && p > 0 && !ports.Contains(p))
                        ports.Add(p);
                }
            }
        }
        catch { }
        return ports;
    }

    /// <summary>在目标页执行 wx.login；成功返回 code。页面没有 wx 时 error 含 no wx.login。</summary>
    public static (bool Ok, string Code, string Error) TryWxLogin(string wsUrl, int timeoutSec = 12)
    {
        if (string.IsNullOrWhiteSpace(wsUrl) || !wsUrl.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
            return (false, "", "no websocket");
        const string expr = """
(() => new Promise((resolve, reject) => {
  try {
    const w = (typeof wx !== 'undefined' && wx) || (typeof GameGlobal !== 'undefined' && GameGlobal.wx) || null;
    if (!w || typeof w.login !== 'function') { reject(new Error('no wx.login')); return; }
    let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; reject(new Error('wx.login timeout')); } }, 10000);
    w.login({
      success: (r) => { if (done) return; done = true; clearTimeout(timer); resolve({ code: (r && r.code) || '', errMsg: (r && r.errMsg) || '' }); },
      fail: (e) => { if (done) return; done = true; clearTimeout(timer); reject(new Error((e && e.errMsg) || 'wx.login fail')); }
    });
  } catch (e) { reject(e); }
}))()
""";
        try
        {
            var node = Evaluate(wsUrl, expr, awaitPromise: true, timeoutSec: timeoutSec);
            if (node == null) return (false, "", "empty evaluate result");
            // exceptionDetails
            if (node["exceptionDetails"] is JsonObject ex)
            {
                var msg = "";
                if (ex["exception"] is JsonObject exObj)
                {
                    msg = JsonFile.Str(exObj, "description");
                    if (msg.Length == 0) msg = JsonFile.Str(exObj, "value");
                }
                if (msg.Length == 0) msg = JsonFile.Str(ex, "text");
                return (false, "", string.IsNullOrEmpty(msg) ? "evaluate exception" : msg);
            }
            var result = node["result"] as JsonObject;
            if (result == null) return (false, "", "no result");
            // {type:"object", value:{code,errMsg}} 或 nested value
            string code = "";
            if (result["value"] is JsonObject vo)
                code = JsonFile.Str(vo, "code");
            else if (result["value"] is JsonValue jv && jv.TryGetValue<string>(out var s))
                code = s ?? "";
            if (string.IsNullOrEmpty(code) && result["description"] is JsonValue)
            {
                // 个别实现只回 description
            }
            if (string.IsNullOrEmpty(code))
                return (false, "", "wx.login returned empty code");
            return (true, code, "");
        }
        catch (Exception ex)
        {
            return (false, "", ex.Message);
        }
    }

    static JsonObject Evaluate(string wsUrl, string expression, bool awaitPromise, int timeoutSec)
    {
        using var ws = new ClientWebSocket();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        ws.ConnectAsync(new Uri(wsUrl), cts.Token).GetAwaiter().GetResult();
        int id = Interlocked.Increment(ref _evalId);
        var req = new JsonObject
        {
            ["id"] = id,
            ["method"] = "Runtime.evaluate",
            ["params"] = new JsonObject
            {
                ["expression"] = expression,
                ["awaitPromise"] = awaitPromise,
                ["returnByValue"] = true,
                ["userGesture"] = true,
            },
        };
        var payload = Encoding.UTF8.GetBytes(req.ToJsonString(JsonFile.Compact));
        ws.SendAsync(payload, WebSocketMessageType.Text, true, cts.Token).GetAwaiter().GetResult();

        var deadline = DateTime.UtcNow.AddSeconds(timeoutSec);
        while (DateTime.UtcNow < deadline && ws.State == WebSocketState.Open)
        {
            var msg = ReceiveMessage(ws, cts.Token);
            if (msg == null) break;
            JsonObject o;
            try { o = JsonNode.Parse(msg) as JsonObject; } catch { continue; }
            if (o == null) continue;
            if (JsonFile.Int(o, "id") == id)
                return o["result"] as JsonObject ?? o;
        }
        return null;
    }

    static string ReceiveMessage(ClientWebSocket ws, CancellationToken ct)
    {
        var buf = new byte[65536];
        using var ms = new MemoryStream();
        while (true)
        {
            var result = ws.ReceiveAsync(buf, ct).GetAwaiter().GetResult();
            if (result.MessageType == WebSocketMessageType.Close) return null;
            ms.Write(buf, 0, result.Count);
            if (result.EndOfMessage) break;
            if (ms.Length > 4 * 1024 * 1024) return null;
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    // ---------- 抓 wx.request / wx.login（只读：包一层记录后原样放行） ----------

    /// <summary>页内装钩：包 wx.request / wx.login，把请求与响应压进 __jskpCap。幂等；页面没有 wx 返回 no-wx。</summary>
    public const string WxCaptureInstaller = """
(function(){
 try{
  var g=(typeof GameGlobal!=='undefined'&&GameGlobal)||(typeof globalThis!=='undefined'?globalThis:this);
  var w=(typeof wx!=='undefined'&&wx)||(g&&g.wx)||null;
  if(!w) return 'no-wx';
  if(g.__jskpCapInstalled) return 'already';
  g.__jskpCap=g.__jskpCap||[];
  function s(x){try{if(x==null)return x;if(typeof x==='string')return x.length>8000?x.slice(0,8000):x;var t=JSON.stringify(x);return t&&t.length>8000?t.slice(0,8000):t;}catch(e){return String(x);}}
  function rec(o){try{o.ts=Date.now();g.__jskpCap.push(o);if(g.__jskpCap.length>800)g.__jskpCap.shift();}catch(e){}}
  if(typeof w.request==='function'){
   var _req=w.request.bind(w);
   w.request=function(opt){
    try{
     opt=opt||{};var id=Math.random().toString(36).slice(2);
     rec({ev:'request',id:id,url:opt.url,method:opt.method||'GET',header:s(opt.header),data:s(opt.data),dataType:opt.dataType});
     var us=opt.success,uf=opt.fail;
     opt.success=function(res){rec({ev:'response',id:id,url:opt.url,statusCode:res&&res.statusCode,header:s(res&&res.header),data:s(res&&res.data)});if(us)return us.apply(this,arguments);};
     opt.fail=function(err){rec({ev:'fail',id:id,url:opt.url,err:s(err)});if(uf)return uf.apply(this,arguments);};
    }catch(e){rec({ev:'hook-error',msg:String(e)});}
    return _req(opt);
   };
  }
  if(typeof w.login==='function'){
   var _login=w.login.bind(w);
   w.login=function(opt){opt=opt||{};var us=opt.success;opt.success=function(res){rec({ev:'login',code:res&&res.code,errMsg:res&&res.errMsg});if(us)return us.apply(this,arguments);};return _login(opt);};
  }
  g.__jskpCapInstalled=true;
  return 'installed';
 }catch(e){return 'err:'+e;}
})()
""";

    const string WxCaptureDrain = """
(function(){try{var g=(typeof GameGlobal!=='undefined'&&GameGlobal)||globalThis;var a=g.__jskpCap||[];g.__jskpCap=[];return JSON.stringify(a);}catch(e){return '[]';}})()
""";

    /// <summary>对一个 CDP target 的常连接：同步发请求、按 id 取回结果，期间的事件直接跳过。</summary>
    public sealed class CdpClient : IDisposable
    {
        readonly ClientWebSocket _ws = new();
        int _id = 1000;
        public string Url { get; }
        public bool Connected => _ws.State == WebSocketState.Open;

        CdpClient(string url) { Url = url; }

        public static CdpClient Connect(string wsUrl, int timeoutSec = 8)
        {
            if (string.IsNullOrWhiteSpace(wsUrl) || !wsUrl.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
                return null;
            var c = new CdpClient(wsUrl);
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
                c._ws.ConnectAsync(new Uri(wsUrl), cts.Token).GetAwaiter().GetResult();
                return c;
            }
            catch
            {
                try { c._ws.Dispose(); } catch { }
                return null;
            }
        }

        public JsonObject Call(string method, JsonObject parameters = null, int timeoutSec = 10)
        {
            if (!Connected) return null;
            int id = Interlocked.Increment(ref _id);
            var req = new JsonObject { ["id"] = id, ["method"] = method };
            if (parameters != null) req["params"] = parameters;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
            var payload = Encoding.UTF8.GetBytes(req.ToJsonString(JsonFile.Compact));
            _ws.SendAsync(payload, WebSocketMessageType.Text, true, cts.Token).GetAwaiter().GetResult();
            var deadline = DateTime.UtcNow.AddSeconds(timeoutSec);
            while (DateTime.UtcNow < deadline && Connected)
            {
                var msg = ReceiveMessage(_ws, cts.Token);
                if (msg == null) break;
                JsonObject o;
                try { o = JsonNode.Parse(msg) as JsonObject; } catch { continue; }
                if (o == null) continue;
                if (JsonFile.Int(o, "id") == id) return o;
            }
            return null;
        }

        public string EvaluateString(string expression, bool awaitPromise = false, int timeoutSec = 10)
        {
            var resp = Call("Runtime.evaluate", new JsonObject
            {
                ["expression"] = expression,
                ["awaitPromise"] = awaitPromise,
                ["returnByValue"] = true,
                ["userGesture"] = true,
            }, timeoutSec);
            var result = resp?["result"]?["result"] as JsonObject ?? resp?["result"] as JsonObject;
            if (result == null) return "";
            if (result["value"] is JsonValue jv)
            {
                if (jv.TryGetValue<string>(out var s)) return s ?? "";
                return jv.ToJsonString().Trim('"');
            }
            return JsonFile.Str(result, "description");
        }

        /// <summary>装钩：Page.addScriptToEvaluateOnNewDocument（后续导航）+ 立刻 Runtime.evaluate 一次。</summary>
        public string InstallWxCapture()
        {
            try
            {
                Call("Page.enable", timeoutSec: 5);
                Call("Runtime.enable", timeoutSec: 5);
                Call("Page.addScriptToEvaluateOnNewDocument", new JsonObject { ["source"] = WxCaptureInstaller }, 5);
            }
            catch { }
            return EvaluateString(WxCaptureInstaller, false, 8);
        }

        public JsonArray DrainWxCapture()
        {
            var raw = EvaluateString(WxCaptureDrain, false, 8);
            if (string.IsNullOrWhiteSpace(raw)) return new JsonArray();
            try { return JsonNode.Parse(raw) as JsonArray ?? new JsonArray(); }
            catch { return new JsonArray(); }
        }

        public void Dispose()
        {
            try { if (_ws.State == WebSocketState.Open) _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None).Wait(1000); } catch { }
            try { _ws.Dispose(); } catch { }
        }
    }

    /// <summary>在所有相关调试口上装钩；返回已装上的连接（调用方负责 Dispose）。</summary>
    public static List<CdpClient> InstallWxCaptureAll(string box, out int tried)
    {
        tried = 0;
        var clients = new List<CdpClient>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var port in DiscoverDebugPorts(box))
        {
            foreach (var tab in TabsOnPort(port))
            {
                if (!tab.Ws.StartsWith("ws://", StringComparison.OrdinalIgnoreCase)) continue;
                if (IsQrTab(tab.Url, tab.Title)) continue;
                if (!seen.Add(tab.Ws)) continue;
                tried++;
                var c = CdpClient.Connect(tab.Ws);
                if (c == null) continue;
                var r = c.InstallWxCapture() ?? "";
                // no-wx 也保留连接：轮询时会再次 Install；游戏中心/运行时晚一点才挂上 wx
                clients.Add(c);
                Log.Box(box, $"CDP 抓包注入 {r} 标签页={ShortTab(tab)}");
            }
        }
        return clients;
    }

    static string ShortTab(Tab t)
    {
        var u = t.Url ?? "";
        if (u.Length > 60) u = u[..57] + "...";
        return $"{t.Type}|{u}|{t.Title}";
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
            Log.Box(box, "CDP 刷新游戏中心页（忽略缓存）");
            return true;
        }
        catch (Exception ex)
        {
            Log.Box(box, "CDP 刷新页面失败：" + ex.Message);
            return false;
        }
    }
}
