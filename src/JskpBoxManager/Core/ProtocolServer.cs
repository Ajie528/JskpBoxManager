using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 本机协议 HTTP 服务：脚本读 JSKP_SERVER 后调用 /wxapp/getCode。
/// 仅监听 127.0.0.1；若配置了 token，需 Authorization: Bearer &lt;token&gt;。
/// </summary>
public sealed class ProtocolServer : IDisposable
{
    static readonly object Gate = new();
    static ProtocolServer _instance;

    readonly HttpListener _listener = new();
    readonly CancellationTokenSource _cts = new();
    Thread _thread;
    ProtocolConfig _cfg;

    public bool Running { get; private set; }
    public string LastError { get; private set; } = "";
    public ProtocolConfig Config => _cfg;
    public string BaseUrl => _cfg?.BaseUrl ?? "";

    public static ProtocolServer Current
    {
        get { lock (Gate) return _instance; }
    }

    public static ProtocolServer EnsureStarted()
    {
        lock (Gate)
        {
            var cfg = ProtocolConfig.EnsureToken(ProtocolConfig.Load());
            if (!cfg.Enabled)
            {
                _instance?.Stop();
                _instance = null;
                return null;
            }
            if (_instance != null && _instance.Running
                && _instance._cfg.Port == cfg.Port
                && _instance._cfg.Token == cfg.Token)
                return _instance;
            _instance?.Stop();
            _instance = new ProtocolServer();
            _instance.Start(cfg);
            return _instance.Running ? _instance : null;
        }
    }

    public static void StopCurrent()
    {
        lock (Gate)
        {
            _instance?.Stop();
            _instance = null;
        }
    }

    public static string StatusText()
    {
        var cfg = ProtocolConfig.Load();
        var cur = Current;
        if (cur != null && cur.Running)
            return $"协议服务运行中  {cur.BaseUrl}  （令牌已配置）";
        if (cfg.Enabled)
            return string.IsNullOrEmpty(cur?.LastError)
                ? $"协议服务已启用但未在听（端口 {cfg.Port}）"
                : $"协议服务启动失败：{cur.LastError}";
        return "协议服务未启用";
    }

    public void Start(ProtocolConfig cfg)
    {
        _cfg = cfg ?? ProtocolConfig.Load();
        LastError = "";
        try
        {
            _listener.Prefixes.Clear();
            // HttpListener 要求尾斜杠
            _listener.Prefixes.Add($"http://127.0.0.1:{_cfg.Port}/");
            _listener.Start();
            Running = true;
            _thread = new Thread(Loop) { IsBackground = true, Name = "jskp-protocol-server" };
            _thread.Start();
            Log.App($"协议服务已启动：{_cfg.BaseUrl}");
        }
        catch (Exception ex)
        {
            Running = false;
            LastError = ex.Message;
            Log.App("协议服务启动失败：" + ex.Message);
        }
    }

    public void Stop()
    {
        try { _cts.Cancel(); } catch { }
        try { if (_listener.IsListening) _listener.Stop(); } catch { }
        try { _listener.Close(); } catch { }
        Running = false;
            Log.App("协议服务已停止");
    }

    public void Dispose() => Stop();

    void Loop()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try { ctx = _listener.GetContext(); }
            catch when (_cts.IsCancellationRequested) { break; }
            catch { continue; }
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try { Handle(ctx); }
                catch (Exception ex)
                {
                    try { WriteJson(ctx.Response, 500, new JsonObject { ["ok"] = false, ["error"] = ex.Message }); }
                    catch { }
                }
            });
        }
    }

    void Handle(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var res = ctx.Response;
        res.Headers["Access-Control-Allow-Origin"] = "*";
        res.Headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
        res.Headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";

        if (req.HttpMethod == "OPTIONS")
        {
            res.StatusCode = 204;
            res.Close();
            return;
        }

        var path = (req.Url?.AbsolutePath ?? "/").TrimEnd('/').ToLowerInvariant();
        if (path.Length == 0) path = "/";

        if (path is "/" or "/health")
        {
            WriteJson(res, 200, new JsonObject
            {
                ["ok"] = true,
                ["service"] = "jskp-protocol",
                ["version"] = AppInfo.Version,
                ["app_id"] = AppInfo.GameAppId,
                ["game"] = AppInfo.GameTitle,
                ["endpoints"] = new JsonArray { "GET /token?ref=qb1", "GET /accounts", "GET /health" },
                ["note"] = "/token 跑抓包解密取业务 token（约 2 分钟、会冷启动该箱、需装 Wireshark）",
            });
            return;
        }

        if (!Authorize(req))
        {
            WriteJson(res, 401, new JsonObject { ["ok"] = false, ["error"] = "unauthorized" });
            return;
        }

        if (path == "/accounts" && req.HttpMethod == "GET")
        {
            WriteJson(res, 200, ListAccounts());
            return;
        }

        if (path is "/token" or "/wxapp/token")
        {
            HandleToken(req, res);
            return;
        }

        if (path is "/wxapp/getcode" or "/wx/getcode")
        {
            if (req.HttpMethod != "POST" && req.HttpMethod != "GET")
            {
                WriteJson(res, 405, new JsonObject { ["ok"] = false, ["error"] = "method not allowed" });
                return;
            }
            HandleGetCode(req, res);
            return;
        }

        WriteJson(res, 404, new JsonObject { ["ok"] = false, ["error"] = "not found", ["hint"] = "GET /token?ref=qb1（取业务 token，需装 Wireshark）" });
    }

    bool Authorize(HttpListenerRequest req)
    {
        if (string.IsNullOrEmpty(_cfg.Token)) return true;
        var auth = req.Headers["Authorization"] ?? "";
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            && string.Equals(auth["Bearer ".Length..].Trim(), _cfg.Token, StringComparison.Ordinal))
            return true;
        var q = req.QueryString["token"] ?? "";
        return string.Equals(q, _cfg.Token, StringComparison.Ordinal);
    }

    void HandleGetCode(HttpListenerRequest req, HttpListenerResponse res)
    {
        string body = "";
        if (req.HasEntityBody)
        {
            using var r = new StreamReader(req.InputStream, req.ContentEncoding ?? Encoding.UTF8);
            body = r.ReadToEnd();
        }
        JsonObject o = null;
        if (!string.IsNullOrWhiteSpace(body))
        {
            try { o = JsonNode.Parse(body) as JsonObject; } catch { }
        }
        o ??= new JsonObject();

        var reference = FirstNonEmpty(
            JsonFile.Str(o, "ref"), JsonFile.Str(o, "box"), JsonFile.Str(o, "account"),
            req.QueryString["ref"], req.QueryString["box"]);
        var appId = FirstNonEmpty(JsonFile.Str(o, "app_id"), JsonFile.Str(o, "appId"), req.QueryString["app_id"], AppInfo.GameAppId);
        bool ensure = JsonFile.Bool(o, "ensure_running")
                      ?? JsonFile.Bool(o, "ensureRunning")
                      ?? !string.Equals(req.QueryString["ensure_running"], "0", StringComparison.Ordinal);
        int timeout = JsonFile.Int(o, "timeout") ?? JsonFile.Int(o, "timeout_sec") ?? 45;

        if (reference.Length == 0)
        {
            WriteJson(res, 400, new JsonObject { ["ok"] = false, ["error"] = "缺少 ref（qbN / 数字 / uin）" });
            return;
        }

            Log.App($"协议 getCode  ref={reference}  app_id={appId}  ensure={ensure}");
        var result = WxLoginCode.Get(reference, appId, ensure, timeout);
        WriteJson(res, result.Ok ? 200 : 502, result.ToJson());
    }

    /// <summary>GET/POST /token?ref=qb1[&seconds=130]：跑抓包解密流程，返回业务 token（耗时约 2 分钟，会冷启动该箱）。</summary>
    void HandleToken(HttpListenerRequest req, HttpListenerResponse res)
    {
        string body = "";
        if (req.HasEntityBody)
        {
            using var r = new StreamReader(req.InputStream, req.ContentEncoding ?? Encoding.UTF8);
            body = r.ReadToEnd();
        }
        JsonObject o = null;
        if (!string.IsNullOrWhiteSpace(body)) try { o = JsonNode.Parse(body) as JsonObject; } catch { }
        o ??= new JsonObject();

        var reference = FirstNonEmpty(JsonFile.Str(o, "ref"), JsonFile.Str(o, "box"), req.QueryString["ref"], req.QueryString["box"]);
        if (reference.Length == 0)
        {
            WriteJson(res, 400, new JsonObject { ["ok"] = false, ["error"] = "缺少 ref（qbN / 数字 / uin）" });
            return;
        }
        var box = WxLoginCode.ResolveBox(reference);
        if (box.Length == 0)
        {
            WriteJson(res, 400, new JsonObject { ["ok"] = false, ["error"] = "找不到账号：" + reference });
            return;
        }

        var extra = new List<string>();
        var sec = FirstNonEmpty(JsonFile.Str(o, "seconds"), req.QueryString["seconds"]);
        if (sec.Length > 0) { extra.Add("--seconds"); extra.Add(sec); }

            Log.App($"协议 /token  ref={reference}  box={box}");
        var result = new TokenSession(box, extra) { Quiet = true }.Capture(out var error);
        if (result == null)
        {
            WriteJson(res, 502, new JsonObject { ["ok"] = false, ["box"] = box, ["error"] = error });
            return;
        }
        result["box"] = box;
        WriteJson(res, 200, result);
    }

    static JsonObject ListAccounts()
    {
        var arr = new JsonArray();
        foreach (var box in Sandboxie.QueryBoxes())
        {
            var live = Ilink.Live(box);
            var vault = Ilink.VaultState(box);
            var st = live.Valid ? live : vault;
            arr.Add(new JsonObject
            {
                ["box"] = box,
                ["ref"] = box,
                ["uin"] = st.Uin,
                ["username"] = st.Username,
                ["valid"] = st.Valid,
                ["need_scan"] = NeedScan.Pending(box),
                ["running"] = new BoxView(box).HasGameWindow,
                ["note"] = Notes.Load().GetValueOrDefault(box) ?? "",
            });
        }
        return new JsonObject { ["ok"] = true, ["app_id"] = AppInfo.GameAppId, ["accounts"] = arr };
    }

    static string FirstNonEmpty(params string[] xs)
    {
        foreach (var x in xs)
            if (!string.IsNullOrWhiteSpace(x)) return x.Trim();
        return "";
    }

    static void WriteJson(HttpListenerResponse res, int status, JsonNode node)
    {
        var bytes = Encoding.UTF8.GetBytes(node.ToJsonString(JsonFile.Pretty));
        res.StatusCode = status;
        res.ContentType = "application/json; charset=utf-8";
        res.ContentLength64 = bytes.Length;
        res.OutputStream.Write(bytes, 0, bytes.Length);
        res.Close();
    }
}
