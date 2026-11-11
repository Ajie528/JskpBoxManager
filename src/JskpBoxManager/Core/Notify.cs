using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 过期未续期提醒配置（notify.json）。
///
/// 支持的渠道都只要一个「推送地址 + 密钥」，不需要额外服务：
///   · pushplus   微信推送，https://www.pushplus.plus  →  token
///   · serverchan Server酱（微信），https://sct.ftqq.com → SendKey
///   · bark       iOS
///   · webhook    自定义 POST，body 带 title/content
/// </summary>
public sealed class NotifyConfig
{
    public bool Enabled;
    /// <summary>pushplus | serverchan | bark | webhook</summary>
    public string Channel = "pushplus";
    /// <summary>pushplus 的 token / Server酱的 SendKey / bark 的 key 或完整地址 / webhook 的完整 URL。</summary>
    public string Token = "";
    /// <summary>密钥超过多少小时没续期就提醒。默认 20。</summary>
    public double WarnHours = ProtocolRenew.KeyMaxAgeHours;
    /// <summary>同一个账号两次提醒之间至少隔多少小时，避免刷屏。默认 6。</summary>
    public double RepeatHours = 6;
    /// <summary>每 N 分钟主动连服务器探测一次凭证是否还有效。**会真实换 key**，所以有 30 分钟下限。</summary>
    public bool ProbeEnabled;
    public int ProbeMinutes = 120;

    /// <summary>
    /// 全局默认：密钥不到这么多小时就不做任何轮换（探测/预检都跳过），避免为「确认一下」白白滚掉一次额度。
    /// 单个沙箱可在主界面「轮换额度」里覆盖。0 = 用 <see cref="Keepalive.DefaultMinKeyAgeHours"/>。
    /// </summary>
    public double ProbeMinKeyAgeHours = 0;

    /// <summary>全局默认：每个号每天最多换几次 key。0 = 用 <see cref="CredentialProbe.MaxRotationsPerDay"/>。</summary>
    public int MaxRotationsPerDay = 0;

    public string Describe()
    {
        var name = Channel switch
        {
            "pushplus" => "PushPlus（微信）",
            "serverchan" => "Server酱（微信）",
            "bark" => "Bark（iOS）",
            "webhook" => "自定义 Webhook",
            _ => Channel,
        };
        return Token.Length == 0 ? $"{name}（未填密钥）" : name;
    }

    public static NotifyConfig Load()
    {
        var cfg = new NotifyConfig();
        var o = JsonFile.ReadObject(AppPaths.NotifyJson);
        if (o == null) return cfg;
        cfg.Enabled = JsonFile.Bool(o, "enabled") ?? false;
        var ch = JsonFile.Str(o, "channel");
        if (ch.Length > 0) cfg.Channel = ch;
        cfg.Token = JsonFile.Str(o, "token").Trim();
        cfg.WarnHours = JsonFile.Double(o, "warnHours") ?? ProtocolRenew.KeyMaxAgeHours;
        cfg.RepeatHours = JsonFile.Double(o, "repeatHours") ?? 6;
        cfg.ProbeEnabled = JsonFile.Bool(o, "probeEnabled") ?? false;
        cfg.ProbeMinutes = Math.Clamp(JsonFile.Int(o, "probeMinutes") ?? 120,
            CredentialProbe.MinProbeMinutes, 720);
        cfg.ProbeMinKeyAgeHours = Math.Clamp(JsonFile.Double(o, "probeMinKeyAgeHours") ?? 0, 0, 168);
        cfg.MaxRotationsPerDay = Math.Clamp(JsonFile.Int(o, "maxRotationsPerDay") ?? 0, 0, 50);
        if (cfg.WarnHours < 1) cfg.WarnHours = 1;
        if (cfg.RepeatHours < 1) cfg.RepeatHours = 1;
        return cfg;
    }

    public static void Save(NotifyConfig cfg)
    {
        JsonFile.WriteObject(AppPaths.NotifyJson, new JsonObject
        {
            ["enabled"] = cfg.Enabled,
            ["channel"] = cfg.Channel,
            ["token"] = cfg.Token ?? "",
            ["warnHours"] = cfg.WarnHours,
            ["repeatHours"] = cfg.RepeatHours,
            ["probeEnabled"] = cfg.ProbeEnabled,
            ["probeMinutes"] = cfg.ProbeMinutes,
            ["probeMinKeyAgeHours"] = cfg.ProbeMinKeyAgeHours,
            ["maxRotationsPerDay"] = cfg.MaxRotationsPerDay,
        });
    }

    public bool Ready => Enabled && Token.Trim().Length > 0;

    /// <summary>界面展示用：实际生效的每号每日轮换上限。</summary>
    public int EffectiveMaxRotations => MaxRotationsPerDay > 0 ? MaxRotationsPerDay : CredentialProbe.MaxRotationsPerDay;

    /// <summary>界面展示用：实际生效的「密钥不到多少小时不轮换」。</summary>
    public double EffectiveMinKeyAgeHours => ProbeMinKeyAgeHours > 0 ? ProbeMinKeyAgeHours : Keepalive.DefaultMinKeyAgeHours;
}

/// <summary>
/// 过期未续期提醒。
///
/// 检查所有沙箱的凭证年龄（取 live 与金库中较新的那把），超过阈值就推一条微信。
/// 同一账号在 RepeatHours 内只提醒一次；恢复续期后自动清除记录。
///
/// 状态文件 logs\notify-state.json：{ "qb1": { "lastAt": "...", "keySha": "...", "ageHours": 23.5 } }
/// </summary>
public static class Notifier
{
    static readonly object Gate = new();

    static string StatePath => Path.Combine(AppPaths.Logs, "notify-state.json");

    sealed class Entry
    {
        public DateTime LastAt = DateTime.MinValue;
        public string KeySha = "";
        public double AgeHours;
    }

    static Dictionary<string, Entry> LoadState()
    {
        var d = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        var o = JsonFile.ReadObject(StatePath);
        if (o == null) return d;
        foreach (var kv in o)
        {
            if (kv.Value is not JsonObject e) continue;
            var at = JsonFile.Str(e, "lastAt");
            d[kv.Key] = new Entry
            {
                LastAt = DateTime.TryParse(at, out var t) ? t : DateTime.MinValue,
                KeySha = JsonFile.Str(e, "keySha"),
                AgeHours = JsonFile.Double(e, "ageHours") ?? 0,
            };
        }
        return d;
    }

    static void SaveState(Dictionary<string, Entry> d)
    {
        var o = new JsonObject();
        foreach (var kv in d.OrderBy(x => Sandboxie.BoxNumber(x.Key)))
        {
            o[kv.Key] = new JsonObject
            {
                ["lastAt"] = kv.Value.LastAt == DateTime.MinValue ? "" : kv.Value.LastAt.ToString("yyyy-MM-dd HH:mm:ss"),
                ["keySha"] = kv.Value.KeySha,
                ["ageHours"] = Math.Round(kv.Value.AgeHours, 1),
            };
        }
        try { JsonFile.WriteObject(StatePath, o); } catch { }
    }

    /// <summary>
    /// 检查一遍所有沙箱，把超期未续期的推给用户。
    /// 返回本次实际发出的提醒条数（0 表示没有需要提醒的）。
    /// </summary>
    /// <summary>检查结果：超期账号名单 + 是否真的发出去了。</summary>
    public sealed record CheckResult(int Overdue, int Sent, string Error)
    {
        public bool Failed => Error != null;
    }

    /// <summary>
    /// 检查一遍所有沙箱，把超期未续期的推给用户。
    /// 返回超期数量与实际发出数量（区分「没有超期」和「推送失败」）。
    /// </summary>
    public static CheckResult Check(IEnumerable<string> boxes, NotifyConfig cfg = null)
    {
        cfg ??= NotifyConfig.Load();
        if (!cfg.Ready) return new CheckResult(0, 0, "通知未启用或没填推送密钥");
        lock (Gate)
        {
            int sent = 0;
            var state = LoadState();
            var overdue = new List<(string Box, string Note, string Uin, double Age, string KeySha, string Phase)>();

            foreach (var box in boxes)
            {
                IlinkState live = null, vault = null;
                try
                {
                    live = Ilink.Live(box);
                    vault = Ilink.VaultState(box);
                }
                catch { continue; }
                var best = live is { Valid: true } && (vault == null || !vault.Valid || live.WriteUtc >= vault.WriteUtc)
                    ? live
                    : vault;
                if (best == null || !best.Valid || best.WriteUtc == DateTime.MinValue)
                {
                    // 没有有效凭证：不需要提醒（要么没登录，要么早就标了需要扫码）
                    if (state.Remove(box)) { }
                    continue;
                }

                double age = (DateTime.UtcNow - best.WriteUtc).TotalHours;
                if (age < cfg.WarnHours)
                {
                    // 已经续上了，清掉提醒记录，下次超期能立刻再提醒
                    state.Remove(box);
                    continue;
                }

                // 同一把 key 且距上次提醒还没到 RepeatHours：跳过
                if (state.TryGetValue(box, out var prev)
                    && prev.KeySha == best.KeyHash
                    && (DateTime.Now - prev.LastAt).TotalHours < cfg.RepeatHours)
                    continue;

                var note = Notes.Load().GetValueOrDefault(box, "");
                var phase = BoxStatusFile.Read(box)?.Phase;
                overdue.Add((box, note, best.Uin, age, best.KeyHash, phase == BoxPhase.InGame ? "游戏中"
                    : phase == BoxPhase.Resident ? "常驻" : "已停止"));
            }

            if (overdue.Count == 0) return new CheckResult(0, 0, null);

            var title = $"向僵管家：{overdue.Count} 个账号超过 {cfg.WarnHours:0.#} 小时没有续期";
            var sb = new StringBuilder();
            sb.AppendLine($"以下账号的免扫凭证已超过 {cfg.WarnHours:0.#} 小时没有换新，有掉线/弹码风险：");
            sb.AppendLine();
            foreach (var x in overdue.OrderByDescending(o => o.Age))
            {
                var who = x.Note.Length > 0 ? $"{x.Box}（{x.Note}）" : x.Box;
                sb.AppendLine($"· {who}：{x.Age:F1} 小时，{x.Phase}");
            }
            sb.AppendLine();
            sb.AppendLine("请打开管家确认：如果是游戏一直开着，关掉游戏就会自动续期；");
            sb.AppendLine("如果已停箱，可以直接点「⚡ 纯协议续期」。");
            var content = sb.ToString();

            var err = Send(cfg, title, content);
            if (err != null)
            {
                Log.App("推送失败：" + err);
                return new CheckResult(overdue.Count, 0, err);
            }

            var now = DateTime.Now;
            foreach (var x in overdue)
                state[x.Box] = new Entry { LastAt = now, KeySha = x.KeySha, AgeHours = x.Age };
            SaveState(state);
            sent = overdue.Count;

            Log.App($"过期提醒：已通过 {cfg.Channel} 推送 {sent} 条");
            foreach (var x in overdue)
                Log.Box(x.Box, $"过期提醒：凭证已 {x.Age:F1} 小时未续期 → 已通过 {cfg.Channel} 推送");
            try
            {
                Ilink.WriteEvent("app", "notify-overdue", new JsonObject
                {
                    ["count"] = sent,
                    ["channel"] = cfg.Channel,
                    ["boxes"] = string.Join(",", overdue.Select(o => o.Box)),
                });
            }
            catch { }
            return new CheckResult(overdue.Count, sent, null);
        }
    }

    /// <summary>兼容旧调用：只关心「有没有发出去」，失败也算 0。</summary>
    public static int CheckAndNotify(IEnumerable<string> boxes, NotifyConfig cfg = null)
        => Check(boxes, cfg).Sent;

    /// <summary>发一条测试消息，返回错误文字（成功返回 null）。</summary>
    public static string SendTest(NotifyConfig cfg)
    {
        if (cfg == null || cfg.Token.Trim().Length == 0) return "还没填推送密钥";
        return Send(cfg, "向僵管家：测试通知", $"如果你看到这条，说明通知已配置好。\n\n发送时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
    }

    static string Send(NotifyConfig cfg, string title, string content)
    {
        try
        {
            var (url, body) = BuildRequest(cfg, title, content);
            if (url.Length == 0) return "推送地址为空";
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            if (body.StartsWith('{'))
                req.Content = new StringContent(body, Encoding.UTF8, "application/json");
            else
                req.Content = new FormUrlEncodedContent(ParseForm(body));
            using var resp = http.Send(req);
            var text = "";
            try { text = new StreamReader(resp.Content.ReadAsStream()).ReadToEnd(); } catch { }
            if (!resp.IsSuccessStatusCode)
                return $"HTTP {(int)resp.StatusCode} {text.Trim()}";

            // PushPlus / Server酱 用 code 字段表示业务错误（Bark 不返回 code）
            if (JsonNode.Parse(text) is JsonObject o && JsonFile.Int(o, "code") is int code && code != 0 && code != 200)
            {
                var msg = JsonFile.Str(o, "msg");
                if (msg.Length == 0) msg = JsonFile.Str(o, "message");
                return $"推送被拒绝 code={code}" + (msg.Length > 0 ? "：" + msg : "");
            }
            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    static IEnumerable<KeyValuePair<string, string>> ParseForm(string body)
    {
        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int i = pair.IndexOf('=');
            if (i <= 0) continue;
            yield return new KeyValuePair<string, string>(
                Uri.UnescapeDataString(pair[..i]), Uri.UnescapeDataString(pair[(i + 1)..]));
        }
    }

    static (string Url, string Body) BuildRequest(NotifyConfig cfg, string title, string content)
    {
        var token = (cfg.Token ?? "").Trim();
        switch ((cfg.Channel ?? "").ToLowerInvariant())
        {
            case "pushplus":
                return ("https://www.pushplus.plus/send", new JsonObject
                {
                    ["token"] = token,
                    ["title"] = title,
                    ["content"] = content,
                    ["template"] = "html",
                }.ToJsonString(JsonFile.Compact));

            case "serverchan":
            {
                // SendKey 形如 SCT123456T...；也支持完整 URL
                var url = token.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? token
                    : $"https://sctapi.ftqq.com/{token}.send";
                return (url, FormBody(("title", title), ("desp", content)));
            }

            case "bark":
            {
                var url = token.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? token
                    : $"https://api.day.app/{token}";
                return (url.TrimEnd('/'), new JsonObject
                {
                    ["title"] = title,
                    ["body"] = content,
                    ["group"] = "向僵管家",
                }.ToJsonString(JsonFile.Compact));
            }

            case "webhook":
                return (token, new JsonObject
                {
                    ["title"] = title,
                    ["content"] = content,
                    ["text"] = title + "\n" + content,
                }.ToJsonString(JsonFile.Compact));

            default:
                return ("", "");
        }
    }

    static string FormBody(params (string Key, string Value)[] pairs)
        => string.Join("&", pairs.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value ?? "")}"));
}
