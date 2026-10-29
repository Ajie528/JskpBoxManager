using System.Globalization;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 免扫链：一次扫码之后，每次免扫自动授权换新密钥都接在同一条链上，直到被顶掉 / 过期要求重新扫码。
/// 从事件日志（只看本机）推出来，用来判断服务端有没有「最长寿命」。
/// </summary>
public sealed record AuthChain(string Uin, DateTime Start, bool StartKnown, int Renewals, DateTime LastRenew)
{
    public double Days => (DateTime.Now - Start).TotalDays;

    public string Text
    {
        get
        {
            var span = DateTime.Now - Start;
            var len = span.TotalDays >= 1 ? $"{(int)span.TotalDays} 天 {span.Hours} 小时" : $"{Math.Max(0, (int)span.TotalHours)} 小时";
            var from = StartKnown ? $"自 {Start:MM-dd HH:mm} 扫码起" : $"自 {Start:MM-dd HH:mm}（更早的没有记录）起";
            return $"{from}已免扫 {len}，免扫换新 {Renewals} 次" + (Renewals > 0 ? $"（最近 {LastRenew:MM-dd HH:mm}）" : "");
        }
    }

    /// <summary>每个沙箱当前这条链；被顶掉 / 要求扫码后没有新链的沙箱不在结果里。</summary>
    public static Dictionary<string, AuthChain> Load()
    {
        var d = new Dictionary<string, AuthChain>();
        foreach (var line in Log.Tail(AppPaths.EventLog, 20000))
        {
            JsonObject o;
            try { o = JsonNode.Parse(line) as JsonObject; } catch { continue; }
            if (o == null) continue;
            if (JsonFile.Str(o, "pc") is var pc && pc.Length > 0 && pc != Environment.MachineName) continue;
            var box = JsonFile.Str(o, "box");
            var uin = JsonFile.Str(o, "uin");
            switch (JsonFile.Str(o, "event"))
            {
                case "scan-login":
                case "new-identity":
                    if (Time(o, "writtenAt") is DateTime t0) d[box] = new AuthChain(uin, t0, true, 0, t0);
                    break;
                case "key-rotated":
                    if (Time(o, "writtenAt") is not DateTime t) break;
                    if (d.TryGetValue(box, out var c) && c.Uin == uin) d[box] = c with { Renewals = c.Renewals + 1, LastRenew = t };
                    else d[box] = new AuthChain(uin, Time(o, "prevAt") ?? t, false, 1, t);
                    break;
                case "key-revoked":
                    d.Remove(box);
                    break;
            }
        }
        return d;
    }

    public static AuthChain For(string box) => Load().GetValueOrDefault(box);

    static DateTime? Time(JsonObject o, string key) =>
        DateTime.TryParseExact(JsonFile.Str(o, key), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var t) ? t : null;
}
