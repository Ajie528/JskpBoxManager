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

    /// <summary>
    /// 从日志里追出的「真实扫码时间」。key-rotated 事件带 prevAt（上一把密钥写入时间），
    /// 一路向前回溯就能摸到扫码那次之前的最后一把密钥，比「日志里第一条记录」精确得多。
    /// </summary>
    static DateTime? TraceScanStart(string box, string uin, DateTime fallback)
    {
        // 把所有本机事件读成 (事件, uin, writtenAt, prevAt) 序列
        var evs = new List<(string ev, string uin, DateTime? written, DateTime? prev)>();
        foreach (var line in Log.Tail(AppPaths.EventLog, 40000))
        {
            JsonObject o;
            try { o = JsonNode.Parse(line) as JsonObject; } catch { continue; }
            if (o == null) continue;
            if (JsonFile.Str(o, "pc") is var pc && pc.Length > 0 && pc != Environment.MachineName) continue;
            if (JsonFile.Str(o, "box") != box) continue;
            evs.Add((JsonFile.Str(o, "event"), JsonFile.Str(o, "uin"), Time(o, "writtenAt"), Time(o, "prevAt")));
        }
        if (evs.Count == 0) return null;

        // 从最后一次扫码/换身份事件往前找：它的 prevAt 就是「扫码前最后一把密钥」的写入时间
        for (int i = evs.Count - 1; i >= 0; i--)
            if (evs[i].ev is "scan-login" or "new-identity" && evs[i].written is not null)
                return evs[i].written;

        // 没有扫码事件（日志滚掉了）：沿 key-rotated 的 prevAt 链一路往前，取最早的那个 prevAt
        DateTime? oldest = null;
        foreach (var e in evs)
        {
            if (e.ev != "key-rotated") continue;
            if (e.uin.Length > 0 && uin.Length > 0 && e.uin != uin) continue;   // 换过号的旧链不算
            if (e.prev is DateTime p && (oldest == null || p < oldest)) oldest = p;
        }
        if (oldest != null) return oldest;
        return evs[0].written is DateTime w && w < fallback ? w : null;
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

        // 第二轮：对「起点不是确知扫码」的链，用 prevAt 回溯 + 旧版日志里的扫码标记补准。
        foreach (var box in d.Keys.ToList())
        {
            var c = d[box];
            if (c.StartKnown) continue;
            var traced = TraceScanStart(box, c.Uin, c.Start);
            var legacy = LegacyScanMark(box);
            // 两个来源都只提供「不晚于」的信息时，取更早的那个（免扫寿命只会被低估，不会虚高）
            var earliest = (traced, legacy) switch
            {
                (DateTime a, DateTime b) => a < b ? a : b,
                (DateTime a, null) => a,
                (null, DateTime b) => b,
                _ => (DateTime?)null,
            };
            if (earliest is DateTime e && e < c.Start)
                d[box] = c with { Start = e, StartKnown = ScanBaseline.IsConfirmed(box) };
        }
        return d;
    }

    /// <summary>
    /// 旧版（PowerShell）程序留下的扫码标记，形如
    /// <c>10:01:37 [qb3] QR page gone (scanned) -&gt; reopen GameUrl ...</c>。
    /// 只有时分秒没有日期，按「最近一次早于当前时间」推断日期。
    /// </summary>
    static DateTime? LegacyScanMark(string box)
    {
        var legacyLogs = new[]
        {
            @"C:\application\jskp-sandbox\logs",
            Path.Combine(AppPaths.AppDir, "logs"),
        };
        DateTime? best = null;
        foreach (var dir in legacyLogs.Distinct())
        {
            var f = Path.Combine(dir, box + ".log");
            if (!File.Exists(f)) continue;
            try
            {
                var info = new FileInfo(f);
                // 只扫最后 200k 行，旧日志可能有几十 MB
                foreach (var line in File.ReadLines(f).TakeLast(4000))
                {
                    int i = line.IndexOf("QR page gone (scanned)", StringComparison.OrdinalIgnoreCase);
                    if (i < 0) continue;
                    var stamp = line[..Math.Min(i, 12)].Trim();
                    if (!TimeSpan.TryParse(stamp, out var tod)) continue;
                    // 推断日期：取日志文件的修改日，时刻晚于文件时刻就往前退一天
                    var day = info.LastWriteTime.Date;
                    var dt = day + tod;
                    if (dt > info.LastWriteTime) dt = dt.AddDays(-1);
                    if (best == null || dt > best) best = dt;
                }
            }
            catch { }
        }
        return best;
    }

    public static AuthChain For(string box) => Load().GetValueOrDefault(box);

    static DateTime? Time(JsonObject o, string key) =>
        DateTime.TryParseExact(JsonFile.Str(o, key), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var t) ? t : null;
}
