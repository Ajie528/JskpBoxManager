using System.Globalization;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 历史凭证的「被拒冷却」。
///
/// <para>
/// 免扫失效时程序会把金库 + 最多 30 份历史快照逐把发 AutoAuth 确认（每把约 0.1 秒）。
/// 这套机制能救回不少号，但有个代价：**每把都是真请求**。qb4 在 2026-11-10 的
/// 04:15 和 08:42 把同样 16 把全试了一遍，一天内白打 32 次 AutoAuth——而这个号之所以被判异常，
/// 恰恰就是被这类高频请求喂出来的。
/// </para>
///
/// <para>
/// 但也**不能**登记成永久作废。<see cref="RecoverSession"/> 的实测反例：
/// qb4 的 <c>c21a5cc3</c> 在 11-07 15:27 探测是 -13，11-09 10:38 再用它时
/// 服务端却接受了（并换出 a4d97938）。所以 -13 对历史 key 只是「此刻不认」，
/// 不是「永远不认」。
/// </para>
///
/// <para>
/// 折中：被拒的 key 进冷却期（默认 6 小时），期间不再重试；过期后自动重新参与。
/// 冷却状态存在 <c>profiles\qbN\credential\history-cooldown.json</c>，只记哈希。
/// </para>
/// </summary>
public static class HistoryCooldown
{
    /// <summary>被拒一次后安静多久（小时）。参照保活失败退避的上限，不宜太短。</summary>
    public const double DefaultHours = 6;

    static string Path_Of(string box) => Path.Combine(BoxPaths.CredentialDir(box), "history-cooldown.json");

    /// <summary>记一次拒绝。</summary>
    public static void Mark(string box, string keyHash, long code, double hours = DefaultHours)
    {
        if (string.IsNullOrWhiteSpace(keyHash)) return;
        try
        {
            var o = Load(box);
            o[keyHash] = new JsonObject
            {
                ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ["code"] = code,
                ["hours"] = hours,
            };
            Prune(o);
            JsonFile.WriteObject(Path_Of(box), o);
        }
        catch (Exception ex) { Log.Box(box, "历史凭证冷却：记录失败 " + ex.Message); }
    }

    /// <summary>这把 key 现在能不能试（不在冷却期就返回 true）。</summary>
    public static bool Allowed(string box, string keyHash)
    {
        if (string.IsNullOrWhiteSpace(keyHash)) return true;
        try
        {
            var o = Load(box);
            if (o[keyHash] is not JsonObject e) return true;
            var at = JsonFile.Str(e, "at");
            double hours = JsonFile.Double(e, "hours") ?? DefaultHours;
            if (!DateTime.TryParseExact(at, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal, out var t)) return true;
            return (DateTime.Now - t).TotalHours >= hours;
        }
        catch { return true; }
    }

    /// <summary>这把 key 若在冷却期，还剩多少小时；不在冷却期返回 null。</summary>
    public static double? RemainingHours(string box, string keyHash)
    {
        if (string.IsNullOrWhiteSpace(keyHash)) return null;
        try
        {
            var o = Load(box);
            if (o[keyHash] is not JsonObject e) return null;
            if (!DateTime.TryParseExact(JsonFile.Str(e, "at"), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal, out var t)) return null;
            double hours = JsonFile.Double(e, "hours") ?? DefaultHours;
            double left = hours - (DateTime.Now - t).TotalHours;
            return left > 0 ? left : null;
        }
        catch { return null; }
    }

    /// <summary>成功用上这把 key：清掉它的冷却记录。</summary>
    public static void Clear(string box, string keyHash)
    {
        try
        {
            var o = Load(box);
            if (o.Remove(keyHash)) JsonFile.WriteObject(Path_Of(box), o);
        }
        catch { }
    }

    public static void ClearAll(string box)
    {
        try { File.Delete(Path_Of(box)); } catch { }
    }

    /// <summary>冷却中的 key 数（界面/日志用）。</summary>
    public static int Count(string box)
    {
        try
        {
            var o = Load(box);
            Prune(o);
            return o.Count;
        }
        catch { return 0; }
    }

    static JsonObject Load(string box) => JsonFile.ReadObject(Path_Of(box)) ?? new JsonObject();

    /// <summary>丢掉早已过期的条目，避免文件无限增长（保留 7 天）。</summary>
    static void Prune(JsonObject o)
    {
        var cut = DateTime.Now.AddDays(-7);
        foreach (var key in o.Select(kv => kv.Key).ToList())
        {
            if (o[key] is not JsonObject e) { o.Remove(key); continue; }
            if (!DateTime.TryParseExact(JsonFile.Str(e, "at"), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal, out var t) || t < cut)
                o.Remove(key);
        }
    }
}
