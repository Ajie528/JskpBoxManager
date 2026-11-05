using System.Globalization;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 扫码时间基准：每个沙箱「最后一次真实扫码（授权）是什么时候」。
///
/// 为什么要单独存文件：授权窗口是 30 天，而事件日志只保留最近若干条，
/// 一个不常动的号过几天日志就滚掉了，之后再也算不出它扫了多久。
/// 所以第一次确认到扫码时刻就落盘（logs\qbN.scan.json），以后一直用它。
///
/// 可信度分三档：
///   <see cref="SourceQrScan"/>  「QR page gone (scanned)」这类硬证据
///   <see cref="SourceManual"/>   ManualAuth 事件（扫码登录时运行时自己发的）
///   <see cref="SourceTrace"/>   从 key-rotated 的 prevAt 链回溯出来的（下限，可能更早）
/// </summary>
public static class ScanBaseline
{
    public const string SourceQrScan = "qr-scan";
    public const string SourceManual = "manual";
    public const string SourceTrace = "trace";
    public const string SourceBackfill = "backfill";

    static string FileOf(string box) => Path.Combine(AppPaths.Logs, box + ".scan.json");

    /// <summary>确知的扫码时间（qr-scan / manual / 用户手动补录）；回溯值不算。</summary>
    public static bool IsConfirmed(string box) => Load(box)?.Confirmed == true;

    public sealed class Entry
    {
        public DateTime AtUtc;
        public string Uin = "";
        public string Source = "";
        public bool Confirmed => Source is SourceQrScan or SourceManual or SourceBackfill;
    }

    public static Entry Load(string box)
    {
        var o = JsonFile.ReadObject(FileOf(box));
        if (o == null) return null;
        if (!DateTime.TryParseExact(JsonFile.Str(o, "at"), "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var at)) return null;
        return new Entry { AtUtc = at.ToUniversalTime(), Uin = JsonFile.Str(o, "uin"), Source = JsonFile.Str(o, "source") };
    }

    /// <summary>
    /// 记一条基准。<paramref name="overwrite"/> 为 false 时只在不比现有的更新时跳过，
    /// 保证「已有确知值」不会被后到的回溯值覆盖成更晚的时间。
    /// </summary>
    public static void Save(string box, DateTime localAt, string uin, string source, bool overwrite = false)
    {
        var cur = Load(box);
        if (cur != null && !overwrite)
        {
            // 已有确知值就不动；现有值更早也不动（宁可少算，不虚报免扫时长）
            if (cur.Confirmed) return;
            if (cur.AtUtc <= localAt.ToUniversalTime() && !IsConfirmedSource(source)) return;
        }
        Directory.CreateDirectory(AppPaths.Logs);
        JsonFile.WriteObject(FileOf(box), new JsonObject
        {
            ["at"] = localAt.ToString("yyyy-MM-dd HH:mm:ss"),
            ["uin"] = uin,
            ["source"] = source,
            ["savedAt"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
        });
    }

    static bool IsConfirmedSource(string s) => s is SourceQrScan or SourceManual or SourceBackfill;

    /// <summary>删除基准（换号扫描、清登录、删沙箱时调用）。</summary>
    public static void Clear(string box)
    {
        try { File.Delete(FileOf(box)); } catch { }
    }

    /// <summary>
    /// 从现有证据里补齐所有沙箱的基准。返回补了多少个。
    /// 证据优先级：已有基准 &gt; 事件日志里的 scan-login &gt; 旧版日志的 scanned 标记 &gt; prevAt 回溯。
    /// </summary>
    public static int BackfillAll(IEnumerable<string> boxes, Dictionary<string, AuthChain> chains)
    {
        int n = 0;
        foreach (var box in boxes)
        {
            var ev = Load(box);
            if (ev?.Confirmed == true) continue;
            if (!chains.TryGetValue(box, out var chain)) continue;
            var src = chain.StartKnown ? SourceQrScan : SourceTrace;
            Save(box, chain.Start, chain.Uin, src);
            if (src != SourceTrace) n++;
        }
        return n;
    }
}
