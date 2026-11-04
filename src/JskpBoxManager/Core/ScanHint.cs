namespace JskpBoxManager.Core;

/// <summary>
/// 授权方式的证据（只记时间戳，不记密钥）：区分这次换新钥匙是「扫码登录」还是「免扫自动授权」。
///
/// 为什么需要它：以前靠「need-scan 文件是否存在」判断是不是扫码登录，结果把
/// 「加载期过早弹出的授权页 + 之后 AutoAuth 成功」误记成扫码（qb15 11-04 12:08 就是这样：
/// 用户只是关掉了扫码框，根本没扫，程序却记了一条 scan-login），
/// 免扫链寿命（自扫码起已免扫 N 天）因此被不断重置、统计失真。
///
/// 判据：
///   manual   —— 抓到 ManualAuth（手机扫码才走的一次性接口），扫码的铁证；
///   qr-scan  —— 程序真的进入了「等用户扫码」状态（授权页不会自己走、也没有金库可用时才进）；
///   overlay  —— 只是加载期过早弹出的授权层，程序关掉它让运行时自动授权，不算扫码；
///   autoauth —— 服务端对 AutoAuth 返回 ret=0，免扫授权成功。
///
/// 因此「扫码」= manual 或 qr-scan，overlay 不参与判定。
/// </summary>
public static class ScanHint
{
    const string Manual = "manual", QrScan = "qr-scan", Overlay = "overlay", AutoOk = "autoauth-ok";

    static string FileOf(string box) => Path.Combine(BoxPaths.CredentialDir(box), "auth-evidence.txt");

    /// <summary>抓到 ManualAuth：手机扫码登录。</summary>
    public static void MarkManualAuth(string box) => Mark(box, Manual);

    /// <summary>程序判定「必须人工扫码」，进入等扫码状态。</summary>
    public static void MarkQrScan(string box) => Mark(box, QrScan);

    /// <summary>加载期过早弹出的授权层（程序会自己关掉并重开 GameUrl），不算扫码。</summary>
    public static void MarkOverlay(string box) => Mark(box, Overlay);

    /// <summary>服务端对 AutoAuth 返回成功（免扫授权）。</summary>
    public static void MarkAutoAuthOk(string box) => Mark(box, AutoOk);

    static void Mark(string box, string kind)
    {
        try
        {
            Directory.CreateDirectory(BoxPaths.CredentialDir(box));
            File.AppendAllText(FileOf(box), $"{kind} {DateTime.UtcNow.Ticks}\r\n");
            Compress(box);
        }
        catch { }
    }

    /// <summary>证据只看最近的，文件不会无限长。</summary>
    static void Compress(string box)
    {
        try
        {
            var p = FileOf(box);
            var lines = File.ReadAllLines(p);
            if (lines.Length <= 200) return;
            File.WriteAllLines(p, lines.Skip(lines.Length - 120));
        }
        catch { }
    }

    static bool Since(string box, string kind, DateTime? after)
    {
        try
        {
            if (!File.Exists(FileOf(box))) return false;
            long floor = after?.Ticks ?? 0;
            foreach (var line in File.ReadAllLines(FileOf(box)))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2 || parts[0] != kind) continue;
                if (!long.TryParse(parts[1], out var ticks)) continue;
                if (ticks > floor) return true;
            }
        }
        catch { }
        return false;
    }

    public static bool ManualSince(string box, DateTime? after) => Since(box, Manual, after);
    public static bool QrScanSince(string box, DateTime? after) => Since(box, QrScan, after);
    public static bool OverlaySince(string box, DateTime? after) => Since(box, Overlay, after);
    public static bool AutoAuthOkSince(string box, DateTime? after) => Since(box, AutoOk, after);

    /// <summary>这段时间之后是否有过真正的扫码登录（manual 或 qr-scan）。</summary>
    public static bool ScannedSince(string box, DateTime? after) =>
        ManualSince(box, after) || QrScanSince(box, after);

    /// <summary>清掉证据（重新扫码、清登录、换号时用）。</summary>
    public static void Clear(string box)
    {
        try { File.Delete(FileOf(box)); } catch { }
    }

    /// <summary>
    /// 只清掉「扫码」类证据（manual / qr-scan），保留 overlay / autoauth。
    /// 用于「免扫重试」「试历史 key」这类明确要重新赌一次免扫的操作：否则旧的扫码记录会让
    /// 下一次换新钥匙被继续算成扫码登录，免扫链寿命一直起不来。
    /// </summary>
    public static void ClearQrScanMarks(string box)
    {
        try
        {
            var p = FileOf(box);
            if (!File.Exists(p)) return;
            var keep = File.ReadAllLines(p)
                .Where(l => !l.StartsWith(Manual + " ", StringComparison.Ordinal) && !l.StartsWith(QrScan + " ", StringComparison.Ordinal))
                .ToArray();
            File.WriteAllLines(p, keep);
        }
        catch { }
    }
}
