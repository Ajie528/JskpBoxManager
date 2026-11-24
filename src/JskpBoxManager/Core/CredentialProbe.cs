using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 每日换 key 计数（防把整条授权链滚废）。
///
/// <para>
/// ★ 1.5.63 起本类**不再包含主动探测功能**。
/// 原来这里有一套「每 N 分钟连服务器发 AutoAuth 确认凭证是否有效」的定时调度
/// （Start/Stop/Loop/Probe/Schedule），1.5.63 已整体删除，原因见
/// <c>docs\免扫寿命实测-20261124.md</c>：
///   · AutoAuthKey 实测没有寿命上限（宿主机账号放 97 天零活动仍 `code=0`，
///     qb3 等号 19 天前的旧 key 同样有效），所以「为了确认而换钥」没有收益；
///   · AutoAuth 是轮换语义，探一次就真换一把 key，探得越勤额度烧得越凶；
///   · 额度异常本身就是风控特征：qb4 在 2026-11-22 单日重开 513 次后被 -13 永久废号，
///     连它 10 天前的老 key 一并失效（响应头 uin 返回 0）。
/// </para>
/// <para>
/// 保留下来的只有「记账」这部分：所有换 key 的路径（协议续期、冷启动、手动开游戏、
/// 历史凭证恢复）都会调用 <see cref="RecordRotationPublic"/> 记一行，
/// 保活任务据此判断今天是否已经换够，避免把授权链滚废。
/// </para>
/// </summary>
public static class CredentialProbe
{
    /// <summary>单个号每天最多换几次 key。超过就跳过，等明天。可在界面按沙箱覆盖。</summary>
    public const int MaxRotationsPerDay = 8;

    static string RotateLogPath(string box) => Path.Combine(AppPaths.Logs, box + ".rotate-log");

    /// <summary>今天已经换过几次 key（按 key 哈希去重，同一把重复保存只算一次）。</summary>
    public static int RotationsToday(string box)
    {
        try
        {
            var p = RotateLogPath(box);
            if (!File.Exists(p)) return 0;
            var today = DateTime.Today.ToString("yyyy-MM-dd") + " ";
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadLines(p))
            {
                if (!line.StartsWith(today, StringComparison.Ordinal)) continue;
                // 行格式：「yyyy-MM-dd HH:mm:ss <keySha> <why>」
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 3) seen.Add(parts[2]);
                else seen.Add(line);
            }
            return seen.Count;
        }
        catch { return 0; }
    }

    /// <summary>今天最后一次换 key 的时间；没有记录返回 null。用于「密钥太新就别再滚」的判断。</summary>
    public static DateTime? LastRotationAt(string box)
    {
        try
        {
            var p = RotateLogPath(box);
            if (!File.Exists(p)) return null;
            foreach (var line in File.ReadLines(p).Reverse())
            {
                if (line.Length < 19) continue;
                if (DateTime.TryParseExact(line[..19], "yyyy-MM-dd HH:mm:ss",
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeLocal, out var t))
                    return t;
            }
        }
        catch { }
        return null;
    }

    static void RecordRotation(string box, string newKey, string why)
    {
        try
        {
            // 同一把 key 不重复记账：Ilink.Save 会在每次保活/看门循环里被调用，
            // 若不去重，一次轮换会被记几十次，「每日上限」立刻被虚假耗尽。
            if (newKey.Length > 0)
            {
                var p0 = RotateLogPath(box);
                var todayPrefix = DateTime.Today.ToString("yyyy-MM-dd") + " ";
                if (File.Exists(p0))
                    foreach (var line in File.ReadLines(p0))
                        if (line.StartsWith(todayPrefix, StringComparison.Ordinal)
                            && line.Contains(" " + newKey + " ", StringComparison.OrdinalIgnoreCase))
                            return;
            }
            Directory.CreateDirectory(AppPaths.Logs);
            File.AppendAllText(RotateLogPath(box),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {newKey} {why}\r\n", new UTF8Encoding(false));
        }
        catch { }
    }

    /// <summary>
    /// 保活等其它路径换 key 后也要记账，否则「每日上限」统计不到。
    /// <para>
    /// 这是 v1.5.37 补的：以前只有 <see cref="ProtocolRenew"/> 那条协议路径记账，
    /// 冷启动和手动开游戏滚出来的新 key 只写 <c>key-rotated</c> 事件，不进 rotate-log，
    /// 于是「今天已换 8 次」这条风控判据对最常见的轮换方式完全失效。
    /// </para>
    /// </summary>
    public static void RecordRotationPublic(string box, string newKey, string why) => RecordRotation(box, newKey, why);

    /// <summary>今天还能换几次 key（到 0 表示该停了，避免把整条授权链滚废）。</summary>
    public static int RotationsLeftToday(string box) => Math.Max(0, MaxRotationsPerDay - RotationsToday(box));

    /// <summary>今天是否已经换够了（到上限就不再动，避免服务端把整条链当异常）。</summary>
    public static bool RotationBudgetExhausted(string box) => RotationsToday(box) >= MaxRotationsPerDay;
}
