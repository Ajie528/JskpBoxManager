using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 采集「免扫失效」的数据样板：把**同一时刻所有号的截面**导成一个目录，用来横向对比。
///
/// <para>
/// 为什么要这个：以前每次号失效都是临时翻自己的日志，看完只知道自己这个号出事了，
/// 不知道「1.9 天就死」到底算异常还是正常。把 16 个号的链龄、换新次数、密钥年龄、
/// 最后返回码摆在一起，异常的那个会自己跳出来——qb4 的 1.9 天对着别人的 10～20 天，
/// 一眼就能看出问题不在"服务端固定一天寿命"。
/// </para>
///
/// <para>
/// 落盘位置：<c>&lt;程序目录&gt;\samples\yyyyMMdd-HHmmss\</c>。
/// 只有哈希与数值，**没有任何明文密钥**。
/// </para>
/// </summary>
public static class Samples
{
    public sealed record Capture(string Dir, List<string> Findings)
    {
        public int BoxCount { get; init; }
    }

    /// <summary>采一次。boxes 传界面/命令行已经算好的汇总，避免重复读文件。</summary>
    public static Capture Take(List<BoxSummary> boxes)
    {
        var dir = Path.Combine(AppPaths.Samples, DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        Directory.CreateDirectory(dir);

        // 原始事件全量留一份：摘要只是看法，事件才是证据
        try
        {
            if (File.Exists(AppPaths.EventLog))
            {
                using var src = new FileStream(AppPaths.EventLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var dst = File.Create(Path.Combine(dir, "events.jsonl"));
                src.CopyTo(dst);
            }
        }
        catch { }

        foreach (var b in boxes) CopyBoxArtifacts(b.Box, dir);

        var findings = BuildFindings(boxes);
        var md = BuildReport(boxes, findings);
        File.WriteAllText(Path.Combine(dir, "摘要.md"), md, new UTF8Encoding(false));
        JsonFile.WriteObject(Path.Combine(dir, "摘要.json"), BuildJson(boxes));

        Log.App($"samples: captured {boxes.Count} boxes -> {dir}");
        return new Capture(dir, findings) { BoxCount = boxes.Count };
    }

    /// <summary>把某个号最相关的几个小文件原样拷进样板目录（都只有哈希）。</summary>
    static void CopyBoxArtifacts(string box, string dir)
    {
        void One(string src, string name)
        {
            try { if (File.Exists(src)) File.Copy(src, Path.Combine(dir, name), true); } catch { }
        }
        One(Path.Combine(AppPaths.Logs, box + ".rotate-log"), box + ".rotate-log");
        One(Path.Combine(AppPaths.Logs, box + ".probe.json"), box + ".probe.json");
        One(Path.Combine(AppPaths.Logs, box + ".renew-attempt"), box + ".renew-attempt");
        One(BoxPaths.NeedScanFile(box), box + ".need-scan.txt");
        One(Path.Combine(BoxPaths.CredentialDir(box), "history-cooldown.json"), box + ".history-cooldown.json");
    }

    // ---------------- 报告 ----------------

    static string BuildReport(List<BoxSummary> boxes, List<string> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# 免扫状态截面");
        sb.AppendLine();
        sb.AppendLine($"- 采集时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"- 电脑：{Environment.MachineName}    程序：{AppInfo.VersionLabel}");
        sb.AppendLine($"- 程序目录：{AppPaths.AppDir}");
        sb.AppendLine($"- 沙箱数：{boxes.Count}");
        sb.AppendLine();

        // 横向表：只留定位问题需要的列
        sb.AppendLine("| 沙箱 | 状态 | 链龄 | 换新 | 今日 | 密钥年龄 | 授权剩余 | 备注 |");
        sb.AppendLine("|---|---|---|---|---|---|---|---|");
        foreach (var b in Sorted(boxes))
        {
            var chain = b.ScanDays is double d ? $"{d:0.#}d" : "-";
            var age = b.KeyAgeHours is double k ? $"{k:0.#}h" : "-";
            var left = b.AuthDaysLeft is double l ? (l > 0 ? $"{l:0.#}d" : "超窗") : "-";
            var flags = new List<string>();
            if (b.Login == LoginLevel.NeedScan) flags.Add("需扫码");
            else if (b.Login == LoginLevel.Suspect) flags.Add("疑似失效");
            if (b.RotationsTodayText.Length > 0) flags.Add("换" + b.RotationsTodayText);
            sb.AppendLine($"| {b.Box} | {b.PhaseText} | {chain} | {b.Chain?.Renewals.ToString() ?? "-"} | "
                + $"{CredentialProbe.RotationsToday(b.Box)} | {age} | {left} | {string.Join(" ", flags)} |");
        }
        sb.AppendLine();

        sb.AppendLine("### 列的含义");
        sb.AppendLine();
        sb.AppendLine("| 列 | 含义 | 异常信号 |");
        sb.AppendLine("|---|---|---|");
        sb.AppendLine("| 链龄 | 从最近一次**扫码**到现在的天数 | 多数号 10～20 天、个别 1～2 天 → 那个号有问题 |");
        sb.AppendLine("| 换新 | 这条链一共免扫换过多少次 key | 明显少于链龄天数 → 保活没在干活 |");
        sb.AppendLine("| 今日 | 今天已换次数 / 每日上限 | 贴着上限 → 有东西在反复滚 key |");
        sb.AppendLine("| 密钥年龄 | 当前这把 key 多久前写入 | 很新却已被拒 → 死的不是密钥，是整条链 |");
        sb.AppendLine();

        sb.AppendLine("## 逐号细节");
        sb.AppendLine();
        foreach (var b in Sorted(boxes))
        {
            sb.AppendLine($"### {b.Box}{(b.Note.Length > 0 ? $"（{b.Note}）" : "")}");
            sb.AppendLine();
            sb.AppendLine($"- 状态：{b.PhaseText}    登录：{b.LoginText}");
            sb.AppendLine("- 免扫链：" + (b.ScanDays is double d
                ? $"{d:0.#} 天  起于 {b.ScanUtc.ToLocalTime():MM-dd HH:mm}{(b.ScanKnown ? "" : "（推算）")}"
                  + $"，期间换新 {b.Chain?.Renewals ?? 0} 次"
                : "无（未扫码或已中断）"));
            sb.AppendLine($"- 当前密钥：{(b.Live.Valid ? b.Live.KeyHash : b.Vault.KeyHash)}"
                + $"  年龄 {(b.KeyAgeHours is double k ? $"{k:0.#} 小时" : "无")}"
                + $"  今日换新 {CredentialProbe.RotationsToday(b.Box)} 次");

            if (NeedScan.Pending(b.Box))
                sb.AppendLine($"- 待扫码：{NeedScan.Reason(b.Box)}"
                    + (NeedScan.Superseded(b.Box, b.Live) ? "（已被新凭证取代）" : ""));
            var attempt = ProtocolRenew.LastAttemptAt(b.Box);
            if (attempt is DateTime at && ProtocolRenew.AttemptPending(b.Box))
                sb.AppendLine($"- **有未确认的续期标记**：{at:yyyy-MM-dd HH:mm:ss}"
                    + "（存在它时启动预检与主动探测都会跳过这个号）");
            int cooling = HistoryCooldown.Count(b.Box);
            if (cooling > 0)
                sb.AppendLine($"- 历史凭证冷却中：{cooling} 把（被拒后 {HistoryCooldown.DefaultHours:0} 小时内不再重试）");
            if (b.LastRevoke.Length > 0) sb.AppendLine($"- 最近判死：{b.LastRevoke.Replace("\n", "；")}");
            if (b.LastRefresh.Length > 0) sb.AppendLine($"- 最近保活：{b.LastRefresh}");
            if (b.AuthRejectAlert.Length > 0) sb.AppendLine($"- 告警：{b.AuthRejectAlert}");
            if (b.Warning.Length > 0) sb.AppendLine($"- 其它：{b.Warning.Replace("\n", "；")}");
            sb.AppendLine();
        }

        if (findings.Count > 0)
        {
            sb.AppendLine("## 自动体检");
            sb.AppendLine();
            foreach (var f in findings) sb.AppendLine("- " + f);
            sb.AppendLine();
        }

        sb.AppendLine("## 三类已知失效（对照用）");
        sb.AppendLine();
        sb.AppendLine("1. **被别处扫码顶掉**：整条链一起失效（连几十天前的历史 key 全部 -13），只能重扫。");
        sb.AppendLine("2. **保活根本没跑**：链龄短、换新次数少，日志里是 `refresh skipped: ...`。");
        sb.AppendLine("3. **本地凭证坏了但服务端还认**：历史 key 里有一把返回 0，用「历史凭证恢复」能救。");
        return sb.ToString();
    }

    /// <summary>一眼可见的异常点。规则都很保守，只报「对照其它号明显不对」的情况。</summary>
    static List<string> BuildFindings(List<BoxSummary> boxes)
    {
        var list = new List<string>();

        // 用本机其它号的中位链龄当基准，避免用写死的天数
        var chains = boxes.Where(b => b.ScanDays is not null).Select(b => b.ScanDays!.Value).OrderBy(x => x).ToList();
        double median = chains.Count > 0 ? chains[chains.Count / 2] : 0;

        foreach (var b in Sorted(boxes))
        {
            var attempt = ProtocolRenew.LastAttemptAt(b.Box);
            if (attempt is DateTime at && ProtocolRenew.AttemptPending(b.Box))
                list.Add($"**{b.Box}** 留着 `{b.Box}.renew-attempt`（{at:yyyy-MM-dd HH:mm}）："
                    + "它会让启动预检与主动探测永久跳过这个号，等于失去自动确认能力。");

            if (b.ScanDays is double d && median > 0 && d * 3 < median && b.Login is LoginLevel.NeedScan or LoginLevel.Suspect)
                list.Add($"**{b.Box}** 链只活了 {d:0.#} 天就要扫码（本机中位 {median:0.#} 天）："
                    + "优先查多设备互踢 / 保活没跑，别先怀疑服务端寿命。");

            if (b.KeyAgeHours is double k && k < 3 && b.Login is LoginLevel.NeedScan)
                list.Add($"**{b.Box}** 密钥才 {k:0.#} 小时就已经被判废：死的不是密钥，是整条链。");

            int today = CredentialProbe.RotationsToday(b.Box);
            if (today >= 8)
                list.Add($"**{b.Box}** 今天已换 {today} 次 key：贴着风控上限，继续滚只会更快把链滚废。");
        }
        return list;
    }

    static JsonObject BuildJson(List<BoxSummary> boxes)
    {
        var arr = new JsonArray();
        foreach (var b in Sorted(boxes))
            arr.Add(new JsonObject
            {
                ["box"] = b.Box,
                ["phase"] = b.PhaseText,
                ["login"] = b.LoginText,
                ["chainDays"] = b.ScanDays is double d ? Math.Round(d, 2) : null,
                ["chainStart"] = b.ScanDays is null ? null : b.ScanUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                ["chainKnown"] = b.ScanKnown,
                ["renewals"] = b.Chain?.Renewals,
                ["rotationsToday"] = CredentialProbe.RotationsToday(b.Box),
                ["keyHash"] = b.Live.Valid ? b.Live.KeyHash : b.Vault.KeyHash,
                ["keyAgeHours"] = b.KeyAgeHours is double k ? Math.Round(k, 1) : null,
                ["authDaysLeft"] = b.AuthDaysLeft is double l ? Math.Round(l, 1) : null,
                ["needScan"] = NeedScan.Pending(b.Box) ? NeedScan.Reason(b.Box) : null,
                ["attemptAt"] = ProtocolRenew.LastAttemptAt(b.Box)?.ToString("yyyy-MM-dd HH:mm:ss"),
                ["historyCooling"] = HistoryCooldown.Count(b.Box),
            });
        return new JsonObject
        {
            ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            ["pc"] = Environment.MachineName,
            ["app"] = AppInfo.Version,
            ["boxes"] = arr,
        };
    }

    static IEnumerable<BoxSummary> Sorted(List<BoxSummary> boxes)
        => boxes.OrderBy(b => Sandboxie.BoxNumber(b.Box));
}
