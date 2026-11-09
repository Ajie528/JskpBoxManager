using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

public enum LoginLevel
{
    Ok,
    Unknown,
    /// <summary>保活时服务端回过 AutoAuth ret=-13：凭证大概率已失效，但还没到「必须扫码」那一步。</summary>
    Suspect,
    NeedScan,
    None
}

/// <summary>界面上一行沙箱的状态汇总（只读文件和进程，不改任何东西）。</summary>
public sealed class BoxSummary
{
    public string Box = "";
    public string Note = "";
    public bool Running;
    public bool InGame;
    public string Phase = "";
    public string PhaseText = "";
    public LoginLevel Login;
    public string LoginText = "";
    public string Uin = "";
    public DateTime LastRenewUtc = DateTime.MinValue;
    public string Keepalive = "";
    public bool KeepaliveOn;
    /// <summary>今天已换 key 次数 / 上限，如 "2/8"；无凭证时为空。</summary>
    public string RotationsTodayText = "";
    /// <summary>密钥年龄（小时），用于界面提示「还新，先不动」。</summary>
    public double? KeyAgeHours;
    /// <summary>今天剩余可换次数。</summary>
    public int RotationsLeft;
    /// <summary>该沙箱实际生效的「密钥满多少小时强制续期」。</summary>
    public double ForceRenewHoursEffective = 20;
    /// <summary>完整说明（详情面板 / 悬停提示）。</summary>
    public string LastRefresh = "";
    /// <summary>表格里的短文本。</summary>
    public string LastRefreshShort = "";
    public string Warning = "";
    public IlinkState Live = new();
    public IlinkState Vault = new();
    public RoleInfo Role;
    public AuthChain Chain;
    /// <summary>最近一次被服务端判死（key-revoked）的说明；没有则空。</summary>
    public string LastRevoke = "";

    /// <summary>保活时服务端回过拒绝授权（AutoAuth ret≠0）且之后没有恢复：给出醒目告警。</summary>
    public string AuthRejectAlert = "";
    /// <summary>告警级别的服务器返回码（通常是 -13 = 密钥已被作废）。</summary>
    public int AuthRejectRet = 0;

    // ---------- 扫码授权窗口（参考 YYB-Go-Enhanced 的 30 天模型） ----------
    //
    // 微信的扫码授权是一条「从扫码那天起算」的窗口，而不是「密钥多久没用」。
    // 参考实现里 refresh_token_observed_at 记的就是扫码时间，判据是：
    //   满 25 天 → rescan_recommended（提前 5 天提醒，留出重扫余地）
    //   满 30 天 → 窗口结束，必须重扫
    // 这跟我们 docs\服务端规则测试.md 里「从扫码起约一天」的实测不符，
    // 说明我们这边的号被顶得更快（多设备互踢 / 频繁冷启），
    // 所以这里两条线一起显示：参考模型的剩余天数 + 我们自己的实测寿命。

    /// <summary>参考模型的扫码授权窗口长度（天）。</summary>
    public const int AuthWindowDays = 30;
    /// <summary>满这么多天开始建议重扫（参考实现取 25）。</summary>
    public const int RescanWarnDays = 25;

    /// <summary>本机记录到的扫码时间（免扫链起点）；没有记录则 MinValue。</summary>
    public DateTime ScanUtc = DateTime.MinValue;
    /// <summary>扫码时间是否确知（false = 只追到「更早的没有记录」）。</summary>
    public bool ScanKnown;
    /// <summary>基准来源：qr-scan / manual / trace / backfill。</summary>
    public string ScanSource = "";

    /// <summary>距扫码已过多少天；没有扫码记录时为 null。</summary>
    public double? ScanDays => ScanUtc == DateTime.MinValue ? null : (DateTime.UtcNow - ScanUtc).TotalDays;

    /// <summary>按 30 天窗口算，还剩多少天；已过期则为负。</summary>
    public double? AuthDaysLeft => ScanDays is double d ? AuthWindowDays - d : null;

    /// <summary>按参考模型是否该建议重新扫码。</summary>
    public bool RescanSuggested => ScanDays is double d && d >= RescanWarnDays;

    public static BoxSummary Build(string box, Dictionary<string, string> notes, KeepConfig keep, Dictionary<string, JsonObject> lastRefresh,
        Dictionary<string, AuthChain> chains, Dictionary<string, JsonObject> revokes = null)
    {
        revokes ??= LastRevokeEvents();
        var s = new BoxSummary { Box = box, Note = notes.GetValueOrDefault(box, ""), Role = Roles.Load(box) };
        s.Live = Ilink.Live(box);
        s.Vault = Ilink.VaultState(box);
        var best = s.Live.Valid && s.Live.WriteUtc >= s.Vault.WriteUtc ? s.Live : s.Vault;
        s.Uin = best.Valid ? best.Uin : "";
        s.LastRenewUtc = best.Valid ? best.WriteUtc : DateTime.MinValue;

        // 先在算登录状态之前解析「上次保活被服务端拒绝授权」，因为登录状态要用它决定「疑似失效」。
        JsonObject refreshEv = lastRefresh.TryGetValue(box, out var re) ? re : null;
        DateTime? refreshAt = null;
        if (refreshEv != null
            && DateTime.TryParseExact(JsonFile.Str(refreshEv, "at"), "yyyy-MM-dd HH:mm:ss", null, System.Globalization.DateTimeStyles.None, out var rat))
            refreshAt = rat;
        if (refreshEv != null && refreshAt != null
            && JsonFile.Int(refreshEv, "authRet") is int earlyRet && earlyRet != 0
            && JsonFile.Str(refreshEv, "result") is not "ok")
        {
            // 之后又写过更新的凭证 = 已恢复，不算告警
            bool recoveredNow = s.LastRenewUtc > refreshAt.Value.ToUniversalTime();
            if (!recoveredNow)
            {
                s.AuthRejectRet = earlyRet;
                var kind = earlyRet == -13 ? "密钥已被服务端作废（多半是同一微信号在别处扫码顶掉）"
                                           : "服务端拒绝了自动授权";
                var msg0 = JsonFile.Str(refreshEv, "authMsg");
                s.AuthRejectAlert =
                    $"{refreshAt.Value:MM-dd HH:mm} 保活时{kind}，ret={earlyRet}"
                    + (msg0.Length > 0 ? $"（{msg0}）" : "")
                    + "。本地这把凭证已不可用，建议尽快重新扫码；在此之前保活会一直失败。";
            }
        }

        bool revoked = s.Vault.Valid && Ilink.IsRevoked(box, s.Vault.KeyHash) && !(s.Live.Valid && s.Live.KeyHash != s.Vault.KeyHash);
        if ((NeedScan.Pending(box) && !NeedScan.Superseded(box, s.Live)) || revoked)
        {
            s.Login = LoginLevel.NeedScan;
            s.LoginText = revoked ? "需要扫码（已被顶掉）" : "需要扫码";
        }
        else if (s.Vault.Valid || s.Live.Valid)
        {
            // 有凭证，但保活时服务端明确拒绝过授权且之后没恢复：标成「疑似失效」而不是「免扫可用」，
            // 让人早点知道这把钥匙已经不能用了（否则要等下次启动弹扫码才会发现）。
            if (s.AuthRejectAlert.Length > 0)
            {
                s.Login = LoginLevel.Suspect;
                s.LoginText = "疑似失效";
            }
            else
            {
                s.Login = LoginLevel.Ok;
                s.LoginText = "免扫可用";
            }
            if (chains.TryGetValue(box, out var chain) && chain.Uin == s.Uin) s.Chain = chain;
        }
        else
        {
            s.Login = LoginLevel.None;
            s.LoginText = "未登录";
        }

        // 扫码授权窗口：起点优先用持久化基准（不会被日志滚动冲掉），
        // 其次用免扫链起点（从事件日志推算）。
        // 链存在时即使 Uin 变了也照用（换号重扫会重建链，Start 就是新扫码时间）。
        var baseline = ScanBaseline.Load(box);
        if (baseline == null && s.Chain != null)
        {
            // 还没基准文件：把这次推算的结果落盘，下次就不用再算（事件日志会滚动）
            ScanBaseline.Save(box, s.Chain.Start, s.Chain.Uin,
                s.Chain.StartKnown ? ScanBaseline.SourceQrScan : ScanBaseline.SourceTrace);
            baseline = ScanBaseline.Load(box);
        }
        if (baseline != null)
        {
            s.ScanUtc = baseline.AtUtc;
            s.ScanKnown = baseline.Confirmed;
            s.ScanSource = baseline.Source;
        }
        else if (s.Chain != null)
        {
            s.ScanUtc = s.Chain.Start.ToUniversalTime();
            s.ScanKnown = s.Chain.StartKnown;
            s.ScanSource = s.Chain.StartKnown ? ScanBaseline.SourceQrScan : ScanBaseline.SourceTrace;
        }

        var view = new BoxView(box);
        s.Running = view.HasQqOrGame;
        s.InGame = s.Running && view.HasGameWindow;
        var st = BoxStatusFile.Read(box);
        string mode = BoxRuntime.LauncherMode(box);
        if (s.InGame) { s.Phase = "ingame"; s.PhaseText = "游戏中"; }
        else if (st != null && st.Phase == BoxPhase.Resident && s.Running)
        {
            s.Phase = "resident";
            s.PhaseText = string.IsNullOrWhiteSpace(st.Text) ? "常驻保活中（轻量）" : st.Text;
        }
        else if (mode == "refresh") { s.Phase = "busy"; s.PhaseText = "保活中…"; }
        else if (st != null && mode.Length > 0 && st.Phase is BoxPhase.Starting or BoxPhase.WaitingScan or BoxPhase.InGame or BoxPhase.Resident)
        {
            s.Phase = st.Phase == BoxPhase.WaitingScan ? "scan" : st.Phase == BoxPhase.Resident ? "resident" : "busy";
            s.PhaseText = st.Text;
        }
        else if (s.Running) { s.Phase = "busy"; s.PhaseText = "运行中"; }
        else { s.Phase = "idle"; s.PhaseText = st != null && st.Phase == BoxPhase.Failed ? st.Text : "未运行"; }

        var pol = keep.For(box);
        s.KeepaliveOn = keep.EnabledFor(box);
        s.Keepalive = !s.KeepaliveOn ? "关" : s.Login == LoginLevel.None ? "登录后生效" : pol.Describe(box);
        // 今日轮换额度：让「每天最多换几次」在界面上看得见，而不是只存在于日志里
        try
        {
            int quota = pol.EffectiveMaxRotations;
            int used = CredentialProbe.RotationsToday(box);
            s.RotationsLeft = Math.Max(0, quota - used);
            if (s.Live.Valid || s.Vault.Valid) s.RotationsTodayText = $"{used}/{quota}";
            s.KeyAgeHours = ProtocolRenew.KeyAgeHours(box);
            s.ForceRenewHoursEffective = pol.EffectiveForceRenewHours;
        }
        catch { }
        if (lastRefresh.TryGetValue(box, out var ev)
            && DateTime.TryParseExact(JsonFile.Str(ev, "at"), "yyyy-MM-dd HH:mm:ss", null, System.Globalization.DateTimeStyles.None, out var at))
        {
            var r = JsonFile.Str(ev, "result");
            var word = r switch
            {
                "ok" => "成功", "in-game" => "游戏中跳过", "resident-skip" => "常驻跳过",
                "revoked" => "被顶掉", "suspected" => "疑似失效（未确认被顶）",
                "qr" or "qr-seen" => "要扫码",
                "no-game" => "没进游戏", "no-rewrite" => "未换新", _ => r,
            };
            // 保活失败后又手动启动 / 扫码换新过：失败已经过时，标出来，免得和「最近免扫换新」看着矛盾
            bool recovered = r is not ("ok" or "in-game") && s.Login == LoginLevel.Ok && s.LastRenewUtc > at.ToUniversalTime();
            s.LastRefreshShort = $"{Clock(at)} {word}" + (recovered ? "·已恢复" : "");
            s.LastRefresh = $"{at:MM-dd HH:mm} {word}";
            if (JsonFile.Int(ev, "authRet") is int ret && ret != 0)
                s.LastRefresh += $"（服务器拒绝授权 ret={ret}" + (JsonFile.Str(ev, "authMsg") is { Length: > 0 } m ? $"：{m}）" : "）");
            if (recovered)
                s.LastRefresh += $"；之后 {s.LastRenewUtc.ToLocalTime():MM-dd HH:mm} 已重新登录，现在免扫正常";
        }

        if (revokes.TryGetValue(box, out var rev)
            && DateTime.TryParseExact(JsonFile.Str(rev, "at"), "yyyy-MM-dd HH:mm:ss", null, System.Globalization.DateTimeStyles.None, out var revAt))
        {
            var parts = new List<string>();
            if (JsonFile.Double(rev, "keyAgeHours") is double age) parts.Add($"密钥已用 {age:0.#} 小时");
            if (JsonFile.Double(rev, "chainDays") is double days) parts.Add($"免扫链活了 {days:0.#} 天");
            if (JsonFile.Int(rev, "chainRenewals") is int rn) parts.Add($"期间换新 {rn} 次");
            var detail = parts.Count > 0 ? "（" + string.Join("，", parts) + "）" : "";
            // 被顶后又恢复了就标成历史
            bool recoveredAfter = s.Login == LoginLevel.Ok && s.LastRenewUtc > revAt.ToUniversalTime();
            s.LastRevoke = (recoveredAfter ? "历史：" : "") + $"{revAt:MM-dd HH:mm} 被服务端判死{detail}"
                + (recoveredAfter ? "，之后已重新扫码恢复" : "，需重新扫码");
        }
        s.BuildScanWindowText();
        return s;
    }

    /// <summary>本机实测的免扫最长寿命（天）。由调用方从现有的所有免扫链里统计出来。</summary>
    public static double LongestChainDays = 0;

    /// <summary>统计当前所有沙箱里最长的那条免扫链，作为「本机能活多久」的参考。</summary>
    public static void MarkLongestChain(List<BoxSummary> list)
    {
        LongestChainDays = list.Where(s => s.ScanDays is not null).Select(s => s.ScanDays!.Value)
                               .DefaultIfEmpty(0).Max();
    }

    /// <summary>表格里的短文本，例如「5.3/30 天」或「已超窗口」。</summary>
    public string ScanAgeShort = "";
    /// <summary>悬停 / 详情的完整说明。</summary>
    public string ScanAgeTip = "";
    /// <summary>窗口告警（满 25 天或已过期时非空，并进 ⚠ 列）。</summary>
    public string ScanWindowAlert = "";

    void BuildScanWindowText()
    {
        if (ScanDays is not double days)
        {
            ScanAgeShort = "—";
            ScanAgeTip = "没有扫过码的记录（免扫链已断或日志被清），无法推算授权窗口";
            return;
        }

        var left = AuthWindowDays - days;
        var srcText = ScanSource switch
        {
            ScanBaseline.SourceQrScan => "扫码时记录",
            ScanBaseline.SourceManual => "扫码时记录",
            ScanBaseline.SourceBackfill => "手动补录",
            ScanBaseline.SourceTrace => "由密钥历史回溯（下限）",
            _ => "未知",
        };
        var known = ScanKnown ? "" : "，实际可能更早";

        // 表格短文本：优先显示「还剩多少」，比「已过多少」更直观
        ScanAgeShort = left <= 0 ? "已过期" : $"{left:0.#} 天";

        var lines = new List<string>
        {
            $"扫码时间 {ScanUtc.ToLocalTime():yyyy-MM-dd HH:mm}（{srcText}{known}）",
            $"已过 {days:0.#} 天，授权窗口 {AuthWindowDays} 天 → {(left > 0 ? $"还剩 {left:0.#} 天" : $"已超出 {(-left):0.#} 天")}",
            $"到期时间约 {ScanUtc.ToLocalTime().AddDays(AuthWindowDays):yyyy-MM-dd HH:mm}",
        };
        if (LongestChainDays > 0)
            lines.Add($"本机最长免扫链已 {LongestChainDays:0.#} 天（实测寿命，不是理论上限）");
        if (Chain is { Renewals: > 0 } c)
            lines.Add($"期间免扫换新 {c.Renewals} 次，最近 {c.LastRenew:MM-dd HH:mm}");
        if (!ScanKnown)
            lines.Add("提示：这是推算值。下次扫码后会写入精确基准，之后一直准确。");
        ScanAgeTip = string.Join("\n", lines);

        if (left <= 0)
            ScanWindowAlert = $"扫码已 {days:0.#} 天，超出 {AuthWindowDays} 天授权窗口 {(-left):0.#} 天，随时可能要求重新扫码。";
        else if (days >= RescanWarnDays)
            ScanWindowAlert = $"扫码已 {days:0.#} 天，进入建议重扫区（窗口 {AuthWindowDays} 天，还剩 {left:0.#} 天）。";
        if (ScanWindowAlert.Length > 0 && !ScanKnown)
            ScanWindowAlert += "（起点是推算值，实际可能更早）";
    }

    static string Clock(DateTime t) =>
        t.Date == DateTime.Today ? $"今天 {t:HH:mm}" : t.Date == DateTime.Today.AddDays(-1) ? $"昨天 {t:HH:mm}" : $"{t:MM-dd HH:mm}";

    /// <summary>从事件日志里取每个沙箱最近一次「被服务端判死」(key-revoked) 事件。</summary>
    public static Dictionary<string, JsonObject> LastRevokeEvents()
    {
        var d = new Dictionary<string, JsonObject>();
        foreach (var line in Log.Tail(AppPaths.EventLog, 8000))
        {
            try
            {
                if (JsonNode.Parse(line) is not JsonObject o) continue;
                if (JsonFile.Str(o, "event") != "key-revoked") continue;
                if (JsonFile.Str(o, "pc") is var pc && pc.Length > 0 && pc != Environment.MachineName) continue;
                d[JsonFile.Str(o, "box")] = o;
            }
            catch { }
        }
        return d;
    }

    /// <summary>从事件日志里取每个沙箱最近一次保活结果。</summary>
    public static Dictionary<string, JsonObject> LastRefreshEvents()
    {
        var d = new Dictionary<string, JsonObject>();
        foreach (var line in Log.Tail(AppPaths.EventLog, 4000))
        {
            try
            {
                if (JsonNode.Parse(line) is not JsonObject o) continue;
                if (JsonFile.Str(o, "event") != "refresh") continue;
                if (JsonFile.Str(o, "pc") is var pc && pc.Length > 0 && pc != Environment.MachineName) continue;
                d[JsonFile.Str(o, "box")] = o;
            }
            catch { }
        }
        return d;
    }

    /// <summary>同一个微信号登在两个沙箱里会互相顶掉：给出提醒。</summary>
    public static void MarkDuplicates(List<BoxSummary> list)
    {
        foreach (var g in list.Where(s => s.Uin.Length > 0).GroupBy(s => s.Uin).Where(g => g.Count() > 1))
        {
            var names = string.Join("、", g.Select(x => x.Box));
            foreach (var s in g)
                s.Warning = s.Warning.Length > 0
                    ? $"与 {names} 是同一个微信号，会互相顶掉\n{s.Warning}"
                    : $"与 {names} 是同一个微信号，会互相顶掉";
        }
    }

    /// <summary>把「保活被服务端拒绝授权」的告警并入表格的 ⚠ 列。</summary>
    public static void MarkAuthRejects(List<BoxSummary> list)
    {
        foreach (var s in list)
        {
            if (s.AuthRejectAlert.Length > 0)
                s.Warning = s.Warning.Length > 0 ? s.AuthRejectAlert + "\n" + s.Warning : s.AuthRejectAlert;
            // 扫码授权窗口告警优先级低于「已被拒绝」，但比「同号互顶」更该先看到
            if (s.ScanWindowAlert.Length > 0 && s.Login == LoginLevel.Ok)
                s.Warning = s.Warning.Length > 0 ? s.Warning + "\n" + s.ScanWindowAlert : s.ScanWindowAlert;
        }
    }
}
