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
        return s;
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
            if (s.AuthRejectAlert.Length > 0)
                s.Warning = s.Warning.Length > 0 ? s.AuthRejectAlert + "\n" + s.Warning : s.AuthRejectAlert;
    }
}
