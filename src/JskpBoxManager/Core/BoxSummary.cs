using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

public enum LoginLevel { Ok, Unknown, NeedScan, None }

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
    public string LastRefresh = "";
    public string Warning = "";
    public IlinkState Live = new();
    public IlinkState Vault = new();
    public RoleInfo Role;

    public static BoxSummary Build(string box, Dictionary<string, string> notes, KeepConfig keep, Dictionary<string, JsonObject> lastRefresh)
    {
        var s = new BoxSummary { Box = box, Note = notes.GetValueOrDefault(box, ""), Role = Roles.Load(box) };
        s.Live = Ilink.Live(box);
        s.Vault = Ilink.VaultState(box);
        var best = s.Live.Valid && s.Live.WriteUtc >= s.Vault.WriteUtc ? s.Live : s.Vault;
        s.Uin = best.Valid ? best.Uin : "";
        s.LastRenewUtc = best.Valid ? best.WriteUtc : DateTime.MinValue;

        bool revoked = s.Vault.Valid && Ilink.IsRevoked(box, s.Vault.KeyHash) && !(s.Live.Valid && s.Live.KeyHash != s.Vault.KeyHash);
        if ((NeedScan.Pending(box) && !NeedScan.Superseded(box, s.Live)) || revoked)
        {
            s.Login = LoginLevel.NeedScan;
            s.LoginText = revoked ? "需要扫码（已被顶掉）" : "需要扫码";
        }
        else if (s.Vault.Valid || s.Live.Valid)
        {
            s.Login = LoginLevel.Ok;
            s.LoginText = "免扫可用";
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
        else if (mode == "refresh") { s.Phase = "busy"; s.PhaseText = "保活中…"; }
        else if (st != null && mode.Length > 0 && st.Phase is BoxPhase.Starting or BoxPhase.WaitingScan or BoxPhase.InGame)
        {
            s.Phase = st.Phase == BoxPhase.WaitingScan ? "scan" : "busy";
            s.PhaseText = st.Text;
        }
        else if (s.Running) { s.Phase = "busy"; s.PhaseText = "运行中"; }
        else { s.Phase = "idle"; s.PhaseText = st != null && st.Phase == BoxPhase.Failed ? st.Text : "未运行"; }

        var pol = keep.For(box);
        s.KeepaliveOn = keep.EnabledFor(box);
        s.Keepalive = !s.KeepaliveOn ? "关" : s.Login == LoginLevel.None ? "登录后生效" : pol.Describe(box);
        if (lastRefresh.TryGetValue(box, out var ev))
        {
            var r = JsonFile.Str(ev, "result");
            var at = JsonFile.Str(ev, "at");
            s.LastRefresh = (at.Length >= 16 ? at[5..16] : at) + " " + (r switch
            {
                "ok" => "成功", "in-game" => "游戏中跳过", "revoked" => "被顶掉", "qr" or "qr-seen" => "要扫码",
                "no-game" => "没进游戏", "no-rewrite" => "未换新", _ => r,
            });
        }
        return s;
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
            foreach (var s in g) s.Warning = $"与 {names} 是同一个微信号，会互相顶掉";
        }
    }
}
