using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;
using JskpBoxManager.Core;

namespace JskpBoxManager.UI;

public sealed class BoxRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;

    public string Box { get; }
    public BoxSummary Summary { get; private set; }

    public BoxRow(string box) { Box = box; }

    public string Note => Summary?.Note is { Length: > 0 } n ? n : "（未备注）";
    public string PhaseText => Summary?.PhaseText ?? "读取中…";
    public string LoginText => Summary?.LoginText ?? "";
    public string LoginTip => Summary?.LoginTip ?? "";
    public string Keepalive => Summary?.Keepalive ?? "";
    public string LastRefresh => Summary?.LastRefresh ?? "";
    public string LastRefreshShort => Summary?.LastRefreshShort ?? "";
    public string Warning => Summary?.Warning ?? "";
    public Visibility WarningVisibility => Warning.Length > 0 ? Visibility.Visible : Visibility.Collapsed;

    public string RoleText => Summary?.Role is { HasName: true } r ? r.Name : "—";
    public string RoleTip => Summary?.Role is { HasName: true } r
        ? $"{r.Name}  等级 {r.Level}  {r.ServerName}\n读取于 {r.CapturedAt:MM-dd HH:mm}"
        : "进游戏后自动读取";
    public string AttackText => Summary?.Role is { HasAttack: true } r ? r.Attack : "—";

    public string RenewText => Summary == null || Summary.LastRenewUtc == DateTime.MinValue ? "—" : Ago(Summary.LastRenewUtc);

    /// <summary>今日已换次数 / 上限。</summary>
    public string RotationsText => Summary?.RotationsTodayText is { Length: > 0 } t ? t : "—";

    public Brush RotationsFg => Summary switch
    {
        null => Brushes.Gray(),
        { RotationsTodayText: not { Length: > 0 } } => Brushes.Gray(),
        { RotationsLeft: 0 } => Brushes.Red(),
        { RotationsLeft: 1 or 2 } => Brushes.Orange(),
        _ => Brushes.Hex("#4B5563"),
    };

    public string RotationsTip
    {
        get
        {
            var s = Summary;
            if (s == null) return "";
            var lines = new List<string>();
            lines.Add(s.RotationsTodayText is { Length: > 0 } t
                ? $"今天已换 {t} 次 key（上限见右）"
                : "今天还没换过 key");
            if (s.KeyAgeHours is double h)
                lines.Add($"当前密钥 {h:F1} 小时（满 {s.ForceRenewHoursEffective:0.#} 小时强制续期）");
            if (s.RotationsLeft == 0)
                lines.Add("今日额度已用完：不再轮换，等明天。频繁轮换会被服务端整链判废。");
            else lines.Add($"今天还能换 {s.RotationsLeft} 次");
            lines.Add("可在右侧「静默保活 → 轮换额度」里改每天最多换几次。");
            return string.Join("\n", lines);
        }
    }

    public string ScanAgeText => Summary?.ScanAgeShort ?? "—";
    public string ScanAgeTip => Summary?.ScanAgeTip ?? "";
    public Brush ScanAgeFg => Summary switch
    {
        null => Brushes.Gray(),
        { ScanDays: not double } => Brushes.Gray(),
        { ScanDays: double d } when d >= BoxSummary.AuthWindowDays => Brushes.Red(),
        { ScanDays: double d } when d >= BoxSummary.RescanWarnDays => Brushes.Orange(),
        _ => Brushes.Hex("#4B5563"),
    };

    public Brush PhaseBrush => Summary?.Phase switch
    {
        "ingame" => Brushes.Green(),
        "resident" => Brushes.Blue(),
        "busy" => Brushes.Blue(),
        "scan" => Brushes.Orange(),
        _ => Summary != null && Summary.PhaseText != "未运行" ? Brushes.Red() : Brushes.Gray(),
    };

    public Brush LoginBg => Summary?.Login switch
    {
        LoginLevel.Ok => Brushes.Hex("#DCFCE7"),
        LoginLevel.Suspect => Brushes.Hex("#FEF3C7"),
        LoginLevel.NeedScan => Brushes.Hex("#FEE2E2"),
        _ => Brushes.Hex("#F3F4F6"),
    };

    public Brush LoginFg => Summary?.Login switch
    {
        LoginLevel.Ok => Brushes.Hex("#166534"),
        LoginLevel.Suspect => Brushes.Hex("#92400E"),
        LoginLevel.NeedScan => Brushes.Hex("#991B1B"),
        _ => Brushes.Hex("#4B5563"),
    };

    public static string Ago(DateTime utc)
    {
        var span = DateTime.UtcNow - utc;
        if (span.TotalMinutes < 1) return "刚刚";
        if (span.TotalHours < 1) return $"{(int)span.TotalMinutes} 分钟前";
        if (span.TotalDays < 1) return $"{(int)span.TotalHours} 小时前";
        return $"{(int)span.TotalDays} 天前";
    }

    public void Update(BoxSummary s)
    {
        Summary = s;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }

    static class Brushes
    {
        static readonly Dictionary<string, SolidColorBrush> Cache = new();
        public static SolidColorBrush Hex(string hex)
        {
            if (Cache.TryGetValue(hex, out var b)) return b;
            b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
            b.Freeze();
            return Cache[hex] = b;
        }
        public static SolidColorBrush Green() => Hex("#16A34A");
        public static SolidColorBrush Blue() => Hex("#2563EB");
        public static SolidColorBrush Orange() => Hex("#F59E0B");
        public static SolidColorBrush Red() => Hex("#DC2626");
        public static SolidColorBrush Gray() => Hex("#9CA3AF");
    }
}
