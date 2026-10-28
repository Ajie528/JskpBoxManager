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
    public string Keepalive => Summary?.Keepalive ?? "";
    public string LastRefresh => Summary?.LastRefresh ?? "";
    public string Warning => Summary?.Warning ?? "";
    public Visibility WarningVisibility => Warning.Length > 0 ? Visibility.Visible : Visibility.Collapsed;

    public string RenewText => Summary == null || Summary.LastRenewUtc == DateTime.MinValue ? "—" : Ago(Summary.LastRenewUtc);

    public Brush PhaseBrush => Summary?.Phase switch
    {
        "ingame" => Brushes.Green(),
        "busy" => Brushes.Blue(),
        "scan" => Brushes.Orange(),
        _ => Summary != null && Summary.PhaseText != "未运行" ? Brushes.Red() : Brushes.Gray(),
    };

    public Brush LoginBg => Summary?.Login switch
    {
        LoginLevel.Ok => Brushes.Hex("#DCFCE7"),
        LoginLevel.NeedScan => Brushes.Hex("#FEE2E2"),
        _ => Brushes.Hex("#F3F4F6"),
    };

    public Brush LoginFg => Summary?.Login switch
    {
        LoginLevel.Ok => Brushes.Hex("#166534"),
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
