using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>按窗口标题识别界面。Sandboxie 的 BoxNameTitle 会给标题加 [qb1] / [#] 前缀。</summary>
public static class Titles
{
    public static bool IsGame(string t) => !string.IsNullOrWhiteSpace(t) && t.Contains(AppInfo.GameTitle, StringComparison.Ordinal);

    public static bool IsGameForBox(string t, string box)
    {
        if (!IsGame(t)) return false;
        if (Regex.IsMatch(t, @"\[qb\d+\]")) return t.Contains("[" + box + "]");
        return true;
    }

    /// <summary>真正需要人工扫码的授权页（不含 WMPF 启动时短暂的 WXRuntime_Log 标签）。</summary>
    public static bool IsStrictQr(string t)
    {
        if (string.IsNullOrWhiteSpace(t)) return false;
        return t.Contains("授权申请") || t.Contains("扫码授权");
    }

    public static bool IsWmpfSetup(string t) => !string.IsNullOrWhiteSpace(t) && (t.Contains("WXRuntime_Log") || t.Contains("http://data/"));
    public static bool IsRestorePage(string t) => !string.IsNullOrWhiteSpace(t) && t.Contains("要恢复页面");
    public static bool IsMiniProgramFail(string t) => !string.IsNullOrWhiteSpace(t) && (t.Contains("无法打开小程序") || t.Contains("打开小程序失败"));

    public static bool IsGameUpdateRestart(string t)
    {
        if (string.IsNullOrWhiteSpace(t)) return false;
        if (t.Contains("版本已经更新") || t.Contains("重新启动游戏更新") || t.Contains("请重新启动游戏")) return true;
        var s = t.Trim();
        return s == "提示" || Regex.IsMatch(s, @"\]\s*提示$");
    }

    public static bool IsWeChatShell(string t) => !string.IsNullOrWhiteSpace(t) && !IsGame(t) && t.Contains("微信");

    public static bool IsIme(string title, string cls, string proc)
    {
        title ??= ""; cls ??= ""; proc ??= "";
        if (title is "Default IME" or "MSCTFIME UI" or "HintWnd" || title.StartsWith("Sogou")) return true;
        if (title.Contains("候选") || title.Contains("组词") || title.Contains("输入法")) return true;
        if (cls is "IME" or "MSCTFIME UI" || cls.Contains("SoPY") || cls.Contains("Sogou") || cls.Contains("IME")) return true;
        if (cls.Contains("TF_FloatingLangBar") || cls.Contains("CiceroUIWndFrame")) return true;
        return proc.StartsWith("Sogou") || proc.StartsWith("SG") || proc == "ChsIME" || proc.Contains("InputMethod");
    }

    public static bool IsJunk(string title, string cls)
    {
        if (IsIme(title, cls, "")) return false;
        title ??= ""; cls ??= "";
        return title.Contains("要恢复页面") || title.Contains("游戏中心") || cls.Contains("StatusTray") || cls.Contains("PowerMessage");
    }
}
