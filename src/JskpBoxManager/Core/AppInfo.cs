using System.IO;
using System.Reflection;

namespace JskpBoxManager.Core;

public static class AppInfo
{
    public const string ProductName = "向僵多开管家";
    public const string GameTitle = "向僵尸开炮";
    public const string GameAppId = "wx31a9c726536cdacc";
    public const string GameUrl = "https://pcgame.qqbrowser.qq.com/main?openGameId=wx31a9c726536cdacc&openGameSource=5";

    static readonly Assembly Asm = typeof(AppInfo).Assembly;

    /// <summary>1.0.0 这样的版本号（来自 Directory.Build.props）。</summary>
    public static string Version
    {
        get
        {
            var info = Asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";
            int plus = info.IndexOf('+');
            return plus > 0 ? info[..plus] : info;
        }
    }

    /// <summary>构建时的 git 提交（短）；没有 git 时为空。</summary>
    public static string Commit
    {
        get
        {
            var info = Asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "";
            int plus = info.IndexOf('+');
            if (plus < 0) return "";
            var c = info[(plus + 1)..];
            return c.Length > 7 ? c[..7] : c;
        }
    }

    public static string VersionLabel => string.IsNullOrEmpty(Commit) ? "v" + Version : $"v{Version} ({Commit})";

    public static DateTime BuildTime
    {
        get
        {
            var v = Asm.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == "BuildTime")?.Value;
            if (DateTime.TryParse(v, out var t)) return t;
            try { return File.GetLastWriteTime(ExePath); } catch { return DateTime.MinValue; }
        }
    }

    public static string ExePath => Path.Combine(AppPaths.AppDir, "JskpBoxManager.exe");

    public static string ReadChangelog()
    {
        using var s = Asm.GetManifestResourceStream("CHANGELOG.md");
        if (s == null) return "";
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }
}
