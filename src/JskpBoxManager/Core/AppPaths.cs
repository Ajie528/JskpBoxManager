using System.IO;

namespace JskpBoxManager.Core;

/// <summary>
/// 程序目录 = exe 所在目录。所有数据（金库、日志、配置）都放在这里，整个目录拷到别的电脑即可使用。
/// 布局与旧版 PowerShell 程序一致，方便直接导入。
/// </summary>
public static class AppPaths
{
    public static string AppDir { get; } = AppContext.BaseDirectory.TrimEnd('\\');

    public static string Profiles => Path.Combine(AppDir, "profiles");
    public static string Logs => Path.Combine(AppDir, "logs");
    public static string PathsJson => Path.Combine(AppDir, "paths.json");
    public static string KeepaliveJson => Path.Combine(AppDir, "keepalive.json");
    public static string NotesJson => Path.Combine(AppDir, "box-notes.json");
    public static string MigratedJson => Path.Combine(AppDir, "migrated.json");
    public static string EventLog => Path.Combine(Logs, "ilink-events.jsonl");

    public static string BoxLog(string box) => Path.Combine(Logs, box + ".log");
    public static string BoxState(string box) => Path.Combine(Logs, box + ".state.json");
    public static string BoxLauncherPid(string box) => Path.Combine(Logs, box + ".launcher");
    public static string BoxRefreshPhase(string box) => Path.Combine(Logs, box + ".refresh");

    public static void EnsureDirs()
    {
        Directory.CreateDirectory(Profiles);
        Directory.CreateDirectory(Logs);
    }
}
