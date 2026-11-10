using System.IO;

namespace JskpBoxManager.Core;

/// <summary>
/// 程序目录 = exe 所在目录。所有数据（金库、日志、配置）都放在这里，整个目录拷到别的电脑即可使用。
/// 布局与旧版 PowerShell 程序一致，方便直接导入。
/// </summary>
public static class AppPaths
{
    /// <summary>单文件发布会解压到临时目录运行（AppContext.BaseDirectory 指向那里），数据目录必须按 exe 的真实位置算。</summary>
    public static string AppDir { get; private set; } = ResolveAppDir();

    /// <summary>命令行可用 --appdir 指向已有金库/日志的安装目录（与 exe 所在目录不同时）。</summary>
    public static void UseDataDir(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
            throw new DirectoryNotFoundException("数据目录不存在：" + dir);
        AppDir = Path.GetFullPath(dir).TrimEnd('\\');
        EnvDetect.Reload();
    }

    static string ResolveAppDir()
    {
        var exe = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(exe) && !Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            return Path.GetDirectoryName(exe)!.TrimEnd('\\');
        return AppContext.BaseDirectory.TrimEnd('\\');
    }

    public static string Profiles => Path.Combine(AppDir, "profiles");
    public static string Logs => Path.Combine(AppDir, "logs");
    /// <summary>分析用的数据样板（免扫失效排查）。只放哈希与数值，不含明文密钥。</summary>
    public static string Samples => Path.Combine(AppDir, "samples");
    public static string PathsJson => Path.Combine(AppDir, "paths.json");
    public static string KeepaliveJson => Path.Combine(AppDir, "keepalive.json");
    public static string ProtocolJson => Path.Combine(AppDir, "protocol.json");
    public static string NotifyJson => Path.Combine(AppDir, "notify.json");
    public static string TrimJson => Path.Combine(AppDir, "trim.json");
    public static string NotesJson => Path.Combine(AppDir, "box-notes.json");
    public static string MigratedJson => Path.Combine(AppDir, "migrated.json");
    public static string EventLog => Path.Combine(Logs, "ilink-events.jsonl");

    public static string BoxLog(string box) => Path.Combine(Logs, box + ".log");
    public static string BoxState(string box) => Path.Combine(Logs, box + ".state.json");
    public static string BoxLauncherPid(string box) => Path.Combine(Logs, box + ".launcher");
    public static string BoxRefreshPhase(string box) => Path.Combine(Logs, box + ".refresh");

    /// <summary>保活到点但沙箱被常驻看门进程占着时写的续期请求，由常驻循环执行真实 AutoAuth 后续期。</summary>
    public static string BoxRenewRequest(string box) => Path.Combine(Logs, box + ".renew");

    public static void EnsureDirs()
    {
        Directory.CreateDirectory(Profiles);
        Directory.CreateDirectory(Logs);
    }
}
