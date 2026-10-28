using System.Windows;
using JskpBoxManager.Core;
using JskpBoxManager.UI;

namespace JskpBoxManager;

/// <summary>
/// 一个 exe 两种用法：
///   JskpBoxManager.exe              打开管理界面
///   JskpBoxManager.exe launch qbN   后台启动游戏并看门（桌面快捷方式、界面「启动」都走这里）
///   JskpBoxManager.exe refresh qbN  静默保活（计划任务调用）
///   JskpBoxManager.exe stop|clear|status qbN
/// </summary>
public partial class App : Application
{
    Mutex _guiMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        AppPaths.EnsureDirs();
        DispatcherUnhandledException += (_, ex) =>
        {
            Log.App("UI exception: " + ex.Exception);
            MessageBox.Show("出现了一个意外错误：\n" + ex.Exception.Message + "\n\n详细信息已写入 logs\\app.log", AppInfo.ProductName, MessageBoxButton.OK, MessageBoxImage.Error);
            ex.Handled = true;
        };

        var args = e.Args;
        if (args.Length >= 1 && args[0].Length > 0 && !args[0].StartsWith("-"))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            int code = RunCli(args);
            Shutdown(code);
            return;
        }

        _guiMutex = new Mutex(true, @"Local\JskpBoxManager.Gui", out bool first);
        if (!first)
        {
            MessageBox.Show("管理界面已经打开了（看看任务栏）。", AppInfo.ProductName, MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(0);
            return;
        }
        Log.App($"gui start {AppInfo.VersionLabel} dir={AppPaths.AppDir}");
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        var w = new MainWindow();
        MainWindow = w;
        w.Show();
        int snap = Array.IndexOf(args, "--snapshot");
        if (snap >= 0 && snap + 1 < args.Length) w.SnapshotAfterLoad(args[snap + 1]);
    }

    static int RunCli(string[] args)
    {
        var cmd = args[0].ToLowerInvariant();
        var box = args.Length >= 2 ? args[1] : "";
        try
        {
            if (cmd is "version" or "--version")
            {
                Console(AppInfo.VersionLabel);
                return 0;
            }
            if (!Sandboxie.IsBoxName(box))
            {
                Console($"用法：JskpBoxManager.exe launch|refresh|stop|clear|status qbN");
                return 2;
            }
            switch (cmd)
            {
                case "launch": return new LaunchSession(box).Run();
                case "refresh": return new RefreshSession(box).Run();
                case "stop": BoxRuntime.StopForce(box, true); return 0;
                case "clear": BoxRuntime.ClearLogin(box); return 0;
                case "status":
                    var keep = Keepalive.Load();
                    var s = BoxSummary.Build(box, Notes.Load(), keep, BoxSummary.LastRefreshEvents());
                    Console(Diagnostics.EnvironmentReport(new List<BoxSummary> { s }));
                    return 0;
                default:
                    Console("未知命令：" + cmd);
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Log.Box(Sandboxie.IsBoxName(box) ? box : "app", $"{cmd} EXCEPTION: {ex}");
            return 1;
        }
    }

    /// <summary>WinExe 没有自己的控制台：从命令行运行时附着到父控制台输出。</summary>
    static void Console(string text)
    {
        if (System.Console.IsOutputRedirected)
        {
            using var w = new StreamWriter(System.Console.OpenStandardOutput(), new System.Text.UTF8Encoding(false));
            w.WriteLine(text);
            return;
        }
        if (Win32.AttachConsole(-1))
        {
            System.Console.OutputEncoding = System.Text.Encoding.UTF8;
            System.Console.WriteLine();
            System.Console.WriteLine(text);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _guiMutex?.ReleaseMutex(); } catch { }
        base.OnExit(e);
    }
}
