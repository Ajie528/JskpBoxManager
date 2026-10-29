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
    const string GuiMutexName = @"Local\JskpBoxManager.Gui";
    Mutex _guiMutex;

    /// <summary>自动更新重启前先放掉单实例锁，新版才能马上接手。</summary>
    public static void ReleaseGuiLock()
    {
        if (Current is not App app || app._guiMutex == null) return;
        try { app._guiMutex.ReleaseMutex(); } catch { }
        try { app._guiMutex.Dispose(); } catch { }
        app._guiMutex = null;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        AppPaths.EnsureDirs();
        var args = e.Args;
        bool cli = args.Length >= 1 && args[0].Length > 0 && !args[0].StartsWith("-");
        DispatcherUnhandledException += (_, ex) =>
        {
            Log.App((cli ? "CLI exception: " : "UI exception: ") + ex.Exception);
            ex.Handled = true;
            if (cli) { Shutdown(1); return; }
            MessageBox.Show("出现了一个意外错误：\n" + ex.Exception.Message + "\n\n详细信息已写入 logs\\app.log", AppInfo.ProductName, MessageBoxButton.OK, MessageBoxImage.Error);
        };

        if (cli)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            int code = RunCli(args);
            Shutdown(code);
            return;
        }

        bool afterUpdate = args.Contains("--updated-from");
        int wait = Array.IndexOf(args, "--wait-pid");
        if (wait >= 0 && wait + 1 < args.Length && int.TryParse(args[wait + 1], out var oldPid))
        {
            Log.App($"restart after update: waiting old pid {oldPid}");
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(oldPid);
                if (!p.WaitForExit(30000)) Log.App($"old pid {oldPid} still running after 30s");
            }
            catch { }
        }
        Updater.Cleanup();

        bool first = AcquireGuiLock(afterUpdate ? 30 : 0);
        if (!first && !args.Contains("--snapshot"))
        {
            Log.App("gui already running -> exit");
            MessageBox.Show("管理界面已经打开了（看看任务栏）。", AppInfo.ProductName, MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(0);
            return;
        }
        Log.App($"gui start {AppInfo.VersionLabel} dir={AppPaths.AppDir}");
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        var w = new MainWindow();
        MainWindow = w;
        w.Show();
        int from = Array.IndexOf(args, "--updated-from");
        if (from >= 0 && from + 1 < args.Length) w.ShowUpdatedNotice(args[from + 1]);
        int snap = Array.IndexOf(args, "--snapshot");
        if (snap >= 0 && snap + 1 < args.Length) w.SnapshotAfterLoad(args[snap + 1]);
    }

    /// <summary>拿单实例锁；更新后重启时旧窗口可能还没退干净，最多重试 retrySeconds 秒。</summary>
    bool AcquireGuiLock(int retrySeconds)
    {
        var deadline = DateTime.Now.AddSeconds(retrySeconds);
        while (true)
        {
            _guiMutex = new Mutex(true, GuiMutexName, out bool created);
            if (created) return true;
            try
            {
                if (_guiMutex.WaitOne(0)) return true;
            }
            catch (AbandonedMutexException) { return true; }
            _guiMutex.Dispose();
            _guiMutex = null;
            if (DateTime.Now >= deadline) return false;
            Thread.Sleep(500);
        }
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
            if (cmd == "update") return RunUpdate();
            ApplyAppDir(args);
            if (!Sandboxie.IsBoxName(box))
            {
                Console("用法：JskpBoxManager.exe launch|refresh|stop|clear|status|role|observe|hook|lean qbN [--appdir 目录]");
                return 2;
            }
            switch (cmd)
            {
                case "launch": return new LaunchSession(box).Run();
                case "refresh": return new RefreshSession(box).Run();
                case "observe": return new ObserveSession(box, args.Skip(2)).Run();
                case "hook": return new HookObserveSession(box, args.Skip(2)).Run();
                case "lean": return new LeanProbeSession(box, args.Skip(2)).Run();
                case "stop": BoxRuntime.StopForce(box, true); return 0;
                case "clear": BoxRuntime.ClearLogin(box); return 0;
                case "role":
                    var r = RoleCapture.ReadOnce(box, true, !args.Contains("--dry"));
                    Console($"{box}  {r.Message}");
                    return r.NameFound ? 0 : 1;
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

    /// <summary>
    /// --appdir 指向含 profiles 的安装目录。hook/lean 在 exe 旁没有金库时（例如从仓库 bin 目录运行），
    /// 在 exe 所在目录及上级目录（含 dist）里找 JskpBoxManager-* 安装目录，取 qb1 最近用过的那个。
    /// </summary>
    static void ApplyAppDir(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (!args[i].Equals("--appdir", StringComparison.OrdinalIgnoreCase)) continue;
            AppPaths.UseDataDir(args[i + 1]);
            return;
        }
        var cmd = args[0].ToLowerInvariant();
        if (cmd is not ("hook" or "lean")) return;
        if (Directory.Exists(Path.Combine(AppPaths.Profiles, "qb1"))) return;
        var roots = new List<string>();
        for (var d = new DirectoryInfo(AppPaths.AppDir); d != null && roots.Count < 20; d = d.Parent)
        {
            roots.Add(d.FullName);
            roots.Add(Path.Combine(d.FullName, "dist"));
        }
        var best = roots.Where(Directory.Exists)
            .SelectMany(r => { try { return Directory.GetDirectories(r, "JskpBoxManager-*"); } catch { return Array.Empty<string>(); } })
            .Where(c => Directory.Exists(Path.Combine(c, "profiles", "qb1")))
            .OrderByDescending(c => File.GetLastWriteTimeUtc(Path.Combine(c, "logs", "qb1.log")))
            .FirstOrDefault();
        if (best != null) AppPaths.UseDataDir(best);
    }

    /// <summary>命令行更新：有新版就下载、校验、替换（不打开界面）。</summary>
    static int RunUpdate()
    {
        try
        {
            var info = Task.Run(() => Updater.CheckAsync()).GetAwaiter().GetResult();
            if (info == null) { Console($"已经是最新版本 {AppInfo.VersionLabel}"); return 0; }
            var file = Task.Run(() => Updater.DownloadAsync(info, null)).GetAwaiter().GetResult();
            Updater.ApplyAndRestart(file, false);
            Console($"已从 v{AppInfo.Version} 更新到 v{info.Version}");
            return 0;
        }
        catch (Exception ex)
        {
            Console("更新失败：" + ex.Message);
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
