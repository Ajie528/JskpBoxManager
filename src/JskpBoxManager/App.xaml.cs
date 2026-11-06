using System.Text.RegularExpressions;
using System.Windows;
using JskpBoxManager.Core;
using JskpBoxManager.UI;

namespace JskpBoxManager;

/// <summary>
/// 一个 exe 两种用法：
///   JskpBoxManager.exe              打开管理界面
///   JskpBoxManager.exe launch qbN   后台启动游戏并看门（桌面快捷方式、界面「启动」都走这里）
///   JskpBoxManager.exe refresh qbN  静默保活（计划任务调用）
///   JskpBoxManager.exe getcode qbN  取本游戏 wx.login code
///   JskpBoxManager.exe capture qbN  CDP 抓 wx.request / wx.login
///   JskpBoxManager.exe keylog qbN   导出游戏 TLS 密钥（配合抓包解密业务 HTTPS）
///   JskpBoxManager.exe token qbN    一条龙：抓包+keylog+解密，输出业务 token（需 Wireshark）
///   JskpBoxManager.exe unpack qbN   定位并解包游戏 wxapkg
///   JskpBoxManager.exe server       本机协议 HTTP 服务
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
            // launch/refresh/stop 常由快捷方式/计划任务拉起，不弹黑窗；诊断类命令要看得见输出
            if (NeedsCliConsole(args[0])) Win32.EnsureCliConsole();
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

    static bool NeedsCliConsole(string cmd) => cmd.ToLowerInvariant() is
        "version" or "--version" or "update" or "server" or "getcode" or "wxcode"
        or "capture" or "keylog" or "token" or "unpack" or "observe" or "hook" or "trim" or "status" or "role"
        or "recover" or "cred-save" or "cred-load" or "help" or "/?" or "-h" or "--help" or "notify";

    static int RunCli(string[] args)
    {
        var cmd = args[0].ToLowerInvariant();
        var box = args.Length >= 2 ? args[1] : "";
        try
        {
            if (cmd is "help" or "/?" or "-h" or "--help")
            {
                Console("用法：");
                Console("  .\\JskpBoxManager.exe capture qb1 --seconds 120");
                Console("  .\\JskpBoxManager.exe unpack qb1");
                Console("  .\\JskpBoxManager.exe getcode qb1");
                Console("  .\\JskpBoxManager.exe server");
                Console("  .\\JskpBoxManager.exe launch|refresh|stop|clear|status qbN");
                Console("PowerShell 必须加 .\\ 前缀；看输出请在本窗口运行，不要双击 exe。");
                return 0;
            }
            if (cmd is "version" or "--version")
            {
                Console(AppInfo.VersionLabel);
                return 0;
            }
            if (cmd == "update") return RunUpdate();
            if (cmd == "server") return RunServer(args);
            if (cmd.Equals("notify", StringComparison.OrdinalIgnoreCase))
            {
                ApplyAppDir(args);
                return RunNotify(args);
            }
            if (cmd is "getcode" or "wxcode")
            {
                ApplyAppDir(args);
                return RunGetCode(args);
            }
            ApplyAppDir(args);
            if (!Sandboxie.IsBoxName(box))
            {
                Console("用法：JskpBoxManager.exe launch|refresh|stop|clear|status|role|protorenew|scanbase|observe|hook|getcode|capture|keylog|token|unpack|server qbN [--appdir 目录]");
                return 2;
            }
            // 沙箱在 Sandboxie 里没有配置时，任何启动/清理动作都会让 Start.exe 弹
            // 「无效的沙盒名参数」模态框（无人值守时会把流程卡死）。这里统一拦掉。
            // removebox 允许执行：用户可能只是想清掉残留数据。
            if (cmd != "removebox" && cmd != "delbox" && cmd != "status" && cmd != "scanbase" && !Sandboxie.BoxExists(box))
            {
                Console($"{box} 在 Sandboxie 里不存在（可能已被删除），请先在本程序里新建沙箱");
                return 1;
            }
            switch (cmd)
            {
                case "launch": return new LaunchSession(box).Run();
                case "refresh": return new RefreshSession(box).Run();
                case "observe": return new ObserveSession(box, args.Skip(2)).Run();
                case "hook": return new HookObserveSession(box, args.Skip(2)).Run();
                case "capture": return new CaptureSession(box, args.Skip(2)).Run();
                case "keylog": return new SslKeylogSession(box, args.Skip(2)).Run();
                case "token": return new TokenSession(box, args.Skip(2)).Run();
                case "unpack": return RunUnpack(box, args.Skip(2).ToArray());
                case "trim": Console(BoxRuntime.DeepTrimMemory(box)); return 0;
                case "recover": return new RecoverSession(box).Run();
                case "protorenew":
                {
                    bool dry = args.Contains("--dry");
                    bool force = args.Contains("--force");
                    if (!dry && !force)
                    {
                        var (ok2, why2) = ProtocolRenew.CheckRenewable(box);
                        if (!ok2) { Console(why2); return 3; }
                    }
                    var pr = ProtocolRenew.Renew(box, dry);
                    Console(pr.Message);
                    return pr.Ok ? 0 : 1;
                }
                case "scanbase":
                {
                    // 手动补录 / 查看扫码基准：scanbase qbN [yyyy-MM-dd HH:mm:ss]
                    var when = args.Skip(2).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal)
                                                              && a != AppPaths.AppDir);
                    if (when == null)
                    {
                        var b = ScanBaseline.Load(box);
                        Console(b == null ? $"{box}：没有扫码基准"
                            : $"{box}：{b.AtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  uin={b.Uin}  来源={b.Source}"
                              + $"  已过 {(DateTime.UtcNow - b.AtUtc).TotalDays:0.#} 天");
                        return 0;
                    }
                    if (!DateTime.TryParse(when, out var dt))
                    { Console($"时间格式不对：{when}（要 yyyy-MM-dd HH:mm:ss）"); return 2; }
                    ScanBaseline.Save(box, dt, "", ScanBaseline.SourceBackfill, overwrite: true);
                    Console($"{box} 扫码基准已设为 {dt:yyyy-MM-dd HH:mm:ss}（来源：手动补录）");
                    return 0;
                }
                case "stop": BoxRuntime.StopForce(box, true); return 0;
                case "clear": BoxRuntime.ClearLogin(box); return 0;
                case "delbox":
                case "removebox":
                    var removed = BoxSetup.RemoveBox(box);
                    Console(removed
                        ? $"已删除沙箱 {box}（含登录、游戏包、备注、保活任务、配置、快捷方式）"
                        : $"已清除沙箱 {box} 的数据，但 Sandboxie 配置未确认删除（见 logs\\{box}.log）");
                    return removed ? 0 : 1;
                case "cred-save":
                case "cred-load":
                {
                    // 重放实验用：把整套凭证导出到目录 / 从目录写回沙箱 live
                    string dir = "";
                    for (int i = 0; i < args.Length - 1; i++)
                        if (args[i].Equals("--dir", StringComparison.OrdinalIgnoreCase)) dir = args[i + 1];
                    if (dir.Length == 0) { Console($"用法：JskpBoxManager.exe {cmd} {box} --dir 目录"); return 2; }
                    if (cmd == "cred-load" && Sandboxie.Pids(box).Count > 0)
                    { Console($"{box} 还在运行，先 stop {box} 再导入"); return 1; }
                    bool ok = cmd == "cred-save" ? Ilink.ExportLive(box, dir) : Ilink.ImportToLive(box, dir);
                    Console($"{cmd} {box} {(ok ? "成功" : "失败（沙箱里没有 ilink 凭证？）")} dir={dir}");
                    if (ok) Console((cmd == "cred-save" ? "已导出：" : "已写回 live：") + Ilink.Live(box));
                    return ok ? 0 : 1;
                }
                case "role":
                    var r = RoleCapture.ReadOnce(box, true, !args.Contains("--dry"));
                    Console($"{box}  {r.Message}");
                    return r.NameFound ? 0 : 1;
                case "status":
                    var keep = Keepalive.Load();
                    var s = BoxSummary.Build(box, Notes.Load(), keep, BoxSummary.LastRefreshEvents(), AuthChain.Load());
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
    /// --appdir 指向含 profiles 的安装目录。hook 在 exe 旁没有金库时（例如从仓库 bin 目录运行），
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
        // capture/keylog/unpack/getcode 必须和界面、协议服务用同一个目录，不能跳到别的安装目录
        if (cmd is not ("hook")) return;
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

    static int RunUnpack(string box, string[] args)
    {
        string outDir = "";
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals("--out", StringComparison.OrdinalIgnoreCase)) outDir = args[i + 1];
        var found = Wxapkg.Locate(box);
        Console($"找到 {found.Count} 个 .wxapkg：");
        foreach (var f in found.Take(20))
            Console($"  {f.Size / 1024}KB  {f.WriteUtc.ToLocalTime():MM-dd HH:mm}  {f.Rel}");
        if (found.Count == 0)
        {
            Console("没有包。请先启动一次游戏让沙箱下载，或确认金库里有 Applet 缓存。");
            return 1;
        }
        var r = Wxapkg.UnpackBox(box, string.IsNullOrWhiteSpace(outDir) ? null : outDir);
        if (!r.Ok)
        {
            Console("解包失败：" + r.Error);
            if (r.OutDir.Length > 0) Console("输出目录：" + r.OutDir);
            return 1;
        }
        Console($"解包成功：{r.Files} 个文件 → {r.OutDir}");
        Console("登录相关线索（login-hints.txt）：");
        foreach (var h in r.LoginHits.Take(40)) Console("  " + h);
        if (r.LoginHits.Count == 0) Console("  （未自动命中关键词，请到输出目录里搜 login / code / session）");
        return 0;
    }

    /// <summary>本机协议服务：脚本用 JSKP_SERVER 指向这里取 wx.login code。Ctrl+C 结束。</summary>
    static int RunServer(string[] args)
    {
        ApplyAppDir(args);
        var cfg = ProtocolConfig.Load();
        cfg.Enabled = true;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals("--port", StringComparison.OrdinalIgnoreCase) && int.TryParse(args[i + 1], out int p))
                cfg.Port = Math.Clamp(p, 1024, 65535);
            if (args[i].Equals("--token", StringComparison.OrdinalIgnoreCase))
                cfg.Token = args[i + 1];
        }
        ProtocolConfig.EnsureToken(cfg);
        ProtocolConfig.Save(cfg);
        var srv = new ProtocolServer();
        srv.Start(cfg);
        if (!srv.Running)
        {
            Console("协议服务启动失败：" + srv.LastError);
            return 1;
        }
        Console($"协议服务已启动 {srv.BaseUrl}");
        Console($"环境变量示例：");
        Console($"  set JSKP_SERVER={srv.BaseUrl}");
        Console($"  set JSKP_PROTOCOL_TOKEN={cfg.Token}");
        Console($"取码：POST {srv.BaseUrl}/wxapp/getCode  JSON {{\"ref\":\"qb1\",\"app_id\":\"{AppInfo.GameAppId}\"}}");
        Console("按 Ctrl+C 结束。");
        try { Thread.Sleep(Timeout.Infinite); }
        catch { }
        finally { srv.Stop(); }
        return 0;
    }

    /// <summary>命令行直接取一次 code（不经 HTTP）。</summary>
    static int RunGetCode(string[] args)
    {
        var box = args.Length >= 2 ? args[1] : "";
        if (!Sandboxie.IsBoxName(box) && !Regex.IsMatch(box ?? "", @"^\d+$"))
        {
            Console("用法：JskpBoxManager.exe getcode qbN [--no-ensure]");
            return 2;
        }
        bool ensure = !args.Any(a => a.Equals("--no-ensure", StringComparison.OrdinalIgnoreCase));
        var r = WxLoginCode.Get(box, AppInfo.GameAppId, ensure);
        if (!r.Ok)
        {
            Console("取码失败：" + r.Error);
            return 1;
        }
        Console(r.Code);
        return 0;
    }

    /// <summary>
    /// 命令行：JskpBoxManager.exe notify [--check|--test] [--appdir 目录]
    ///   --check（默认）扫描所有沙箱，把超过阈值没续期的推给用户；
    ///   --test       发一条测试消息，验证通道是否配好。
    /// </summary>
    static int RunNotify(string[] args)
    {
        var cfg = NotifyConfig.Load();
        if (args.Contains("--test"))
        {
            if (!cfg.Ready)
            {
                Console("通知未启用或没填推送密钥（程序目录 notify.json）");
                return 2;
            }
            var err = Notifier.SendTest(cfg);
            Console(err == null ? $"测试消息已通过 {cfg.Describe()} 发出，请查收" : "发送失败：" + err);
            return err == null ? 0 : 1;
        }
        if (!cfg.Ready)
        {
            Console("通知未启用或没填推送密钥（程序目录 notify.json）");
            return 2;
        }
        var boxes = Sandboxie.QueryBoxes();
        if (args.Contains("--probe"))
        {
            int ok = 0, bad = 0, skip = 0;
            foreach (var b in boxes)
            {
                var r = CredentialProbe.Probe(b, cfg);
                if (r.Skipped) { skip++; Console($"{b}  跳过：{r.Message}"); }
                else if (r.Ok) { ok++; Console($"{b}  有效（已换新 key）"); }
                else if (r.Rejected) { bad++; Console($"{b}  已失效：{r.Message}"); }
                else { bad++; Console($"{b}  探测失败：{r.Message}"); }
            }
            Console($"探测完成：{ok} 有效，{bad} 失效/失败，{skip} 跳过");
            return bad > 0 ? 1 : 0;
        }

        var r2 = Notifier.Check(boxes, cfg);
        if (r2.Overdue == 0)
        {
            Console($"检查了 {boxes.Count} 个沙箱，没有超过 {cfg.WarnHours:0.#} 小时未续期的账号");
            return 0;
        }
        if (r2.Failed)
        {
            Console($"发现 {r2.Overdue} 个超期账号，但推送失败：{r2.Error}");
            return 1;
        }
        Console($"已提醒 {r2.Sent} 个超期账号（通过 {cfg.Describe()}）");
        return 0;
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

    /// <summary>WinExe CLI 输出：EnsureCliConsole 会把 stdout 统一绑成 UTF-8（被重定向或弹控制台都是），避免中文乱码。</summary>
    static void Console(string text)
    {
        try
        {
            Win32.EnsureCliConsole();
            System.Console.WriteLine(text);
        }
        catch
        {
            try
            {
                using var w = new StreamWriter(System.Console.OpenStandardOutput(), new System.Text.UTF8Encoding(false));
                w.WriteLine(text);
            }
            catch { }
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _guiMutex?.ReleaseMutex(); } catch { }
        base.OnExit(e);
    }
}
