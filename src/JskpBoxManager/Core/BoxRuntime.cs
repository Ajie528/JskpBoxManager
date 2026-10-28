using System.Diagnostics;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

public static class BoxRuntime
{
    // ---------- 浏览器启动 ----------

    /// <summary>箱内更新会把 chrome_elf.dll 改名为 *_del_*，沙箱视图就挡住硬盘上的真文件。</summary>
    static void EnsureQqProgramReadable(string box)
    {
        var exe = EnvDetect.QqCoreExe();
        if (!File.Exists(exe)) return;
        var verDir = Path.GetDirectoryName(exe)!;
        if (!Sandboxie.Query(box, "ReadFilePath").Contains(verDir, StringComparer.OrdinalIgnoreCase))
        {
            Sandboxie.Append(box, "ReadFilePath", verDir);
            Log.Box(box, "ReadFilePath browser core -> " + verDir);
        }
        var m = Regex.Match(verDir, @"^([A-Za-z]):\\(.*)$");
        if (!m.Success) return;
        var overlay = Path.Combine(BoxPaths.SandboxBoxRoot(box), "drive", m.Groups[1].Value, m.Groups[2].Value);
        if (!Directory.Exists(overlay) || File.Exists(Path.Combine(overlay, "chrome_elf.dll"))) return;
        if (Directory.GetFiles(overlay, "chrome_elf.dll_del_*").Length == 0) return;
        if (new BoxView(box).HasQqOrGame)
        {
            Log.Box(box, "skip clearing hidden chrome_elf.dll (browser still running)");
            return;
        }
        try { Directory.Delete(overlay, true); } catch { }
        Log.Box(box, "cleared sandbox copy of browser core (it had hidden chrome_elf.dll)");
    }

    public static List<string> LaunchArgs(string box)
    {
        EnsureQqProgramReadable(box);
        return new List<string>
        {
            EnvDetect.QqCoreExe(),
            "--no-first-run", "--no-sandbox", "--ignore-gpu-blocklist",
            "--disable-session-crashed-bubble", "--hide-crash-restore-bubble",
            "--remote-debugging-port=" + BoxPaths.DebugPort(box), "--remote-allow-origins=*",
            "--wmpf_root_dir=" + BoxPaths.WmpfLive(box),
            AppInfo.GameUrl,
        };
    }

    public static void StartBrowser(string box, string why)
    {
        Sandboxie.StartInBox(box, LaunchArgs(box));
        Log.Box(box, "QQBrowser start issued (" + why + ")");
    }

    /// <summary>沙箱里常强杀 QQ，下次会弹「非正常关闭」并恢复 WXRuntime_Log 旧标签。启动前清掉会话快照，标记正常退出。</summary>
    public static void ClearCrashRestore(string box)
    {
        var ud = BoxPaths.UserData(box);
        if (!Directory.Exists(ud)) return;
        int removed = 0;
        var sess = Path.Combine(ud, "Default", "Sessions");
        if (Directory.Exists(sess))
            foreach (var f in Directory.GetFiles(sess))
                try { File.Delete(f); removed++; } catch { }
        foreach (var rel in new[] { "Current Session", "Current Tabs", "Last Session", "Last Tabs" })
        {
            var p = Path.Combine(ud, "Default", rel);
            try { if (File.Exists(p)) { File.Delete(p); removed++; } } catch { }
        }
        SetJsonField(Path.Combine(ud, "Local State"), "exited_cleanly", "true", false);
        foreach (var pref in new[] { "Preferences", "Preferences_02", "Preferences_01" })
        {
            var p = Path.Combine(ud, "Default", pref);
            SetJsonField(p, "exit_type", "Normal", true);
            SetJsonField(p, "restore_on_startup", "1", false);
        }
        Log.Box(box, $"clear browser crash session files={removed}");
    }

    static void SetJsonField(string path, string field, string value, bool asString)
    {
        try
        {
            if (!File.Exists(path)) return;
            var raw = File.ReadAllText(path);
            var repl = asString ? $"\"{field}\":\"{value}\"" : $"\"{field}\":{value}";
            var pat = asString ? $"\"{Regex.Escape(field)}\"\\s*:\\s*\"[^\"]*\"" : $"\"{Regex.Escape(field)}\"\\s*:\\s*(true|false|\"[^\"]*\"|\\d+)";
            string raw2;
            var re = new Regex(pat);
            if (re.IsMatch(raw)) raw2 = re.Replace(raw, repl, 1);
            else if (Regex.IsMatch(raw, @"^\s*\{")) raw2 = new Regex(@"^\s*\{").Replace(raw, "{" + repl + ",", 1);
            else return;
            if (raw2 != raw) File.WriteAllText(path, raw2);
        }
        catch { }
    }

    /// <summary>首次在沙箱里用微信运行时：把主机上已下载的运行时拷进箱，免得箱内重新下载。</summary>
    public static void EnsureWxRuntimeInBox(string box)
    {
        var hostRt = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Tencent\QQBrowser\User Data", BoxPaths.RuntimeName);
        var boxRt = Path.Combine(BoxPaths.UserData(box), BoxPaths.RuntimeName);
        if (!File.Exists(Path.Combine(hostRt, @"runtime\WeChatAppEx.exe"))) return;
        bool need = !File.Exists(Path.Combine(boxRt, @"runtime\WeChatAppEx.exe"));
        if (!need)
        {
            try { need = Directory.EnumerateFiles(boxRt, "*", SearchOption.AllDirectories).Take(10).Count() < 10; } catch { need = true; }
        }
        if (!need) return;
        try { if (Directory.Exists(boxRt)) Directory.Delete(boxRt, true); } catch { }
        Robo.Run(hostRt, boxRt, "/E", "/COPY:DAT", "/R:1", "/W:1");
        Log.Box(box, "copied WeChat runtime from host into sandbox");
    }

    /// <summary>开机后 SbieSvc 虽已运行，RPC 仍可能长时间超时（SBIE2203）。用 listpids 探测，连续两次够快才算就绪。禁止用 /reload 催服务。</summary>
    public static bool WaitRpcReady(string box, int timeoutSec)
    {
        Sandboxie.EnsureService();
        var deadline = DateTime.Now.AddSeconds(timeoutSec);
        int ok = 0;
        while (DateTime.Now < deadline)
        {
            if (Sandboxie.ProbeListPidsMs(box) <= 4000) { if (++ok >= 2) return true; }
            else ok = 0;
            Thread.Sleep(2000);
        }
        Log.Box(box, "Sbie RPC still slow after wait (SBIE2203 risk) -> continue anyway");
        return false;
    }

    public static bool WaitBoxQuiet(string box, int timeoutSec)
    {
        var deadline = DateTime.Now.AddSeconds(timeoutSec);
        while (DateTime.Now < deadline)
        {
            var pids = Sandboxie.Pids(box);
            if (pids.Count == 0) return true;
            bool busy = pids.Select(ProcessUtil.NameOf).Any(n => n is "cmd" or "powershell" or "conhost" or "QQBrowser" or "WeChatAppEx" or "WeChatAppHost");
            if (!busy) return true;
            Thread.Sleep(400);
        }
        return false;
    }

    /// <summary>冷启动时第一次注入常遇到 SBIE2112/2181，然后 WeChatAppEx SBIE1231。先跑一个小命令把沙箱暖起来。</summary>
    public static void Warmup(string box, bool light)
    {
        Log.Box(box, light ? "warmup sandbox (light retry)" : "warmup sandbox (avoid SBIE2112/2181/1231)");
        if (!light) WaitRpcReady(box, 60);
        WaitBoxQuiet(box, light ? 8 : 12);
        try
        {
            var p = ProcessUtil.StartDetached(EnvDetect.SbieStart, new[] { "/box:" + box, ProcessUtil.System32("cmd.exe"), "/c", "ping -n 3 127.0.0.1 >nul" }, true);
            p?.WaitForExit(10000);
        }
        catch { }
        Thread.Sleep(1000);
        if (!light) WaitBoxQuiet(box, 8);
        EnsureWxRuntimeInBox(box);
        Log.Box(box, "warmup done");
    }

    // ---------- 后台启动进程登记 ----------

    /// <summary>登记本进程为该沙箱的后台启动/看门进程（停止沙箱时据此结束它）。</summary>
    public static void RegisterLauncher(string box, string mode)
    {
        try { File.WriteAllText(AppPaths.BoxLauncherPid(box), $"pid={Environment.ProcessId}\r\nmode={mode}\r\nat={DateTime.Now:o}"); } catch { }
    }

    public static void UnregisterLauncher(string box)
    {
        try
        {
            var p = AppPaths.BoxLauncherPid(box);
            if (File.Exists(p) && File.ReadAllText(p).Contains($"pid={Environment.ProcessId}\r")) File.Delete(p);
        }
        catch { }
    }

    public static int LauncherPid(string box)
    {
        try
        {
            var p = AppPaths.BoxLauncherPid(box);
            if (!File.Exists(p)) return 0;
            var m = Regex.Match(File.ReadAllText(p), @"pid=(\d+)");
            if (!m.Success) return 0;
            int pid = int.Parse(m.Groups[1].Value);
            return ProcessUtil.IsAlive(pid) && ProcessUtil.NameOf(pid).Equals(Path.GetFileNameWithoutExtension(AppInfo.ExePath), StringComparison.OrdinalIgnoreCase) ? pid : 0;
        }
        catch { return 0; }
    }

    public static string LauncherMode(string box)
    {
        if (LauncherPid(box) == 0) return "";
        try
        {
            var m = Regex.Match(File.ReadAllText(AppPaths.BoxLauncherPid(box)), @"mode=(\w+)");
            return m.Success ? m.Groups[1].Value : "";
        }
        catch { return ""; }
    }

    /// <summary>结束该沙箱的后台启动/看门进程，包括旧版 PowerShell 的 launch-qb-game.ps1。</summary>
    public static int StopLaunchers(string box)
    {
        int killed = 0;
        int pid = LauncherPid(box);
        if (pid > 0 && pid != Environment.ProcessId) { ProcessUtil.Kill(pid); killed++; }
        var pattern = new Regex(@"launch-qb-game\.ps1.*-Box\s+" + Regex.Escape(box) + @"\b", RegexOptions.IgnoreCase);
        foreach (var (p, _) in ProcessUtil.FindByCommandLine("powershell.exe", c => pattern.IsMatch(c)))
            if (p != Environment.ProcessId) { ProcessUtil.Kill(p); killed++; }
        try { File.Delete(AppPaths.BoxLauncherPid(box)); } catch { }
        return killed;
    }

    // ---------- 停止 / 清除 ----------

    static void CloseBrowserGracefully(string box, int waitSec)
    {
        var view = new BoxView(box);
        int closed = 0;
        foreach (var pid in view.Pids)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                if (p.ProcessName != "QQBrowser" || p.MainWindowHandle == IntPtr.Zero) continue;
                Win32.RestoreTopLevel(p.MainWindowHandle);
                Win32.PostMessage(p.MainWindowHandle, Win32.WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                closed++;
            }
            catch { }
        }
        if (closed == 0) return;
        var deadline = DateTime.Now.AddSeconds(waitSec);
        while (DateTime.Now < deadline)
        {
            if (!Sandboxie.Pids(box).Any(id => ProcessUtil.NameOf(id) == "QQBrowser")) return;
            Thread.Sleep(400);
        }
    }

    static void KillBoxProcesses(string box)
    {
        foreach (var pid in Sandboxie.Pids(box))
        {
            var n = ProcessUtil.NameOf(pid);
            // 不杀 Sandboxie 自己的助手进程，否则可能弹「无效的沙箱名参数」
            if (n.StartsWith("Sandboxie", StringComparison.OrdinalIgnoreCase) || n is "SbieSvc" or "SbieCtrl" or "SandMan") continue;
            ProcessUtil.Kill(pid);
        }
    }

    /// <summary>停箱前后各存一次凭证；停完标记浏览器正常退出。</summary>
    public static void StopSoft(string box, bool saveLogin)
    {
        if (!Sandboxie.IsBoxName(box)) return;
        try { Ilink.Save(box, "stop-before"); } catch { }
        if (saveLogin)
        {
            // 全量比对上万个游戏文件会让「停止」卡很久：只在指纹显示有热更新时收包
            try { if (VaultSync.LivePackageNewerThanVault(box)) VaultSync.HarvestGamePackage(box); } catch { }
        }
        CloseBrowserGracefully(box, 2);
        KillBoxProcesses(box);
        Thread.Sleep(1000);
        Sandboxie.Terminate(box);
        var deadline = DateTime.Now.AddSeconds(8);
        while (DateTime.Now < deadline && new BoxView(box).HasQqOrGame) Thread.Sleep(500);
        try { Ilink.Save(box, "stop-after"); } catch { }
        if (saveLogin)
        {
            try { VaultSync.SyncRuntimeFromLive(box); } catch { }
        }
        try { ClearCrashRestore(box); } catch { }
    }

    public static void StopForce(string box, bool saveLogin)
    {
        if (!Sandboxie.IsBoxName(box)) return;
        Log.Box(box, "force stop box start");
        int k = StopLaunchers(box);
        if (k > 0) Log.Box(box, $"killed launcher/watch processes={k}");
        StopSoft(box, saveLogin);
        Thread.Sleep(1000);
        Sandboxie.Terminate(box);
        Thread.Sleep(2000);
        var left = Sandboxie.Pids(box);
        if (left.Count > 0)
        {
            KillBoxProcesses(box);
            Sandboxie.Terminate(box);
            Thread.Sleep(1000);
            left = Sandboxie.Pids(box);
        }
        BoxStatusFile.Write(box, BoxPhase.Stopped, "已停止");
        Log.Box(box, $"force stop box end pids_left={left.Count}");
    }

    /// <summary>
    /// 清除登录：删沙箱内容、沙箱和金库里的 ilink 凭证/历史/旧版备份，停保活任务。游戏包和备注保留。
    /// 不走 StopSoft：那里会在停箱前把凭证存回金库。
    /// </summary>
    public static void ClearLogin(string box)
    {
        Log.Box(box, "clear login start");
        StopLaunchers(box);
        Sandboxie.Terminate(box);
        Thread.Sleep(2000);
        Sandboxie.DeleteContentsSilent(box);
        Thread.Sleep(1000);
        var live = BoxPaths.WmpfLive(box);
        foreach (var rel in new[] { "ilink", "device_uuid_0" })
        {
            var p = Path.Combine(live, rel);
            try
            {
                if (Directory.Exists(p)) Directory.Delete(p, true);
                else if (File.Exists(p)) File.Delete(p);
            }
            catch { }
        }
        if (Ilink.Live(box).Valid) Log.Box(box, "clear login WARNING: live ilink credential still present (box busy?)");
        var prof = BoxPaths.Vault(box);
        Directory.CreateDirectory(prof);
        Ilink.ClearVault(box);
        Roles.Clear(box);
        foreach (var rel in new[] { "browser", "backups", "userdata" })
            try { var p = Path.Combine(prof, rel); if (Directory.Exists(p)) Directory.Delete(p, true); } catch { }
        foreach (var rel in new[]
                 {
                     "session-token.json", "oauth-tokens.json", "refresh-need-scan.txt", "refresh-need-scan.event",
                     "refresh-qr-streak.txt", "cookie-count.txt", "cookie-memory.txt", @"wmpf\device_uuid_0", @"wmpf\psk.key",
                 })
            try { File.Delete(Path.Combine(prof, rel)); } catch { }
        foreach (var f in Directory.GetFiles(prof, "login-ok.txt*")) try { File.Delete(f); } catch { }
        Directory.CreateDirectory(BoxPaths.WmpfVault(box));
        try { File.Delete(AppPaths.BoxRefreshPhase(box)); } catch { }
        Keepalive.RemoveTask(box);
        BoxStatusFile.Write(box, BoxPhase.Stopped, "登录已清除，下次启动需要扫码");
        Log.Box(box, "clear login done (vault + sandbox credential removed, game package kept)");
    }

    /// <summary>「释放浏览器内存」：隐藏 QQ 窗口、杀页面渲染进程、回收 QQ 工作集。不动游戏进程。</summary>
    public static string ReleaseBrowserMemory(string box)
    {
        var view = new BoxView(box);
        if (view.Empty) return "沙箱没有在运行。";
        bool game = view.HasGameWindow;
        try { Cdp.CloseExtraTabs(box); } catch { }
        if (game) try { Cdp.CloseQrTabs(box); } catch { }
        int hidden = view.HideBrowserKeepGame(game);
        int killed = game ? view.KillBrowserRenderers() : 0;
        Thread.Sleep(300);
        var (before, after) = new BoxView(box).TrimBrowserMemory();
        Log.Box(box, $"release browser memory hidden={hidden} killed={killed} workingSet {before / 1048576}MB -> {after / 1048576}MB");
        return $"隐藏了 {hidden} 个浏览器窗口，结束 {killed} 个页面进程，QQ 浏览器内存 {before / 1048576} MB → {after / 1048576} MB。";
    }
}
