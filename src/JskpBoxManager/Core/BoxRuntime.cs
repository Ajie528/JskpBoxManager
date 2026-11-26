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
            Log.Box(box, "浏览器内核只读路径 → " + verDir);
        }
        var m = Regex.Match(verDir, @"^([A-Za-z]):\\(.*)$");
        if (!m.Success) return;
        var overlay = Path.Combine(BoxPaths.SandboxBoxRoot(box), "drive", m.Groups[1].Value, m.Groups[2].Value);
        if (!Directory.Exists(overlay) || File.Exists(Path.Combine(overlay, "chrome_elf.dll"))) return;
        if (Directory.GetFiles(overlay, "chrome_elf.dll_del_*").Length == 0) return;
        if (new BoxView(box).HasQqOrGame)
        {
            Log.Box(box, "跳过清理被隐藏的 chrome_elf.dll（浏览器还在运行）");
            return;
        }
        try { Directory.Delete(overlay, true); } catch { }
        Log.Box(box, "已清理沙箱内的浏览器内核副本（它藏了 chrome_elf.dll）");
    }

    /// <summary>保活/启动用的浏览器启动命令。Full=游戏中心；RuntimeOnly=只拉起微信运行时（常驻恢复用）。</summary>
    public enum LaunchMode { Full, RuntimeOnly }

    public static List<string> LaunchArgs(string box, LaunchMode mode = LaunchMode.Full)
    {
        EnsureQqProgramReadable(box);
        if (mode == LaunchMode.RuntimeOnly)
        {
            EnsureWxRuntimeInBox(box);
            var exe = Path.Combine(BoxPaths.UserData(box), BoxPaths.RuntimeName, @"runtime\WeChatAppEx.exe");
            return new List<string> { exe, "--wmpf_root_dir=" + BoxPaths.WmpfLive(box) };
        }
        var args = new List<string>
        {
            EnvDetect.QqCoreExe(),
            "--no-first-run", "--no-sandbox", "--ignore-gpu-blocklist",
            "--disable-session-crashed-bubble", "--hide-crash-restore-bubble",
            "--remote-debugging-port=" + BoxPaths.DebugPort(box), "--remote-allow-origins=*",
            "--wmpf_root_dir=" + BoxPaths.WmpfLive(box),
        };
        args.Add(AppInfo.GameUrl);
        return args;
    }

    public static bool StartBrowser(string box, string why, LaunchMode mode = LaunchMode.Full)
    {
        if (!Sandboxie.StartInBox(box, LaunchArgs(box, mode)))
        {
            Log.Box(box, "跳过启动 QQ 浏览器：Sandboxie 里没有这个沙箱");
            BoxStatusFile.Write(box, BoxPhase.Failed, "沙箱在 Sandboxie 里不存在（可能已被删除）");
            return false;
        }
        Log.Box(box, mode == LaunchMode.Full
            ? "QQ 浏览器已启动（" + why + "）"
            : $"QQ 浏览器已启动（{why}，模式={mode}）");
        return true;
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
        Log.Box(box, $"清理浏览器崩溃恢复会话 文件数={removed}");
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
        Log.Box(box, "已把微信运行时从主机复制进沙箱");
    }

    /// <summary>
    /// 检查 Sandboxie 服务是否被拖垮；如果被拖垮且当前有管理员权限，**自动重启服务把它降回基线**。
    ///
    /// <para>
    /// **注意：这个检查与「qb1 卡在游戏中心」那个故障无关。**
    /// 2026-11-26 实测：SbieSvc 重启到 12MB 全新状态后，故障照样复现；
    /// 而后来真正修好它的是「清空卡在驱动里的残留进程」。
    /// 这里保留的只是针对「服务内存异常膨胀」这一独立问题的兜底。
    /// </para>
    /// <para>
    /// **判据只有内存一项，阈值 250MB。** 这是 2026-11-26 用实测数据定的，
    /// 1.5.64 的第一版判据（内存 >100MB 或 线程 >40）是错的：
    /// </para>
    /// <list type="bullet">
    /// <item>线程数没有区分度：重启后立刻就是 65 线程、一整天不变，这是 5.74.1 的常态。</item>
    /// <item>内存 100MB 阈值太低：正常波动就能到 50MB，会误报。</item>
    /// <item>实测健康 → 恶化的分界：重启后 10~18MB，qb12 整夜跑游戏后涨到 172MB。</item>
    /// </list>
    /// <para>
    /// **为什么必须重启服务而不是等它自己降**：实测把 16 个沙箱全停（进程数 0）后
    /// 静置 30 秒，WorkingSet 仍是 177MB 纹丝不动——这是已分配不归还的内存。
    /// </para>
    /// </summary>
    /// <returns>返回给用户看的说明；健康时返回 null。</returns>
    public static string CheckSbieHealth(string box)
    {
        try
        {
            long mb = Sandboxie.ServiceMemoryMb();
            if (mb < 250) return null;

            var head = $"SbieSvc 已涨到 {mb}MB（重启后正常 10~20MB），这会拖垮沙箱："
                     + "浏览器建不出子进程、卡在游戏中心，并刷 SBIE2203。";

            if (!Sandboxie.IsElevated)
            {
                Log.Box(box, "⚠ " + head + " 当前不是管理员，无法自动重启服务 → 请重启电脑。");
                return head + " 当前不是管理员，无法自动重启服务 → 请重启电脑。";
            }

            // 停服务会杀掉所有沙箱内进程，先确认没有沙箱在跑
            int running = 0;
            try
            {
                foreach (var b in Sandboxie.QueryBoxes())
                    if (Sandboxie.Pids(b).Count > 0) running++;
            }
            catch { }
            if (running > 0)
            {
                Log.Box(box, "⚠ " + head + $" 但有 {running} 个沙箱还在跑，暂不重启服务（会杀掉它们）。");
                return head + $" 但有 {running} 个沙箱还在跑，暂不重启服务（会杀掉它们）。";
            }

            Log.Box(box, $"Sandboxie 服务占用 {mb}MB 偏高 → 自动重启 SbieSvc 降回基线");
            BoxStatusFile.Write(box, BoxPhase.Starting, "正在重置 Sandboxie 服务…");
            var err = Sandboxie.RestartService();
            if (err != null)
            {
                Log.Box(box, "⚠ 自动重启 SbieSvc 失败：" + err + " → 请手动重启电脑");
                return head + " 自动重启失败：" + err + " → 请重启电脑。";
            }

            // 重启后等一下让它把运行时库加载完
            Thread.Sleep(2000);
            long after = Sandboxie.ServiceMemoryMb();
            Log.Box(box, $"SbieSvc 已重启：{mb}MB → {after}MB");
            return null;   // 修好了就不必打扰用户
        }
        catch (Exception ex)
        {
            Log.Box(box, "检查 Sandboxie 服务健康度出错：" + ex.Message);
            return null;
        }
    }

    /// <summary>
    /// 清理「实际在沙箱里、但 Sandboxie 已经不认」的残留进程。
    ///
    /// <para>
    /// ★★ **已停用（2026-11-26）**，只保留代码供参考，`Warmup` 里不再调用。
    /// </para>
    /// <para>
    /// **为什么停用**：设计这个函数的依据是「listpids 返回空 = Sandboxie 看不见任何进程」，
    /// 但实测发现——**qb1 正在游戏中（日志有 `role read attack=82855`）时，
    /// `Start.exe /box:qb1 /listpids` 照样稳定返回空**。也就是说
    /// 「listpids 返回空」根本不能区分「沙箱真空」和「沙箱有进程但 API 坏了」。
    /// 按这个判据去清理，会把正在运行的游戏进程全部误杀。
    /// </para>
    /// <para>
    /// 当时确实观察到 22 个 QQBrowser + 4 个孤儿 SandboxieCrypto，
    /// 手动杀掉后 qb1 恢复正常（19 秒进游戏）。但**无法证明那些是「僵尸」还是
    /// 「正常运行的进程」**——同一时刻 qb1 正被看门进程管理着。
    /// 这个因果没搞清楚之前，自动清理是危险的。
    /// </para>
    /// </summary>
    [Obsolete("判据不可靠（listpids 在沙箱有进程时也可能返回空），会误杀运行中的游戏。勿启用。")]
    public static int CleanupZombies(string box)
    {
        try
        {
            // 先看本沙箱有没有活着的进程（listpids 权威）
            var own = Sandboxie.Pids(box);
            if (own.Count > 0) return 0;

            var zombies = Sandboxie.FindZombies(box, own);
            if (zombies.Count == 0) return 0;

            Log.Box(box, $"发现 {zombies.Count} 个卡在 Sandboxie 里的僵尸进程（listpids 看不见它们）"
                + "→ 清理。这会让后续启动不再报 SBIE2203、不再卡在游戏中心");
            int killed = Sandboxie.KillZombies(zombies);
            // 给驱动一点时间回收句柄
            Thread.Sleep(1500);
            Log.Box(box, $"僵尸进程清理完成：杀掉 {killed}/{zombies.Count} 个");
            return killed;
        }
        catch (Exception ex)
        {
            Log.Box(box, "清理僵尸进程出错：" + ex.Message);
            return 0;
        }
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
        Log.Box(box, "等待后 Sbie RPC 仍然很慢（有 SBIE2203 风险）→ 继续执行");
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
        Log.Box(box, light ? "预热沙箱（轻量重试）" : "预热沙箱（规避 SBIE2112/2181/1231）");
        // 先看 Sandboxie 服务本身健不健康：泄漏到一定程度时下面这些预热全都会白做
        CheckSbieHealth(box);
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
        Log.Box(box, "预热完成");
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
        Log.Box(box, "强制停箱：开始");
        int k = StopLaunchers(box);
        if (k > 0) Log.Box(box, $"已结束后台启动/看门进程 数量={k}");
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
        Log.Box(box, $"强制停箱：结束 剩余进程={left.Count}");
    }

    /// <summary>
    /// 清除登录：删沙箱内容、沙箱和金库里的 ilink 凭证/历史/旧版备份，停保活任务。游戏包和备注保留。
    /// 不走 StopSoft：那里会在停箱前把凭证存回金库。
    /// </summary>
    public static void ClearLogin(string box)
    {
        Log.Box(box, "清除登录：开始");
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
        if (Ilink.Live(box).Valid) Log.Box(box, "清除登录警告：沙箱里的 ilink 凭证还在（沙箱没停干净？）");
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
        ScanHint.Clear(box);
        foreach (var f in Directory.GetFiles(prof, "login-ok.txt*")) try { File.Delete(f); } catch { }
        Directory.CreateDirectory(BoxPaths.WmpfVault(box));
        try { File.Delete(AppPaths.BoxRefreshPhase(box)); } catch { }
        Keepalive.RemoveTask(box);
        BoxStatusFile.Write(box, BoxPhase.Stopped, "登录已清除，下次启动需要扫码");
        Log.Box(box, "清除登录完成（金库与沙箱凭证已删，游戏包保留）");
        // 登录清掉了，授权窗口的起点也随之失效；下次扫码会重新写基准
        ScanBaseline.Clear(box);
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
        Log.Box(box, $"释放浏览器内存 隐藏窗口={hidden} killed={killed} workingSet {before / 1048576}MB -> {after / 1048576}MB");
        return $"隐藏了 {hidden} 个浏览器窗口，结束 {killed} 个页面进程，QQ 浏览器内存 {before / 1048576} MB → {after / 1048576} MB。";
    }

    /// <summary>深度压缩：含游戏本体（WeChatAppEx）一起压工作集。工作集会大降，但正在玩时会回升、提交(私有字节)不变。
    /// 注意：压游戏本体会把 ilink 心跳/网络线程换出，可能拖断长连接——仅供手动点一下看效果，别用在保活/常驻上。</summary>
    public static string DeepTrimMemory(string box)
    {
        var view = new BoxView(box);
        if (view.Empty) return "沙箱没有在运行。";
        // 常驻态靠 ilink 长连接活着：压掉游戏本体等于把心跳线程换出，实测会直接 AppSessionTimeout 掉线，
        // 之后只能重新扫码（qb4 11-03 压完 24 分钟内就 sessiontimeout，第二天要扫码）。这种情况只压浏览器。
        if (BoxStatusFile.Read(box)?.Phase == BoxPhase.Resident)
        {
            try { Cdp.CloseExtraTabs(box); } catch { }
            var (b0, a0) = view.TrimBrowserMemory();
            Log.Box(box, $"拒绝深度压缩（常驻需要保住长连接）→ 只压 QQ 浏览器 {b0 / 1048576}MB -> {a0 / 1048576}MB");
            return $"常驻保活中，为保住 ilink 长连接只压了 QQ 浏览器：{b0 / 1048576} MB → {a0 / 1048576} MB。要压游戏请先停掉常驻。";
        }
        try { Cdp.CloseExtraTabs(box); } catch { }
        var (before, after) = view.TrimAllMemory();
        Log.Box(box, $"深度压缩内存（含游戏）工作集 {before / 1048576}MB -> {after / 1048576}MB");
        return $"工作集 {before / 1048576} MB → {after / 1048576} MB（含游戏，正玩会回升；提交不变）";
    }

    /// <summary>自动压内存：只压 QQ 浏览器工作集，**不动**游戏本体 WeChatAppEx（避免把心跳/长连接线程换出）。</summary>
    public static string AutoTrimMemory(string box)
    {
        var view = new BoxView(box);
        if (view.Empty) return "沙箱没有在运行。";
        try { Cdp.CloseExtraTabs(box); } catch { }
        var (before, after) = view.TrimBrowserMemory();
        Log.Box(box, $"自动压缩内存（仅 QQ 浏览器）工作集 {before / 1048576}MB -> {after / 1048576}MB");
        return $"QQ 浏览器工作集 {before / 1048576} MB → {after / 1048576} MB（不含游戏）";
    }    /// <summary>删掉 QQ 浏览器的纯缓存目录（HTTP 缓存 / 代码缓存 / GPU 缓存 / Service Worker）。不动登录凭证、cookies、游戏包。</summary>
    static int ClearBrowserCache(string box)
    {
        var def = Path.Combine(BoxPaths.UserData(box), "Default");
        int n = 0;
        foreach (var rel in new[] { "Cache", "Code Cache", "GPUCache", "Service Worker", "Service Worker\\CacheStorage", "DawnCache", "GrShaderCache" })
        {
            var p = Path.Combine(def, rel);
            try { if (Directory.Exists(p)) { Directory.Delete(p, true); n++; } } catch { }
        }
        foreach (var rel in new[] { "ShaderCache", "GrShaderCache", "GraphiteDawnCache" })
        {
            var p = Path.Combine(BoxPaths.UserData(box), rel);
            try { if (Directory.Exists(p)) { Directory.Delete(p, true); n++; } } catch { }
        }
        return n;
    }

    /// <summary>
    /// 免扫重试：停箱 → 清本地会话/浏览器缓存（保留金库免扫凭证）→ 清需扫码/作废标记 → 还原金库凭证。
    /// 处理「本地缓存/凭证损坏弹扫码，但服务器上的 AutoAuthKey 其实还有效」的情况；真被顶（服务端 ret=-13 / 自然过期）时冷启后仍会弹扫码。
    /// 返回 (Ok, Message)：Ok=false 表示金库里根本没有可用免扫凭证，这次只能重新扫码。
    /// </summary>
    public static (bool Ok, string Message) ScanFreeRelogin(string box)
    {
        var vault = Ilink.VaultState(box);
        if (!vault.Valid)
            return (false, "金库里没有可用的免扫凭证，这次只能重新扫码。");

        Log.Box(box, "免扫重试：停箱、清本地会话与缓存、清需扫码/作废标记、还原金库");
        StopLaunchers(box);
        Sandboxie.Terminate(box);
        Thread.Sleep(1500);

        ClearCrashRestore(box);
        int cleared = ClearBrowserCache(box);

        // 用户明确赌这次扫码框是本地损坏：清需扫码标记 + 撤销作废登记，真被顶的话冷启后会重新弹出来
        NeedScan.Clear(box);
        NeedScan.ClearQrStreak(box);
        Ilink.ClearRevoked(box);
        ScanHint.ClearQrScanMarks(box);

        var cred = Ilink.Restore(box, "scan-free-relogin");
        Log.Box(box, $"免扫重试就绪 已清缓存目录={cleared} 个，金库 key {vault.KeyHash} restore={cred}");
        return (true, $"已清本地会话与缓存、还原免扫凭证（key {vault.KeyHash}），正在重新免扫进入…");
    }

    /// <summary>
    /// 手动试某一把历史 key：停箱 → 清本地会话/缓存 → 撤销这把 key 的作废登记 → 把它写进 live。之后由调用方冷启验证。
    /// </summary>
    public static (bool Ok, string Message) TryHistoryKey(string box, string srcDir, string keyHash)
    {
        Log.Box(box, $"试历史 key {keyHash}：停箱、清缓存、写入沙箱");
        StopLaunchers(box);
        Sandboxie.Terminate(box);
        Thread.Sleep(1500);

        ClearCrashRestore(box);
        ClearBrowserCache(box);
        NeedScan.Clear(box);
        NeedScan.ClearQrStreak(box);
        Ilink.ClearRevokedKey(box, keyHash);
        ScanHint.ClearQrScanMarks(box);

        if (!Ilink.RestoreCredentialSet(box, srcDir))
            return (false, "这份备份读不出有效凭证。");
        return (true, $"已写入历史 key {(keyHash.Length >= 8 ? keyHash[..8] : keyHash)}，正在冷启动验证…");
    }
}
