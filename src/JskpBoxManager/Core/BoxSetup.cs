using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>新建沙箱（Sandboxie 配置与旧版相同）和桌面快捷方式。</summary>
public static class BoxSetup
{
    static readonly string[] BorderColors =
    {
        "#02f6f6", "#22c55e", "#f59e0b", "#ec4899", "#8b5cf6",
        "#06b6d4", "#84cc16", "#f97316", "#ef4444", "#3b82f6",
    };

    public static string NextBoxName(IEnumerable<string> existing)
    {
        var set = new HashSet<string>(existing, StringComparer.OrdinalIgnoreCase);
        int n = 1;
        while (set.Contains("qb" + n)) n++;
        return "qb" + n;
    }

    public static void RepairGlobalImages()
    {
        Sandboxie.AppendMissing("GlobalSettings", "SpecialImage", new[]
        {
            "chrome,WeChatAppEx.exe", "chrome,WeChatAppHost.exe", "chrome,crashpad_handler.exe",
            "chrome,QQBrowser.exe", "chrome,CefRendererProcess.exe",
        });
    }

    public static void ConfigureBox(string box)
    {
        int index = Math.Max(1, Sandboxie.BoxNumber(box));
        foreach (var (k, v) in new[]
                 {
                     ("Enabled", "y"), ("ConfigLevel", "10"), ("UseFileDeleteV2", "y"), ("UseRegDeleteV2", "y"),
                     ("BlockNetworkFiles", "y"), ("DropAdminRights", "n"), ("FakeAdminRights", "y"),
                     // n：避免 WeChatAppEx 的 SBIE2335/2336 界面初始化失败，也让主机能隐藏 QQ 窗口
                     ("UseSbieDeskHack", "n"), ("BoxNameTitle", "y"), ("CopyLimitKb", "1048576"),
                     ("EnableEFS", "n"), ("HideOtherBoxes", "y"),
                 })
            Sandboxie.Set(box, k, v);

        Sandboxie.Set(box, "CustomChromiumFlags", "--disable-features=PrintCompositorLPAC --no-sandbox --ignore-gpu-blocklist --enable-webgl --enable-unsafe-swiftshader --use-angle=d3d11");
        Sandboxie.Set(box, "BorderColor", BorderColors[(index - 1) % BorderColors.Length] + ",ttl");
        Sandboxie.AppendMissing(box, "LingerProcess", new[] { "WeChatAppEx.exe", "WeChatAppHost.exe", "QQBrowser.exe" });
        Sandboxie.AppendMissing(box, "Template", new[] { "SkipHook", "AutoRecoverIgnore", "LingerPrograms", "FileCopy" });

        // 旧配置拦截搜狗会导致沙箱内看不到输入/候选；整表重建，去掉输入法相关项
        var keep = Sandboxie.Query(box, "ClosedFilePath")
            .Where(p => !Regex.IsMatch(p, @"Sogou|SGTool|SGSmart|SogouExe|SoPY|sogoupy|\.ime", RegexOptions.IgnoreCase)).ToList();
        foreach (var p in new[] { @"*\GameAssistEmulator.exe", @"*\GameAssistVm.exe", @"*\TGABoxHeadless.exe", @"*\AndrowsFG.exe" })
            if (!keep.Contains(p)) keep.Add(p);
        Sandboxie.Clear(box, "ClosedFilePath");
        foreach (var p in keep) Sandboxie.Append(box, "ClosedFilePath", p);

        Sandboxie.AppendMissing(box, "OpenIpcPath", new[] { @"\RPC Control\*", @"BaseNamedObjects\*", @"\BaseNamedObjects\*" });
        Sandboxie.AppendMissing(box, "OpenWinClass", new[] { "IME", "MSCTFIME UI", "*SoPY*", "*Sogou*" });

        var prof = BoxPaths.Vault(box);
        var userData = Path.Combine(prof, "userdata");
        foreach (var d in new[] { userData, BoxPaths.WmpfVault(box), BoxPaths.BrowserVault(box) }) Directory.CreateDirectory(d);
        Sandboxie.AppendMissing(box, "WriteFilePath", new[]
        {
            prof, userData, Path.Combine(userData, "WXRuntime_Log"), BoxPaths.WmpfVault(box), BoxPaths.BrowserVault(box),
            @"%Local AppData%\Tencent\QQBrowser\User Data\Default\Network",
            @"%Local AppData%\Tencent\QQBrowser\User Data\WXRuntime_Log",
            @"%Local AppData%\Tencent\QQBrowser\User Data\WXRuntime_Log\mmkv",
            @"%Local AppData%\Tencent\QQBrowser\User Data\WXRuntime_Log\WMPF",
            @"%Local AppData%\Tencent\QQBrowser\User Data\WXRuntime_Log\web",
            @"%AppData%\Tencent\QQPCMgr\radiumv3\wmpfdata",
        });
        Sandboxie.AppendMissing(box, "OpenFilePath", new[] { prof, BoxPaths.WmpfVault(box), BoxPaths.BrowserVault(box) });
        Sandboxie.AppendMissing(box, "HideHostProcess", new[]
        {
            "Weixin.exe", "WeixinExt.exe", "WeChat.exe", "WeChatAppEx.exe", "WeChatAppHost.exe", "QQBrowser.exe", "MAL.exe",
            "GameAssist.exe", "GameAssistLauncher.exe", "GameAssistService.exe", "Androws.exe", "AndrowsLauncher.exe", "CefRendererProcess.exe",
        });
    }

    public static string CreateBox(IEnumerable<string> existing)
    {
        var box = NextBoxName(existing);
        RepairGlobalImages();
        ConfigureBox(box);
        Sandboxie.Reload();
        try { CreateShortcut(box, ""); } catch { }
        return box;
    }

    /// <summary>彻底删除一个沙箱：停箱、删沙箱内容、删金库（登录/游戏包/角色档案/备注）、删保活任务、删 Sandboxie 配置段、删桌面快捷方式。不可恢复。</summary>
    /// <returns>配置段是否已确认删除。false 表示 Sandboxie 那边没删掉（界面应立即提示，而不是假装成功）。</returns>
    public static bool RemoveBox(string box)
    {
        if (!Sandboxie.IsBoxName(box)) throw new ArgumentException("沙箱名不合法：" + box);
        Log.Box(box, "删除沙箱：开始");
        try { BoxRuntime.StopForce(box, false); } catch { }
        try { Sandboxie.DeleteContentsSilent(box); } catch { }
        // delete_sandbox_silent 偶尔不认路（沙箱从没跑过、或 ini 里段已被清空），兜底删磁盘目录
        try
        {
            var root = BoxPaths.SandboxBoxRoot(box);
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
        catch (Exception ex) { Log.Box(box, "删除沙箱：删沙箱目录失败 " + ex.Message); }
        try { Keepalive.RemoveTask(box); } catch { }
        try { RemoveShortcuts(box); } catch { }
        // 删角色档案与备注（否则新沙箱复用了同一个 qbN 会继承上一个号的角色名）
        try { Roles.Clear(box); } catch { }
        try { Notes.Set(box, ""); } catch { }
        // 删金库（整个 profiles\qbN）
        try { var prof = BoxPaths.Vault(box); if (Directory.Exists(prof)) Directory.Delete(prof, true); } catch (Exception ex) { Log.Box(box, "删除沙箱：删金库失败 " + ex.Message); }
        // 删运行时状态/日志旁文件
        try { File.Delete(AppPaths.BoxRefreshPhase(box)); } catch { }
        try { File.Delete(AppPaths.BoxLauncherPid(box)); } catch { }
        try { File.Delete(AppPaths.BoxRenewRequest(box)); } catch { }
        try { File.Delete(AppPaths.BoxState(box)); } catch { }
        try { File.Delete(BoxPaths.NeedScanFile(box)); } catch { }
        try { File.Delete(BoxPaths.NeedScanStamp(box)); } catch { }
        try { File.Delete(BoxPaths.QrStreakFile(box)); } catch { }
        try { ScanBaseline.Clear(box); } catch { }
        // 最后删 Sandboxie 配置段并重载。这一步必须是「确认删掉」才算成功，
        // 否则界面删了、重启又出现——旧版 delete 语法无效就是从这里静默漏掉的。
        bool sectionGone = false;
        try { sectionGone = Sandboxie.DeleteSection(box); }
        catch (Exception ex) { Log.Box(box, "删除沙箱：删 Sandboxie 配置段失败 " + ex.Message); }
        Sandboxie.Reload();
        if (!sectionGone)
            Log.Box(box, "删除沙箱：删完配置段仍在（Sandboxie 未确认删除）");
        Log.Box(box, sectionGone ? "remove box done" : "remove box done (section left)");
        return sectionGone;
    }

    /// <summary>删掉指向该沙箱的桌面快捷方式（qbN.lnk / qbN-角色名.lnk / 老的 jskp-*.lnk，靠 launch 参数判断）。</summary>
    static void RemoveShortcuts(string box)
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null) return;
        dynamic shell = Activator.CreateInstance(shellType);
        try
        {
            foreach (var f in Directory.GetFiles(Desktop, "*.lnk"))
            {
                var name = Path.GetFileName(f);
                bool legacyName = name == $"向僵尸开炮-QQ沙箱{Sandboxie.BoxNumber(box)}.lnk";
                bool match = legacyName;
                if (!match && (name.StartsWith("jskp-", StringComparison.OrdinalIgnoreCase)
                               || Regex.IsMatch(name, @"^qb\d+(-.*)?\.lnk$", RegexOptions.IgnoreCase)))
                {
                    try
                    {
                        dynamic l = shell.CreateShortcut(f);
                        string target = l.TargetPath ?? "";
                        string args = l.Arguments ?? "";
                        match = target.EndsWith(@"\" + box + ".cmd", StringComparison.OrdinalIgnoreCase)
                                || (target.EndsWith("JskpBoxManager.exe", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(args, @"\blaunch\s+" + box + @"\b"));
                    }
                    catch { }
                }
                if (match) try { File.Delete(f); } catch { }
            }
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
        }
    }

    // ---------- 桌面快捷方式 ----------

    static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    static string SafeFileName(string s) => Regex.Replace(s ?? "", @"[\\/:*?""<>|]", " ").Trim();

    /// <summary>
    /// 快捷方式直接指向本程序 exe + 参数，不经过 PowerShell（旧版 .lnk 里带 powershell -ExecutionPolicy Bypass 会被火绒当木马删）。
    /// 同一沙箱的旧快捷方式（包括旧版指向 shortcuts\qbN.cmd 的、以及曾用 jskp- 前缀命名的）会被替换。
    ///
    /// 命名统一为 <c>qbN-角色名</c>（如 <c>qb1-清沫丶.lnk</c>），没有角色名时就叫 <c>qbN</c>。
    /// 箱号在前、角色名在后：桌面按名称排序时同箱的几个会挨在一起，也方便一眼对上界面的列表。
    /// </summary>
    public static string CreateShortcut(string box, string note)
    {
        note = SafeFileName(note);
        var stem = note.Length > 0 ? $"{box}-{note}" : box;
        var path = Path.Combine(Desktop, stem + ".lnk");
        var shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null) return null;
        dynamic shell = Activator.CreateInstance(shellType);
        try
        {
            foreach (var f in Directory.GetFiles(Desktop, "*.lnk"))
            {
                if (string.Equals(f, path, StringComparison.OrdinalIgnoreCase)) continue;
                var name = Path.GetFileName(f);
                bool legacyName = name == $"向僵尸开炮-QQ沙箱{Sandboxie.BoxNumber(box)}.lnk";
                bool sameBox = false;
                // 老命名（jskp-xxx.lnk）、纯箱号（qbN.lnk）、以及带角色名的（qbN-xxx.lnk）
                // 都可能指向同一个箱，统一靠 launch 参数判断，避免改备注后留下残影。
                if (name.StartsWith("jskp-", StringComparison.OrdinalIgnoreCase)
                    || Regex.IsMatch(name, @"^qb\d+(-.*)?\.lnk$", RegexOptions.IgnoreCase))
                {
                    try
                    {
                        dynamic l = shell.CreateShortcut(f);
                        string target = l.TargetPath ?? "";
                        string args = l.Arguments ?? "";
                        sameBox = target.EndsWith(@"\" + box + ".cmd", StringComparison.OrdinalIgnoreCase)
                                  || (target.EndsWith("JskpBoxManager.exe", StringComparison.OrdinalIgnoreCase)
                                      && Regex.IsMatch(args, @"\blaunch\s+" + box + @"\b"));
                    }
                    catch { }
                }
                if (legacyName || sameBox) try { File.Delete(f); } catch { }
            }
            dynamic lnk = shell.CreateShortcut(path);
            lnk.TargetPath = AppInfo.ExePath;
            lnk.Arguments = "launch " + box;
            lnk.WorkingDirectory = AppPaths.AppDir;
            lnk.WindowStyle = 7;
            lnk.Description = note.Length > 0 ? $"向僵尸开炮 {note}（{box}）" : $"向僵尸开炮 {box}";
            // 用本程序自己的图标，不再借 QQ 浏览器的
            lnk.IconLocation = AppInfo.ExePath + ",0";
            lnk.Save();
            return path;
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
        }
    }

    public static string CreateManagerShortcut()
    {
        var path = Path.Combine(Desktop, AppInfo.ProductName + ".lnk");
        var shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null) return null;
        dynamic shell = Activator.CreateInstance(shellType);
        try
        {
            dynamic lnk = shell.CreateShortcut(path);
            lnk.TargetPath = AppInfo.ExePath;
            lnk.Arguments = "";
            lnk.WorkingDirectory = AppPaths.AppDir;
            lnk.Description = AppInfo.ProductName;
            lnk.IconLocation = AppInfo.ExePath + ",0";
            lnk.Save();
            return path;
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
        }
    }
}
