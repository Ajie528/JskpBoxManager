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

    // ---------- 桌面快捷方式 ----------

    static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    static string SafeFileName(string s) => Regex.Replace(s ?? "", @"[\\/:*?""<>|]", " ").Trim();

    /// <summary>
    /// 快捷方式直接指向本程序 exe + 参数，不经过 PowerShell（旧版 .lnk 里带 powershell -ExecutionPolicy Bypass 会被火绒当木马删）。
    /// 同一沙箱的旧快捷方式（包括旧版指向 shortcuts\qbN.cmd 的）会被替换。
    /// </summary>
    public static string CreateShortcut(string box, string note)
    {
        note = SafeFileName(note);
        var path = Path.Combine(Desktop, note.Length > 0 ? $"jskp-{note}.lnk" : $"jskp-{box}.lnk");
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
                if (name.StartsWith("jskp-", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        dynamic l = shell.CreateShortcut(f);
                        string target = l.TargetPath ?? "";
                        string args = l.Arguments ?? "";
                        sameBox = target.EndsWith(@"\" + box + ".cmd", StringComparison.OrdinalIgnoreCase)
                                  || (target.EndsWith("JskpBoxManager.exe", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(args, @"\blaunch\s+" + box + @"\b"));
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
            lnk.IconLocation = File.Exists(EnvDetect.QqExe) ? EnvDetect.QqExe + ",0" : AppInfo.ExePath + ",0";
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
