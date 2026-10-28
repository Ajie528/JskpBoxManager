namespace JskpBoxManager.Core;

/// <summary>沙箱 live 与金库之间同步运行时状态和游戏包（凭证本身由 <see cref="Ilink"/> 负责）。</summary>
public static class VaultSync
{
    static readonly string[] RuntimeTops = { "WMPF", "mmkv", "web", "xworker", "xwebConfig", "locales", "crashpad" };
    const string GameCache = "__GAME_FILE_CACHE";

    static readonly EnumerationOptions Deep = new() { RecurseSubdirectories = true, IgnoreInaccessible = true };

    static IEnumerable<string> GameCacheDirs(string root)
    {
        if (!Directory.Exists(root)) return Enumerable.Empty<string>();
        try { return Directory.EnumerateDirectories(root, GameCache, Deep).ToList(); }
        catch { return Enumerable.Empty<string>(); }
    }

    static string RelTo(string root, string full) => full[root.TrimEnd('\\').Length..].TrimStart('\\');

    /// <summary>金库 → 沙箱。凭证按「新覆盖旧」；沙箱凭证已是最新时，其余运行时文件只补缺，不拿旧文件回滚。</summary>
    public static void PushVaultToLive(string box)
    {
        var vault = BoxPaths.WmpfVault(box);
        var live = BoxPaths.WmpfLive(box);
        if (!Directory.Exists(vault)) return;
        Directory.CreateDirectory(live);

        foreach (var dir in new[] { "WmpfCache", "cache" })
        {
            var s = Path.Combine(vault, dir);
            if (Directory.Exists(s)) Robo.MergeNewer(s, Path.Combine(live, dir));
        }
        var cred = Ilink.Restore(box, "push-vault");
        bool liveIsCurrent = cred is "same" or "live-newer" or "revoked";
        var vaultApplet = Path.Combine(vault, "Applet");
        var liveApplet = Path.Combine(live, "Applet");
        if (Directory.Exists(vaultApplet))
        {
            if (liveIsCurrent)
                Robo.Run(vaultApplet, liveApplet, "/E", "/COPY:DAT", "/XC", "/XN", "/XO", "/XD", GameCache, "/R:1", "/W:1");
            else
                Robo.Run(vaultApplet, liveApplet, "/E", "/COPY:DAT", "/XD", GameCache, "/R:2", "/W:2");
            foreach (var c in GameCacheDirs(vaultApplet))
                Robo.MergeNewer(c, Path.Combine(liveApplet, RelTo(vaultApplet, c)));
        }
        foreach (var top in RuntimeTops)
        {
            var s = Path.Combine(vault, top);
            if (!Directory.Exists(s)) continue;
            if (liveIsCurrent) Robo.MergeMissing(s, Path.Combine(live, top));
            else Robo.Mirror(s, Path.Combine(live, top));
        }
        var uuid = Path.Combine(vault, "device_uuid_0");
        var liveUuid = Path.Combine(live, "device_uuid_0");
        if (File.Exists(uuid) && !File.Exists(liveUuid))
            try { File.Copy(uuid, liveUuid, true); } catch { }
        Log.Box(box, $"vault -> live pushed (credential {cred})");
    }

    /// <summary>沙箱 → 金库（运行时状态）。沙箱凭证无效时整套都不写回。</summary>
    public static bool SyncRuntimeFromLive(string box)
    {
        var vault = BoxPaths.WmpfVault(box);
        var live = BoxPaths.WmpfLive(box);
        if (!Directory.Exists(live)) return false;
        Directory.CreateDirectory(vault);
        var cred = Ilink.Save(box, "sync-live");
        if (cred != "saved" && cred != "unchanged") return false;
        foreach (var top in RuntimeTops)
        {
            var s = Path.Combine(live, top);
            if (Directory.Exists(s)) Robo.Mirror(s, Path.Combine(vault, top));
        }
        var liveApplet = Path.Combine(live, "Applet");
        if (Directory.Exists(liveApplet))
            Robo.Run(liveApplet, Path.Combine(vault, "Applet"), "/E", "/COPY:DAT", "/XD", GameCache, "/R:2", "/W:2");
        return true;
    }

    public sealed record PackageFingerprint(DateTime Newest, string LaunchConfig);

    /// <summary>用缓存目录最新文件时间 + launch.config 判断是否有热更新（只取样，不全量统计）。</summary>
    public static PackageFingerprint Fingerprint(string wmpfRoot)
    {
        var newest = DateTime.MinValue;
        if (!Directory.Exists(wmpfRoot)) return new(newest, "");
        foreach (var c in GameCacheDirs(wmpfRoot))
        {
            try
            {
                var top = new DirectoryInfo(c).EnumerateFiles("*", Deep).OrderByDescending(f => f.LastWriteTime).Take(30);
                foreach (var f in top) if (f.LastWriteTime > newest) newest = f.LastWriteTime;
                var dt = Directory.GetLastWriteTime(c);
                if (dt > newest) newest = dt;
            }
            catch { }
        }
        string stamp = "";
        try
        {
            var lc = new DirectoryInfo(wmpfRoot).EnumerateFiles("launch.config", Deep).OrderByDescending(f => f.LastWriteTime).FirstOrDefault();
            if (lc != null)
            {
                stamp = $"{lc.LastWriteTime:yyyyMMddHHmmss}:{lc.Length}";
                if (lc.LastWriteTime > newest) newest = lc.LastWriteTime;
            }
        }
        catch { }
        return new(newest, stamp);
    }

    public static bool LivePackageNewerThanVault(string box)
    {
        var live = Fingerprint(BoxPaths.WmpfLive(box));
        var vault = Fingerprint(BoxPaths.WmpfVault(box));
        if (live.Newest == DateTime.MinValue) return false;
        if (vault.Newest == DateTime.MinValue) return true;
        if (live.Newest > vault.Newest.AddSeconds(20)) return true;
        return live.LaunchConfig.Length > 0 && live.LaunchConfig != vault.LaunchConfig;
    }

    /// <summary>只合并游戏下载/缓存树和热更新元数据，较新的覆盖较旧的。返回有变化的项数。</summary>
    public static int SyncGamePackage(string srcRoot, string dstRoot)
    {
        if (!Directory.Exists(srcRoot)) return 0;
        Directory.CreateDirectory(dstRoot);
        int n = 0;
        foreach (var dir in new[] { "WmpfCache", "cache" })
        {
            var s = Path.Combine(srcRoot, dir);
            if (Directory.Exists(s) && Robo.Copied(Robo.MergeNewer(s, Path.Combine(dstRoot, dir)))) n++;
        }
        var srcApplet = Path.Combine(srcRoot, "Applet");
        if (!Directory.Exists(srcApplet)) return n;
        foreach (var c in GameCacheDirs(srcApplet))
            if (Robo.Copied(Robo.MergeNewer(c, Path.Combine(dstRoot, RelTo(srcRoot, c))))) n++;

        IEnumerable<FileInfo> patchFiles;
        try
        {
            patchFiles = new DirectoryInfo(srcApplet).EnumerateFiles("*", Deep)
                .Where(f => f.Name is "patchFuncIndexList.json" or "adapter-config.json" or "launch.config")
                .Where(f => !f.FullName.Contains("\\" + GameCache + "\\", StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
        catch { patchFiles = Enumerable.Empty<FileInfo>(); }
        foreach (var f in patchFiles)
        {
            var dst = Path.Combine(dstRoot, RelTo(srcRoot, f.FullName));
            bool copy = true;
            if (File.Exists(dst))
            {
                var di = new FileInfo(dst);
                // 补丁索引以更大的为准（更新完成），避免较新但被截断的文件覆盖
                if (f.Name == "patchFuncIndexList.json")
                {
                    if (f.Length < di.Length) copy = false;
                    else if (f.Length == di.Length && f.LastWriteTime <= di.LastWriteTime) copy = false;
                }
                else if (f.LastWriteTime <= di.LastWriteTime && f.Length <= di.Length) copy = false;
            }
            if (!copy) continue;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                File.Copy(f.FullName, dst, true);
                n++;
            }
            catch { }
        }
        return n;
    }

    /// <summary>把沙箱里的游戏包收进金库（清沙箱后不必重新下载）。</summary>
    public static int HarvestGamePackage(string box)
    {
        var n = SyncGamePackage(BoxPaths.WmpfLive(box), BoxPaths.WmpfVault(box));
        if (n > 0)
        {
            Log.Box(box, $"game package harvested sandbox -> vault items~{n}");
            try { File.WriteAllText(Path.Combine(BoxPaths.Vault(box), "game-package-ok.txt"), $"ok {DateTime.Now:yyyy-MM-dd HH:mm:ss} items~{n}"); } catch { }
        }
        return n;
    }

    /// <summary>
    /// 启动前准备：沙箱凭证有效就先存进金库；无效/缺失时从金库还原。
    /// 沙箱被整箱清空（没有 Applet）时直接完整还原，省掉一次必失败的冷启动和游戏包重新下载。
    /// </summary>
    public static void PrepareBeforeLaunch(string box)
    {
        try
        {
            var live = BoxPaths.WmpfLive(box);
            bool liveEmpty = !Directory.Exists(Path.Combine(live, "Applet"));
            if (liveEmpty && Directory.Exists(BoxPaths.WmpfVault(box)))
            {
                Log.Box(box, "sandbox runtime empty -> full restore from vault before launch");
                PushVaultToLive(box);
                return;
            }
            if (Ilink.Live(box).Valid) Ilink.Save(box, "pre-launch");
            else Ilink.Restore(box, "pre-launch-live-missing");
        }
        catch (Exception ex)
        {
            Log.Box(box, "pre-launch ilink check error: " + ex.Message);
        }
    }
}
