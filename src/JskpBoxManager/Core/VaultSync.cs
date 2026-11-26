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
        Log.Box(box, $"金库 → 沙箱 已推送（凭证 {cred}）");
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

    /// <summary>
    /// 缓存目录的定位缓存（按根目录记）。
    ///
    /// <para>
    /// 1.5.65 之前 <see cref="Fingerprint"/> 每次都调 <see cref="GameCacheDirs"/>，
    /// 而它用 <c>Directory.EnumerateDirectories(root, "__GAME_FILE_CACHE", Deep)</c>
    /// 递归扫遍整个根目录——实测 qb1 金库要 **1110ms** 才能找到那 1 个目录
    /// （因为它遍历了 4 万个文件）。缓存目录的位置在一个游戏版本周期内不会变，
    /// 没必要每次都重扫。
    /// </para>
    /// </summary>
    static readonly Dictionary<string, string> CacheDirMemo = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 取最新文件时间，但**不枚举全部文件**。
    ///
    /// <para>
    /// 旧写法是 <c>EnumerateFiles("*", Deep).OrderByDescending(LastWriteTime).Take(30)</c>，
    /// 为了取最新 30 个要把 2 万个文件全部枚举并排序（实测 325~443ms）。
    /// </para>
    /// <para>
    /// 新写法利用一个事实：**目录的 LastWriteTime 只会因「其中直接子项被增删」而变化**，
    /// 文件内容被改写不会更新父目录时间。所以「有没有新文件」用目录时间戳判断即可，
    /// 只有怀疑有新内容时才在**浅层**取样（最多 2 层），不再做全递归。
    /// 热更新会新增/替换文件，父目录时间必然会变，这个判据够用。
    /// </para>
    /// </summary>
    static DateTime NewestSample(string root, int maxDepth = 2, int maxEntries = 400)
    {
        var newest = DateTime.MinValue;
        try
        {
            var di = new DirectoryInfo(root);
            if (!di.Exists) return newest;
            var stack = new Stack<(DirectoryInfo Dir, int Depth)>();
            stack.Push((di, 0));
            int seen = 0;
            while (stack.Count > 0 && seen < maxEntries)
            {
                var (dir, depth) = stack.Pop();
                seen++;
                try
                {
                    // 目录自身的时间戳：直接子项增删会更新它
                    if (dir.LastWriteTime > newest) newest = dir.LastWriteTime;
                    foreach (var f in dir.EnumerateFiles())
                    {
                        seen++;
                        if (f.LastWriteTime > newest) newest = f.LastWriteTime;
                        if (seen >= maxEntries) break;
                    }
                    if (depth >= maxDepth) continue;
                    foreach (var sub in dir.EnumerateDirectories())
                        stack.Push((sub, depth + 1));
                }
                catch { }
            }
        }
        catch { }
        return newest;
    }

    /// <summary>用缓存目录最新文件时间 + launch.config 判断是否有热更新（只取样，不全量统计）。</summary>
    public static PackageFingerprint Fingerprint(string wmpfRoot)
    {
        var newest = DateTime.MinValue;
        if (!Directory.Exists(wmpfRoot)) return new(newest, "");

        // 缓存目录位置做了记忆化：找到一次就不再重扫（旧实现每次都递归全目录找它）
        string cacheDir = null;
        if (CacheDirMemo.TryGetValue(wmpfRoot, out var memo) && Directory.Exists(memo)) cacheDir = memo;
        else
        {
            var hit = GameCacheDirs(wmpfRoot).FirstOrDefault();
            if (hit != null)
            {
                cacheDir = hit;
                CacheDirMemo[wmpfRoot] = hit;
            }
        }

        if (cacheDir != null)
        {
            var t = NewestSample(cacheDir);
            if (t > newest) newest = t;
        }

        // launch.config 只在 Applet 下，按已知层级找，不做全递归
        string stamp = "";
        try
        {
            var applet = Path.Combine(wmpfRoot, "Applet");
            if (Directory.Exists(applet))
            {
                foreach (var sub in Directory.EnumerateDirectories(applet))
                {
                    var lc = Path.Combine(sub, "launch.config");
                    if (!File.Exists(lc)) continue;
                    var fi = new FileInfo(lc);
                    var cand = $"{fi.LastWriteTime:yyyyMMddHHmmss}:{fi.Length}";
                    // 取时间最新那个
                    if (stamp.Length == 0 || string.CompareOrdinal(cand, stamp) > 0) stamp = cand;
                    if (fi.LastWriteTime > newest) newest = fi.LastWriteTime;
                }
            }
            // Applet 直属也可能有
            var direct = Path.Combine(applet, "launch.config");
            if (File.Exists(direct))
            {
                var fi = new FileInfo(direct);
                var cand = $"{fi.LastWriteTime:yyyyMMddHHmmss}:{fi.Length}";
                if (string.CompareOrdinal(cand, stamp) > 0) stamp = cand;
                if (fi.LastWriteTime > newest) newest = fi.LastWriteTime;
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
            Log.Box(box, $"游戏包已从沙箱收进金库 约 {n} 项");
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
                Log.Box(box, "沙箱运行时为空 → 启动前从金库完整还原");
                PushVaultToLive(box);
                return;
            }
            if (Ilink.Live(box).Valid) Ilink.Save(box, "pre-launch");
            else Ilink.Restore(box, "pre-launch-live-missing");
        }
        catch (Exception ex)
        {
            Log.Box(box, "启动前凭证检查出错：" + ex.Message);
        }
    }
}
