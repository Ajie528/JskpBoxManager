using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>从旧版 PowerShell 程序目录（含 launch-qb-game.ps1 和 profiles\）导入金库、备注、保活配置和路径配置。</summary>
public static class Migration
{
    public sealed record Candidate(string Dir, int Boxes, DateTime LastWrite);

    public static bool IsLegacyDir(string dir) =>
        Directory.Exists(Path.Combine(dir, "profiles")) && File.Exists(Path.Combine(dir, "launch-qb-game.ps1"));

    public static bool AlreadyMigrated => File.Exists(AppPaths.MigratedJson);

    public static bool HasOwnData =>
        Directory.Exists(AppPaths.Profiles) && Directory.GetDirectories(AppPaths.Profiles, "qb*").Length > 0;

    public static List<Candidate> FindCandidates()
    {
        var dirs = new List<string> { @"C:\application\jskp-sandbox" };
        var parent = Path.GetDirectoryName(AppPaths.AppDir);
        if (parent != null)
        {
            dirs.Add(Path.Combine(parent, "jskp-auto-login"));
            dirs.Add(Path.Combine(parent, "jskp-sandbox"));
            try { dirs.AddRange(Directory.GetDirectories(parent)); } catch { }
        }
        foreach (var root in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady).Select(d => d.RootDirectory.FullName))
            foreach (var rel in new[] { @"application\jskp-sandbox", @"jskp-sandbox", @"game_script\jskp-auto-login" })
                dirs.Add(Path.Combine(root, rel));

        var list = new List<Candidate>();
        foreach (var d in dirs.Select(x => x.TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (string.Equals(d, AppPaths.AppDir, StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                if (!IsLegacyDir(d)) continue;
                var boxes = Directory.GetDirectories(Path.Combine(d, "profiles"), "qb*");
                var last = boxes.Select(Directory.GetLastWriteTime).DefaultIfEmpty(DateTime.MinValue).Max();
                list.Add(new Candidate(d, boxes.Length, last));
            }
            catch { }
        }
        return list.OrderByDescending(c => c.LastWrite).ToList();
    }

    /// <summary>
    /// 导入：profiles 只补新的（金库里更新的文件不会被旧的盖掉）；配置文件本机没有才拷。
    /// 之后把计划任务改指向本程序、重建桌面快捷方式。
    /// </summary>
    public static string Import(string from, IProgress<string> progress)
    {
        AppPaths.EnsureDirs();
        int boxes = 0;
        foreach (var src in Directory.GetDirectories(Path.Combine(from, "profiles"), "qb*"))
        {
            var box = Path.GetFileName(src);
            progress?.Report($"正在导入 {box} 的金库…");
            Robo.Run(src, Path.Combine(AppPaths.Profiles, box), "/E", "/XO", "/COPY:DAT", "/R:1", "/W:1");
            boxes++;
        }
        var copied = new List<string>();
        foreach (var name in new[] { "box-notes.json", "keepalive.json", "paths.json" })
        {
            var s = Path.Combine(from, name);
            var d = Path.Combine(AppPaths.AppDir, name);
            if (File.Exists(s) && !File.Exists(d))
            {
                File.Copy(s, d);
                copied.Add(name);
            }
        }
        var evSrc = Path.Combine(from, "logs", "ilink-events.jsonl");
        if (File.Exists(evSrc))
        {
            try
            {
                var lines = File.ReadAllText(evSrc);
                File.AppendAllText(AppPaths.EventLog, lines);
            }
            catch { }
        }
        EnvDetect.Reload();

        progress?.Report("正在更新计划任务和快捷方式…");
        var allBoxes = Sandboxie.QueryBoxes();
        var notes = Notes.Load();
        foreach (var b in allBoxes)
        {
            // 新版用自己的金库路径，给沙箱补上对应的放行规则（旧路径保留不影响）
            try
            {
                var prof = BoxPaths.Vault(b);
                Sandboxie.AppendMissing(b, "WriteFilePath", new[] { prof, BoxPaths.WmpfVault(b), BoxPaths.BrowserVault(b) });
                Sandboxie.AppendMissing(b, "OpenFilePath", new[] { prof, BoxPaths.WmpfVault(b), BoxPaths.BrowserVault(b) });
            }
            catch { }
            try { BoxSetup.CreateShortcut(b, notes.GetValueOrDefault(b, "")); } catch { }
        }
        var taskErrors = Keepalive.SyncAll(allBoxes);
        JsonFile.WriteObject(AppPaths.MigratedJson, new JsonObject
        {
            ["from"] = from,
            ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            ["boxes"] = boxes,
            ["app"] = AppInfo.Version,
        });
        Log.App($"imported legacy data from {from} boxes={boxes} files={string.Join(",", copied)} taskErrors={taskErrors.Count}");
        var msg = $"已从 {from} 导入 {boxes} 个沙箱的登录金库。";
        if (copied.Count > 0) msg += $"\n同时导入了：{string.Join("、", copied)}。";
        if (taskErrors.Count > 0) msg += "\n\n部分计划任务没更新成功：\n" + string.Join("\n", taskErrors);
        return msg;
    }

    public static void MarkSkipped()
    {
        JsonFile.WriteObject(AppPaths.MigratedJson, new JsonObject { ["skipped"] = true, ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") });
    }
}
