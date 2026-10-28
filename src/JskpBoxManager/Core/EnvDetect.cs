using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace JskpBoxManager.Core;

/// <summary>
/// 自动识别 Sandboxie-Plus、QQ 浏览器和沙箱根目录。需要手工指定时写 paths.json：
/// { "qqExe": "...", "sbieStart": "...", "sandboxRoot": "..." }（与旧版相同）
/// </summary>
public static class EnvDetect
{
    static readonly object Gate = new();
    static bool _loaded;
    static string _sbieStart = "", _qqExe = "", _sandboxRoot = "";

    public static string SbieStart { get { Load(); return _sbieStart; } }
    public static string SbieDir => string.IsNullOrEmpty(SbieStart) ? "" : Path.GetDirectoryName(SbieStart)!;
    public static string SbieIni => string.IsNullOrEmpty(SbieDir) ? "" : Path.Combine(SbieDir, "SbieIni.exe");
    public static string QqExe { get { Load(); return _qqExe; } }
    public static string SandboxRoot { get { Load(); return _sandboxRoot; } }

    public static bool SbieOk => File.Exists(SbieStart) && File.Exists(SbieIni);
    public static bool QqOk => File.Exists(QqExe);

    public static void Reload()
    {
        lock (Gate) { _loaded = false; }
        Load();
    }

    static void Load()
    {
        lock (Gate)
        {
            if (_loaded) return;
            _sbieStart = FindSbieStart() ?? "";
            _qqExe = FindQqBrowser() ?? "";
            _sandboxRoot = FindSandboxRoot();
            _loaded = true;
        }
    }

    public static string ConfigValue(string key)
    {
        var o = JsonFile.ReadObject(AppPaths.PathsJson);
        return JsonFile.Str(o, key).Trim();
    }

    public static void SaveConfigValue(string key, string value)
    {
        var o = JsonFile.ReadObject(AppPaths.PathsJson) ?? new JsonObject();
        if (string.IsNullOrWhiteSpace(value)) o.Remove(key);
        else o[key] = value;
        JsonFile.WriteObject(AppPaths.PathsJson, o);
        Reload();
    }

    static IEnumerable<string> FixedDriveRoots()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            bool ok;
            try { ok = d.DriveType == DriveType.Fixed && d.IsReady; } catch { ok = false; }
            if (ok) yield return d.RootDirectory.FullName;
        }
    }

    static string Reg(RegistryKey root, string path, string name)
    {
        try
        {
            using var k = root.OpenSubKey(path);
            return k?.GetValue(name)?.ToString() ?? "";
        }
        catch { return ""; }
    }

    static IEnumerable<(string DisplayName, RegistryKey Key)> UninstallEntries(bool includeUser)
    {
        var roots = new List<(RegistryKey, string)>
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        };
        if (includeUser) roots.Add((Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"));
        foreach (var (root, path) in roots)
        {
            RegistryKey baseKey;
            try { baseKey = root.OpenSubKey(path); } catch { continue; }
            if (baseKey == null) continue;
            using (baseKey)
            {
                foreach (var sub in baseKey.GetSubKeyNames())
                {
                    RegistryKey k;
                    try { k = baseKey.OpenSubKey(sub); } catch { continue; }
                    if (k == null) continue;
                    var name = k.GetValue("DisplayName")?.ToString() ?? "";
                    yield return (name, k);
                    k.Dispose();
                }
            }
        }
    }

    static string StartExeFromRawPath(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var v = raw.Trim();
        if (v.StartsWith('"'))
        {
            int end = v.IndexOf('"', 1);
            v = end > 1 ? v[1..end] : v.Trim('"');
        }
        else
        {
            var m = Regex.Match(v, @"^(?i)(.*?\.(?:exe|sys))\b");
            if (m.Success) v = m.Groups[1].Value;
        }
        v = Regex.Replace(v, @"^\\+\?\?\\", "");
        v = Regex.Replace(v, @"^\\\\\?\\", "");
        v = Environment.ExpandEnvironmentVariables(v);
        var sr = Regex.Match(v, @"^(?i)\\SystemRoot\\(.*)$");
        if (sr.Success) v = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), sr.Groups[1].Value);
        try
        {
            if (!File.Exists(v)) return null;
            var start = Path.Combine(Path.GetDirectoryName(v)!, "Start.exe");
            return File.Exists(start) ? start : null;
        }
        catch { return null; }
    }

    static string FindSbieStart()
    {
        var cfg = ConfigValue("sbieStart");
        if (cfg.Length > 0 && File.Exists(cfg)) return cfg;

        foreach (var svc in new[] { "SbieSvc", "SbieDrv" })
        {
            var hit = StartExeFromRawPath(Reg(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\" + svc, "ImagePath"));
            if (hit != null) return hit;
        }

        foreach (var (name, k) in UninstallEntries(false))
        {
            if (!name.Contains("Sandboxie", StringComparison.OrdinalIgnoreCase)) continue;
            var loc = (k.GetValue("InstallLocation")?.ToString() ?? "").Trim().Trim('"').TrimEnd('\\');
            if (loc.Length > 0 && File.Exists(Path.Combine(loc, "Start.exe"))) return Path.Combine(loc, "Start.exe");
            foreach (var prop in new[] { "DisplayIcon", "UninstallString", "QuietUninstallString" })
            {
                var hit = StartExeFromRawPath(k.GetValue(prop)?.ToString());
                if (hit != null) return hit;
            }
        }

        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        foreach (var p in new[] { Path.Combine(pf, @"Sandboxie-Plus\Start.exe"), Path.Combine(pf86, @"Sandboxie-Plus\Start.exe"), Path.Combine(pf, @"Sandboxie\Start.exe") })
            if (File.Exists(p)) return p;

        foreach (var root in FixedDriveRoots())
            foreach (var rel in new[] { @"Sandboxie-Plus\Start.exe", @"Program Files\Sandboxie-Plus\Start.exe", @"Program Files (x86)\Sandboxie-Plus\Start.exe", @"Sandboxie\Start.exe" })
            {
                var p = Path.Combine(root, rel);
                if (File.Exists(p)) return p;
            }
        return null;
    }

    static string FindSandboxRoot()
    {
        var cfg = ConfigValue("sandboxRoot");
        if (cfg.Length > 0) return cfg.TrimEnd('\\', '/');
        var user = Environment.UserName;
        var sysDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!.TrimEnd('\\');
        var fallback = Path.Combine(sysDrive + "\\", "Sandbox", user);
        var ini = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Sandboxie.ini");
        try
        {
            if (!File.Exists(ini)) return fallback;
            // Sandboxie.ini 是 UTF-16 LE（带 BOM），ReadAllLines 会自动识别
            foreach (var line in File.ReadAllLines(ini))
            {
                var m = Regex.Match(line, @"^\s*FileRootPath\s*=\s*(.*)$");
                if (!m.Success) continue;
                var v = m.Groups[1].Value.Trim().Trim('"');
                v = Regex.Replace(v, @"^\\+\?\?\\", "");
                v = Regex.Replace(v, @"^\?\\", "");
                v = v.Replace("%USER%", user, StringComparison.OrdinalIgnoreCase).Replace("%SystemDrive%", sysDrive, StringComparison.OrdinalIgnoreCase);
                v = Regex.Replace(v, @"\\?%SANDBOX%\s*$", "", RegexOptions.IgnoreCase).TrimEnd('\\', '/');
                return string.IsNullOrWhiteSpace(v) ? fallback : v;
            }
        }
        catch { }
        return fallback;
    }

    static string FindQqBrowser()
    {
        var cfg = ConfigValue("qqExe");
        if (cfg.Length > 0 && File.Exists(cfg)) return cfg;

        foreach (var (root, path) in new[]
        {
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Tencent\QQBrowser"),
            (Registry.LocalMachine, @"SOFTWARE\Tencent\QQBrowser"),
            (Registry.CurrentUser, @"SOFTWARE\Tencent\QQBrowser"),
        })
        {
            var cands = new List<string> { Reg(root, path, "Exe") };
            foreach (var dir in new[] { Reg(root, path, "InstallDir"), Reg(root, path, "") })
            {
                var d = dir.Trim().Trim('"');
                if (d.Length > 0) cands.Add(d.TrimEnd('\\') + @"\QQBrowser.exe");
            }
            foreach (var c in cands)
            {
                var v = c.Trim().Trim('"');
                if (v.EndsWith("QQBrowser.exe", StringComparison.OrdinalIgnoreCase) && File.Exists(v)) return v;
            }
        }

        foreach (var (root, path) in new[]
        {
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\QQBrowser.exe"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\QQBrowser.exe"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\QQBrowser.exe"),
        })
        {
            var v = Reg(root, path, "").Trim().Trim('"');
            if (v.Length > 0 && File.Exists(v)) return v;
        }

        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var p in new[] { Path.Combine(pf, @"Tencent\QQBrowser\QQBrowser.exe"), Path.Combine(pf86, @"Tencent\QQBrowser\QQBrowser.exe"), Path.Combine(local, @"Tencent\QQBrowser\QQBrowser.exe") })
            if (File.Exists(p)) return p;

        foreach (var (name, k) in UninstallEntries(true))
        {
            if (!name.Contains("QQ浏览器") && !name.Contains("QQBrowser", StringComparison.OrdinalIgnoreCase)) continue;
            var loc = (k.GetValue("InstallLocation")?.ToString() ?? "").Trim().Trim('"');
            if (loc.Length > 0 && File.Exists(Path.Combine(loc, "QQBrowser.exe"))) return Path.Combine(loc, "QQBrowser.exe");
            var disp = Regex.Replace(k.GetValue("DisplayIcon")?.ToString() ?? "", ",.*$", "").Trim().Trim('"');
            if (disp.EndsWith("QQBrowser.exe", StringComparison.OrdinalIgnoreCase) && File.Exists(disp)) return disp;
            if (disp.Length > 0)
            {
                var dir = Path.GetDirectoryName(disp);
                if (dir != null && File.Exists(Path.Combine(dir, "QQBrowser.exe"))) return Path.Combine(dir, "QQBrowser.exe");
            }
        }
        return null;
    }

    static string _qqCore;

    /// <summary>
    /// 根目录的 QQBrowser.exe 只是启动器，可能加载旧内核；游戏中心要 22.x 内核才有 launchWeApp。
    /// 优先用版本子目录里带 chrome.dll 的那个。
    /// </summary>
    public static string QqCoreExe()
    {
        if (_qqCore != null && File.Exists(_qqCore)) return _qqCore;
        var exe = QqExe;
        if (!File.Exists(exe)) return exe;
        var dir = Path.GetDirectoryName(exe)!;
        if (File.Exists(Path.Combine(dir, "chrome.dll"))) return _qqCore = exe;
        string best = null;
        var bestVer = new Version(0, 0, 0, 0);
        try
        {
            foreach (var d in Directory.GetDirectories(dir))
            {
                var name = Path.GetFileName(d);
                if (!Version.TryParse(name, out var ver) || name.Count(c => c == '.') != 3) continue;
                if (!File.Exists(Path.Combine(d, "QQBrowser.exe")) || !File.Exists(Path.Combine(d, "chrome.dll"))) continue;
                if (ver > bestVer) { bestVer = ver; best = Path.Combine(d, "QQBrowser.exe"); }
            }
        }
        catch { }
        return _qqCore = best ?? exe;
    }

    public static string QqVersion()
    {
        try
        {
            var core = QqCoreExe();
            if (!File.Exists(core)) return "";
            var dirName = Path.GetFileName(Path.GetDirectoryName(core));
            if (Version.TryParse(dirName, out _)) return dirName;
            return FileVersionInfo.GetVersionInfo(core).FileVersion ?? "";
        }
        catch { return ""; }
    }

    public static string SbieVersion()
    {
        try
        {
            var p = Path.Combine(SbieDir, "SandMan.exe");
            if (!File.Exists(p)) p = SbieStart;
            return File.Exists(p) ? (FileVersionInfo.GetVersionInfo(p).ProductVersion ?? "") : "";
        }
        catch { return ""; }
    }
}
