using System.IO.Compression;
using System.Text;

namespace JskpBoxManager.Core;

/// <summary>导出诊断包：日志、事件、配置和凭证摘要（只有哈希，不含明文密钥），方便发给别人排查。</summary>
public static class Diagnostics
{
    public static string EnvironmentReport(List<BoxSummary> boxes)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{AppInfo.ProductName} {AppInfo.VersionLabel}");
        sb.AppendLine($"时间      {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"电脑      {Environment.MachineName} / {Environment.UserName}");
        sb.AppendLine($"系统      {Environment.OSVersion}");
        sb.AppendLine($"程序目录  {AppPaths.AppDir}");
        sb.AppendLine($"Sandboxie {EnvDetect.SbieStart} ({EnvDetect.SbieVersion()})");
        sb.AppendLine($"QQ浏览器  {EnvDetect.QqExe} 内核 {EnvDetect.QqVersion()}");
        sb.AppendLine($"沙箱根目录 {EnvDetect.SandboxRoot}");
        sb.AppendLine();
        foreach (var b in boxes)
        {
            sb.AppendLine($"[{b.Box}] {b.Note}  {b.PhaseText}  {b.LoginText}  保活={b.Keepalive}  上次保活={b.LastRefresh}");
            sb.AppendLine($"    live  {b.Live}");
            sb.AppendLine($"    vault {b.Vault}");
            if (NeedScan.Pending(b.Box)) sb.AppendLine($"    need-scan {NeedScan.Reason(b.Box)}");
            var task = Keepalive.TaskCommand(b.Box);
            sb.AppendLine($"    task  {(task == null ? "(无)" : task)}");
            if (b.Warning.Length > 0) sb.AppendLine($"    ! {b.Warning}");
        }
        return sb.ToString();
    }

    public static string Export(List<BoxSummary> boxes)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var zipPath = Path.Combine(desktop, $"jskp-诊断-{Environment.MachineName}-{DateTime.Now:yyyyMMdd-HHmmss}.zip");
        using var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create);

        void AddText(string name, string text)
        {
            var e = zip.CreateEntry(name);
            using var w = new StreamWriter(e.Open(), new UTF8Encoding(true));
            w.Write(text);
        }

        void AddFile(string path, string name, long maxBytes = 4 * 1024 * 1024)
        {
            try
            {
                if (!File.Exists(path)) return;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length > maxBytes) fs.Seek(-maxBytes, SeekOrigin.End);
                var e = zip.CreateEntry(name);
                using var o = e.Open();
                fs.CopyTo(o);
            }
            catch { }
        }

        AddText("环境与状态.txt", EnvironmentReport(boxes));
        if (Directory.Exists(AppPaths.Logs))
            foreach (var f in Directory.GetFiles(AppPaths.Logs))
            {
                var n = Path.GetFileName(f);
                if (n.EndsWith(".log") || n.EndsWith(".jsonl") || n.EndsWith(".state.json")) AddFile(f, "logs/" + n);
            }
        foreach (var n in new[] { "keepalive.json", "box-notes.json", "paths.json", "migrated.json" })
            AddFile(Path.Combine(AppPaths.AppDir, n), n);
        foreach (var b in boxes)
        {
            AddFile(Path.Combine(BoxPaths.CredentialDir(b.Box), "credential.json"), $"profiles/{b.Box}/credential.json");
            AddFile(BoxPaths.RevokedFile(b.Box), $"profiles/{b.Box}/revoked.txt");
            AddFile(BoxPaths.NeedScanFile(b.Box), $"profiles/{b.Box}/refresh-need-scan.txt");
        }
        return zipPath;
    }
}
