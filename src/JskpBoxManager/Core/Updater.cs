using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

public sealed record UpdateInfo(string Version, string Tag, string Notes, string ExeUrl, long ExeSize, string Sha256, string PageUrl, DateTime Published);

/// <summary>
/// 自动更新：读 GitHub 仓库最新 Release，下载里面的 JskpBoxManager.exe，校验后替换自己。
/// 运行中的 exe 不能覆盖但可以改名：当前 exe → .old，新 exe 放到原位置，重启界面；.old 下次启动时删掉。
/// 正在运行的游戏看门进程继续用旧映像，不受影响；计划任务和快捷方式指向的路径不变，下次就是新版。
/// </summary>
public static class Updater
{
    public const string Repo = "Ajie528/JskpBoxManager";
    public static string ReleasesPage => $"https://github.com/{Repo}/releases";
    const string ExeAsset = "JskpBoxManager.exe";
    static string StateJson => Path.Combine(AppPaths.AppDir, "update.json");
    static string UpdateDir => Path.Combine(AppPaths.AppDir, "update");

    static HttpClient NewClient(TimeSpan timeout)
    {
        var http = new HttpClient { Timeout = timeout };
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("JskpBoxManager", AppInfo.Version));
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return http;
    }

    public static bool IsNewer(string remote, string local)
    {
        static Version Parse(string s)
        {
            s = (s ?? "").Trim().TrimStart('v', 'V');
            int cut = s.IndexOfAny(new[] { '-', '+', ' ' });
            if (cut > 0) s = s[..cut];
            return System.Version.TryParse(s, out var v) ? v : new Version(0, 0);
        }
        return Parse(remote) > Parse(local);
    }

    /// <summary>查最新版本；没有新版本返回 null，网络失败抛异常。</summary>
    public static async Task<UpdateInfo> CheckAsync(CancellationToken ct = default)
    {
        using var http = NewClient(TimeSpan.FromSeconds(20));
        using var resp = await http.GetAsync($"https://api.github.com/repos/{Repo}/releases/latest", ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) { SaveState(DateTime.Now, null); return null; }
        resp.EnsureSuccessStatusCode();
        var o = JsonNode.Parse(await resp.Content.ReadAsStringAsync(ct)) as JsonObject;
        SaveState(DateTime.Now, null);
        if (o == null) return null;
        var tag = JsonFile.Str(o, "tag_name");
        if (!IsNewer(tag, AppInfo.Version)) return null;

        string url = "", sha = "", shaUrl = "";
        long size = 0;
        if (o["assets"] is JsonArray assets)
            foreach (var a in assets.OfType<JsonObject>())
            {
                var name = JsonFile.Str(a, "name");
                if (name.Equals(ExeAsset, StringComparison.OrdinalIgnoreCase))
                {
                    url = JsonFile.Str(a, "browser_download_url");
                    long.TryParse(JsonFile.Str(a, "size"), out size);
                    var digest = JsonFile.Str(a, "digest");
                    if (digest.StartsWith("sha256:")) sha = digest[7..];
                }
                else if (name.Equals(ExeAsset + ".sha256", StringComparison.OrdinalIgnoreCase))
                    shaUrl = JsonFile.Str(a, "browser_download_url");
            }
        if (url.Length == 0) return null;
        if (sha.Length == 0 && shaUrl.Length > 0)
            try { sha = (await http.GetStringAsync(shaUrl, ct)).Trim().Split(' ', '\t', '\r', '\n')[0]; } catch { }
        DateTime.TryParse(JsonFile.Str(o, "published_at"), out var published);
        return new UpdateInfo(tag.TrimStart('v', 'V'), tag, JsonFile.Str(o, "body"), url, size, sha.ToLowerInvariant(),
            JsonFile.Str(o, "html_url"), published.ToLocalTime());
    }

    /// <summary>启动时自动检查：每 6 小时最多一次；用户选了「跳过这个版本」的不再提醒。</summary>
    public static async Task<UpdateInfo> CheckAutoAsync()
    {
        var (last, skip) = LoadState();
        if (DateTime.Now - last < TimeSpan.FromHours(6)) return null;
        UpdateInfo info;
        try { info = await CheckAsync(); }
        catch (HttpRequestException)
        {
            await Task.Delay(TimeSpan.FromSeconds(20));
            info = await CheckAsync();
        }
        if (info != null && info.Version == skip) return null;
        return info;
    }

    public static void Skip(string version) => SaveState(LoadState().Last, version);

    static (DateTime Last, string Skip) LoadState()
    {
        var o = JsonFile.ReadObject(StateJson);
        DateTime.TryParse(JsonFile.Str(o, "lastCheck"), out var last);
        return (last, JsonFile.Str(o, "skipVersion"));
    }

    static void SaveState(DateTime last, string skip)
    {
        try
        {
            skip ??= LoadState().Skip;
            JsonFile.WriteObject(StateJson, new JsonObject { ["lastCheck"] = last.ToString("yyyy-MM-dd HH:mm:ss"), ["skipVersion"] = skip });
        }
        catch { }
    }

    public static async Task<string> DownloadAsync(UpdateInfo info, IProgress<double> progress, CancellationToken ct = default)
    {
        Directory.CreateDirectory(UpdateDir);
        var target = Path.Combine(UpdateDir, $"JskpBoxManager-{info.Version}.exe");
        var part = target + ".part";
        using var http = NewClient(TimeSpan.FromMinutes(30));
        http.DefaultRequestHeaders.Accept.Clear();
        using (var resp = await http.GetAsync(info.ExeUrl, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            resp.EnsureSuccessStatusCode();
            long total = resp.Content.Headers.ContentLength ?? info.ExeSize;
            await using var src = await resp.Content.ReadAsStreamAsync(ct);
            await using var dst = File.Create(part);
            var buf = new byte[1 << 16];
            long got = 0;
            int n;
            while ((n = await src.ReadAsync(buf, ct)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, n), ct);
                got += n;
                if (total > 0) progress?.Report((double)got / total);
            }
        }
        var len = new FileInfo(part).Length;
        if (info.ExeSize > 0 && len != info.ExeSize) throw new IOException($"下载不完整（{len}/{info.ExeSize} 字节），请重试");
        if (info.Sha256.Length > 0)
        {
            string actual;
            await using (var fs = File.OpenRead(part)) actual = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct)).ToLowerInvariant();
            if (actual != info.Sha256) throw new IOException("下载的文件校验失败（SHA256 不一致），已放弃更新");
        }
        File.Move(part, target, true);
        return target;
    }

    /// <summary>替换 exe 并重启界面；失败时恢复原样并抛异常。</summary>
    public static void ApplyAndRestart(string newExe, bool restartGui = true)
    {
        var exe = AppInfo.ExePath;
        var old = exe + ".old";
        try { if (File.Exists(old)) File.Delete(old); } catch { old = exe + $".{DateTime.Now:yyyyMMddHHmmss}.old"; }
        File.Move(exe, old);
        try { File.Move(newExe, exe); }
        catch
        {
            try { File.Move(old, exe); } catch { }
            throw;
        }
        Log.App($"update applied {AppInfo.Version} -> {exe}");
        if (!restartGui) return;
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, WorkingDirectory = AppPaths.AppDir };
        psi.ArgumentList.Add("--wait-pid");
        psi.ArgumentList.Add(Environment.ProcessId.ToString());
        psi.ArgumentList.Add("--updated-from");
        psi.ArgumentList.Add(AppInfo.Version);
        Process.Start(psi);
    }

    /// <summary>删掉上次更新留下的旧 exe 和下载缓存（旧 exe 还被看门进程占用时下次再删）。</summary>
    public static void Cleanup()
    {
        try
        {
            foreach (var f in Directory.GetFiles(AppPaths.AppDir, "JskpBoxManager.exe*.old"))
                try { File.Delete(f); } catch { }
            if (Directory.Exists(UpdateDir))
                foreach (var f in Directory.GetFiles(UpdateDir))
                    try { File.Delete(f); } catch { }
        }
        catch { }
    }
}
