using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// 定位并解包「向僵尸开炮」的 wxapkg（WMPF / QQ 浏览器小游戏包）。
/// 支持：未加密 V1 包；PC/WMPF 常见异或加密包（用 AppID 派生密钥）。
/// 命令：JskpBoxManager.exe unpack qbN [--out 目录]
/// </summary>
public static class Wxapkg
{
    public sealed record Found(string Path, long Size, DateTime WriteUtc, string Rel);

    public sealed record UnpackResult(bool Ok, string OutDir, int Files, string Error, List<string> LoginHits);

    /// <summary>在沙箱 live / 金库里找本游戏相关的 .wxapkg（按修改时间新→旧）。</summary>
    public static List<Found> Locate(string box)
    {
        var roots = new[]
        {
            BoxPaths.WmpfLive(box),
            BoxPaths.WmpfVault(box),
            Path.Combine(BoxPaths.UserData(box), BoxPaths.RuntimeName),
        };
        var list = new List<Found>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots.Where(Directory.Exists))
        {
            IEnumerable<FileInfo> files;
            try
            {
                files = new DirectoryInfo(root).EnumerateFiles("*.wxapkg", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                    MaxRecursionDepth = 12,
                });
            }
            catch { continue; }

            foreach (var f in files)
            {
                if (!seen.Add(f.FullName)) continue;
                // 优先带本游戏 appid 的路径；其它包也列出来备选
                bool game = f.FullName.Contains(AppInfo.GameAppId, StringComparison.OrdinalIgnoreCase)
                            || f.DirectoryName?.Contains(AppInfo.GameAppId, StringComparison.OrdinalIgnoreCase) == true;
                string rel;
                try { rel = f.FullName[root.TrimEnd('\\').Length..].TrimStart('\\'); }
                catch { rel = f.Name; }
                list.Add(new Found(f.FullName, f.Length, f.LastWriteTimeUtc, (game ? "[game] " : "") + rel));
            }
        }
        return list
            .OrderByDescending(f => f.Rel.StartsWith("[game]", StringComparison.Ordinal) ? 1 : 0)
            .ThenByDescending(f => f.WriteUtc)
            .ToList();
    }

    public static UnpackResult UnpackBox(string box, string outDir = null)
    {
        var pkgs = Locate(box);
        if (pkgs.Count == 0)
            return new UnpackResult(false, "", 0, "找不到 .wxapkg（请先启动一次游戏，让沙箱下好包）", new());

        outDir ??= Path.Combine(AppPaths.Logs, "wxapkg-" + box);
        Directory.CreateDirectory(outDir);

        // 写一份索引
        var index = new JsonArray();
        foreach (var p in pkgs)
            index.Add(new JsonObject { ["path"] = p.Path, ["size"] = p.Size, ["rel"] = p.Rel, ["at"] = p.WriteUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") });
        JsonFile.WriteObject(Path.Combine(outDir, "packages.json"), new JsonObject { ["box"] = box, ["appId"] = AppInfo.GameAppId, ["packages"] = index });

        int total = 0;
        var hits = new List<string>();
        string lastErr = "";
        // 先解带 [game] 的，最多解前 8 个避免爆炸
        foreach (var pkg in pkgs.Take(8))
        {
            var name = Sanitize(Path.GetFileNameWithoutExtension(pkg.Path));
            if (name.Length == 0) name = "pkg";
            var dest = Path.Combine(outDir, name + "_" + Ilink.ShortSha256(Encoding.UTF8.GetBytes(pkg.Path))[..8]);
            try
            {
                var (n, err, pkgHits) = UnpackFile(pkg.Path, dest, AppInfo.GameAppId);
                if (n > 0)
                {
                    total += n;
                    hits.AddRange(pkgHits);
                    Log.Box(box, $"解包 wxapkg 完成，共 {n} 个文件：{pkg.Rel} → {dest}");
                }
                else lastErr = err;
            }
            catch (Exception ex)
            {
                lastErr = ex.Message;
                Log.Box(box, "wxapkg 解包失败：" + ex.Message + " @ " + pkg.Path);
            }
        }

        hits = hits.Distinct(StringComparer.OrdinalIgnoreCase).Take(80).ToList();
        File.WriteAllLines(Path.Combine(outDir, "login-hints.txt"), hits, new UTF8Encoding(false));
        if (total == 0)
            return new UnpackResult(false, outDir, 0, string.IsNullOrEmpty(lastErr) ? "解包失败（格式不认识或密钥不对）" : lastErr, hits);
        return new UnpackResult(true, outDir, total, "", hits);
    }

    /// <summary>解单个 wxapkg。返回 (文件数, 错误, 登录相关命中路径)。</summary>
    public static (int Files, string Error, List<string> LoginHits) UnpackFile(string pkgPath, string outDir, string appId)
    {
        var raw = File.ReadAllBytes(pkgPath);
        if (raw.Length < 14) return (0, "文件太小", new());

        // 尝试：明文 → AppID 异或 → 其它常见异或
        byte[] data = null;
        string mode = "";
        foreach (var (label, buf) in Candidates(raw, appId))
        {
            if (LooksLikeWxapkg(buf))
            {
                data = buf;
                mode = label;
                break;
            }
        }
        if (data == null) return (0, "无法识别/解密 wxapkg（已试明文与 AppID 异或）", new());

        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "_meta.txt"), $"src={pkgPath}\r\nmode={mode}\r\nsize={raw.Length}\r\n", new UTF8Encoding(false));

        try
        {
            return ParseAndWrite(data, outDir);
        }
        catch (Exception ex)
        {
            return (0, "解析失败：" + ex.Message, new());
        }
    }

    static IEnumerable<(string Label, byte[] Buf)> Candidates(byte[] raw, string appId)
    {
        yield return ("plain", raw);
        if (!string.IsNullOrEmpty(appId))
        {
            yield return ("xor-appid", Xor(raw, Encoding.UTF8.GetBytes(appId)));
            // 部分 PC 包用 appid 的 md5 前若干字节
            var md5 = MD5.HashData(Encoding.UTF8.GetBytes(appId));
            yield return ("xor-md5", Xor(raw, md5));
            yield return ("xor-md5-16", Xor(raw, md5.AsSpan(0, 16).ToArray()));
        }
        // 老包：首字节 0xBE 标记加密，密钥长度在后面 —— 简化：跳过首字节再试 appid
        if (raw.Length > 1 && raw[0] == 0xBE)
            yield return ("skip1+xor-appid", Xor(raw.AsSpan(1).ToArray(), Encoding.UTF8.GetBytes(appId ?? "")));
    }

    static byte[] Xor(byte[] data, byte[] key)
    {
        if (key == null || key.Length == 0) return data;
        var o = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) o[i] = (byte)(data[i] ^ key[i % key.Length]);
        return o;
    }

    /// <summary>
    /// 标准头：[0]=0xBE，[1]u32 info1，[5]u32 索引长度，[9]u32 数据长度，[13]=0xED，[14]u32 文件数，[18] 起是条目。
    /// </summary>
    static bool LooksLikeWxapkg(byte[] b)
    {
        if (b == null || b.Length < 22) return false;
        if (b[0] == 0xBE && b[13] == 0xED)
        {
            try
            {
                int n = ReadU32Be(b, 14);
                return n is > 0 and < 50000;
            }
            catch { return false; }
        }
        // 部分解密后首字节变成其它标记但仍有 name 表
        try
        {
            // 扫前 64 字节找「看起来像文件数 + 随后是 / 开头的路径」
            for (int off = 0; off < Math.Min(32, b.Length - 10); off++)
            {
                int n = ReadU32Be(b, off);
                if (n is <= 0 or > 20000) continue;
                int nameLenOff = off + 4;
                if (nameLenOff + 4 >= b.Length) continue;
                int nameLen = ReadU32Be(b, nameLenOff);
                if (nameLen is < 1 or > 512) continue;
                if (nameLenOff + 4 + nameLen > b.Length) continue;
                var name = Encoding.UTF8.GetString(b, nameLenOff + 4, Math.Min(nameLen, 8));
                if (name.StartsWith('/') || name.Contains('.')) return true;
            }
        }
        catch { }
        return false;
    }

    static (int Files, string Error, List<string> LoginHits) ParseAndWrite(byte[] data, string outDir)
    {
        // 条目：u32be nameLen, name, u32be offset, u32be size（offset 相对整个文件）
        int pos;
        int fileCount;
        if (data[0] == 0xBE && data.Length > 18 && data[13] == 0xED)
        {
            fileCount = ReadU32Be(data, 14);
            pos = 18;
        }
        else
        {
            // 退化：找第一个合理 fileCount
            pos = -1;
            fileCount = 0;
            for (int off = 0; off < 32; off++)
            {
                int n = ReadU32Be(data, off);
                if (n is > 0 and < 20000)
                {
                    pos = off + 4;
                    fileCount = n;
                    break;
                }
            }
            if (pos < 0) return (0, "找不到文件表", new());
        }

        var entries = new List<(string Name, int Off, int Size)>();
        for (int i = 0; i < fileCount; i++)
        {
            int nameLen = ReadU32Be(data, pos); pos += 4;
            if (nameLen is < 1 or > 1024 || pos + nameLen + 8 > data.Length)
                return (0, $"文件表损坏 @#{i}", new());
            string name = Encoding.UTF8.GetString(data, pos, nameLen); pos += nameLen;
            int off = ReadU32Be(data, pos); pos += 4;
            int size = ReadU32Be(data, pos); pos += 4;
            if (off < 0 || size < 0 || off + size > data.Length) continue;
            name = name.Replace('\\', '/').TrimStart('/');
            if (name.Length == 0 || name.Contains("..")) continue;
            entries.Add((name, off, size));
        }

        var hits = new List<string>();
        int written = 0;
        foreach (var (name, off, size) in entries)
        {
            var dest = Path.Combine(outDir, name.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.WriteAllBytes(dest, data.AsSpan(off, size).ToArray());
            written++;
            if (IsLoginHint(name, data.AsSpan(off, Math.Min(size, 256 * 1024)).ToArray()))
                hits.Add(name);
        }
        return (written, "", hits);
    }

    static readonly Regex LoginKw = new(
        @"login|code2session|session_key|wx\.login|getCode|auth\.|/user/|openid|access_token|jscode",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static bool IsLoginHint(string name, byte[] content)
    {
        if (LoginKw.IsMatch(name)) return true;
        // 只扫文本类
        if (!(name.EndsWith(".js") || name.EndsWith(".json") || name.EndsWith(".html") || name.EndsWith(".txt")))
            return false;
        string text;
        try { text = Encoding.UTF8.GetString(content); }
        catch { return false; }
        return LoginKw.IsMatch(text);
    }

    static int ReadU32Be(byte[] b, int i) =>
        (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3];

    static string Sanitize(string s)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
        return s;
    }
}
