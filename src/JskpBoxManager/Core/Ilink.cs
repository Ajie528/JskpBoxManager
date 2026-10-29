using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

public sealed class IlinkState
{
    public bool Valid;
    public string Path = "";
    public string Rel = "";
    public string Uin = "";
    public string Username = "";
    public string KeyHash = "";
    public string PskHash = "";
    public DateTime WriteUtc = DateTime.MinValue;

    public double? AgeHours => WriteUtc == DateTime.MinValue ? null : Math.Round((DateTime.UtcNow - WriteUtc).TotalHours, 2);
    public string WriteLocal => WriteUtc == DateTime.MinValue ? "" : WriteUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public override string ToString() => !Valid ? "invalid"
        : $"uin={Uin} key={KeyHash} psk={PskHash} at={WriteUtc.ToLocalTime():MM-dd HH:mm:ss}";
}

public sealed class LaunchBaseline
{
    public bool Valid;
    public string Uin = "";
    public string KeyHash = "";
    public DateTime KeyWriteUtc;
    public DateTime LaunchUtc;
}

/// <summary>
/// 微信运行时 ilink 登录凭证守护。
///
/// 扫码后运行时写入 ilink\default\tdi\&lt;ilinkapp&gt;\0\6\tdi_account.txt，其中 kTdiKeyAutoauthKey /
/// kTdiKeyAutoauthEncKey 是免扫码自动授权的长效凭证。每次免扫成功，运行时会换一把新密钥。
/// 实测旧密钥不会立刻作废，但越旧越可能失效，所以坚持：
///   1. 沙箱里的凭证一旦更新就写进金库；
///   2. 还原只在沙箱凭证缺失/无效，或金库确实更新时进行，绝不拿旧的覆盖新的；
///   3. 无效凭证（扫码页、被清空）永远不写进金库；
///   4. 被服务端拒绝（被别的设备扫码顶掉）的密钥登记作废，不再拿来还原。
/// </summary>
public static class Ilink
{
    public const int HistoryKeep = 12;

    static readonly string[] RoboExclude = { "/XF", "*.statistic", "monitordata_*", "/XD", "kvcomm" };

    /// <summary>与凭证配套、决定登哪个号的文件。只换 tdi_account.txt 时运行时会按这些文件登回原来的号。</summary>
    public static readonly string[] CompanionRels =
    {
        "device_uuid_0",
        @"Applet\cfcd208495d565ef66e7dff9f98764da\data\2\applet.db",
        @"Applet\cfcd208495d565ef66e7dff9f98764da\data\2\applet.db-wal",
        @"Applet\cfcd208495d565ef66e7dff9f98764da\data\2\applet.db-shm",
        @"WMPF\mpfastload\mpkv.db",
        @"WMPF\mpfastload\mpkv.db.crc",
    };

    // ---------- 事件日志（只记哈希，tools/报告用） ----------

    public static void WriteEvent(string box, string evt, JsonObject data = null)
    {
        try
        {
            var o = new JsonObject
            {
                ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ["pc"] = Environment.MachineName,
                ["box"] = box,
                ["event"] = evt,
                ["app"] = AppInfo.Version,
            };
            if (data != null)
                foreach (var kv in data.ToList())
                {
                    data.Remove(kv.Key);
                    o[kv.Key] = kv.Value;
                }
            Directory.CreateDirectory(AppPaths.Logs);
            lock (typeof(Ilink))
                File.AppendAllText(AppPaths.EventLog, o.ToJsonString(JsonFile.Compact) + "\r\n", new UTF8Encoding(false));
        }
        catch { }
    }

    // ---------- 读取 ----------

    public static FileInfo AccountFile(string wmpfRoot)
    {
        var tdi = System.IO.Path.Combine(wmpfRoot, @"ilink\default\tdi");
        if (!Directory.Exists(tdi)) return null;
        try
        {
            return new DirectoryInfo(tdi)
                .EnumerateFiles("tdi_account.txt", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault();
        }
        catch { return null; }
    }

    /// <summary>共享读：运行时开着文件时也能读。</summary>
    public static byte[] ReadShared(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buf = new byte[fs.Length];
            int read = 0;
            while (read < buf.Length)
            {
                int n = fs.Read(buf, read, buf.Length - read);
                if (n <= 0) break;
                read += n;
            }
            return buf;
        }
        catch { return null; }
    }

    public static string ShortSha256(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0) return "";
        return Convert.ToHexString(SHA256.HashData(bytes))[..16].ToLowerInvariant();
    }

    public static IlinkState Read(string wmpfRoot)
    {
        var st = new IlinkState();
        var f = AccountFile(wmpfRoot);
        if (f == null) return st;
        st.Path = f.FullName;
        st.Rel = f.FullName[wmpfRoot.TrimEnd('\\').Length..].TrimStart('\\');
        st.WriteUtc = f.LastWriteTimeUtc;
        var bytes = ReadShared(f.FullName);
        if (bytes == null) return st;
        var kv = new Dictionary<string, string>();
        foreach (var raw in Encoding.UTF8.GetString(bytes).Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            int i = line.IndexOf('=');
            if (i <= 0) continue;
            kv[line[..i].Trim()] = line[(i + 1)..].Trim();
        }
        kv.TryGetValue("kTdiKeyAutoauthKey", out var key);
        kv.TryGetValue("kTdiKeyAutoauthEncKey", out var enc);
        kv.TryGetValue("kTdiKeyUin", out var uin);
        kv.TryGetValue("kTdiKeyUsername", out var user);
        st.Uin = uin ?? "";
        st.Username = user ?? "";
        if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(enc) && st.Uin.Length > 0 && st.Uin != "0")
        {
            st.Valid = true;
            st.KeyHash = ShortSha256(Encoding.UTF8.GetBytes(key + "|" + enc));
        }
        st.PskHash = ShortSha256(ReadShared(System.IO.Path.Combine(wmpfRoot, @"ilink\default\psk.key")));
        return st;
    }

    public static IlinkState Live(string box) => Read(BoxPaths.WmpfLive(box));
    public static IlinkState VaultState(string box) => Read(BoxPaths.WmpfVault(box));

    /// <summary>把沙箱里当前这套凭证（ilink + psk + 配套文件）原样导出到一个目录，用于重放实验。只读，不动金库。</summary>
    public static bool ExportLive(string box, string dir)
    {
        Directory.CreateDirectory(dir);
        return CopyTree(BoxPaths.WmpfLive(box), dir);
    }

    /// <summary>把之前导出的一套凭证原样写回沙箱 live（覆盖），用于重放实验。沙箱必须已停。</summary>
    public static bool ImportToLive(string box, string dir) => CopyTree(dir, BoxPaths.WmpfLive(box));

    // ---------- 复制 ----------

    static bool CopyTree(string srcRoot, string dstRoot)
    {
        var src = System.IO.Path.Combine(srcRoot, "ilink");
        var dst = System.IO.Path.Combine(dstRoot, "ilink");
        if (!Directory.Exists(src)) return false;
        Directory.CreateDirectory(dst);
        var opts = new List<string> { "/MIR", "/COPY:DAT", "/R:2", "/W:1" };
        opts.AddRange(RoboExclude);
        Robo.Run(src, dst, opts.ToArray());
        var rels = new List<string>();
        var acct = AccountFile(srcRoot);
        if (acct != null) rels.Add(acct.FullName[srcRoot.TrimEnd('\\').Length..].TrimStart('\\'));
        rels.Add(@"ilink\default\psk.key");
        rels.AddRange(CompanionRels);
        CopyFileSet(srcRoot, dstRoot, rels);
        return true;
    }

    /// <summary>共享读逐个拷贝并保留修改时间；源里没有的 sqlite -wal/-shm 在目标里删掉，避免拼出不一致的库。</summary>
    static int CopyFileSet(string srcRoot, string dstRoot, IEnumerable<string> rels)
    {
        int n = 0;
        foreach (var rel in rels)
        {
            var from = System.IO.Path.Combine(srcRoot, rel);
            var to = System.IO.Path.Combine(dstRoot, rel);
            if (!File.Exists(from))
            {
                if ((rel.EndsWith("-wal") || rel.EndsWith("-shm")) && File.Exists(to))
                    try { File.Delete(to); } catch { }
                continue;
            }
            var bytes = ReadShared(from);
            if (bytes == null) continue;
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(to)!);
                File.WriteAllBytes(to, bytes);
                try { File.SetLastWriteTimeUtc(to, File.GetLastWriteTimeUtc(from)); } catch { }
                n++;
            }
            catch { }
        }
        return n;
    }

    static void SaveHistorySnapshot(string box, string wmpfRoot, string tag)
    {
        var st = Read(wmpfRoot);
        if (!st.Valid) return;
        var histRoot = System.IO.Path.Combine(BoxPaths.CredentialDir(box), "history");
        var dir = System.IO.Path.Combine(histRoot, $"{DateTime.Now:yyyyMMdd-HHmmss}-{st.KeyHash[..8]}-{tag}");
        Directory.CreateDirectory(dir);
        var rels = new List<string> { st.Rel, @"ilink\default\psk.key" };
        rels.AddRange(CompanionRels);
        CopyFileSet(wmpfRoot, dir, rels);
        try
        {
            var old = new DirectoryInfo(histRoot).GetDirectories().OrderByDescending(d => d.Name).Skip(HistoryKeep);
            foreach (var d in old) try { d.Delete(true); } catch { }
        }
        catch { }
    }

    static void WriteManifest(string box, IlinkState st, string reason)
    {
        var o = new JsonObject
        {
            ["box"] = box,
            ["savedAt"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            ["reason"] = reason,
            ["uin"] = st.Uin,
            ["username"] = st.Username,
            ["keySha"] = st.KeyHash,
            ["pskSha"] = st.PskHash,
            ["writtenAt"] = st.WriteLocal,
            ["file"] = "wmpf\\" + st.Rel,
            ["app"] = AppInfo.Version,
        };
        try { JsonFile.WriteObject(System.IO.Path.Combine(BoxPaths.CredentialDir(box), "credential.json"), o); } catch { }
    }

    // ---------- 保存 / 还原 ----------

    /// <summary>返回 saved / unchanged / invalid-live / vault-newer / revoked</summary>
    public static string Save(string box, string reason = "save")
    {
        var liveRoot = BoxPaths.WmpfLive(box);
        var vaultRoot = BoxPaths.WmpfVault(box);
        var live = Read(liveRoot);
        if (!live.Valid)
        {
            Log.Box(box, $"ilink save skipped ({reason}): live credential invalid");
            return "invalid-live";
        }
        if (IsRevoked(box, live.KeyHash)) return "revoked";
        var vault = Read(vaultRoot);
        bool vaultRevoked = IsRevoked(box, vault.KeyHash);
        if (vault.Valid && vault.KeyHash == live.KeyHash && vault.PskHash == live.PskHash && vault.WriteUtc >= live.WriteUtc)
            return "unchanged";
        if (vault.Valid && !vaultRevoked && vault.KeyHash != live.KeyHash && vault.WriteUtc > live.WriteUtc.AddSeconds(2))
        {
            Log.Box(box, $"ilink save refused ({reason}): vault newer than live | vault {vault} | live {live}");
            return "vault-newer";
        }
        Directory.CreateDirectory(vaultRoot);
        CopyTree(liveRoot, vaultRoot);
        var after = Read(vaultRoot);
        if (!after.Valid || after.KeyHash != live.KeyHash)
        {
            Log.Box(box, $"ilink save FAILED ({reason}): vault copy does not match live");
            return "invalid-live";
        }
        if (!vault.Valid || vault.KeyHash != live.KeyHash)
        {
            SaveHistorySnapshot(box, vaultRoot, reason);
            bool scanned = File.Exists(BoxPaths.NeedScanFile(box));
            if (vault.Valid && vault.Uin == live.Uin && scanned)
            {
                WriteEvent(box, "scan-login", new JsonObject
                {
                    ["uin"] = live.Uin, ["keySha"] = live.KeyHash, ["writtenAt"] = live.WriteLocal,
                    ["prevAt"] = vault.WriteLocal, ["reason"] = reason,
                });
            }
            else if (vault.Valid && vault.Uin == live.Uin)
            {
                // 同一身份换了密钥 = 一次成功的免扫自动授权；gapHours = 距上一把密钥写入的时长
                WriteEvent(box, "key-rotated", new JsonObject
                {
                    ["uin"] = live.Uin, ["keySha"] = live.KeyHash, ["prevKeySha"] = vault.KeyHash,
                    ["writtenAt"] = live.WriteLocal, ["prevAt"] = vault.WriteLocal,
                    ["gapHours"] = Math.Round((live.WriteUtc - vault.WriteUtc).TotalHours, 2), ["reason"] = reason,
                });
            }
            else
            {
                WriteEvent(box, "new-identity", new JsonObject
                {
                    ["uin"] = live.Uin, ["keySha"] = live.KeyHash, ["writtenAt"] = live.WriteLocal,
                    ["prevUin"] = vault.Valid ? vault.Uin : "", ["prevAt"] = vault.Valid ? vault.WriteLocal : "", ["reason"] = reason,
                });
            }
        }
        if (vaultRevoked || !vault.Valid || vault.KeyHash != live.KeyHash)
        {
            // 拿到了新的有效密钥（通常是重新扫码），之前的作废登记不再需要
            try { File.Delete(BoxPaths.RevokedFile(box)); } catch { }
        }
        WriteManifest(box, after, reason);
        try { File.WriteAllText(BoxPaths.LoginOkFile(box), $"ok {DateTime.Now:yyyy-MM-dd HH:mm:ss} ilink"); } catch { }
        var changed = vault.Valid && vault.KeyHash == live.KeyHash ? "psk-only" : "key";
        Log.Box(box, $"ilink credential saved ({reason}, {changed}) {after}");
        return "saved";
    }

    /// <summary>返回 restored / same / live-newer / no-vault / revoked</summary>
    public static string Restore(string box, string reason = "restore")
    {
        var liveRoot = BoxPaths.WmpfLive(box);
        var vaultRoot = BoxPaths.WmpfVault(box);
        var vault = Read(vaultRoot);
        var live = Read(liveRoot);
        if (!vault.Valid)
        {
            if (live.Valid) Save(box, reason + "-adopt-live");
            return "no-vault";
        }
        if (IsRevoked(box, vault.KeyHash))
        {
            if (live.Valid && live.KeyHash != vault.KeyHash) Save(box, reason + "-adopt-live");
            Log.Box(box, $"ilink restore skipped ({reason}): vault key {vault.KeyHash} was revoked by server");
            return "revoked";
        }
        if (live.Valid && live.KeyHash == vault.KeyHash)
        {
            if (string.IsNullOrEmpty(live.PskHash) && !string.IsNullOrEmpty(vault.PskHash))
            {
                CopyTree(vaultRoot, liveRoot);
                Log.Box(box, $"ilink restore ({reason}): live psk missing, copied from vault");
            }
            return "same";
        }
        if (live.Valid && live.WriteUtc >= vault.WriteUtc.AddSeconds(-2))
        {
            Log.Box(box, $"ilink restore skipped ({reason}): live is newer | live {live} | vault {vault}");
            Save(box, reason + "-live-newer");
            return "live-newer";
        }
        if (live.Valid) SaveHistorySnapshot(box, liveRoot, "replaced-live");
        Directory.CreateDirectory(liveRoot);
        CopyTree(vaultRoot, liveRoot);
        Log.Box(box, $"ilink credential restored ({reason}) vault {vault} -> live (was {live})");
        return "restored";
    }

    // ---------- 作废识别 ----------

    public static bool IsRevoked(string box, string keyHash)
    {
        if (string.IsNullOrWhiteSpace(keyHash)) return false;
        var p = BoxPaths.RevokedFile(box);
        try
        {
            if (!File.Exists(p)) return false;
            return File.ReadAllLines(p).Any(l => l.Split((char[])null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() == keyHash);
        }
        catch { return false; }
    }

    /// <summary>启动浏览器前调用：记下这次要拿去自动授权的那把密钥。</summary>
    public static LaunchBaseline Baseline(string box)
    {
        var live = Live(box);
        return new LaunchBaseline { Valid = live.Valid, Uin = live.Uin, KeyHash = live.KeyHash, KeyWriteUtc = live.WriteUtc, LaunchUtc = DateTime.UtcNow };
    }

    /// <summary>服务端拒绝自动授权时，运行时会把 tdi_account.txt 重写成无效（或删掉）。</summary>
    public static bool RevokedSinceLaunch(string box, LaunchBaseline b)
    {
        if (b == null || !b.Valid) return false;
        var acct = AccountFile(BoxPaths.WmpfLive(box));
        if (acct == null) return true;
        if (acct.LastWriteTimeUtc <= b.LaunchUtc) return false;
        return !Live(box).Valid;
    }

    /// <summary>被别的设备扫码顶掉，或过期被拒：这把密钥和金库里同号更旧的密钥都不能再用来还原。</summary>
    public static void RegisterRevoked(string box, LaunchBaseline b, string reason)
    {
        Directory.CreateDirectory(BoxPaths.CredentialDir(box));
        var keys = new List<string> { b.KeyHash };
        var vault = VaultState(box);
        if (vault.Valid && vault.Uin == b.Uin && vault.WriteUtc <= b.KeyWriteUtc.AddSeconds(2)) keys.Add(vault.KeyHash);
        var at = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        foreach (var k in keys.Where(k => !string.IsNullOrEmpty(k)).Distinct())
            if (!IsRevoked(box, k))
                try { File.AppendAllText(BoxPaths.RevokedFile(box), $"{k} {at} {reason}\r\n"); } catch { }
        var age = Math.Round((b.LaunchUtc - b.KeyWriteUtc).TotalHours, 2);
        var chain = AuthChain.For(box);
        WriteEvent(box, "key-revoked", new JsonObject
        {
            ["uin"] = b.Uin, ["keySha"] = b.KeyHash, ["keyAgeHours"] = age,
            ["keyAt"] = b.KeyWriteUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"), ["reason"] = reason,
            ["chainDays"] = chain == null ? null : Math.Round(chain.Days, 2),
            ["chainRenewals"] = chain?.Renewals, ["chainStartKnown"] = chain?.StartKnown,
        });
        Log.Box(box, $"ilink key revoked by server (kicked by another device or expired) key={b.KeyHash} age={age}h -> need WeChat scan, vault copy not usable");
    }

    /// <summary>只有金库凭证有效、未作废，且沙箱凭证无效或比金库旧时，「从金库还原再重开」才可能有用。</summary>
    public static bool VaultCanHelp(string box)
    {
        var vault = VaultState(box);
        if (!vault.Valid || IsRevoked(box, vault.KeyHash)) return false;
        var live = Live(box);
        if (!live.Valid) return true;
        if (live.KeyHash == vault.KeyHash) return false;
        return vault.WriteUtc > live.WriteUtc.AddSeconds(2);
    }

    public static bool RenewedSince(string box, DateTime sinceUtc)
    {
        var live = Live(box);
        return live.Valid && live.WriteUtc > sinceUtc;
    }

    public static bool WaitRenewed(string box, DateTime sinceUtc, int timeoutSec, CancellationToken ct = default)
    {
        var deadline = DateTime.Now.AddSeconds(timeoutSec);
        while (DateTime.Now < deadline && !ct.IsCancellationRequested)
        {
            if (RenewedSince(box, sinceUtc))
            {
                Log.Box(box, $"ilink credential rewritten by runtime {Live(box)}");
                return true;
            }
            Thread.Sleep(3000);
        }
        return false;
    }

    public static void ClearVault(string box)
    {
        foreach (var p in new[] { BoxPaths.CredentialDir(box), System.IO.Path.Combine(BoxPaths.WmpfVault(box), "ilink") })
            try { if (Directory.Exists(p)) Directory.Delete(p, true); } catch { }
    }
}
