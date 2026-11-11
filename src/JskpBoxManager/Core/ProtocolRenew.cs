using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 纯协议续期（不启浏览器、不启微信运行时）：直接 mmtls 连 longcloud.weixin.com
/// 发 AutoAuth（cmdid 3198），拿回轮换后的 AutoauthKey / AutoauthEncKey / ServerId。
///
/// 协议实现全部在 C#（<see cref="MmtlsClient"/> + <see cref="MmtlsProtocol"/>），
/// 不依赖 Python / cryptography，单文件发布即可用。
///
/// **为什么必须先落盘再发送**：
/// AutoAuth 是「轮换」语义——请求一旦被服务端接受，旧 key 立即作废。
/// 如果先发送、成功后才写本地，中途断网/程序被杀就会变成
/// 「服务端已换新、本地还是旧的」→ 这把凭证永久报废，只能重新扫码。
/// 所以流程固定为：
///   1. 写 attempted 标记（含发送前的旧 key 指纹）
///   2. 发送并等响应
///   3. 成功 → 把新凭证写回，清掉 attempted
///      失败/超时 → attempted 保留（下次启动能看到「可能已轮换」的告警，不会盲目重放）
/// </summary>
public static class ProtocolRenew
{
    public const string DefaultHost = "longcloud.weixin.com";
    public const int DefaultPort = 5000;

    static string AttemptFile(string box) => Path.Combine(AppPaths.Logs, box + ".renew-attempt");

    /// <summary>
    /// 上次成功续期留下的新凭证快照。用途：运行中的微信运行时内存里还握着旧 key，
    /// 我们换新后它可能把 tdi_account.txt 又写回旧 key（qb15 11-05 15:12 实测 2 秒后就被写回），
    /// 新 key 会因此凭空丢失。有了这份快照才能当场还原。
    /// </summary>
    static string RotatedFile(string box) => Path.Combine(BoxPaths.CredentialDir(box), "protocol-renewed.json");

    /// <summary>
    /// **换到新 key 的第一落点**：只要 AutoAuth 返回成功，就必须立刻把新 key 写进这个文件，
    /// 之后才去做停箱、写 live、推金库这些慢动作。
    ///
    /// <para>
    /// 为什么单独搞一个文件而不是直接写 tdi_account.txt：
    /// 换钥那一刻服务端已经把旧 key 作废了，而本地写 live 必须先把沙箱停干净
    /// （运行中的运行时握着文件、还会把旧 key 写回），中间有 2 秒以上的空窗。
    /// 这段时间里程序崩了 / 断电 / 用户强杀，新 key 就只剩在内存里，这个号直接报废。
    /// 这个文件是**同步立即写**的，不依赖停箱，所以空窗被压到几乎为零。
    /// </para>
    ///
    /// <para>它是「待写」状态：<see cref="CommitPending"/> 写进 live+金库后才删除。</para>
    /// </summary>
    static string PendingFile(string box) => Path.Combine(BoxPaths.CredentialDir(box), "pending-rotated.json");

    public sealed record Result(bool Ok, string Message, string NewKeyHash = "", long Code = long.MaxValue)
    {
        public bool Rejected => Code is -2 or -13 or -14;

        // 纯探测（ProbeFile）成功后带回的新凭证：调用方停箱后再 CommitToFile 落盘
        public byte[] PendingKey { get; init; }
        public byte[] PendingEnc { get; init; }
        public byte[] PendingServerId { get; init; }
        public string SourceFile { get; init; } = "";
    }

    // ---------------- 凭证读写 ----------------

    public sealed class Credential
    {
        public string Path = "";
        /// <summary>金库根（profiles\qbN\wmpf），用于把新凭证同步一份。</summary>
        public string VaultRoot = "";
        public string Uin = "";
        public byte[] AutoKey = Array.Empty<byte>();
        public byte[] EncKey = Array.Empty<byte>();
        public byte[] DeviceId = Array.Empty<byte>();
        public byte[] ServerId = Array.Empty<byte>();
        public string IlinkAppId = "";
        /// <summary>原始行（按顺序），写回时只替换变化的键，不动其它内容。</summary>
        public List<string> Lines = new();
    }

    /// <summary>从沙箱 live 或金库找最新的 tdi_account.txt。</summary>
    public static Credential ReadCredential(string box)
    {
        var roots = new[] { BoxPaths.WmpfLive(box), BoxPaths.WmpfVault(box) };
        string best = null;
        DateTime bestAt = DateTime.MinValue;
        foreach (var root in roots)
        {
            var tdi = Path.Combine(root, "ilink", "default", "tdi");
            if (!Directory.Exists(tdi)) continue;
            foreach (var f in Directory.EnumerateFiles(tdi, "tdi_account.txt", SearchOption.AllDirectories))
            {
                var at = File.GetLastWriteTimeUtc(f);
                if (best == null || at > bestAt) { best = f; bestAt = at; }
            }
        }
        if (best == null) throw new FileNotFoundException("找不到 tdi_account.txt");

        var lines = File.ReadAllLines(best, Encoding.UTF8).ToList();
        var kv = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in lines)
        {
            int i = line.IndexOf('=');
            if (i <= 0) continue;
            kv[line[..i].Trim()] = line[(i + 1)..].Trim();
        }

        var c = new Credential { Path = best, Lines = lines, VaultRoot = BoxPaths.WmpfVault(box) };
        c.Uin = kv.GetValueOrDefault("kTdiKeyUin", "");
        c.AutoKey = B64(kv.GetValueOrDefault("kTdiKeyAutoauthKey", ""));
        c.EncKey = B64(kv.GetValueOrDefault("kTdiKeyAutoauthEncKey", ""));
        c.DeviceId = B64(kv.GetValueOrDefault("kTdiKeyDeviceId", ""));
        c.ServerId = B64(kv.GetValueOrDefault("kTdiKeyServerId", ""));
        c.IlinkAppId = kv.GetValueOrDefault("kTdiKeyIlinkAppId", "");
        if (c.IlinkAppId.Length == 0)
        {
            // tdi_account.txt 没写这项时从目录名反推：...\tdi\ilinkapp_xxx\0\6\tdi_account.txt
            foreach (var part in best.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
                if (part.StartsWith("ilinkapp_", StringComparison.Ordinal)) c.IlinkAppId = part;
        }
        return c;
    }

    static byte[] B64(string s)
    {
        if (s.Length == 0) return Array.Empty<byte>();
        s = s.Replace(" ", "").Replace("\r", "").Replace("\n", "");
        s += new string('=', (4 - s.Length % 4) % 4);
        try { return Convert.FromBase64String(s); } catch { return Array.Empty<byte>(); }
    }

    static void WriteCredential(Credential c, byte[] newKey, byte[] newEnc, byte[] newServerId)
    {
        var nk = Convert.ToBase64String(newKey);
        var ne = Convert.ToBase64String(newEnc);
        var ns = newServerId is { Length: > 0 } ? Convert.ToBase64String(newServerId) : null;
        var outLines = new List<string>(c.Lines);
        bool sawKey = false, sawEnc = false, sawSrv = false;
        for (int i = 0; i < outLines.Count; i++)
        {
            var line = outLines[i];
            if (line.StartsWith("kTdiKeyAutoauthKey=", StringComparison.Ordinal)) { outLines[i] = "kTdiKeyAutoauthKey=" + nk; sawKey = true; }
            else if (line.StartsWith("kTdiKeyAutoauthEncKey=", StringComparison.Ordinal)) { outLines[i] = "kTdiKeyAutoauthEncKey=" + ne; sawEnc = true; }
            else if (ns != null && line.StartsWith("kTdiKeyServerId=", StringComparison.Ordinal)) { outLines[i] = "kTdiKeyServerId=" + ns; sawSrv = true; }
        }
        if (!sawKey) outLines.Add("kTdiKeyAutoauthKey=" + nk);
        if (!sawEnc) outLines.Add("kTdiKeyAutoauthEncKey=" + ne);
        if (ns != null && !sawSrv) outLines.Add("kTdiKeyServerId=" + ns);
        var text = string.Join("\n", outLines) + "\n";
        File.WriteAllText(c.Path, text, new UTF8Encoding(false));

        // 金库同步一份：否则下次「金库比沙箱旧」的判定会把这次续期当成没保存，
        // 冷启动时可能拿旧 key 覆盖回去。写在同一个相对位置下。
        int idx = c.Path.IndexOf(@"\ilink\", StringComparison.OrdinalIgnoreCase);
        if (idx > 0 && c.VaultRoot.Length > 0)
        {
            var rel = c.Path[(idx + 1)..];   // ilink\default\...
            var vaultFile = Path.Combine(c.VaultRoot, rel);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(vaultFile)!);
                File.WriteAllText(vaultFile, text, new UTF8Encoding(false));
            }
            catch (Exception ex) { Log.Box(Path.GetFileName(c.VaultRoot), "协议续期：金库同步失败 " + ex.Message); }
        }
    }

    // ---------------- 纯探测（不写任何文件） ----------------

    /// <summary>
    /// 用指定的凭证文件内容试一次 AutoAuth，**完全不动沙箱文件**。
    ///
    /// 这是「弹扫码框时先判断历史 key 还能不能用」的最优方式：
    ///   · 不发文件、不碰 live、不停箱、不开浏览器
    ///   · 服务端认可 → 返回 0 并带回新 key（此时才需要停箱写入）
    ///   · 服务端拒绝 → 返回 -13，这把直接淘汰
    ///
    /// 注意：**服务端一旦接受就会作废旧 key**。所以这里不能当作「只读校验」，
    /// 成功时必须把新 key 落盘，否则旧 key 已被作废、新 key 又丢了。
    /// 调用方拿到 Ok=true 后必须立即停箱并写入。
    /// </summary>
    public static Result ProbeFile(string path, string boxForLog = "", string host = DefaultHost, int port = DefaultPort)
    {
        Credential cred;
        try { cred = ReadCredentialFile(path); }
        catch (Exception ex) { return new Result(false, "读不到这份凭证：" + ex.Message, "", long.MaxValue); }

        if (cred.AutoKey.Length == 0) return new Result(false, "没有 kTdiKeyAutoauthKey", "", long.MaxValue);
        if (cred.EncKey.Length != 24) return new Result(false, $"encKey 长度 {cred.EncKey.Length}", "", long.MaxValue);
        if (cred.IlinkAppId.Length == 0) return new Result(false, "找不到 kTdiKeyIlinkAppId", "", long.MaxValue);
        if (!ulong.TryParse(cred.Uin, out var uin)) return new Result(false, "Uin 不是数字：" + cred.Uin, "", long.MaxValue);

        var oldHash = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
            Convert.ToBase64String(cred.AutoKey) + "|" + Convert.ToBase64String(cred.EncKey)));
        // 环境变量/标记文件开了留档，就把这次交换的完整过程一起抓下来
        var cap = AutoAuthDump.Enabled ? new AutoAuthCapture { Box = boxForLog, Via = "probe" } : null;
        var (ok, code, newKey, newEnc, newSrv, why) = Exchange(cred, uin, host, port, cap);
        if (cap != null)
        {
            cap.Code = ok ? 0 : code;
            cap.Why = why;
            try { AutoAuthDump.Write(boxForLog, cap); } catch { }
        }
        if (!ok) return new Result(false, why, "", code);
        var hash = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
            Convert.ToBase64String(newKey) + "|" + Convert.ToBase64String(newEnc)));

        // ★ 立刻落盘，不做任何等待。服务端此刻已作废旧 key，
        //   新 key 只要还停留在内存里，任何意外都会让这个号报废。
        //   这里**不能**用「有没有传箱号」当条件省略落盘：没传箱号也要存，
        //   否则调用方一疏忽就丢钥。没有箱号时用一个独立文件名兜住。
        var saveBox = boxForLog.Length > 0 ? boxForLog : "_unknown";
        SavePending(saveBox, cred.Uin, newKey, newEnc, newSrv, hash, oldHash, "probe-file");
        if (boxForLog.Length == 0)
            Log.App($"协议续期：探测换了新 key，但调用方没给箱号（{path}） "
                + $"→ 已存到 profiles\\{saveBox}\\credential\\pending-rotated.json，可能需要手动放置");

        // 新 key 同时存在返回对象里，由调用方停箱后调用 CommitToFile / CommitToBox 落盘
        return new Result(true, $"这把可用（{oldHash} -> {hash}）", hash, 0)
        {
            PendingKey = newKey,
            PendingEnc = newEnc,
            PendingServerId = newSrv,
            SourceFile = path,
        };
    }

    /// <summary>把探测成功后拿到的新 key 写进指定文件（以及同目录金库副本）。调用方应先停箱。</summary>
    public static bool CommitToFile(Result r, out string error)
    {
        error = "";
        if (r?.PendingKey == null || r.PendingKey.Length == 0) { error = "没有待写入的新凭证"; return false; }
        try
        {
            var cred = ReadCredentialFile(r.SourceFile);
            WriteCredential(cred, r.PendingKey, r.PendingEnc, r.PendingServerId);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    // ---------------- 「换到就立刻落盘」的强制通道 ----------------

    /// <summary>
    /// AutoAuth 成功后的**第一步**：把新凭证同步写进 <c>pending-rotated.json</c>。
    ///
    /// <para>
    /// 服务端在返回成功的那一刻就已作废旧 key。此后到写进 live 之间要停箱（2 秒以上），
    /// 这期间任何意外都会让新 key 只剩在内存里→号报废。所以这里不做任何判断、不等待，
    /// 拿到就写，写完才继续后面的流程。
    /// </para>
    ///
    /// <para>
    /// 写失败也**不阻断**后续（继续尝试直接写 live），但要大声记日志——
    /// 因为这意味着这段时间里丢了钥就没有第二次机会。
    /// </para>
    /// </summary>
    public static bool SavePending(string box, string uin, byte[] newKey, byte[] newEnc, byte[] newSrv,
        string newHash, string oldHash, string why)
    {
        try
        {
            Directory.CreateDirectory(BoxPaths.CredentialDir(box));
            JsonFile.WriteObject(PendingFile(box), new JsonObject
            {
                ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ["uin"] = uin,
                ["autoKey"] = Convert.ToBase64String(newKey),
                ["encKey"] = Convert.ToBase64String(newEnc),
                ["serverId"] = newSrv is { Length: > 0 } ? Convert.ToBase64String(newSrv) : "",
                ["keySha"] = newHash,
                ["prevKeySha"] = oldHash,
                ["why"] = why,
            });
            Log.Box(box, $"协议续期：新 key 已立即落盘（{oldHash} → {newHash}，来源 {why}）");
            return true;
        }
        catch (Exception ex)
        {
            Log.Box(box, "协议续期：**严重** 无法把新 key 写入待写文件：" + ex.Message
                + " — the old key is already revoked; falling back to a plain-text sidecar");

            // 兜底一：pending 文件写不了（目录权限/磁盘满/文件被锁），那就直接把新 key
            // 写成一个最朴素的文件放在 logs 下。宁可暴露明文也不能丢钥——
            // 这个号一旦丢了 key 就只能重新扫码，代价远大于日志里有明文。
            try
            {
                Directory.CreateDirectory(AppPaths.Logs);
                var sidecar = Path.Combine(AppPaths.Logs, $"{box}.rotated-{newHash}.txt");
                File.WriteAllText(sidecar,
                    $"at={DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\nuin={uin}\r\n"
                    + $"kTdiKeyAutoauthKey={Convert.ToBase64String(newKey)}\r\n"
                    + $"kTdiKeyAutoauthEncKey={Convert.ToBase64String(newEnc)}\r\n"
                    + (newSrv is { Length: > 0 } ? $"kTdiKeyServerId={Convert.ToBase64String(newSrv)}\r\n" : "")
                    + $"prevKeySha={oldHash}\r\nwhy={why}\r\n",
                    new UTF8Encoding(false));
                Log.Box(box, $"协议续期：新 key 已写入兜底文件 {Path.GetFileName(sidecar)}");
                return true;
            }
            catch (Exception ex2)
            {
                Log.Box(box, "协议续期：**严重** 兜底文件也写入失败：" + ex2.Message);
                return false;
            }
        }
    }

    /// <summary>是否有「已换到新 key 但还没写进 live/金库」的凭证在等着落盘。</summary>
    public static bool HasPending(string box) => File.Exists(PendingFile(box));

    /// <summary>读一份待写凭证（供崩溃后恢复用）；没有返回 null。</summary>
    public static (string Uin, byte[] Key, byte[] Enc, byte[] Srv, string KeySha, string At)? ReadPending(string box)
    {
        try
        {
            if (!File.Exists(PendingFile(box))) return null;
            var o = JsonFile.ReadObject(PendingFile(box));
            var key = B64(JsonFile.Str(o, "autoKey"));
            var enc = B64(JsonFile.Str(o, "encKey"));
            if (key.Length == 0 || enc.Length != 24) return null;
            return (JsonFile.Str(o, "uin"), key, enc, B64(JsonFile.Str(o, "serverId")),
                JsonFile.Str(o, "keySha"), JsonFile.Str(o, "at"));
        }
        catch { return null; }
    }

    /// <summary>
    /// 把待写凭证写进 live + 金库，成功后删掉待写文件。
    /// 调用方负责先确保沙箱已停（运行中的运行时会写回旧 key）。
    /// </summary>
    public static bool CommitPending(string box, out string error)
    {
        error = "";
        var p = ReadPending(box);
        if (p == null) { error = "没有待写凭证"; return false; }
        try
        {
            // 必须 live + 金库都写。只写金库的话，live 里留着的是服务端已作废的旧 key，
            // 启动时要么被运行时直接判死，要么 VaultSync 反手把旧 key 推回来。
            // 这正是 v1.5.38 之前「历史凭证恢复只写一份」踩过的坑。
            var liveRoot = BoxPaths.WmpfLive(box);
            var vaultRoot = BoxPaths.WmpfVault(box);

            // 相对路径取 live 那份（两边结构相同）；live 没有就取金库那份
            var tpl = Ilink.AccountFile(liveRoot) ?? Ilink.AccountFile(vaultRoot);
            if (tpl == null) { error = "找不到 tdi_account.txt"; return false; }
            var rootOfTpl = tpl.FullName.StartsWith(liveRoot, StringComparison.OrdinalIgnoreCase) ? liveRoot : vaultRoot;
            var rel = tpl.FullName[rootOfTpl.TrimEnd('\\').Length..].TrimStart('\\');

            int wrote = 0;
            var errs = new List<string>();
            foreach (var root in new[] { liveRoot, vaultRoot })
            {
                var target = Path.Combine(root, rel);
                try
                {
                    var c = File.Exists(target) ? ReadCredentialFile(target)
                        : new Credential { Path = target, Lines = File.ReadAllLines(tpl.FullName).ToList() };
                    c.Path = target;
                    c.VaultRoot = "";                 // 避免 WriteCredential 内部再同步一遍
                    WriteCredential(c, p.Value.Key, p.Value.Enc, p.Value.Srv);
                    wrote++;
                }
                catch (Exception ex) { errs.Add($"{Path.GetFileName(root)}: {ex.Message}"); }
            }

            if (wrote == 0)
            {
                error = "live/金库都写失败：" + string.Join("；", errs);
                Log.Box(box, "协议续期：待写凭证在 live 与金库都写入失败：" + error);
                return false;
            }

            SaveRotatedSnapshot(box, ReadCredential(box), p.Value.Key, p.Value.Enc, p.Value.Srv, p.Value.KeySha, "");
            try { File.Delete(PendingFile(box)); } catch { }
            Log.Box(box, $"协议续期：待写 key {p.Value.KeySha} 已写入 {wrote} 个文件 "
                + $"(live + vault, saved {p.Value.At})"
                + (errs.Count > 0 ? $" [partial: {string.Join("；", errs)}]" : ""));
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            Log.Box(box, "协议续期：写入待写凭证失败（key 仍在待写文件里）：" + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// 启动/保活时调用：发现有待写凭证就说明上次换钥后没落盘（崩溃或被强杀）。
    /// 直接写进 live+金库并清掉标记，避免那次换钥白做。
    /// 返回是否真的恢复了一份。
    /// </summary>
    public static bool RecoverPending(string box)
    {
        var p = ReadPending(box);
        if (p == null)
        {
            // 文件存在但内容不可读 → 丢掉，否则每次启动都卡在这
            if (File.Exists(PendingFile(box)))
            {
                try { File.Delete(PendingFile(box)); } catch { }
                Log.Box(box, "协议续期：待写文件内容不可读，已丢弃");
            }
            return false;
        }

        // 沙箱里有进程时不能写：运行时会把它内存里的旧 key 写回去
        var (busy, why) = BusyState(box);
        if (busy)
        {
            Log.Box(box, $"协议续期：待写 key {p.Value.KeySha} 存在但沙箱还在忙（{why}）→ 延后处理");
            return false;
        }

        if (!CommitPending(box, out var err))
        {
            Log.Box(box, "协议续期：恢复待写凭证失败：" + err);
            return false;
        }
        CredentialProbe.RecordRotationPublic(box, p.Value.KeySha, "recover-pending");
        Ilink.WriteEvent(box, "key-restored", new JsonObject
        {
            ["keySha"] = p.Value.KeySha,
            ["reason"] = "pending-recovered",
            ["note"] = "上次换钥后未落盘，启动时补写",
        });
        Log.Box(box, $"协议续期：已补写待写 key {p.Value.KeySha}（保存于 {p.Value.At})");
        return true;
    }

    /// <summary>
    /// 把探测拿到的新凭证写进这个沙箱的 <b>live + 金库</b>（不是只写历史快照）。
    ///
    /// <para>
    /// 这一步不能省。AutoAuth 是轮换语义：探测成功那一刻，服务端已经把 key 换成新的了。
    /// 如果只把新 key 写进历史快照，live 和金库里留的还是刚被轮换掉的那把，
    /// 接下来「用恢复出来的旧 key 重新启动」就会让运行时自己再发一次 AutoAuth，
    /// 于是同一个号上同时存在两条有效的 key 分支（服务端那把 a4d97938 + 运行时新滚的 3d0a2ead）。
    /// qb4 在 2026-11-09 10:38 就是这个状态，第二天凌晨两条分支一起被判 -13。
    /// </para>
    /// </summary>
    public static bool CommitToBox(string box, Result r, out string error)
    {
        error = "";
        if (r?.PendingKey == null || r.PendingKey.Length == 0) { error = "没有待写入的新凭证"; return false; }
        try
        {
            // ReadCredential 取 live 与金库中较新那份；调用方刚把候选同步过，两份一致。
            var cred = ReadCredential(box);
            WriteCredential(cred, r.PendingKey, r.PendingEnc, r.PendingServerId);
            try { File.Delete(PendingFile(box)); } catch { }
            Log.Box(box, $"协议续期：新 key {r.NewKeyHash} 已写入沙箱与金库 "
                + $"(was {r.SourceFile}），重启时会用服务端刚下发的那把");
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    /// <summary>从任意一个 tdi_account.txt 读数（不依赖沙箱结构）。</summary>
    public static Credential ReadCredentialFile(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("找不到 " + path);
        var lines = File.ReadAllLines(path, Encoding.UTF8).ToList();
        var kv = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in lines)
        {
            int i = line.IndexOf('=');
            if (i <= 0) continue;
            kv[line[..i].Trim()] = line[(i + 1)..].Trim();
        }
        var c = new Credential { Path = path, Lines = lines, VaultRoot = "" };
        c.Uin = kv.GetValueOrDefault("kTdiKeyUin", "");
        c.AutoKey = B64(kv.GetValueOrDefault("kTdiKeyAutoauthKey", ""));
        c.EncKey = B64(kv.GetValueOrDefault("kTdiKeyAutoauthEncKey", ""));
        c.DeviceId = B64(kv.GetValueOrDefault("kTdiKeyDeviceId", ""));
        c.ServerId = B64(kv.GetValueOrDefault("kTdiKeyServerId", ""));
        c.IlinkAppId = kv.GetValueOrDefault("kTdiKeyIlinkAppId", "");
        if (c.IlinkAppId.Length == 0)
            foreach (var part in path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
                if (part.StartsWith("ilinkapp_", StringComparison.Ordinal)) c.IlinkAppId = part;
        return c;
    }

    // ---------------- attempted 标记 ----------------

    /// <summary>上一次续期留下的「已发送但结果未知」时间；没有标记返回 null。</summary>
    public static DateTime? LastAttemptAt(string box)
    {
        try
        {
            var f = AttemptFile(box);
            if (!File.Exists(f)) return null;
            var o = JsonFile.ReadObject(f);
            return DateTime.TryParseExact(JsonFile.Str(o, "at"), "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var t) ? t : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// 有没有「上次续期结果未知」的标记。<b>会自动清掉已经过期的标记</b>，见 <see cref="IsAttemptStale"/>。
    /// </summary>
    public static bool AttemptPending(string box)
    {
        if (!File.Exists(AttemptFile(box))) return false;
        if (IsAttemptStale(box)) return false;   // 里面已经删掉文件
        return true;
    }

    /// <summary>
    /// 标记是否已经过期。判定按「这个疑问还成不成立」来，命中任一条即清掉：
    /// <list type="number">
    /// <item>live 已经不是发送前那把 key —— 那次请求已被后续动作（扫码 / 历史凭证恢复 / 运行时换新 / 导入）取代。</item>
    /// <item>发送前那把 key 已被登记作废 —— 已经没有「可能换成了新钥匙却没写回」的东西可确认。</item>
    /// <item>标记超过 <see cref="MaxAttemptHours"/> 小时 —— 这么久的「结果未知」早已无从核对，
    ///       再留着它的唯一效果就是让启动预检和主动探测永久跳过这个号。</item>
    /// </list>
    /// <para>
    /// 为什么必须有这套清理：标记本来是防「先发送、没写回，重放会二次消耗」的。但它只在
    /// live 仍是那把 key 时才有意义。旧版把它当永久开关，于是 qb4 / qb16 一旦出现过一次超时，
    /// 之后所有自动确认都被跳过，日志里一路 `previous renew result unknown -> skip`。
    /// </para>
    /// </summary>
    static bool IsAttemptStale(string box)
    {
        try
        {
            var f = AttemptFile(box);
            if (!File.Exists(f)) return false;
            var o = JsonFile.ReadObject(f);
            var oldSha = JsonFile.Str(o, "oldKeySha");
            var atText = JsonFile.Str(o, "at");

            void Drop(string why)
            {
                try { File.Delete(f); } catch { }
                Log.Box(box, "协议续期：已清掉续期标记（" + why + ")");
            }

            if (oldSha.Length > 0)
            {
                var live = Ilink.Live(box);
                if (live.Valid && live.KeyHash != oldSha)
                {
                    Drop($"live key {live.KeyHash} is not the one that was sent ({oldSha}), request superseded");
                    return true;
                }
                if (Ilink.IsRevoked(box, oldSha))
                {
                    Drop($"key {oldSha} has been retired; nothing left to confirm");
                    return true;
                }
            }

            if (DateTime.TryParseExact(atText, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal, out var at)
                && (DateTime.Now - at).TotalHours >= MaxAttemptHours)
            {
                Drop($"marker is {(DateTime.Now - at).TotalHours:F1}h old (limit {MaxAttemptHours}h); "
                    + "keeping it would disable preflight/probe forever");
                return true;
            }
            return false;
        }
        catch { return false; }
    }

    /// <summary>「结果未知」标记最多认多久。超过就不再把它当阻塞条件（见 <see cref="IsAttemptStale"/>）。</summary>
    public const double MaxAttemptHours = 24;

    // ---------------- 续期结果快照（防运行时写回旧 key） ----------------

    /// <summary>沙箱里有没有正在跑的进程/游戏窗：运行中续期会被运行时用内存里的旧 key 覆盖回去。</summary>
    public static (bool Busy, string Why) BusyState(string box)
    {
        try
        {
            var v = new BoxView(box);
            if (v.HasGameWindow) return (true, "游戏正在运行");
            if (v.WeChatRuntimeUp) return (true, "微信运行时正在运行");
            if (v.HasQqOrGame) return (true, "沙箱里还有 QQ 浏览器 / 微信进程");
            return (false, "");
        }
        catch { return (false, ""); }
    }

    /// <summary>
    /// 运行中能不能续期。答案是不能：运行时的内存里握着旧 key，
    /// 服务端换新后它会因为旧 key 失效而写回旧值并断开会话——qb15 11-05 15:11 就是这样
    /// 在续期成功 2 秒后把游戏窗关掉、并把新 key 覆盖掉的。
    /// </summary>
    public static (bool Ok, string Message) CheckRenewable(string box)
    {
        var (busy, why) = BusyState(box);
        if (!busy) return (true, "");
        return (false,
            $"不能续期：{why}。\n\n"
            + "协议续期会让服务端立刻作废旧 key，而运行中的微信运行时内存里还握着那把旧 key：\n"
            + "它会写回旧值并把游戏会话断掉（窗口直接消失，新 key 也会丢）。\n\n"
            + "请先停掉这个沙箱（或等游戏关掉）再续期。");
    }

    /// <summary>续期成功后盯一段时间：运行中续期时，运行时会用内存里的旧 key 覆盖回
    /// tdi_account.txt。发现被覆盖就把快照里的新 key 写回去。</summary>
    static void StartClobberWatch(string box, int seconds)
    {
        var t = new Thread(() =>
        {
            var deadline = DateTime.Now.AddSeconds(seconds);
            while (DateTime.Now < deadline)
            {
                Thread.Sleep(500);
                if (RestoreRotated(box, "runtime-wrote-back-old-key"))
                {
                    try { VaultSync.PushVaultToLive(box); } catch { }
                    return;
                }
                var live = Ilink.Live(box);
                if (live.Valid && live.KeyHash == RotatedKeyHash(box)) return;   // 稳定在新 key
            }
        })
        { IsBackground = true };
        t.Start();
    }

    /// <summary>把刚换到的新凭证原样存一份，供 <see cref="RestoreRotated"/> 还原。</summary>
    static void SaveRotatedSnapshot(string box, Credential c, byte[] newKey, byte[] newEnc, byte[] newSrv,
        string newHash, string prevHash)
    {
        try
        {
            Directory.CreateDirectory(BoxPaths.CredentialDir(box));
            JsonFile.WriteObject(RotatedFile(box), new JsonObject
            {
                ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ["uin"] = c.Uin,
                ["prevKeySha"] = prevHash,
                ["autoKey"] = Convert.ToBase64String(newKey),
                ["encKey"] = Convert.ToBase64String(newEnc),
                ["serverId"] = newSrv is { Length: > 0 } ? Convert.ToBase64String(newSrv) : "",
                ["keySha"] = newHash,
            });
        }
        catch (Exception ex) { Log.Box(box, "协议续期：续期快照保存失败 " + ex.Message); }
    }

    // ---------------- 主动抓取 AutoAuth 响应 ----------------

    /// <summary>
    /// 抓一次 AutoAuth 的完整响应并 dump，用于回答「服务端到底有没有回传有效期」。
    ///
    /// <para>
    /// 与 <see cref="Renew"/> 的区别：这里**只关心拿到响应**，成功时也会把新 key 写回
    /// （因为服务端已经轮换，不写回就丢钥），但会明确告诉调用方这件事发生了。
    /// 拒绝（-13/-14）时同样写 dump —— 那正是最想看的样本。
    /// </para>
    ///
    /// <para>沙箱必须已停：运行中的运行时会把旧 key 写回文件，导致新 key 丢失。</para>
    /// </summary>
    /// <param name="from">用哪份凭证：live/vault 优先，或指定某个 tdi_account.txt 路径。</param>
    public static (AutoAuthCapture Capture, string Report) CaptureOnce(string box, string from = "",
        bool commitOnSuccess = true, string host = DefaultHost, int port = DefaultPort)
    {
        var cred = from.Length > 0 ? ReadCredentialFile(from) : ReadCredential(box);
        var cap = new AutoAuthCapture { Box = box, Via = "capture" };
        if (!ulong.TryParse(cred.Uin, out var uin))
        {
            cap.DecryptError = "Uin 不是数字：" + cred.Uin;
            return (cap, "凭证里的 uin 不可用：" + cred.Uin);
        }
        if (cred.EncKey.Length != 24 || cred.AutoKey.Length == 0)
        {
            cap.DecryptError = "凭证不完整";
            return (cap, $"凭证不完整：key={cred.AutoKey.Length}B enc={cred.EncKey.Length}B");
        }

        var (ok, code, newKey, newEnc, newSrv, why) = Exchange(cred, uin, host, port, cap);
        cap.Code = ok ? 0 : code;
        cap.Why = why;

        // ★ 无论调用方要不要 commit，新 key 都必须立刻落盘。
        //   服务端已经轮换了，旧 key 作废；`--no-commit` 只该阻止「写进 live」，
        //   绝不能连「保存到磁盘」都省掉，否则这个号直接报废。
        if (ok && cap.NewKeySha.Length > 0)
            SavePending(box, cred.Uin, newKey, newEnc, newSrv, cap.NewKeySha, cap.OldKeySha, "capture");

        string extra = "";
        if (ok && commitOnSuccess)
        {
            // 服务端已经轮换了：不写回就是直接丢钥
            try
            {
                // 必须 live + 金库一起写。
                // WriteCredential 按 cred.Path 写，而 ReadCredential 取的是「live 与金库中较新那份」，
                // live 比金库新时就只改了 live（qb1 实测：抓完 live=6409afb9、金库还是 21ac88de 的旧状态），
                // 启动时 Ilink.Restore 会因「vault 更旧」而把它推回去，等于白抓一次。
                var liveRoot = BoxPaths.WmpfLive(box);
                var vaultRoot = BoxPaths.WmpfVault(box);
                var idx = cred.Path.IndexOf(@"\ilink\", StringComparison.OrdinalIgnoreCase);
                if (idx > 0)
                {
                    var rel = cred.Path[(idx + 1)..];          // ilink\default\tdi\...
                    foreach (var root in new[] { liveRoot, vaultRoot })
                    {
                        var target = Path.Combine(root, rel);
                        if (!File.Exists(target)) continue;
                        WriteCredential(ReadCredentialFile(target), newKey, newEnc, newSrv);
                    }
                }
                else
                {
                    // --from 指向历史快照：直接写那份
                    WriteCredential(cred, newKey, newEnc, newSrv);
                }

                extra = "已写回新凭证到 live + 金库";
                // 记账：否则「每号每天最多换 N 次」这条风控判据会漏掉抓取产生的轮换
                CredentialProbe.RecordRotationPublic(box, cap.NewKeySha, "autoauth-capture");
                var lv = Ilink.Live(box);
                if (lv.Valid && lv.KeyHash == cap.NewKeySha)
                {
                    // 校验通过才清 pending，否则留着让下次启动补写
                    try { File.Delete(Path.Combine(BoxPaths.CredentialDir(box), "pending-rotated.json")); } catch { }
                }
                else
                {
                    extra += $"（⚠ live 校验不符：{lv.KeyHash}，新 key 留在 pending-rotated.json 待下次启动补写）";
                    Log.Box(box, $"AutoAuth 抓取：沙箱 key {lv.KeyHash} ≠ 期望值 {cap.NewKeySha} → 保留待写文件");
                }
            }
            catch (Exception ex)
            {
                // 写 live 失败时新 key 仍在 pending-rotated.json 里，下次启动会自动补写
                extra = "写回 live 失败：" + ex.Message + "（新 key 已存 pending-rotated.json，下次启动自动补写）";
            }
        }
        else if (ok)
        {
            extra = "⚠ 未写进 live（--no-commit），但新 key 已存 pending-rotated.json"
                + " —— 旧 key 已被服务端轮换掉，务必让程序补写完（跑一次 status 或保活即可）";
        }

        var report = AutoAuthDump.Write(box, cap);
        Log.Box(box, $"AutoAuth 抓取（{cap.Via}）：{AutoAuthDump.Summary(cap)} {extra}".TrimEnd());
        return (cap, report);
    }

    /// <summary>当前这把凭证最后一次换新距今多少小时；live 和金库取较新的那个。没有有效凭证返回 null。</summary>
    public static double? KeyAgeHours(string box)    {
        DateTime newest = DateTime.MinValue;
        try
        {
            foreach (var st in new[] { Ilink.Live(box), Ilink.VaultState(box) })
                if (st.Valid && st.WriteUtc > DateTime.MinValue && st.WriteUtc > newest) newest = st.WriteUtc;
        }
        catch { return null; }
        if (newest == DateTime.MinValue) return null;
        return (DateTime.UtcNow - newest).TotalHours;
    }

    /// <summary>
    /// 密钥最长能用多久就必须强制续期一次。实测免扫链约一天撞墙，留 4 小时余量。
    /// 这是**硬约束**：不管游戏在不在跑、常驻还是普通模式，超过就必须续。
    /// </summary>
    public const double KeyMaxAgeHours = 20;

    /// <summary>这把凭证是不是已经超过硬上限，必须马上续期。</summary>
    public static bool KeyOverdue(string box)
    {
        var age = KeyAgeHours(box);
        return age != null && age.Value >= KeyMaxAgeHours;
    }

    /// <summary>密钥年龄简短文本，用于日志。</summary>
    public static string KeyAgeText(string box)
    {
        var age = KeyAgeHours(box);
        return age == null ? "unknown" : $"{age:F1}h";
    }

    /// <summary>上一次协议续期换到的 key 哈希；没有返回空串。</summary>
    public static string RotatedKeyHash(string box)
        => JsonFile.Str(JsonFile.ReadObject(RotatedFile(box)), "keySha");

    /// <summary>
    /// 「续期快照」最多认多久。运行时把旧 key 写回只发生在续期后几十秒内；
    /// 超过这个时间还留着快照，就会把之后「有意恢复的旧凭证」误判成被写回。
    /// qb16 就因此来回打架：恢复 → Save 立刻又改回快照里的死 key → 再恢复…
    /// </summary>
    const double SnapshotMaxMinutes = 30;

    /// <summary>
    /// 运行时把续期结果写回旧 key 时用：把快照里的新 key 写回去。
    /// 只在「live 变回了续期前的旧 key」时才动手——运行时自己合法换新（live 是第三把 key）不算。
    /// 返回 true 表示确实发生了「新 key 被覆盖」并已还原。
    /// </summary>
    public static bool RestoreRotated(string box, string reason)
    {
        var o = JsonFile.ReadObject(RotatedFile(box));
        var hash = JsonFile.Str(o, "keySha");
        var prevHash = JsonFile.Str(o, "prevKeySha");
        if (hash.Length == 0 || prevHash.Length == 0) return false;

        // 快照过期就别再拿它纠错了，否则会一直把后续的正常变更拉回旧值
        var atText = JsonFile.Str(o, "at");
        if (DateTime.TryParse(atText, out var at) && (DateTime.Now - at).TotalMinutes > SnapshotMaxMinutes)
        {
            try { File.Delete(RotatedFile(box)); } catch { }
            Log.Box(box, $"协议续期：续期快照已过期（{(DateTime.Now - at).TotalMinutes:F0} 分钟）→ 已丢弃，不再还原");
            return false;
        }

        var live = Ilink.Live(box);
        if (!live.Valid) return false;
        if (live.KeyHash == hash) return false;        // 还是新 key，没被覆盖
        if (live.KeyHash != prevHash)
        {
            // 既不是新 key 也不是续期前的旧 key：运行时自己换了一把更新的，快照作废
            try { File.Delete(RotatedFile(box)); } catch { }
            Log.Box(box, $"协议续期：运行时自己换成了 {live.KeyHash} → 丢弃过期快照");
            return false;
        }
        var key = B64(JsonFile.Str(o, "autoKey"));
        var enc = B64(JsonFile.Str(o, "encKey"));
        if (key.Length == 0 || enc.Length != 24) return false;
        var cred = ReadCredential(box);
        try
        {
            WriteCredential(cred, key, enc, B64(JsonFile.Str(o, "serverId")));
            // 已经用掉了，删掉快照，避免同一次续期被反复"纠正"
            try { File.Delete(RotatedFile(box)); } catch { }
            Log.Box(box, $"协议续期：运行时把旧 key 写回了 {live.KeyHash} → 已还原续期后的新 key {hash} ({reason})");
            Ilink.WriteEvent(box, "key-restored", new JsonObject
            {
                ["keySha"] = hash, ["clobberedBy"] = live.KeyHash, ["reason"] = reason,
            });
            return true;
        }
        catch (Exception ex)
        {
            Log.Box(box, "协议续期：还原续期后的 key 失败 " + ex.Message);
            return false;
        }
    }

    /// <summary>丢掉续期快照：当有人「有意」换了一套凭证（恢复历史、导入、清登录）时调用。</summary>
    public static void DropSnapshot(string box, string reason)
    {
        try
        {
            if (!File.Exists(RotatedFile(box))) return;
            File.Delete(RotatedFile(box));
            Log.Box(box, "协议续期：已丢弃续期快照（" + reason + ")");
        }
        catch { }
    }

    public static void ClearAttempt(string box)
    {
        try { File.Delete(AttemptFile(box)); } catch { }
    }

    // ---------------- 主流程 ----------------

    /// <summary>续期一个沙箱。会真实发送并轮换服务端密钥。</summary>
    /// <param name="dryRun">true = 只构造不发送（不写 attempted、不落盘）。</param>
    /// <param name="afterRotate">
    /// 成功换钥后调用（用于观察运行时是否又把旧 key 写回）。沙箱运行中续期必须传，否则新 key 会丢。
    /// </param>
    public static Result Renew(string box, bool dryRun = false, string host = DefaultHost, int port = DefaultPort,
        Action afterRotate = null)
    {
        Credential cred;
        try { cred = ReadCredential(box); }
        catch (Exception ex) { return new Result(false, "读不到凭证：" + ex.Message); }

        if (cred.AutoKey.Length == 0) return new Result(false, "凭证里没有 kTdiKeyAutoauthKey");
        if (cred.EncKey.Length != 24) return new Result(false, $"encKey 长度 {cred.EncKey.Length}，应为 24");
        if (cred.IlinkAppId.Length == 0) return new Result(false, "找不到 kTdiKeyIlinkAppId，无法填 wpkg 字段 24");
        if (!ulong.TryParse(cred.Uin, out var uin)) return new Result(false, "Uin 不是数字：" + cred.Uin);

        // ---- 1. 发送前先落盘 ----
        var busyBefore = BusyState(box).Busy;
        var oldKeyHash = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
            Convert.ToBase64String(cred.AutoKey) + "|" + Convert.ToBase64String(cred.EncKey)));
        if (!dryRun)
        {
            try
            {
                Directory.CreateDirectory(AppPaths.Logs);
                JsonFile.WriteObject(AttemptFile(box), new JsonObject
                {
                    ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["uin"] = cred.Uin,
                    ["oldKeySha"] = oldKeyHash,
                    ["stage"] = "sent",
                });
            }
            catch (Exception ex)
            {
                Log.Box(box, "协议续期：写不了续期标记，为避免丢钥在发送前放弃：" + ex.Message);
                return new Result(false, "无法写续期标记，为避免丢密钥已放弃发送：" + ex.Message);
            }
            Log.Box(box, $"协议续期：续期标记已写入（旧 key {oldKeyHash})");
        }

        // ---- 2. 发送 ----
        try
        {
            if (dryRun)
            {
                var plainDry = MmtlsProtocol.BuildAutoAuthPlain(cred.DeviceId, cred.AutoKey);
                var (hybDry, tmpDry) = MmtlsProtocol.HybridEncrypt(plainDry, cred.EncKey);
                tmpDry.Dispose();
                var bodyDry = MmtlsProtocol.Concat(
                    MmtlsProtocol.SessionWpkgHead(uin, cred.ServerId, Encoding.ASCII.GetBytes(cred.IlinkAppId)), hybDry);
                return new Result(true, $"演练完成：明文 {plainDry.Length} 字节，hybrid {hybDry.Length} 字节，"
                    + $"请求体 {bodyDry.Length} 字节（未发送）");
            }

            var capRenew = AutoAuthDump.Enabled ? new AutoAuthCapture { Box = box, Via = "renew" } : null;
            var (ok, code, newKey, newEnc, newSrv, why) = Exchange(cred, uin, host, port, capRenew);
            if (capRenew != null)
            {
                capRenew.Code = ok ? 0 : code;
                capRenew.Why = why;
                try { AutoAuthDump.Write(box, capRenew); } catch { }
            }
            if (!ok) return Fail(box, why, code);

            // ---- 3. 立刻落盘（第一落点），再做后面的慢动作 ----
            var hash = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
                Convert.ToBase64String(newKey) + "|" + Convert.ToBase64String(newEnc)));
            SavePending(box, cred.Uin, newKey, newEnc, newSrv, hash, oldKeyHash, "renew");

            try { WriteCredential(cred, newKey, newEnc, newSrv); }
            catch (Exception ex)
            {
                // 写盘失败但 pending 还在 → 下次启动自动补写，不算丢钥
                return Fail(box, "写回凭证失败（新 key 已存 pending-rotated.json，下次启动自动补写）：" + ex.Message, 0);
            }
            ClearAttempt(box);

            // WriteCredential 只写了 cred.Path 那一份。ReadCredential 取的是「live 与金库中较新那份」，
            // 所以可能只写了金库、沙箱 live 还留着被轮换掉的旧 key。必须把另一份也补上，
            // 否则启动时要么跑旧 key 直接失败，要么 VaultSync 反过来把旧 key 推回去。
            try
            {
                foreach (var root in new[] { BoxPaths.WmpfLive(box), BoxPaths.WmpfVault(box) })
                {
                    var tpl = Ilink.AccountFile(root);
                    if (tpl == null) continue;
                    var cur = ReadCredentialFile(tpl.FullName);
                    if (cur.AutoKey.Length == 0) continue;
                    var curHash = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
                        Convert.ToBase64String(cur.AutoKey) + "|" + Convert.ToBase64String(cur.EncKey)));
                    if (curHash == hash) continue;         // 已经是新 key，不用动
                    cur.Path = tpl.FullName;
                    cur.VaultRoot = "";
                    WriteCredential(cur, newKey, newEnc, newSrv);
                    Log.Box(box, $"协议续期：新 key 也写入了 {(root == BoxPaths.WmpfLive(box) ? "沙箱（live）" : "金库（vault）")} "
                        + $"（原为 {curHash}）");
                }
            }
            catch (Exception ex)
            {
                Log.Box(box, "协议续期：另一份凭证同步失败（待写文件保留）：" + ex.Message);
            }

            // 只有确认「live 与金库都是新 key」才删 pending。
            var liveNow = Ilink.Live(box);
            var vaultNow = Ilink.VaultState(box);
            bool liveOk = liveNow.Valid && liveNow.KeyHash == hash;
            bool vaultOk = vaultNow.Valid && vaultNow.KeyHash == hash;
            if (liveOk && vaultOk)
            {
                try { File.Delete(PendingFile(box)); } catch { }
            }
            else
            {
                Log.Box(box, $"协议续期：写入后 沙箱={liveNow.KeyHash} 金库={vaultNow.KeyHash}，期望 {hash} "
                    + "-> keep pending file so the next start can repair it");
            }

            SaveRotatedSnapshot(box, cred, newKey, newEnc, newSrv, hash, oldKeyHash);
            Log.Box(box, $"协议续期成功：新 key={hash} enc=24 serverId={newSrv.Length}");
            if (busyBefore) StartClobberWatch(box, 120);
            try { afterRotate?.Invoke(); }
            catch (Exception ex) { Log.Box(box, "协议续期：afterRotate 回调失败 " + ex.Message); }
            return new Result(true, $"协议续期成功，新 key={hash}", hash, 0);
        }
        catch (Exception ex)
        {
            return Fail(box, ex.Message, long.MaxValue);
        }
    }

    /// <summary>
    /// 真正发一次 AutoAuth 并解析结果。不写任何文件——把「网络交换」和「落盘」分开，
    /// 才能做到「弹扫码框时先不停箱判断历史 key 还能不能用」。
    /// </summary>
    /// <param name="capture">非空时把这次交换的完整过程（请求/密文/逐层字段）填进去，供 <see cref="AutoAuthDump"/> 输出。</param>
    static (bool Ok, long Code, byte[] NewKey, byte[] NewEnc, byte[] NewSrv, string Why)
        Exchange(Credential cred, ulong uin, string host, int port, AutoAuthCapture capture = null)
    {
        var plain = MmtlsProtocol.BuildAutoAuthPlain(cred.DeviceId, cred.AutoKey);
        var (hybrid, temp) = MmtlsProtocol.HybridEncrypt(plain, cred.EncKey);
        using var tempGuard = temp;
        var appId = Encoding.ASCII.GetBytes(cred.IlinkAppId);
        var body = MmtlsProtocol.Concat(
            MmtlsProtocol.SessionWpkgHead(uin, cred.ServerId, appId), hybrid);

        if (capture != null)
        {
            capture.Host = host;
            capture.Port = port;
            capture.Uin = uin.ToString();
            capture.OldKeySha = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
                Convert.ToBase64String(cred.AutoKey) + "|" + Convert.ToBase64String(cred.EncKey)));
            capture.OldEncLen = cred.EncKey.Length + "B";
            capture.PlainLen = plain.Length;
            capture.HybridLen = hybrid.Length;
            capture.BodyLen = body.Length;
            capture.RequestHex = Convert.ToHexString(body);
        }

        using var conn = new MmtlsClient(host, port);
        conn.Handshake();
        conn.SendApp(MmtlsProtocol.CmdAutoAuth, body);
        var (cmd, _, resp) = conn.RecvApp();

        if (capture != null)
        {
            capture.RespCmdId = (int)cmd;
            capture.RespBodyLen = resp.Length;
            capture.RespBodyHex = Convert.ToHexString(resp);
        }

        if (cmd != MmtlsProtocol.CmdAutoAuth)
            return (false, long.MaxValue, null, null, null, $"响应 cmdid 是 {cmd}，不是 {MmtlsProtocol.CmdAutoAuth}");

        var hybridResp = StripWpkgHead(resp);
        if (capture != null)
        {
            capture.WpkgHeadLen = resp.Length - hybridResp.Length;
            capture.CipherLen = hybridResp.Length;
            capture.CipherHex = Convert.ToHexString(hybridResp);
        }

        byte[] decoded;
        try { decoded = MmtlsProtocol.HybridDecrypt(hybridResp, temp); }
        catch (Exception ex)
        {
            if (capture != null) capture.DecryptError = ex.Message;
            return (false, long.MaxValue, null, null, null, "响应解密失败：" + ex.Message);
        }

        if (capture != null)
        {
            capture.DecodedLen = decoded.Length;
            capture.DecodedHex = Convert.ToHexString(decoded);
            capture.Top = MmtlsProtocol.PbParse(decoded);
        }

        var f = MmtlsProtocol.PbParse(decoded);
        if (!f.TryGetValue(1, out var baseF) || baseF.Bytes.Length == 0)
            return (false, long.MaxValue, null, null, null, "响应缺 base 结果块");
        var bf = MmtlsProtocol.PbParse(baseF.Bytes);
        long code = bf.TryGetValue(1, out var codeF) ? MmtlsProtocol.AsSigned(codeF.Num) : long.MaxValue;

        if (capture != null)
        {
            capture.Base = bf;
            capture.Code = code;
            if (f.TryGetValue(2, out var u0) && u0.Bytes.Length > 0)
            {
                capture.Unified = MmtlsProtocol.PbParse(u0.Bytes);
                if (capture.Unified.TryGetValue(2, out var s0) && s0.Bytes.Length > 0)
                    capture.Session = MmtlsProtocol.PbParse(s0.Bytes);
            }
        }

        if (code != 0)
        {
            var why = code switch
            {
                -2 => "服务端拒绝（-2）：这把凭证已不可用或设备信息不匹配",
                -13 => "凭证已被服务端作废（-13）：多半是同一微信号在别处扫码顶掉，需要重新扫码",
                -14 => "服务端拒绝（-14）：会话/票据已失效",
                _ => $"业务层返回 {code}",
            };
            if (capture != null) capture.Why = why;
            return (false, code, null, null, null, why);
        }

        if (!f.TryGetValue(2, out var unified) || unified.Bytes.Length == 0)
            return (false, 0, null, null, null, "响应缺 unified 块，拿不到新凭证");

        var uf = MmtlsProtocol.PbParse(unified.Bytes);
        if (!uf.TryGetValue(2, out var sectF))
            return (false, 0, null, null, null, "响应缺 session 段");
        var sect = MmtlsProtocol.PbParse(sectF.Bytes);
        byte[] newKey = sect.TryGetValue(3, out var k) ? k.Bytes : Array.Empty<byte>();
        byte[] newEnc = sect.TryGetValue(4, out var e) ? e.Bytes : Array.Empty<byte>();
        byte[] newSrv = sect.TryGetValue(9, out var s) ? s.Bytes : Array.Empty<byte>();

        if (capture != null)
        {
            capture.NewKeyLen = newKey.Length;
            capture.NewEncLen = newEnc.Length;
            capture.NewSrvLen = newSrv.Length;
            if (newKey.Length > 0)
                capture.NewKeySha = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
                    Convert.ToBase64String(newKey) + "|" + Convert.ToBase64String(newEnc)));
        }

        if (newKey.Length == 0 || newEnc.Length != 24)
            return (false, 0, null, null, null, $"服务端返回的新凭证不完整（key={newKey.Length} enc={newEnc.Length}）");

        return (true, 0, newKey, newEnc, newSrv, "");
    }

    static Result Fail(string box, string why, long code)
    {
        Log.Box(box, $"协议续期失败：{why} (code={code})");

        // 服务端明确拒绝（-2/-13/-14）时结果是确定的，必须清掉 attempted 标记。
        // 留着它的后果是永久的：`AttemptPending` 会一直为真，于是启动预检
        // （PreflightCheckLiveKey）与主动探测（CredentialProbe.Probe）都永远跳过这个号，
        // 「上次续期结果未知」这句话会跟到用户手动删文件为止。
        // qb4 实测：11-09 08:06 的标记一路留到 11-10，两次启动的预检都是
        // `previous renew result unknown -> skip`，这个号等于失去了自动确认能力。
        bool definitive = code is -2 or -13 or -14;
        if (definitive) ClearAttempt(box);

        // 只有「结果未知」（超时 / 断网 / 解析失败）才保留标记：那种情况不能盲目重放。
        var tail = definitive
            ? "（服务端已明确拒绝，这把凭证需要重新扫码）"
            : "（上一次请求结果未知，标记已保留，请先确认该号是否仍能免扫）";
        return new Result(false, $"协议续期失败：{why}{tail}", "", code);
    }

    /// <summary>
    /// 从响应体里剥掉 wpkg 头，返回 HybridEcdhResponse 起始处。
    /// 头能正常解析就用它的长度；否则找 08 9F 03 12 41 04 特征串往前退 2 字节。
    /// </summary>
    static byte[] StripWpkgHead(byte[] body)
    {
        if (TryWpkgHeadLen(body, out int hlen) && hlen < body.Length && body[hlen] == 0x0A)
            return body[hlen..];

        var marker = new byte[] { 0x08, 0x9F, 0x03, 0x12, 0x41, 0x04 };
        for (int i = 2; i + marker.Length <= body.Length; i++)
            if (body.AsSpan(i, marker.Length).SequenceEqual(marker))
                return body[(i - 2)..];

        return hlen > 0 && hlen < body.Length ? body[hlen..] : body;
    }

    static bool TryWpkgHeadLen(byte[] data, out int hlen)
    {
        hlen = 0;
        try
        {
            int i = 0;
            (_, i) = MmtlsProtocol.ReadVarint(data, i);
            while (i < data.Length)
            {
                ulong fn;
                (fn, i) = MmtlsProtocol.ReadVarint(data, i);
                if (fn == 0) break;
                (_, i) = MmtlsProtocol.ReadVarint(data, i);
            }
            while (i < data.Length)
            {
                ulong fn;
                (fn, i) = MmtlsProtocol.ReadVarint(data, i);
                if (fn == 0) break;
                ulong ln;
                (ln, i) = MmtlsProtocol.ReadVarint(data, i);
                i += (int)ln;
                if (i > data.Length) return false;
            }
            (_, i) = MmtlsProtocol.ReadVarint(data, i);
            hlen = i;
            return hlen > 0 && hlen <= data.Length;
        }
        catch { return false; }
    }
}
