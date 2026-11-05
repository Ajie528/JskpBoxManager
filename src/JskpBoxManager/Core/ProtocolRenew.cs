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

    public sealed record Result(bool Ok, string Message, string NewKeyHash = "", long Code = long.MaxValue)
    {
        public bool Rejected => Code is -2 or -13 or -14;
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
            catch (Exception ex) { Log.Box(Path.GetFileName(c.VaultRoot), "protocol renew: vault sync failed " + ex.Message); }
        }
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

    public static bool AttemptPending(string box) => LastAttemptAt(box) != null;

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
        catch (Exception ex) { Log.Box(box, "protocol renew: snapshot save failed " + ex.Message); }
    }

    /// <summary>上一次协议续期换到的 key 哈希；没有返回空串。</summary>
    public static string RotatedKeyHash(string box)
        => JsonFile.Str(JsonFile.ReadObject(RotatedFile(box)), "keySha");

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
        var live = Ilink.Live(box);
        if (!live.Valid) return false;
        if (live.KeyHash == hash) return false;        // 还是新 key，没被覆盖
        if (live.KeyHash != prevHash)
        {
            // 既不是新 key 也不是续期前的旧 key：运行时自己换了一把更新的，快照作废
            try { File.Delete(RotatedFile(box)); } catch { }
            Log.Box(box, $"protocol renew: runtime rotated to {live.KeyHash} by itself -> drop stale snapshot");
            return false;
        }
        var key = B64(JsonFile.Str(o, "autoKey"));
        var enc = B64(JsonFile.Str(o, "encKey"));
        if (key.Length == 0 || enc.Length != 24) return false;
        var cred = ReadCredential(box);
        try
        {
            WriteCredential(cred, key, enc, B64(JsonFile.Str(o, "serverId")));
            Log.Box(box, $"protocol renew: runtime wrote back old key {live.KeyHash} -> restored renewed key {hash} ({reason})");
            Ilink.WriteEvent(box, "key-restored", new JsonObject
            {
                ["keySha"] = hash, ["clobberedBy"] = live.KeyHash, ["reason"] = reason,
            });
            return true;
        }
        catch (Exception ex)
        {
            Log.Box(box, "protocol renew: restore renewed key failed " + ex.Message);
            return false;
        }
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
                Log.Box(box, "protocol renew: cannot write attempt marker, abort before send: " + ex.Message);
                return new Result(false, "无法写续期标记，为避免丢密钥已放弃发送：" + ex.Message);
            }
            Log.Box(box, $"protocol renew: attempt marker written (old key {oldKeyHash})");
        }

        // ---- 2. 发送 ----
        try
        {
            var plain = MmtlsProtocol.BuildAutoAuthPlain(cred.DeviceId, cred.AutoKey);
            var (hybrid, temp) = MmtlsProtocol.HybridEncrypt(plain, cred.EncKey);
            using var tempGuard = temp;
            var appId = Encoding.ASCII.GetBytes(cred.IlinkAppId);
            var body = MmtlsProtocol.Concat(
                MmtlsProtocol.SessionWpkgHead(uin, cred.ServerId, appId), hybrid);

            if (dryRun)
                return new Result(true, $"演练完成：明文 {plain.Length} 字节，hybrid {hybrid.Length} 字节，"
                    + $"请求体 {body.Length} 字节（未发送）");

            using var conn = new MmtlsClient(host, port);
            conn.Handshake();
            conn.SendApp(MmtlsProtocol.CmdAutoAuth, body);
            var (cmd, _, resp) = conn.RecvApp();
            if (cmd != MmtlsProtocol.CmdAutoAuth)
                return Fail(box, $"响应 cmdid 是 {cmd}，不是 {MmtlsProtocol.CmdAutoAuth}", long.MaxValue);

            // 响应体 = wpkg 头 + HybridEcdhResponse。头解析不出来时用特征串兜底。
            var hybridResp = StripWpkgHead(resp);
            byte[] decoded;
            try { decoded = MmtlsProtocol.HybridDecrypt(hybridResp, temp); }
            catch (Exception ex) { return Fail(box, "响应解密失败：" + ex.Message, long.MaxValue); }

            // ---- 3. 解析业务结果 ----
            var f = MmtlsProtocol.PbParse(decoded);
            if (!f.TryGetValue(1, out var baseF) || baseF.Bytes.Length == 0)
                return Fail(box, "响应缺 base 结果块", long.MaxValue);
            var bf = MmtlsProtocol.PbParse(baseF.Bytes);
            long code = bf.TryGetValue(1, out var codeF) ? MmtlsProtocol.AsSigned(codeF.Num) : long.MaxValue;
            if (code != 0)
                return Fail(box, code switch
                {
                    -2 => "服务端拒绝（-2）：这把凭证已不可用或设备信息不匹配",
                    -13 => "凭证已被服务端作废（-13）：多半是同一微信号在别处扫码顶掉，需要重新扫码",
                    -14 => "服务端拒绝（-14）：会话/票据已失效",
                    _ => $"业务层返回 {code}",
                }, code);

            if (!f.TryGetValue(2, out var unified) || unified.Bytes.Length == 0)
                return Fail(box, "响应缺 unified 块，拿不到新凭证", 0);

            var uf = MmtlsProtocol.PbParse(unified.Bytes);
            if (!uf.TryGetValue(2, out var sectF))
                return Fail(box, "响应缺 session 段", 0);
            var sect = MmtlsProtocol.PbParse(sectF.Bytes);
            byte[] newKey = sect.TryGetValue(3, out var k) ? k.Bytes : Array.Empty<byte>();
            byte[] newEnc = sect.TryGetValue(4, out var e) ? e.Bytes : Array.Empty<byte>();
            byte[] newSrv = sect.TryGetValue(9, out var s) ? s.Bytes : Array.Empty<byte>();
            if (newKey.Length == 0 || newEnc.Length != 24)
                return Fail(box, $"服务端返回的新凭证不完整（key={newKey.Length} enc={newEnc.Length}）", 0);

            // ---- 4. 写回 ----
            try { WriteCredential(cred, newKey, newEnc, newSrv); }
            catch (Exception ex) { return Fail(box, "写回凭证失败：" + ex.Message, 0); }
            ClearAttempt(box);

            var hash = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
                Convert.ToBase64String(newKey) + "|" + Convert.ToBase64String(newEnc)));
            SaveRotatedSnapshot(box, cred, newKey, newEnc, newSrv, hash, oldKeyHash);
            Log.Box(box, $"protocol renew ok: newKey={hash} enc=24 serverId={newSrv.Length}");
            if (busyBefore) StartClobberWatch(box, 120);
            try { afterRotate?.Invoke(); }
            catch (Exception ex) { Log.Box(box, "protocol renew: afterRotate failed " + ex.Message); }
            return new Result(true, $"协议续期成功，新 key={hash}", hash, 0);
        }
        catch (Exception ex)
        {
            return Fail(box, ex.Message, long.MaxValue);
        }
    }

    static Result Fail(string box, string why, long code)
    {
        Log.Box(box, $"protocol renew failed: {why} (code={code})");
        // attempted 保留：下次操作会提示「上次结果未知」，不盲目重放
        var tail = code is -2 or -13 or -14
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
