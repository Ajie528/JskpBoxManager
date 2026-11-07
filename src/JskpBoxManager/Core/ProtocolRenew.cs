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
            catch (Exception ex) { Log.Box(Path.GetFileName(c.VaultRoot), "protocol renew: vault sync failed " + ex.Message); }
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
        var (ok, code, newKey, newEnc, newSrv, why) = Exchange(cred, uin, host, port);
        if (!ok) return new Result(false, why, "", code);
        var hash = Ilink.ShortSha256(Encoding.UTF8.GetBytes(
            Convert.ToBase64String(newKey) + "|" + Convert.ToBase64String(newEnc)));
        // 新 key 先存在返回对象里，由调用方停箱后调用 CommitToFile 落盘
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

    /// <summary>当前这把凭证最后一次换新距今多少小时；live 和金库取较新的那个。没有有效凭证返回 null。</summary>
    public static double? KeyAgeHours(string box)
    {
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
            Log.Box(box, $"protocol renew: snapshot expired ({(DateTime.Now - at).TotalMinutes:F0}min) -> dropped, no restore");
            return false;
        }

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
            // 已经用掉了，删掉快照，避免同一次续期被反复"纠正"
            try { File.Delete(RotatedFile(box)); } catch { }
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

    /// <summary>丢掉续期快照：当有人「有意」换了一套凭证（恢复历史、导入、清登录）时调用。</summary>
    public static void DropSnapshot(string box, string reason)
    {
        try
        {
            if (!File.Exists(RotatedFile(box))) return;
            File.Delete(RotatedFile(box));
            Log.Box(box, "protocol renew: snapshot dropped (" + reason + ")");
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
                Log.Box(box, "protocol renew: cannot write attempt marker, abort before send: " + ex.Message);
                return new Result(false, "无法写续期标记，为避免丢密钥已放弃发送：" + ex.Message);
            }
            Log.Box(box, $"protocol renew: attempt marker written (old key {oldKeyHash})");
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

            var (ok, code, newKey, newEnc, newSrv, why) = Exchange(cred, uin, host, port);
            if (!ok) return Fail(box, why, code);

            // ---- 3. 写回 ----
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

    /// <summary>
    /// 真正发一次 AutoAuth 并解析结果。不写任何文件——把「网络交换」和「落盘」分开，
    /// 才能做到「弹扫码框时先不停箱判断历史 key 还能不能用」。
    /// </summary>
    static (bool Ok, long Code, byte[] NewKey, byte[] NewEnc, byte[] NewSrv, string Why)
        Exchange(Credential cred, ulong uin, string host, int port)
    {
        var plain = MmtlsProtocol.BuildAutoAuthPlain(cred.DeviceId, cred.AutoKey);
        var (hybrid, temp) = MmtlsProtocol.HybridEncrypt(plain, cred.EncKey);
        using var tempGuard = temp;
        var appId = Encoding.ASCII.GetBytes(cred.IlinkAppId);
        var body = MmtlsProtocol.Concat(
            MmtlsProtocol.SessionWpkgHead(uin, cred.ServerId, appId), hybrid);

        using var conn = new MmtlsClient(host, port);
        conn.Handshake();
        conn.SendApp(MmtlsProtocol.CmdAutoAuth, body);
        var (cmd, _, resp) = conn.RecvApp();
        if (cmd != MmtlsProtocol.CmdAutoAuth)
            return (false, long.MaxValue, null, null, null, $"响应 cmdid 是 {cmd}，不是 {MmtlsProtocol.CmdAutoAuth}");

        var hybridResp = StripWpkgHead(resp);
        byte[] decoded;
        try { decoded = MmtlsProtocol.HybridDecrypt(hybridResp, temp); }
        catch (Exception ex) { return (false, long.MaxValue, null, null, null, "响应解密失败：" + ex.Message); }

        var f = MmtlsProtocol.PbParse(decoded);
        if (!f.TryGetValue(1, out var baseF) || baseF.Bytes.Length == 0)
            return (false, long.MaxValue, null, null, null, "响应缺 base 结果块");
        var bf = MmtlsProtocol.PbParse(baseF.Bytes);
        long code = bf.TryGetValue(1, out var codeF) ? MmtlsProtocol.AsSigned(codeF.Num) : long.MaxValue;
        if (code != 0)
            return (false, code, null, null, null, code switch
            {
                -2 => "服务端拒绝（-2）：这把凭证已不可用或设备信息不匹配",
                -13 => "凭证已被服务端作废（-13）：多半是同一微信号在别处扫码顶掉，需要重新扫码",
                -14 => "服务端拒绝（-14）：会话/票据已失效",
                _ => $"业务层返回 {code}",
            });

        if (!f.TryGetValue(2, out var unified) || unified.Bytes.Length == 0)
            return (false, 0, null, null, null, "响应缺 unified 块，拿不到新凭证");

        var uf = MmtlsProtocol.PbParse(unified.Bytes);
        if (!uf.TryGetValue(2, out var sectF))
            return (false, 0, null, null, null, "响应缺 session 段");
        var sect = MmtlsProtocol.PbParse(sectF.Bytes);
        byte[] newKey = sect.TryGetValue(3, out var k) ? k.Bytes : Array.Empty<byte>();
        byte[] newEnc = sect.TryGetValue(4, out var e) ? e.Bytes : Array.Empty<byte>();
        byte[] newSrv = sect.TryGetValue(9, out var s) ? s.Bytes : Array.Empty<byte>();
        if (newKey.Length == 0 || newEnc.Length != 24)
            return (false, 0, null, null, null, $"服务端返回的新凭证不完整（key={newKey.Length} enc={newEnc.Length}）");

        return (true, 0, newKey, newEnc, newSrv, "");
    }

    /// <summary>
    /// 把 AutoAuth 响应里的字段结构打到日志（JSKP_DUMP_AUTOAUTH=1 时启用）。
    /// 目的：确认服务端是否回传「有效期 / 到期时间」之类的字段——
    /// 有就能算出免扫的真实上限，没有就说明寿命只能靠实测统计。
    /// </summary>
    static void DumpUnknownFields(string box, Dictionary<int, (ulong Num, byte[] Bytes)> uf,
        Dictionary<int, (ulong Num, byte[] Bytes)> sect)
    {
        var sb = new StringBuilder();
        sb.AppendLine("protocol renew: AutoAuth response fields (dump)");
        sb.AppendLine("  unified{session{...}}:");
        foreach (var kv in sect.OrderBy(x => x.Key))
        {
            var (num, bytes) = kv.Value;
            if (bytes.Length > 0)
            {
                var hex = Convert.ToHexString(bytes[..Math.Min(bytes.Length, 32)]);
                sb.AppendLine($"    f{kv.Key} bytes[{bytes.Length}] {hex}" + (bytes.Length > 32 ? "…" : ""));
            }
            else
            {
                // varint 可能是秒/毫秒时间戳或天数，两种都打出来方便判读
                sb.AppendLine($"    f{kv.Key} varint={num}  signed={MmtlsProtocol.AsSigned(num)}"
                    + (num > 1_600_000_000 && num < 2_000_000_000 ? "  (像 unix 秒)" : "")
                    + (num > 1_600_000_000_000 && num < 2_000_000_000_000 ? "  (像 unix 毫秒)" : ""));
            }
        }
        sb.AppendLine("  unified 其它字段:");
        foreach (var kv in uf.OrderBy(x => x.Key))
        {
            if (kv.Key == 2) continue;
            var (num, bytes) = kv.Value;
            sb.AppendLine(bytes.Length > 0
                ? $"    f{kv.Key} bytes[{bytes.Length}] {Convert.ToHexString(bytes[..Math.Min(bytes.Length, 32)])}"
                : $"    f{kv.Key} varint={num}");
        }
        var text = sb.ToString();
        Log.Box(box, text.Replace("\r\n", " | ").Replace("\n", " | ").Trim());
        try
        {
            Directory.CreateDirectory(AppPaths.Logs);
            File.AppendAllText(Path.Combine(AppPaths.Logs, box + ".autoauth-fields.txt"),
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\n{text}\n", new UTF8Encoding(false));
        }
        catch { }
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
