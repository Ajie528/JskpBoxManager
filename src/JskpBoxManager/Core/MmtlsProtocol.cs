using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace JskpBoxManager.Core;

/// <summary>
/// AutoAuth 的业务层实现（纯 C#，无外部依赖）。
///
/// 协议要点（全部实测确认，见 docs\mmtls直连可行性研究.md 6.3A）：
///   明文 = pbLen(1, pbLen(1, Device32)) + pbVar(2, 1901) + pbLen(3, AutoauthKey)
///   wpkg 字段 24 必须填 **kTdiKeyIlinkAppId 字符串**（ilinkapp_xxx），
///       填 32 字节 DeviceId 会被服务端业务层拒成 -2。
///   加密 = Hybrid ECDH：临时 P-256 密钥 + (可选) 24 字节 encKey 包 CEK。
/// </summary>
public static class MmtlsProtocol
{
    public const uint CmdAutoAuth = 3198;
    public const uint CmdManualAuth = 3453;
    public const ulong ClientVersion = 524545;
    public const ulong AppVersion = 1901;

    public static readonly byte[] ServerPub = Convert.FromHexString(
        "04ef87876d6478b15f1796eab12068610541173b7176b67f1dcc86683e901acd44" +
        "d18b4ac36938251d0812dd0cf842aa2d6cbb8115712d1c0087dcefc14a44cd58");

    static readonly byte[] ILinkHkdfSalt = "security hdkf expand"u8.ToArray();

    // ---------------- protobuf ----------------

    public static byte[] Varint(ulong n)
    {
        var o = new List<byte>(10);
        while (true)
        {
            byte b = (byte)(n & 0x7F);
            n >>= 7;
            if (n != 0) o.Add((byte)(b | 0x80));
            else { o.Add(b); return o.ToArray(); }
        }
    }

    public static (ulong Value, int Next) ReadVarint(byte[] d, int i)
    {
        ulong n = 0; int shift = 0;
        while (i < d.Length)
        {
            byte b = d[i++];
            n |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return (n, i);
            shift += 7;
            if (shift > 63) throw new FormatException("varint overflow");
        }
        throw new FormatException("truncated varint");
    }

    public static byte[] PbLen(int field, byte[] data)
    {
        var head = new List<byte> { (byte)((field << 3) | 2) };
        head.AddRange(Varint((ulong)data.Length));
        head.AddRange(data);
        return head.ToArray();
    }

    public static byte[] PbVar(int field, ulong n)
    {
        var o = new List<byte> { (byte)((field << 3) | 0) };
        o.AddRange(Varint(n));
        return o.ToArray();
    }

    /// <summary>解析成 field -&gt; (value, isBytes)。varint 用 ulong 保存（含负数补码）。</summary>
    public static Dictionary<int, (ulong Num, byte[] Bytes)> PbParse(byte[] data)
    {
        var o = new Dictionary<int, (ulong, byte[])>();
        int i = 0;
        while (i < data.Length)
        {
            ulong tag;
            try { (tag, i) = ReadVarint(data, i); } catch { break; }
            int fn = (int)(tag >> 3), wt = (int)(tag & 7);
            if (wt == 0)
            {
                ulong v;
                try { (v, i) = ReadVarint(data, i); } catch { break; }
                o[fn] = (v, Array.Empty<byte>());
            }
            else if (wt == 2)
            {
                ulong ln;
                try { (ln, i) = ReadVarint(data, i); } catch { break; }
                if (i + (int)ln > data.Length) break;
                o[fn] = (0, data[i..(i + (int)ln)]);
                i += (int)ln;
            }
            else break;
        }
        return o;
    }

    /// <summary>把 varint 当有符号读（服务端用补码表示 -2 / -13）。</summary>
    public static long AsSigned(ulong v) => unchecked((long)v);

    // ---------------- AES-GCM（mmtls 布局：body || iv(12) || tag(16)） ----------------

    static byte[] GcmLayoutEncrypt(byte[] key, byte[] aad, byte[] plain)
    {
        var iv = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[plain.Length];
        var tag = new byte[16];
        using var g = new AesGcm(key, 16);
        g.Encrypt(iv, plain, ct, tag, aad);
        var o = new byte[ct.Length + 12 + 16];
        Buffer.BlockCopy(ct, 0, o, 0, ct.Length);
        Buffer.BlockCopy(iv, 0, o, ct.Length, 12);
        Buffer.BlockCopy(tag, 0, o, ct.Length + 12, 16);
        return o;
    }

    static byte[] GcmLayoutDecrypt(byte[] key, byte[] aad, byte[] blob)
    {
        if (blob.Length < 28) throw new CryptographicException("GCM blob 太短");
        int n = blob.Length - 28;
        var ct = blob[..n];
        var iv = blob[n..(n + 12)];
        var tag = blob[(n + 12)..];
        var plain = new byte[n];
        using var g = new AesGcm(key, 16);
        g.Decrypt(iv, ct, tag, plain, aad);
        return plain;
    }

    // ---------------- LZ4 纯 literal ----------------

    public static byte[] Lz4AllLiteral(byte[] data)
    {
        int n = data.Length;
        if (n < 15)
        {
            var o = new byte[1 + n];
            o[0] = (byte)(n << 4);
            Buffer.BlockCopy(data, 0, o, 1, n);
            return o;
        }
        var outb = new List<byte> { 0xF0 };
        int rem = n - 15;
        while (rem >= 255) { outb.Add(255); rem -= 255; }
        outb.Add((byte)rem);
        outb.AddRange(data);
        return outb.ToArray();
    }

    public static byte[] Lz4Decompress(byte[] data)
    {
        var o = new List<byte>(data.Length * 2);
        int i = 0;
        while (i < data.Length)
        {
            byte tok = data[i++];
            int lit = tok >> 4;
            if (lit == 15)
            {
                while (i < data.Length && data[i] == 255) { lit += 255; i++; }
                if (i >= data.Length) throw new FormatException("truncated literal len");
                lit += data[i++];
            }
            if (i + lit > data.Length) throw new FormatException("truncated literals");
            for (int k = 0; k < lit; k++) o.Add(data[i + k]);
            i += lit;
            if (i >= data.Length) break;
            if (i + 2 > data.Length) throw new FormatException("truncated offset");
            int off = data[i] | (data[i + 1] << 8); i += 2;
            if (off <= 0 || off > o.Count) throw new FormatException("bad offset");
            int mlen = (tok & 0x0F) + 4;
            if ((tok & 0x0F) == 15)
            {
                while (i < data.Length && data[i] == 255) { mlen += 255; i++; }
                if (i >= data.Length) throw new FormatException("truncated match len");
                mlen += data[i++];
            }
            int start = o.Count - off;
            for (int k = 0; k < mlen; k++) o.Add(o[start + k]);
        }
        return o.ToArray();
    }

    // ---------------- Hybrid ECDH ----------------

    public sealed class HybridTemp : IDisposable
    {
        public ECDiffieHellman Eph { get; init; }
        public byte[] Okm { get; init; }
        public byte[] Comp { get; init; }
        public byte[] RequestCipher { get; init; }

        public void Dispose()
        {
            try { Eph?.Dispose(); } catch { }
        }
    }

    /// <summary>
    /// 构造 HybridEcdhRequest。encKey 为 24 字节（AutoAuth）或 null（ManualAuth）。
    /// 注意：serverPub 用固定常量（与官方一致），不是握手里的临时公钥。
    /// </summary>
    public static (byte[] Cipher, HybridTemp Temp) HybridEncrypt(byte[] plain, byte[] encKey)
    {
        if (encKey is { Length: > 0 } && encKey.Length != 24)
            throw new ArgumentException($"encKey 长度必须 24，实际 {encKey.Length}");

        var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var ephPub = ExportUncompressed(eph);
        using var srv = PeerFromUncompressed(ServerPub);
        var secretEcdh = eph.DeriveRawSecretAgreement(srv.PublicKey);
        var secret = SHA256.HashData(secretEcdh);

        var hash1 = SHA256.HashData(Concat("1"u8.ToArray(), "415"u8.ToArray(), ephPub));
        var cek = RandomNumberGenerator.GetBytes(32);

        var encCek = GcmLayoutEncrypt(secret[..24], hash1, cek);
        byte[] encSession = Array.Empty<byte>();
        if (encKey is { Length: 24 }) encSession = GcmLayoutEncrypt(encKey, hash1, cek);

        var prk = HMACSHA256.HashData(ILinkHkdfSalt, cek);
        var okm = HkdfExpand(prk, hash1, 56);

        var hash2 = SHA256.HashData(Concat("1"u8.ToArray(), "415"u8.ToArray(), ephPub, encCek, encSession));
        var comp = Lz4AllLiteral(plain);
        var encBody = GcmLayoutEncrypt(okm[..24], hash2, comp);

        var ecdhKey = Concat(PbVar(1, 415), PbLen(2, ephPub));
        var cipher = Concat(
            PbVar(1, 1), PbLen(2, ecdhKey), PbLen(3, encCek), PbLen(4, encSession), PbLen(5, encBody));

        // eph 要留给解密响应（derive 服务端临时公钥），不能释放
        var temp = new HybridTemp { Eph = eph, Okm = okm, Comp = comp, RequestCipher = encBody };
        return (cipher, temp);
    }

    /// <summary>
    /// 解密 HybridEcdhResponse。marker 兜底：真实响应里有时 wpkg 头解析不出，
    /// 要靠 08 9F 03 12 41 04 这个特征串定位。
    /// </summary>
    public static byte[] HybridDecrypt(byte[] response, HybridTemp temp)
    {
        var f = PbParse(response);
        if (!f.TryGetValue(1, out var f1) || f1.Bytes.Length == 0)
            throw new CryptographicException("HybridEcdhResponse 缺 field 1");
        var kf = PbParse(f1.Bytes);
        if (!kf.TryGetValue(2, out var srvPub) || srvPub.Bytes.Length == 0)
            throw new CryptographicException("缺 server pubkey");
        if (!f.TryGetValue(3, out var ct) || ct.Bytes.Length == 0)
            throw new CryptographicException("缺 ciphertext");

        long credType = f.TryGetValue(2, out var ctv) ? (long)ctv.Num : 1;

        using var peer = PeerFromUncompressed(srvPub.Bytes);
        var shared = temp.Eph.DeriveRawSecretAgreement(peer.PublicKey);
        var secret = SHA256.HashData(shared);
        var aad = SHA256.HashData(Concat(
            temp.Okm[24..56], temp.Comp, "415"u8.ToArray(), srvPub.Bytes,
            Encoding.ASCII.GetBytes(credType.ToString())));

        var comp = GcmLayoutDecrypt(secret[..24], aad, ct.Bytes);
        return Lz4Decompress(comp);
    }

    // ---------------- wpkg 头 ----------------

    public static byte[] WpkgHead(SortedDictionary<int, ulong> ints, SortedDictionary<int, byte[]> byts)
    {
        var o = new List<byte>();
        o.AddRange(Varint(1));
        foreach (var kv in ints) { o.AddRange(Varint((ulong)kv.Key)); o.AddRange(Varint(kv.Value)); }
        o.AddRange(Varint(0));
        foreach (var kv in byts)
        {
            o.AddRange(Varint((ulong)kv.Key));
            o.AddRange(Varint((ulong)kv.Value.Length));
            o.AddRange(kv.Value);
        }
        int prefix = o.Count;
        o.Add(0);
        o.AddRange(Varint((ulong)(prefix + 1)));
        return o.ToArray();
    }

    /// <summary>
    /// AutoAuth 的 wpkg 头。ints[25]=17（App instance 清 IsAppAccount），
    /// 字段 24 是 ilinkAppId 字符串，字段 27 是 ServerId。
    /// </summary>
    public static byte[] SessionWpkgHead(ulong uin, byte[] serverId, byte[] ilinkAppId)
    {
        var ints = new SortedDictionary<int, ulong>
        {
            [1] = 1, [2] = uin, [3] = 0, [4] = 0, [5] = ClientVersion, [6] = 11,
            [7] = 0, [8] = 0, [9] = 0, [10] = 1, [11] = 0, [12] = 0, [13] = 0,
            [17] = 0, [18] = 1, [20] = 1504, [21] = 0, [22] = uin, [23] = 0,
            [25] = 17, [26] = 4, [28] = 1, [29] = 1, [30] = 0,
        };
        var byts = new SortedDictionary<int, byte[]>
        {
            [14] = Array.Empty<byte>(),
            [24] = ilinkAppId,
            [27] = serverId,
        };
        return WpkgHead(ints, byts);
    }

    /// <summary>
    /// AutoAuth 明文：pbLen(1, pbLen(1, Device)) + pbVar(2, 1901) + pbLen(3, Key)。
    /// Device 是 32 字节本地设备标识（实测用 kTdiKeyDeviceId 可通过）。
    /// </summary>
    public static byte[] BuildAutoAuthPlain(byte[] device32, byte[] autoKey, ulong appVersion = AppVersion)
        => Concat(PbLen(1, PbLen(1, device32)), PbVar(2, appVersion), PbLen(3, autoKey));

    // ---------------- 工具 ----------------

    public static byte[] Concat(params byte[][] parts)
    {
        int len = 0;
        foreach (var p in parts) len += p.Length;
        var o = new byte[len];
        int at = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, o, at, p.Length); at += p.Length; }
        return o;
    }

    static byte[] HkdfExpand(byte[] prk, byte[] info, int length)
    {
        var o = new byte[length];
        var t = Array.Empty<byte>();
        int filled = 0;
        byte c = 1;
        while (filled < length)
        {
            var buf = Concat(t, info, new[] { c });
            t = HMACSHA256.HashData(prk, buf);
            int take = Math.Min(t.Length, length - filled);
            Buffer.BlockCopy(t, 0, o, filled, take);
            filled += take;
            c++;
        }
        return o;
    }

    public static byte[] ExportUncompressed(ECDiffieHellman k)
    {
        // ECDiffieHellman 的 PublicKey 只支持 ExportSubjectPublicKeyInfo / DeriveRawSecretAgreement；
        // 要拿 X/Y 必须导出 PKCS#7 再解析，或者用 ExportExplicitParameters。
        var p = k.ExportExplicitParameters(false);
        var o = new byte[65];
        o[0] = 0x04;
        Buffer.BlockCopy(p.Q.X!, 0, o, 1, 32);
        Buffer.BlockCopy(p.Q.Y!, 0, o, 33, 32);
        return o;
    }

    public static ECDiffieHellman PeerFromUncompressed(byte[] point)
    {
        if (point.Length != 65 || point[0] != 0x04)
            throw new CryptographicException("不是未压缩 P-256 点");
        return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = point[1..33], Y = point[33..65] },
        });
    }
}
