using System.Security.Cryptography;
using System.Text;

namespace JskpBoxManager.Core;

/// <summary>
/// mmtls 协议层（原生 C# 实现，不依赖 Python / OpenSSL 外部库）。
///
/// 参数全部来自实测（见 docs\mmtls直连可行性研究.md 6.2/6.3A）：
///   记录版本 0xf103、握手套件 0xc02b(P-256)、shortlink magic 0x1110 ver 0x076d、
///   记录 AAD = seq(8) + ct(1) + 0xf1 0x03 + cipherLen(2)。
///
/// 用法：
///   using var c = new MmtlsClient("longcloud.weixin.com", 5000);
///   c.Handshake();
///   c.SendApp(3198, body);
///   var resp = c.RecvApp();
/// </summary>
public sealed class MmtlsClient : IDisposable
{
    public const int RecordVersion = 0xF103;
    public const byte CtHandshake = 0x16;
    public const byte CtAppData = 0x17;

    public const int HsClientHello = 0x01;
    public const int HsServerHello = 0x02;
    public const int HsNewSessionTicket = 0x04;
    public const int HsCertVerify = 0x0F;
    public const int HsFinished = 0x14;

    public const int CipherEcdhe = 0xC02B;
    public const int ExtKeyShare = 0x01;
    public const int GroupP256 = 0x01;
    public const int Group2 = 0x02;
    public const int KeyLen = 65;

    public const int ShortlinkMagic = 0x1110;
    public const int DefaultVer = 0x076D;

    static readonly byte[] LabelExpandedSecret = "expanded secret"u8.ToArray();
    static readonly byte[] LabelHandshakeKeys = "handshake key expansion"u8.ToArray();
    static readonly byte[] LabelAppDataKeys = "application data key expansion"u8.ToArray();
    static readonly byte[] LabelClientFinished = "client finished"u8.ToArray();
    static readonly byte[] LabelServerFinished = "server finished"u8.ToArray();

    readonly System.Net.Sockets.TcpClient _tcp;
    readonly System.Net.Sockets.NetworkStream _net;
    int _tx, _rx;
    byte[] _transcript = Array.Empty<byte>();
    byte[] _rxbuf = Array.Empty<byte>();
    readonly Queue<(byte Ct, byte[] Payload)> _recq = new();
    int _appTx;

    byte[] _appCKey = Array.Empty<byte>(), _appSKey = Array.Empty<byte>();
    byte[] _appCIv = Array.Empty<byte>(), _appSIv = Array.Empty<byte>();

    /// <summary>握手得到的 PSK（type 1=ACCESS / 2=REFRESH）。</summary>
    public List<(int Type, uint Lifetime, byte[] Psk, byte[] Entry)> Psks { get; } = new();

    public MmtlsClient(string host, int port, int timeoutMs = 15000)
    {
        _tcp = new System.Net.Sockets.TcpClient { ReceiveTimeout = timeoutMs, SendTimeout = timeoutMs };
        _tcp.Connect(host, port);
        _net = _tcp.GetStream();
    }

    // ---------------- 记录层 ----------------

    static byte[] BuildRecord(byte ct, byte[] payload)
    {
        var o = new byte[5 + payload.Length];
        o[0] = ct;
        o[1] = (byte)(RecordVersion >> 8);
        o[2] = unchecked((byte)RecordVersion);
        o[3] = (byte)(payload.Length >> 8);
        o[4] = unchecked((byte)payload.Length);
        Buffer.BlockCopy(payload, 0, o, 5, payload.Length);
        return o;
    }

    static int ParseRecords(byte[] data, List<(byte Ct, byte[] Payload)> recs)
    {
        int off = 0;
        while (off + 5 <= data.Length)
        {
            byte ct = data[off];
            int ver = (data[off + 1] << 8) | data[off + 2];
            int ln = (data[off + 3] << 8) | data[off + 4];
            if (ver != RecordVersion || ct is not (0x15 or 0x16 or 0x17 or 0x19 or 0x14)) break;
            int end = off + 5 + ln;
            if (end > data.Length) break;
            var p = new byte[ln];
            Buffer.BlockCopy(data, off + 5, p, 0, ln);
            recs.Add((ct, p));
            off = end;
        }
        return off;
    }

    static byte[] BuildRecordAad(long seq, byte ct, int cipherLen)
    {
        var aad = new byte[13];
        for (int i = 0; i < 8; i++) aad[i] = (byte)(seq >> (56 - i * 8));
        aad[8] = ct; aad[9] = 0xF1; aad[10] = 0x03;
        aad[11] = (byte)(cipherLen >> 8); aad[12] = (byte)cipherLen;
        return aad;
    }

    static byte[] NonceFor(byte[] iv, long seq)
    {
        var n = (byte[])iv.Clone();
        for (int i = 0; i < 8; i++) n[n.Length - 8 + i] ^= (byte)(seq >> (56 - i * 8));
        return n;
    }

    static byte[] GcmEncrypt(byte[] key, byte[] iv, long seq, byte[] plain, byte[] aad)
    {
        var ct = new byte[plain.Length];
        var tag = new byte[16];
        using var g = new AesGcm(key, 16);
        g.Encrypt(NonceFor(iv, seq), plain, ct, tag, aad);
        var o = new byte[ct.Length + 16];
        Buffer.BlockCopy(ct, 0, o, 0, ct.Length);
        Buffer.BlockCopy(tag, 0, o, ct.Length, 16);
        return o;
    }

    static byte[] GcmDecrypt(byte[] key, byte[] iv, long seq, byte[] blob, byte[] aad)
    {
        if (blob.Length < 16) throw new CryptographicException("GCM 密文太短");
        int n = blob.Length - 16;
        var ct = new byte[n];
        var tag = new byte[16];
        Buffer.BlockCopy(blob, 0, ct, 0, n);
        Buffer.BlockCopy(blob, n, tag, 0, 16);
        var plain = new byte[n];
        using var g = new AesGcm(key, 16);
        g.Decrypt(NonceFor(iv, seq), ct, tag, plain, aad);
        return plain;
    }

    // ---------------- HKDF ----------------

    static byte[] HkdfExtract(byte[] salt, byte[] ikm) => HMACSHA256.HashData(salt, ikm);

    static byte[] HkdfExpand(byte[] prk, byte[] info, int length)
    {
        var o = new byte[length];
        var t = Array.Empty<byte>();
        int filled = 0;
        byte counter = 1;
        while (filled < length)
        {
            var buf = new byte[t.Length + info.Length + 1];
            Buffer.BlockCopy(t, 0, buf, 0, t.Length);
            Buffer.BlockCopy(info, 0, buf, t.Length, info.Length);
            buf[^1] = counter;
            t = HMACSHA256.HashData(prk, buf);
            int take = Math.Min(t.Length, length - filled);
            Buffer.BlockCopy(t, 0, o, filled, take);
            filled += take;
            counter++;
        }
        return o;
    }

    static byte[] ExpandLabel(byte[] secret, byte[] label, byte[] context, int length)
    {
        var info = new byte[label.Length + (context?.Length ?? 0)];
        Buffer.BlockCopy(label, 0, info, 0, label.Length);
        if (context is { Length: > 0 }) Buffer.BlockCopy(context, 0, info, label.Length, context.Length);
        return HkdfExpand(secret, info, length);
    }

    // ---------------- 握手 ----------------

    byte[] Send(byte[] data) { _net.Write(data, 0, data.Length); _net.Flush(); return data; }

    (byte Ct, byte[] Payload) RecvRecord()
    {
        if (_recq.Count > 0) return _recq.Dequeue();
        while (true)
        {
            var recs = new List<(byte, byte[])>();
            int off = ParseRecords(_rxbuf, recs);
            if (recs.Count > 0)
            {
                _rxbuf = _rxbuf[off..];
                foreach (var r in recs) _recq.Enqueue(r);
                return _recq.Dequeue();
            }
            var chunk = new byte[65536];
            int n = _net.Read(chunk, 0, chunk.Length);
            if (n <= 0) throw new IOException("peer closed");
            var merged = new byte[_rxbuf.Length + n];
            Buffer.BlockCopy(_rxbuf, 0, merged, 0, _rxbuf.Length);
            Buffer.BlockCopy(chunk, 0, merged, _rxbuf.Length, n);
            _rxbuf = merged;
        }
    }

    static byte[] BuildHandshake(int type, byte[] body)
    {
        var o = new byte[4 + 1 + body.Length];
        int total = 1 + body.Length;
        o[0] = (byte)(total >> 24); o[1] = (byte)(total >> 16); o[2] = (byte)(total >> 8); o[3] = (byte)total;
        o[4] = (byte)type;
        Buffer.BlockCopy(body, 0, o, 5, body.Length);
        return o;
    }

    static (int Type, byte[] Body) SplitHandshake(byte[] payload)
    {
        int total = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
        int n = Math.Min(total, payload.Length - 4);
        var body = new byte[Math.Max(0, n - 1)];
        if (body.Length > 0) Buffer.BlockCopy(payload, 5, body, 0, body.Length);
        return (payload[4], body);
    }

    static ECDiffieHellman CreateP256() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    static byte[] PubOf(ECDiffieHellman k) => k.PublicKey.ExportSubjectPublicKeyInfo().Length > 0
        ? ExportUncompressed(k) : Array.Empty<byte>();

    /// <summary>导出未压缩点格式（04||X||Y），mmtls 要的就是这个。</summary>
    static byte[] ExportUncompressed(ECDiffieHellman k) => MmtlsProtocol.ExportUncompressed(k);

    static ECDiffieHellman PeerFromUncompressed(byte[] point) => MmtlsProtocol.PeerFromUncompressed(point);

    static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    static byte[] Concat(params byte[][] parts)
    {
        int len = parts.Sum(p => p.Length);
        var o = new byte[len];
        int at = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, o, at, p.Length); at += p.Length; }
        return o;
    }

    static byte[] BuildClientHello(byte[] g1, byte[] g2, byte[] rnd, uint ts)
    {
        var body = new List<byte> { 0x03, 0xF1, 0x01 };
        body.Add((byte)(CipherEcdhe >> 8)); body.Add(unchecked((byte)CipherEcdhe));
        body.AddRange(rnd);
        body.Add((byte)(ts >> 24)); body.Add((byte)(ts >> 16)); body.Add((byte)(ts >> 8)); body.Add((byte)ts);

        var ks = new List<byte> { 0x00, 0x10, 0x02 };
        foreach (var (g, p) in new[] { (GroupP256, g1), (Group2, g2) })
        {
            var one = new List<byte>();
            one.Add((byte)(g >> 24)); one.Add((byte)(g >> 16)); one.Add((byte)(g >> 8)); one.Add((byte)g);
            one.Add((byte)(KeyLen >> 8)); one.Add((byte)KeyLen);
            one.AddRange(p);
            int ol = one.Count;
            ks.Add((byte)(ol >> 24)); ks.Add((byte)(ol >> 16)); ks.Add((byte)(ol >> 8)); ks.Add((byte)ol);
            ks.AddRange(one);
        }
        ks.AddRange(new byte[] { 0, 0, 0, 1 });

        var ext = new List<byte> { (byte)ExtKeyShare };
        int kl = ks.Count;
        ext.Add((byte)(kl >> 24)); ext.Add((byte)(kl >> 16)); ext.Add((byte)(kl >> 8)); ext.Add((byte)kl);
        ext.AddRange(ks);

        int el = ext.Count;
        body.Add((byte)(el >> 24)); body.Add((byte)(el >> 16)); body.Add((byte)(el >> 8)); body.Add((byte)el);
        body.AddRange(ext);
        return BuildHandshake(HsClientHello, body.ToArray());
    }

    /// <summary>完整握手。返回 transcript 里的关键哈希，供调用方派生 PSK。</summary>
    public void Handshake()
    {
        using var g1 = CreateP256();
        using var g2 = CreateP256();
        var g1Pub = ExportUncompressed(g1);
        var g2Pub = ExportUncompressed(g2);
        var clientRandom = RandomNumberGenerator.GetBytes(32);
        var ch = BuildClientHello(g1Pub, g2Pub, clientRandom, (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        _transcript = Concat(_transcript, ch);
        Send(BuildRecord(CtHandshake, ch));
        _tx++;

        var (ct, payload) = RecvRecord(); _rx++;
        if (ct != CtHandshake) throw new CryptographicException($"期望 Handshake，收到 0x{ct:x2}");
        var (mt, body) = SplitHandshake(payload);
        if (mt != HsServerHello) throw new CryptographicException($"期望 ServerHello，收到 0x{mt:x2}");
        _transcript = Concat(_transcript, payload);

        // ServerHello: proto(2) cipher(2) random(32) extLen(4) ext
        int o = 2;
        int cipher = (body[o] << 8) | body[o + 1]; o += 2;
        o += 32;
        int extLen = (body[o] << 24) | (body[o + 1] << 16) | (body[o + 2] << 8) | body[o + 3]; o += 4;
        var ext = body[o..Math.Min(o + extLen, body.Length)];
        byte[] serverPub = Array.Empty<byte>();
        if (ext.Length > 0 && ext[0] == ExtKeyShare)
        {
            int eo = 1 + 4 + 2;
            eo += 4;   // group
            int klen = (ext[eo] << 8) | ext[eo + 1]; eo += 2;
            serverPub = ext[eo..Math.Min(eo + klen, ext.Length)];
        }
        if (cipher != CipherEcdhe) throw new CryptographicException($"意外的套件 0x{cipher:x4}");
        if (serverPub.Length == 0) throw new CryptographicException("ServerHello 没有 key share");

        using var peer = PeerFromUncompressed(serverPub);
        var shared = g1.DeriveRawSecretAgreement(peer.PublicKey);
        var secret = Sha256(shared);
        var hsHash = Sha256(_transcript);
        var kb = ExpandLabel(secret, LabelHandshakeKeys, hsHash, 56);
        var hsCKey = kb[0..16]; var hsSKey = kb[16..32];
        var hsCIv = kb[32..44]; var hsSIv = kb[44..56];

        byte[]? hCertV = null;
        byte[]? hFinal = null;
        while (true)
        {
            var (ct2, cp) = RecvRecord();
            long seq = _rx; _rx++;
            var aad = BuildRecordAad(seq, ct2, cp.Length);
            var pt = GcmDecrypt(hsSKey, hsSIv, seq, cp, aad);
            var (mt2, mbody) = SplitHandshake(pt);

            if (mt2 == HsFinished)
            {
                hFinal = Sha256(_transcript);
                int n = (mbody[0] << 8) | mbody[1];
                var got = mbody[2..(2 + n)];
                var want = FinishedVd(secret, false, hFinal);
                if (!got.AsSpan().SequenceEqual(want)) throw new CryptographicException("ServerFinished 校验失败");
                _transcript = Concat(_transcript, pt);
                break;
            }
            _transcript = Concat(_transcript, pt);
            if (mt2 == HsCertVerify) hCertV = Sha256(_transcript);
            else if (mt2 == HsNewSessionTicket) ParseNst(mbody, secret, hCertV);
        }

        var master = ExpandLabel(secret, LabelExpandedSecret, hFinal!, 32);
        var ak = ExpandLabel(master, LabelAppDataKeys, hFinal!, 56);
        _appCKey = ak[0..16]; _appSKey = ak[16..32];
        _appCIv = ak[32..44]; _appSIv = ak[44..56];

        var vd = FinishedVd(secret, true, hFinal!);
        var cf = BuildHandshake(HsFinished, Concat(new[] { (byte)(vd.Length >> 8), (byte)vd.Length }, vd));
        long cseq = _tx;
        var caad = BuildRecordAad(cseq, CtHandshake, cf.Length + 16);
        Send(BuildRecord(CtHandshake, GcmEncrypt(hsCKey, hsCIv, cseq, cf, caad)));
        _tx++;
    }

    void ParseNst(byte[] body, byte[] secret, byte[]? hCertV)
    {
        if (body.Length == 0) return;
        int count = body[0], o = 1;
        for (int i = 0; i < count && o + 4 <= body.Length; i++)
        {
            int elen = (body[o] << 24) | (body[o + 1] << 16) | (body[o + 2] << 8) | body[o + 3]; o += 4;
            if (o + elen > body.Length || elen < 5) break;
            var e = body[o..(o + elen)]; o += elen;
            int type = e[0];
            uint life = (uint)((e[1] << 24) | (e[2] << 16) | (e[3] << 8) | e[4]);
            var label = type == 1 ? "PSK_ACCESS"u8.ToArray() : "PSK_REFRESH"u8.ToArray();
            var psk = ExpandLabel(secret, label, hCertV ?? Array.Empty<byte>(), 32);
            Psks.Add((type, life, psk, e));
        }
    }

    static byte[] FinishedVd(byte[] secret, bool isClient, byte[] hsHash)
    {
        var key = ExpandLabel(secret, isClient ? LabelClientFinished : LabelServerFinished, Array.Empty<byte>(), 32);
        return HMACSHA256.HashData(key, hsHash);
    }

    // ---------------- 应用数据 ----------------

    public static byte[] BuildShortlink(uint cmd, uint seq, byte[] body)
    {
        var o = new byte[16 + body.Length];
        int total = 16 + body.Length;
        o[0] = (byte)(total >> 24); o[1] = (byte)(total >> 16); o[2] = (byte)(total >> 8); o[3] = (byte)total;
        o[4] = (byte)(ShortlinkMagic >> 8); o[5] = unchecked((byte)ShortlinkMagic);
        o[6] = (byte)(DefaultVer >> 8); o[7] = unchecked((byte)DefaultVer);
        o[8] = (byte)(cmd >> 24); o[9] = (byte)(cmd >> 16); o[10] = (byte)(cmd >> 8); o[11] = (byte)cmd;
        o[12] = (byte)(seq >> 24); o[13] = (byte)(seq >> 16); o[14] = (byte)(seq >> 8); o[15] = (byte)seq;
        Buffer.BlockCopy(body, 0, o, 16, body.Length);
        return o;
    }

    public static (uint Cmd, uint Seq, byte[] Body) ParseShortlink(byte[] pkt)
    {
        int total = (pkt[0] << 24) | (pkt[1] << 16) | (pkt[2] << 8) | pkt[3];
        uint cmd = (uint)((pkt[8] << 24) | (pkt[9] << 16) | (pkt[10] << 8) | pkt[11]);
        uint seq = (uint)((pkt[12] << 24) | (pkt[13] << 16) | (pkt[14] << 8) | pkt[15]);
        int end = Math.Min(total, pkt.Length);
        return (cmd, seq, pkt[16..end]);
    }

    public void SendApp(uint cmd, byte[] body)
    {
        var pkt = BuildShortlink(cmd, (uint)_appTx, body);
        _appTx++;
        long seq = _tx;
        var aad = BuildRecordAad(seq, CtAppData, pkt.Length + 16);
        Send(BuildRecord(CtAppData, GcmEncrypt(_appCKey, _appCIv, seq, pkt, aad)));
        _tx++;
    }

    public (uint Cmd, uint Seq, byte[] Body) RecvApp()
    {
        var (ct, pt) = RecvRecord();
        long seq = _rx; _rx++;
        var aad = BuildRecordAad(seq, ct, pt.Length);
        var plain = GcmDecrypt(_appSKey, _appSIv, seq, pt, aad);
        return ParseShortlink(plain);
    }

    public void Dispose()
    {
        try { _net.Dispose(); } catch { }
        try { _tcp.Dispose(); } catch { }
    }
}
