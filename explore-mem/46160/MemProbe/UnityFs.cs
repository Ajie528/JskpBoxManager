using System.Text;

namespace MemProbe;

/// <summary>
/// 极简 UnityFS（AssetBundle）解析器：只做「把内嵌的 TextAsset / 原始数据块捞出来」。
///
/// UnityFS 结构：
///   "UnityFS\0" + version(u32 BE) + unityVersion(串) + unityRevision(串)
///   + size(i64 BE) + compressedBlocksInfoSize(u32 BE) + uncompressedBlocksInfoSize(u32 BE)
///   + flags(u32 BE)
///   → blocksInfo（可能压缩）→ blocks[] → 数据块拼起来 → 里面是 serialized file
///
/// 这里不解析 serialized file 的完整类型树，只按「找可读文本块」的方式捞内容，
/// 够用来找配置表里的键名和数值。
/// </summary>
public static class UnityFs
{
    public sealed record Block(uint UncompressedSize, uint CompressedSize, ushort Flags);
    public sealed record Info(string UnityVersion, string UnityRevision, long Size, uint Flags,
                              List<Block> Blocks, int HeaderSize);

    public static Info ReadInfo(byte[] data)
    {
        // 头部固定部分
        int p = 8;
        uint version = ReadU32BE(data, ref p);
        string unityVer = ReadCStr(data, ref p);
        string unityRev = ReadCStr(data, ref p);
        long size = ReadI64BE(data, ref p);
        uint ciSize = ReadU32BE(data, ref p);
        uint uiSize = ReadU32BE(data, ref p);
        uint flags = ReadU32BE(data, ref p);
        int flagsEnd = p;

        // blocksInfo 起点不确定（不同版本/写入器有不同填充），暴力搜索：
        // 在 flagsEnd..flagsEnd+32 内找一个能让 LZ4 解出 uiSize 字节的位置。
        var blocks = new List<Block>();
        byte[] info = null;
        int infoStart = -1;

        for (int off = flagsEnd; off <= flagsEnd + 32; off++)
        {
            if (off + ciSize > data.Length) break;
            byte[] cand;
            if (ciSize == uiSize)
            {
                cand = new byte[ciSize];
                Buffer.BlockCopy(data, off, cand, 0, (int)ciSize);
            }
            else
            {
                var raw = new byte[ciSize];
                Buffer.BlockCopy(data, off, raw, 0, (int)ciSize);
                cand = new byte[uiSize];
                int n = Lz4.DecompressBlock(raw, cand);
                if (n != uiSize) continue;
            }

            // 解出来的 blocksInfo 里 blockCount 必须合理（前 16 字节 hash 之后是 u32）
            if (cand.Length < 20) continue;
            uint cnt = (uint)(cand[16] << 24 | cand[17] << 16 | cand[18] << 8 | cand[19]);
            if (cnt == 0 || cnt > 5000) continue;
            // 且块大小总和应与文件剩余长度大致相符
            info = cand;
            infoStart = off;
            break;
        }

        if (info == null) return new Info(unityVer, unityRev, size, flags, blocks, data.Length);

        int q = 20;
        uint count = (uint)(info[16] << 24 | info[17] << 16 | info[18] << 8 | info[19]);
        for (uint i = 0; i < count && q + 10 <= info.Length; i++)
        {
            uint us = ReadU32BE(info, ref q);
            uint cs = ReadU32BE(info, ref q);
            ushort fl = (ushort)ReadU16BE(info, ref q);
            blocks.Add(new Block(us, cs, fl));
        }
        return new Info(unityVer, unityRev, size, flags, blocks, infoStart + (int)ciSize);
    }

    /// <summary>把所有数据块解压后拼成一整块（就是 serialized file 的内容）。</summary>
    public static byte[] ReadAllData(byte[] data, Info info, Action<string> log = null)
    {
        var outp = new MemoryStream();
        int p = info.HeaderSize;   // = blocksInfo 起点 + ciSize
        log?.Invoke($"  数据块起点 {p}，共 {info.Blocks.Count} 块");
        long totalCs = info.Blocks.Sum(b => (long)b.CompressedSize);
        log?.Invoke($"  压缩总长 {totalCs}，文件剩余 {data.Length - p}");

        int idx = 0;
        foreach (var b in info.Blocks)
        {
            if (p + b.CompressedSize > data.Length)
            {
                log?.Invoke($"  块#{idx} 越界（需要 {b.CompressedSize}，剩 {data.Length - p}），停止");
                break;
            }
            var chunk = new byte[b.CompressedSize];
            Buffer.BlockCopy(data, p, chunk, 0, (int)b.CompressedSize);
            p += (int)b.CompressedSize;

            byte[] plain;
            uint ctype = (uint)(b.Flags & 0x3F);
            if (ctype == 0 || b.CompressedSize == b.UncompressedSize)
            {
                plain = chunk;
            }
            else
            {
                var dst = new byte[b.UncompressedSize];
                int n = Lz4.DecompressBlock(chunk, dst);
                if (n <= 0)
                {
                    // LZ4 解不出来时先按原始数据收下，不丢块
                    log?.Invoke($"  块#{idx} LZ4 失败（type={ctype}, cs={b.CompressedSize}, us={b.UncompressedSize}）");
                    plain = chunk;
                }
                else plain = dst;
            }
            outp.Write(plain, 0, plain.Length);
            idx++;
        }
        log?.Invoke($"  解出 {outp.Length / 1024.0:N1} KB");
        return outp.ToArray();
    }

    static byte[] Decompress(byte[] src, int wantSize, uint type)
    {
        // type: 0=none 1=LZMA 2/3=LZ4
        try
        {
            if (type == 0) return src;
            if (type is 2 or 3)
            {
                var dst = new byte[wantSize];
                int written = Lz4.DecompressBlock(src, dst);
                if (written > 0) return dst;
            }
        }
        catch { }
        return src;
    }

    // ── 小工具 ──
    static string ReadCStr(byte[] d, ref int p)
    {
        int start = p;
        while (p < d.Length && d[p] != 0) p++;
        var s = Encoding.UTF8.GetString(d, start, p - start);
        p++;
        return s;
    }
    static uint ReadU32BE(byte[] d, ref int p) { uint v = (uint)(d[p] << 24 | d[p + 1] << 16 | d[p + 2] << 8 | d[p + 3]); p += 4; return v; }
    static ushort ReadU16BE(byte[] d, ref int p) { ushort v = (ushort)(d[p] << 8 | d[p + 1]); p += 2; return v; }
    static long ReadI64BE(byte[] d, ref int p) { long v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | d[p + i]; p += 8; return v; }
    static byte[] ReadBytes(byte[] d, ref int p, int n)
    {
        if (p + n > d.Length) n = Math.Max(0, d.Length - p);
        var r = new byte[n];
        Buffer.BlockCopy(d, p, r, 0, n);
        p += n;
        return r;
    }
}

/// <summary>LZ4 块解压（Unity 用的是 LZ4 block 格式，带 4 字节长度前缀的情况也兼容）。</summary>
public static class Lz4
{
    public static int DecompressBlock(byte[] src, byte[] dst)
    {
        int si = 0, di = 0;
        while (si < src.Length)
        {
            int token = src[si++];
            int litLen = token >> 4;
            if (litLen == 15)
            {
                int b;
                do { if (si >= src.Length) return di; b = src[si++]; litLen += b; } while (b == 255);
            }
            if (si + litLen > src.Length || di + litLen > dst.Length) break;
            Buffer.BlockCopy(src, si, dst, di, litLen);
            si += litLen; di += litLen;
            if (si >= src.Length) break;

            if (si + 2 > src.Length) break;
            int offset = src[si] | (src[si + 1] << 8); si += 2;
            if (offset == 0 || offset > di) break;

            int matchLen = token & 0x0F;
            if (matchLen == 15)
            {
                int b;
                do { if (si >= src.Length) return di; b = src[si++]; matchLen += b; } while (b == 255);
            }
            matchLen += 4;
            if (di + matchLen > dst.Length) matchLen = dst.Length - di;
            for (int i = 0; i < matchLen; i++, di++) dst[di] = dst[di - offset];
        }
        return di;
    }
}
