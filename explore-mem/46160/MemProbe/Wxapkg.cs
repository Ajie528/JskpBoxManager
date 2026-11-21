using System.Text;

namespace MemProbe;

/// <summary>
/// wxapkg 解包（只读）。微信小程序包格式：
///   [0..4)  firstMark = 0xBE
///   [4..8)  info1（通常 0）
///   [8..12) indexInfoLength（文件信息区长度）
///   [12..16) bodyLength（数据区长度）
///   [16..20) lastMark = 0xED
///   [20..20+n) 文件数据（依次拼接）
///   [20+n..) 索引：u32 文件数，然后每个文件 (u32 名字长, 名字, u32 偏移, u32 长度)
/// 注意偏移是相对「数据区起点」。
/// </summary>
public static class Wxapkg
{
    public sealed record Entry(string Name, uint Offset, uint Size);

    public static List<Entry> ReadIndex(string path)
    {
        var list = new List<Entry>();
        using var fs = File.OpenRead(path);
        using var br = new BinaryReader(fs);
        // 实测布局（微信 wxapkg v1）：
        //   [0]  BE 00 00 00
        //   [4]  info1 (4)
        //   [8]  indexInfoLength (4, LE，低位在前但实际是 0x2E7B00BE 这类值 → 高字节 0xED 是标记)
        //   [12] ED 标记（indexInfoLength 的最高字节）
        //   [13] bodyLength (3 字节 LE)
        //   [16] 00 00 03 00  未知/标志
        //   [20] 文件数据起点
        byte first = br.ReadByte();
        if (first != 0xBE) throw new InvalidDataException($"不是 wxapkg（首字节 0x{first:X2}）");
        br.ReadBytes(3);
        br.ReadUInt32();                            // info1
        uint rawIndex = br.ReadUInt32();            // 0x2E7B00BE 形态，最高字节是 ED 标记
        uint indexLen = rawIndex & 0x00FFFFFF;      // 去掉标记字节
        uint bodyLen = (uint)(br.ReadByte() | (br.ReadByte() << 8) | (br.ReadByte() << 16));
        br.ReadBytes(4);                            // 00 00 03 00
        const long DATA_START = 20;
        Console.WriteLine($"  [头] indexLen={indexLen}  bodyLen={bodyLen}  数据起点=0x{DATA_START:X}  文件长={fs.Length}");

        // 索引在文件尾，长度 indexLen
        long indexStart = fs.Length - indexLen;
        if (indexStart < DATA_START) throw new InvalidDataException($"索引位置异常 indexLen={indexLen} 文件长={fs.Length}");
        fs.Position = indexStart;
        uint count = br.ReadUInt32();
        if (count > 200000) throw new InvalidDataException($"文件数异常 {count}（索引起点 0x{indexStart:X}）");
        for (uint i = 0; i < count && fs.Position + 4 <= fs.Length; i++)
        {
            uint nameLen = br.ReadUInt32();
            if (nameLen == 0 || nameLen > 4096) break;
            var name = Encoding.UTF8.GetString(br.ReadBytes((int)nameLen));
            uint off = br.ReadUInt32();
            uint size = br.ReadUInt32();
            list.Add(new Entry(name, off, size));
        }
        return list;
    }

    /// <summary>解包到目录；返回解出的文件数。</summary>
    public static int Extract(string path, string outDir)
    {
        var entries = ReadIndex(path);
        Directory.CreateDirectory(outDir);
        const long DATA_START = 14;
        using var fs = File.OpenRead(path);
        int n = 0;
        foreach (var e in entries)
        {
            var rel = e.Name.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
            var target = Path.Combine(outDir, rel);
            var dir = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            fs.Position = DATA_START + e.Offset;
            var buf = new byte[e.Size];
            int got = 0;
            while (got < e.Size)
            {
                int r = fs.Read(buf, got, (int)e.Size - got);
                if (r <= 0) break;
                got += r;
            }
            File.WriteAllBytes(target, buf);
            n++;
        }
        return n;
    }
}
