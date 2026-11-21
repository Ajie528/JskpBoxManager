using System.Text;

namespace MemProbe;

/// <summary>
/// 从内存里把「以 { 开头、以 } 结尾」的一段 JSON 整体抠出来。
/// UTF-16LE / UTF-8 都支持，只读。
/// </summary>
public static class JsonExtract
{
    /// <summary>以 addr 为起点（或附近）向上找最近的 {，再按括号配平走到收尾 }。</summary>
    public static string Around(WinMem mem, long addr, int window = 0x4000)
    {
        // 先用 UTF-16 试，再用 UTF-8
        foreach (bool wide in new[] { true, false })
        {
            var r = TryAround(mem, addr, window, wide);
            if (r != null) return r;
        }
        return null;
    }

    static string TryAround(WinMem mem, long addr, int window, bool wide)
    {
        long start = Math.Max(0, addr - window);
        int len = window * 2;
        var buf = mem.Read(start, len);
        if (buf == null || buf.Length < 8) return null;

        string text = wide
            ? Encoding.Unicode.GetString(buf)
            : Encoding.UTF8.GetString(buf);

        int hit = text.IndexOf("role_name", StringComparison.Ordinal);
        if (hit < 0) return null;

        int open = text.LastIndexOf('{', Math.Max(0, hit));
        if (open < 0) return null;

        int depth = 0;
        bool inStr = false, esc = false;
        for (int i = open; i < text.Length; i++)
        {
            char c = text[i];
            if (inStr)
            {
                if (esc) { esc = false; continue; }
                if (c == '\\') { esc = true; continue; }
                if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == '{') depth++;
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    var json = text.Substring(open, i - open + 1);
                    // 太短的、没有 role_name 的丢弃
                    if (json.Length > 40 && json.Contains("role_name")) return json;
                    return null;
                }
            }
            if (i - open > 20000) return null;   // 防跑飞
        }
        return null;
    }

    /// <summary>扫全进程，收集所有含 role_name 的 JSON（去重）。</summary>
    public static List<(long Addr, string Json)> All(WinMem mem, int limit = 8)
    {
        var found = new List<(long, string)>();
        var seen = new HashSet<string>();
        var wideNeedle = Encoding.Unicode.GetBytes("\"role_name\"");
        var u8Needle = Encoding.UTF8.GetBytes("\"role_name\"");

        void Consider(long baseAddr, byte[] buf, int len, byte[] needle, bool wide)
        {
            int idx = 0;
            while (idx <= len - needle.Length)
            {
                int at = buf.AsSpan(idx, len - idx).IndexOf(needle);
                if (at < 0) break;
                int abs = idx + at;
                long addr = baseAddr + abs;
                var json = Around(mem, addr, 0x800);
                if (json != null && seen.Add(json)) found.Add((addr, json));
                if (found.Count >= limit) return;
                idx = abs + needle.Length;
            }
        }

        mem.Scan(onChunk: (baseAddr, buf, len) =>
        {
            Consider(baseAddr, buf, len, wideNeedle, true);
            Consider(baseAddr, buf, len, u8Needle, false);
            return found.Count >= limit;
        });
        return found;
    }
}
