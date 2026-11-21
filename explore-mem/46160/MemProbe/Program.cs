using System.Drawing;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace MemProbe;

/// <summary>
/// 只读内存勘查工具（不会写目标进程、不注入、不挂线程）。
///
/// 用法：
///   MemProbe map                                   内存区域/模块概况
///   MemProbe find 文本 [--utf16] [--max N] [--ctx N]  在可读私有内存里找字符串
///   MemProbe dump 0x地址 长度                       十六进制 + 可读文本
///   MemProbe ptr 0x地址 [--max N]                    反向找指向该地址的 8 字节指针
///   MemProbe int 数值 [--max N]                      找 int32 值
///   MemProbe near 0x地址 半径                        看某地址周围，标出变化
///
/// 可选：--pid 46160（默认 46160）、--modules（连模块内存一起扫）
/// </summary>
public static class Program
{
    static int _pid = 46160;
    static bool _withModules;
    static int _max = 40;
    static long _from = 0, _to = long.MaxValue;

    static bool InRange(long addr) => addr >= _from && addr < _to;

    public static int Main(string[] args)
    {
        if (args.Length == 0) { Usage(); return 0; }

        var pos = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a == "--pid" && i + 1 < args.Length) { _pid = int.Parse(args[++i]); continue; }
            if (a == "--modules") { _withModules = true; continue; }
            if (a == "--max" && i + 1 < args.Length) { _max = int.Parse(args[++i]); continue; }
            if (a == "--from" && i + 1 < args.Length) { _from = Addr(args[++i]); continue; }
            if (a == "--to" && i + 1 < args.Length) { _to = Addr(args[++i]); continue; }
            pos.Add(a);
        }

        if (pos[0] is "help" or "-h" or "--help") { Usage(); return 0; }

        var sw = Stopwatch.StartNew();
        using var mem = WinMem.Open(_pid);
        Console.WriteLine($"pid={_pid}  {Bitness(mem.Is64Bit)}  打开耗时 {sw.ElapsedMilliseconds}ms");
        Console.WriteLine();

        switch (pos[0].ToLowerInvariant())
        {
            case "map": Map(mem); break;
            case "find": Find(mem, pos.Count > 1 ? pos[1] : "", args); break;
            case "dump": Dump(mem, Addr(pos[1]), Num(pos[2])); break;
            case "ptr": Ptr(mem, Addr(pos[1])); break;
            case "int": FindInt(mem, int.Parse(pos[1])); break;
            case "near": Near(mem, Addr(pos[1]), pos.Count > 2 ? Num(pos[2]) : 0x200); break;
            case "json": Json(mem); break;
            case "procs": Procs(); break;
            case "atk": Atk(mem, pos); break;
            case "region": Region(mem, Addr(pos[1])); break;
            case "regions": BigRegions(mem); break;
            case "nearby": Nearby(mem, Addr(pos[1]), Num(pos[2]), Addr(pos[3]), Addr(pos[4])); break;
            case "multi": Multi(mem, pos.Skip(1).ToArray()); break;
            case "cells": Cells(mem); break;
            case "diff": Diff(mem, Addr(pos[1]), pos.Skip(2).ToArray()); break;
            case "hunt": Hunt(mem, int.Parse(pos[1]), pos.Skip(2).Select(int.Parse).ToArray()); break;
            case "meta": Meta(pos); break;
            case "unpack": Unpack(path: pos[1], outDir: pos.Count > 2 ? pos[2] : null); break;
            case "wxlist": WxList(pos[1]); break;
            case "metamem": MetaMem(mem); break;
            case "metadump": MetaDump(mem, Addr(pos[1]), pos.Count > 2 ? Addr(pos[2]) : 0, pos.Count > 3 ? pos[3] : null); break;
            case "types": Types(pos[1]); break;
            case "findt": FindTypes(pos[1], pos[2]); break;
            case "findf": FindFields(pos[1], pos[2]); break;
            case "tdump": TDump(pos[1], int.Parse(pos[2])); break;
            case "frange": FRange(pos[1], int.Parse(pos[2]), int.Parse(pos[3])); break;
            case "mazehunt": MazeHunt(mem, int.Parse(pos[1]), int.Parse(pos[2])); break;
            case "snap": Snap(mem, pos[1]); break;
            case "snapdiff": SnapDiff(pos[1], pos[2]); break;
            case "snapread": SnapRead(pos[1], Addr(pos[2]), int.Parse(pos[3])); break;
            case "mazecells": MazeCells(mem, Addr(pos[1])); break;
            case "maze": Maze(mem); break;
            case "cfghunt": CfgHunt(mem, int.Parse(pos[1]), pos.Count > 2 ? int.Parse(pos[2]) : 0); break;
            case "cellcfg": CellCfg(mem); break;
            case "uidetect": UiDetect(mem); break;
            case "uidelta": UiDelta(pos[1], pos[2]); break;
            case "skillhunt": SkillHunt(mem); break;
            case "skillnear": SkillNear(mem, Addr(pos[1]), int.Parse(pos[2])); break;
            case "dictfind": DictFind(mem, int.Parse(pos[1]), int.Parse(pos[2])); break;
            case "refs": Refs(mem, Addr(pos[1])); break;
            case "objlist": ObjList(mem, int.Parse(pos[1])); break;
            case "strarr": StrArr(mem, Addr(pos[1]), int.Parse(pos[2])); break;
            case "pairs": Pairs(mem, Addr(pos[1]), int.Parse(pos[2])); break;
            case "skills": Skills(mem, pos.Count > 1 ? int.Parse(pos[1]) : 0); break;
            case "dexport": DictExport(mem, Addr(pos[1])); break;
            case "abs": Abs(pos[1]); break;
            case "abfind": AbFind(pos[1], pos.Skip(2).ToArray()); break;
            case "abdump": AbDump(pos[1], pos.Count > 2 ? pos[2] : null); break;
            case "abscan": AbScan(pos[1], pos.Skip(2).ToArray()); break;
            case "abtable": AbTable(pos[1], pos.Count > 2 ? Addr(pos[2]) : 0); break;
            case "pattern": Pattern(mem, pos.Skip(1).Select(int.Parse).ToArray()); break;
            case "findcards": FindCards(mem, pos.Skip(1).ToArray()); break;
            case "cardlist": FindCardList(mem, int.Parse(pos[1])); break;
            case "cardobj": FindCardObjList(mem, int.Parse(pos[1])); break;
            case "cardptr": FindCardPtr(mem, int.Parse(pos[1])); break;
            case "ocr": Ocr(Addr(pos.Count > 1 ? pos[1] : "0x54399820")); break;
            case "owner": Owner(pos[1], int.Parse(pos[2])); break;            default: Usage(); return 2;
        }
        Console.WriteLine();
        Console.WriteLine($"用时 {sw.Elapsed.TotalSeconds:0.00}s");
        return 0;
    }

    static string Bitness(bool is64) => is64 ? "x64" : "x86(WOW64)";

    static long Addr(string s) => long.Parse(s.Replace("0x", "").Replace("0X", ""),
        s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? NumberStyles.HexNumber : NumberStyles.Integer);

    static int Num(string s) => s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? int.Parse(s[2..], NumberStyles.HexNumber) : int.Parse(s);

    static string Hex(long v) => "0x" + v.ToString("X");

    static void Usage()
    {
        Console.WriteLine("""
        MemProbe —— 只读内存勘查（不改目标进程）

          MemProbe map                                内存区域 + 模块概况
          MemProbe find 文本 [--utf16] [--ctx 180]    在可读私有内存里找字符串
          MemProbe dump 0x地址 长度                    十六进制 + 可读文本
          MemProbe ptr 0x地址                          反向找指向该地址的指针
          MemProbe int 数值                            找 int32 值
          MemProbe near 0x地址 [半径]                  看某地址周围
          MemProbe str 0x地址 长度                     按地址读字符串

        全局开关：--pid N（默认 46160）  --modules（连模块内存一起扫）  --max N（结果上限）
        """);
    }

    // ───────────────────────── map ─────────────────────────

    static void Map(WinMem mem)
    {
        var mods = mem.Modules();
        Console.WriteLine($"模块 {mods.Count} 个：");
        foreach (var m in mods.OrderBy(m => m.Base.ToInt64()).Take(60))
            Console.WriteLine($"  {Hex(m.Base.ToInt64()),-18} {m.Size,12:N0}  {Path.GetFileName(m.Path)}");
        if (mods.Count > 60) Console.WriteLine($"  …… 另有 {mods.Count - 60} 个");
        Console.WriteLine();

        long total = 0, readable = 0, priv = 0;
        int regions = 0, readableRegions = 0, privRegions = 0;
        var byType = new Dictionary<uint, (int Count, long Bytes)>();
        foreach (var m in mem.Regions())
        {
            regions++;
            long size = (long)m.RegionSize;
            total += size;
            if (!byType.TryGetValue(m.Type, out var agg)) agg = (0, 0);
            byType[m.Type] = (agg.Count + 1, agg.Bytes + size);
            if (!WinMem.IsReadable(m)) continue;
            readableRegions++;
            readable += size;
            if (m.Type == 0x20000) { privRegions++; priv += size; }
        }

        Console.WriteLine($"区域共 {regions} 个 / {total / 1048576.0:N1} MB");
        Console.WriteLine($"  可读 {readableRegions} 个 / {readable / 1048576.0:N1} MB");
        Console.WriteLine($"  可读且 MEM_PRIVATE {privRegions} 个 / {priv / 1048576.0:N1} MB");
        Console.WriteLine();
        Console.WriteLine("按类型：");
        foreach (var (t, v) in byType.OrderByDescending(kv => kv.Value.Bytes))
            Console.WriteLine($"  type=0x{t:X}  {v.Count,6} 个  {v.Bytes / 1048576.0,10:N1} MB  ({TypeName(t)})");

        try
        {
            using var p = Process.GetProcessById(_pid);
            Console.WriteLine();
            Console.WriteLine($"工作集 {p.WorkingSet64 / 1048576.0:N1} MB   私有 {p.PrivateMemorySize64 / 1048576.0:N1} MB   " +
                              $"虚拟 {p.VirtualMemorySize64 / 1048576.0:N1} MB   线程 {p.Threads.Count}");
        }
        catch { }
    }

    static string TypeName(uint t) => t switch
    {
        0x20000 => "MEM_PRIVATE",
        0x40000 => "MEM_MAPPED",
        0x1000000 => "MEM_IMAGE",
        _ => "?"
    };

    // ───────────────────────── find ─────────────────────────

    static void Find(WinMem mem, string text, string[] raw)
    {
        if (text.Length == 0) { Console.WriteLine("要找一个非空字符串"); return; }
        bool utf16 = raw.Contains("--utf16") || raw.Contains("--u16");
        int ctxIdx = Array.IndexOf(raw, "--ctx");
        int ctx = ctxIdx >= 0 && ctxIdx + 1 < raw.Length ? int.Parse(raw[ctxIdx + 1]) : 180;

        var needle = utf16 ? Encoding.Unicode.GetBytes(text) : Encoding.UTF8.GetBytes(text);
        Console.WriteLine($"找 {(utf16 ? "UTF-16" : "UTF-8")} \"{text}\"（{needle.Length} 字节），上下文 {ctx} 字节");
        if (_from != 0 || _to != long.MaxValue) Console.WriteLine($"范围 {Hex(_from)}..{Hex(_to)}");
        Console.WriteLine();

        int hits = 0;
        long scanned = 0;
        var perRegion = new Dictionary<long, int>();
        mem.Scan(onChunk: (baseAddr, buf, len) =>
        {
            scanned += len;
            int idx = 0;
            while (idx <= len - needle.Length)
            {
                int at = buf.AsSpan(idx, len - idx).IndexOf(needle);
                if (at < 0) break;
                int abs = idx + at;
                long addr = baseAddr + abs;
                if (!InRange(addr)) { idx = abs + needle.Length; continue; }
                hits++;
                var regionBase = baseAddr;
                perRegion[regionBase] = perRegion.GetValueOrDefault(regionBase) + 1;

                int start = Math.Max(0, abs - ctx);
                int end = Math.Min(len, abs + needle.Length + ctx);
                Console.WriteLine($"── #{hits}  {Hex(addr)}  （区域内 +{abs:X}）");
                Console.WriteLine(Preview(buf, start, end));
                Console.WriteLine();
                if (hits >= _max) { Console.WriteLine($"…已达上限 {_max}"); return true; }
                idx = abs + needle.Length;
            }
            return false;
        }, privateOnly: !_withModules);

        Console.WriteLine($"命中 {hits} 处；扫过 {scanned / 1048576.0:N0} MB");
        foreach (var (b, c) in perRegion.OrderByDescending(kv => kv.Value).Take(12))
            Console.WriteLine($"  区域 {Hex(b)} → {c} 处");
    }

    /// <summary>把一块内存排成「偏移 | 十六进制 | ASCII」三列，方便肉眼找结构。</summary>
    static string Preview(byte[] buf, int start, int end)
    {
        var sb = new StringBuilder();
        int s = start & ~0xF;
        for (int row = s; row < end; row += 16)
        {
            int n = Math.Min(16, end - row);
            if (n <= 0) break;
            sb.Append($"    {row:X6}  ");
            for (int i = 0; i < 16; i++) sb.Append(i < n ? $"{buf[row + i]:X2} " : "   ");
            sb.Append(" | ");
            for (int i = 0; i < n; i++)
            {
                byte c = buf[row + i];
                sb.Append(c >= 0x20 && c < 0x7F ? (char)c : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    // ───────────────────────── dump / str ─────────────────────────

    static void Dump(WinMem mem, long addr, int len)
    {
        var buf = mem.Read(addr, len);
        if (buf == null) { Console.WriteLine($"{Hex(addr)} 读不出来"); return; }
        Console.Write(Preview(buf, 0, buf.Length));
        Console.WriteLine();
        Console.WriteLine("可读文本：");
        Console.WriteLine(WinMem.Printable(buf, buf.Length));
    }

    // ───────────────────────── ptr ─────────────────────────

    static void Ptr(WinMem mem, long target)
    {
        var needle = BitConverter.GetBytes(target);
        Console.WriteLine($"反向找指向 {Hex(target)} 的 8 字节指针");
        int hits = 0;
        mem.Scan(onChunk: (baseAddr, buf, len) =>
        {
            int idx = 0;
            while (idx <= len - 8)
            {
                int at = buf.AsSpan(idx, len - idx).IndexOf(needle);
                if (at < 0) break;
                int abs = idx + at;
                Console.WriteLine($"  {Hex(baseAddr + abs)}  （指向 {Hex(target)}，偏移 0）");
                hits++;
                if (hits >= _max) return true;
                idx = abs + 8;
            }
            return false;
        }, privateOnly: !_withModules);
        Console.WriteLine($"命中 {hits} 处");
    }

    // ───────────────────────── int ─────────────────────────

    static void FindInt(WinMem mem, int value)
    {
        var needle = BitConverter.GetBytes(value);
        Console.WriteLine($"找 int32 = {value}（{Hex(value)}）");
        int hits = 0;
        mem.Scan(onChunk: (baseAddr, buf, len) =>
        {
            // 按 4 字节对齐找
            for (int i = 0; i + 4 <= len; i += 4)
            {
                if (buf[i] != needle[0] || buf[i + 1] != needle[1] || buf[i + 2] != needle[2] || buf[i + 3] != needle[3]) continue;
                if (!InRange(baseAddr + i)) continue;
                Console.WriteLine($"  {Hex(baseAddr + i)}");
                if (++hits >= _max) return true;
            }
            return false;
        }, privateOnly: !_withModules);
        Console.WriteLine($"命中 {hits} 处");
    }

    // ───────────────────────── atk ─────────────────────────

    /// <summary>复现 RoleReader 的 D 型 / C 型攻击力定位，并把所有角色 ID 锚点的候选值打出来对照。</summary>
    static void Atk(WinMem mem, List<string> pos)
    {
        if (pos.Count < 3) { Console.WriteLine("用法：MemProbe atk 角色ID 等级"); return; }
        ulong roleId = ulong.Parse(pos[1]);
        int level = int.Parse(pos[2]);
        const uint MarkerMin = 0x02000000, MarkerMax = 0x0FFFFFFF;
        var needle = BitConverter.GetBytes(roleId);
        var dHits = new List<(long Addr, int Atk, int B4)>();
        var cHits = new List<(long Addr, int Atk, int Gen, uint Marker)>();
        int anchors = 0;

        mem.Scan(chunk: 4 << 20, onChunk: (baseAddr, buf, len) =>
        {
            for (int i = 0; i + 0xBC <= len; i += 4)
            {
                if (buf[i] != needle[0] || buf[i + 7] != needle[7]) continue;
                bool eq = true;
                for (int q = 1; q < 7; q++) if (buf[i + q] != needle[q]) { eq = false; break; }
                if (!eq) continue;
                anchors++;
                int At(int off) => BitConverter.ToInt32(buf, i + off);
                int lv1C = At(0x1C), lv20 = At(0x20), flagB4 = At(0xB4);
                if (lv1C == level && lv20 == level && flagB4 is >= 1 and <= 255)
                {
                    int atk = At(0xB8);
                    if (atk is >= 100 and <= 5000000) dHits.Add((baseAddr + i + 0xB8, atk, flagB4));
                }
                uint marker = unchecked((uint)At(0x64));
                if (lv1C is >= 1 and <= 255 && lv20 == level && marker is >= MarkerMin and <= MarkerMax)
                {
                    int atk = At(0x28);
                    if (atk is >= 100 and <= 5000000) cHits.Add((baseAddr + i + 0x28, atk, At(0x4C), marker));
                }
            }
            return false;
        }, privateOnly: false);

        Console.WriteLine($"角色 ID 锚点 {anchors} 处");
        Console.WriteLine($"D 型（+0xB8，等级双匹配）{dHits.Count} 个：");
        foreach (var (a, v, f) in dHits) Console.WriteLine($"  {Hex(a)}  attack={v}  +0xB4={f}");
        Console.WriteLine($"C 型（+0x28，标记 0x02000000~0x0FFFFFFF）{cHits.Count} 个：");
        foreach (var (a, v, g, m) in cHits.OrderByDescending(x => x.Gen))
            Console.WriteLine($"  {Hex(a)}  attack={v}  +0x4C={g}  +0x64=0x{m:X}");
        Console.WriteLine();
        Console.WriteLine(dHits.Count > 0 ? $"→ 取 D 型：{dHits[0].Atk}"
            : cHits.Count > 0 ? $"→ 取 C 型最新：{cHits.OrderByDescending(x => x.Gen).First().Atk}"
            : "→ 都没命中");
    }

    /// <summary>按子串找字段名（全表扫），同时打印所属类型。</summary>
    static void FindFields(string path, string substr)
    {
        var m = Il2CppMeta.Load(path, 0);
        var hits = m.FindFieldsByName(substr, _max);
        Console.WriteLine($"字段名含 \"{substr}\" 的 {hits.Count} 条：");
        foreach (var h in hits) Console.WriteLine($"  field#{h.FieldIndex,-7} {h.Name,-30} 类型：{h.TypeName}");
    }

    static void FRange(string path, int from, int count)
    {
        var m = Il2CppMeta.Load(path, 0);
        Console.Write(m.DumpFieldRange(from, count));
    }

    /// <summary>把某个类型定义结构体按 32 位逐项解释，用来确定字段表偏移。</summary>
    static void TDump(string path, int typeIndex)
    {
        var m = Il2CppMeta.Load(path, 0);
        Console.WriteLine($"类型 #{typeIndex}  名字=\"{m.TypeNameOf(typeIndex)}\"");
        Console.WriteLine(m.DumpTypeFields(typeIndex));
    }

    /// <summary>找某个字段索引所属的类型，并打印该类型的完整字段表。</summary>
    static void Owner(string path, int fieldIndex)
    {
        var m = Il2CppMeta.Load(path, 0);
        var (typeIdx, typeName) = m.OwnerOfField(fieldIndex);
        Console.WriteLine($"字段 #{fieldIndex} 属于类型 #{typeIdx} \"{typeName}\"");
        if (typeIdx < 0) return;
        var fields = m.FieldsOfType(typeIdx);
        Console.WriteLine($"该类型字段 {fields.Count} 个（声明顺序）：");
        foreach (var f in fields.Take(80)) Console.WriteLine($"  [{f.DeclOrder,3}] {f.Name}");
    }

    /// <summary>从快照文件里读某地址的 int32 序列，用于历史对比。</summary>
    static void SnapRead(string path, long addr, int count)
    {
        var data = File.ReadAllBytes(path);
        long off = addr - 0x3C483C00000L;
        if (off < 0 || off + count * 4 > data.Length) { Console.WriteLine("地址不在快照范围内"); return; }
        for (int i = 0; i < count; i++)
            Console.WriteLine($"  {Hex(addr + i * 4)}  int={BitConverter.ToInt32(data, (int)(off + i * 4))}");
    }

    // ───────────────────────── mazecells ─────────────────────────

    /// <summary>
    /// 解析迷宫格子列表 List&lt;CSMessMapData&gt;。
    /// Il2Cpp List 布局：+0x0C = _size，+0x10 = _items（数组指针，数组元素从 +0x20 起）。
    /// </summary>
    static void MazeCells(WinMem mem, long listAddr)
    {
        var head = mem.Read(listAddr, 0x20);
        if (head == null) { Console.WriteLine($"{Hex(listAddr)} 读不出来"); return; }
        Console.Write(Preview(head, 0, head.Length));
        // 实测（wasm32，指针 4 字节）：
        //   List:  +0x00 klass, +0x04 monitor, +0x08 _items, +0x0C _size, +0x10 _version
        //   Array: +0x00 klass, +0x04 monitor, +0x08 bounds, +0x0C max_length, +0x10 元素起点
        int itemsOff = BitConverter.ToInt32(head, 0x08);
        int size = BitConverter.ToInt32(head, 0x0C);
        long items = WASM_BASE + (uint)itemsOff;
        Console.WriteLine($"_items=0x{itemsOff:X} → {Hex(items)}   _size={size}");
        if (size <= 0 || size > 1000) { Console.WriteLine("不是列表结构"); return; }

        var arrHead = mem.Read(items, 0x20);
        if (arrHead == null) { Console.WriteLine("数组头读不出来"); return; }
        int maxLen = BitConverter.ToInt32(arrHead, 0x0C);
        Console.WriteLine($"数组 max_length={maxLen}  元素起点 {Hex(items + 0x10)}");

        Console.WriteLine($"\n{size} 个元素（每个是指向 CSMessMapData 的 4 字节指针）：");
        Console.WriteLine($"{"idx",-4}{"类型",-6}{"事件id",-8}{"row",-6}{"col",-6}{"flag",-6}{"地址",-16}");
        var rows = new SortedDictionary<int, List<(int Idx, int Type, int Event, int Row, int Col)>>();
        for (int i = 0; i < size; i++)
        {
            var p = mem.Read(items + 0x10 + i * 4, 4);
            if (p == null) break;
            uint off = BitConverter.ToUInt32(p, 0);
            long elem = WASM_BASE + off;
            if (off < 0x1000) { Console.WriteLine($"  [{i}] null"); continue; }
            var body = mem.Read(elem, 0x30);
            if (body == null) { Console.WriteLine($"  [{i}] {Hex(elem)} 读不出来"); continue; }
            // words[0]=klass, [1]=monitor, [2]=事件类型, [3]=事件id, [4]=row, [5]=col/子id, [6]=标志
            int type = BitConverter.ToInt32(body, 0x08);
            int eventId = BitConverter.ToInt32(body, 0x0C);
            int row = BitConverter.ToInt32(body, 0x10);
            int col = BitConverter.ToInt32(body, 0x14);
            int flag = BitConverter.ToInt32(body, 0x18);
            Console.WriteLine($"{i,-4}{type,-6}{eventId,-8}{row,-6}{col,-6}{flag,-6}{Hex(elem),-16}");
            if (!rows.TryGetValue(row, out var lst)) rows[row] = lst = new();
            lst.Add((i, type, eventId, row, col));
        }

        Console.WriteLine("\n按 row 分组：");
        foreach (var (row, list) in rows)
            Console.WriteLine($"  row={row,-3} 共 {list.Count} 格 → " +
                string.Join("  ", list.Select(x => $"#{x.Idx}(类型{x.Type},事件{x.Event},col{x.Col})")));
    }

    // ───────────────────────── snap / snapdiff ─────────────────────────

    const long WASM_BASE = 0x3C480000000L;
    const long WASM_SIZE = 768L << 20;

    /// <summary>把 wasm 线性内存的一段（默认迷宫对象附近 4MB）存成文件，供前后对比。</summary>
    static void Snap(WinMem mem, string outPath)
    {
        long start = 0x3C483C00000L;   // 迷宫对象 0x3C483D0090C 所在段
        long size = 4L << 20;
        var buf = new byte[size];
        long got = 0; int chunk = 1 << 20;
        var tmp = new byte[chunk];
        while (got < size)
        {
            int want = (int)Math.Min(chunk, size - got);
            if (!mem.TryReadInto(start + got, tmp, want, out int read) || read <= 0) break;
            Buffer.BlockCopy(tmp, 0, buf, (int)got, read);
            got += read;
        }
        File.WriteAllBytes(outPath, buf.AsSpan(0, (int)got).ToArray());
        Console.WriteLine($"快照 {Hex(start)} +{got / 1048576.0:N1}MB → {outPath}");
    }

    /// <summary>对比两份快照，列出所有变化的 4 字节单元。</summary>
    static void SnapDiff(string aPath, string bPath)
    {
        var a = File.ReadAllBytes(aPath);
        var b = File.ReadAllBytes(bPath);
        int n = Math.Min(a.Length, b.Length);
        Console.WriteLine($"对比 {Path.GetFileName(aPath)} ({a.Length:N0}B) vs {Path.GetFileName(bPath)} ({b.Length:N0}B)");
        int changed = 0;
        for (int i = 0; i + 4 <= n; i += 4)
        {
            int va = BitConverter.ToInt32(a, i), vb = BitConverter.ToInt32(b, i);
            if (va == vb) continue;
            // 过滤明显是指针/浮点的噪声：保留「至少一边是小整数」的
            bool aSmall = va is >= -100000 and <= 100000;
            bool bSmall = vb is >= -100000 and <= 100000;
            if (!aSmall && !bSmall) continue;
            long addr = 0x3C483C00000L + i;
            Console.WriteLine($"  {Hex(addr)}  {va,10} → {vb,10}   (wasm+0x{addr - WASM_BASE:X})");
            if (++changed >= _max) { Console.WriteLine($"…已达上限 {_max}"); return; }
        }
        Console.WriteLine($"小整数变化 {changed} 处");
    }

    /// <summary>
    /// 对比两份 UI 名字计数文件，找出「这次新出现的 UI」。
    /// 用于：点一下格子 → 再统计 → 差值里就是弹出的界面。
    /// </summary>
    static void UiDelta(string beforeFile, string afterFile)
    {
        var before = ReadCounts(beforeFile);
        var after = ReadCounts(afterFile);
        Console.WriteLine($"{"UI",-28}{"之前",-8}{"之后",-8}变化");
        foreach (var n in after.Keys.Union(before.Keys).OrderBy(k => k))
        {
            int b = before.GetValueOrDefault(n), a = after.GetValueOrDefault(n);
            if (a == b) continue;
            Console.WriteLine($"  {n,-26}{b,-8}{a,-8}{(a > b ? "+" : "")}{a - b}");
        }
    }

    static Dictionary<string, int> ReadCounts(string path)
    {
        var d = new Dictionary<string, int>();
        foreach (var line in File.ReadAllLines(path))
        {
            var parts = line.Split('|');
            if (parts.Length == 2 && int.TryParse(parts[1], out var v)) d[parts[0]] = v;
        }
        return d;
    }

    // ───────────────────────── skillhunt ─────────────────────────

    /// <summary>
    /// 找「待选技能列表」：List&lt;int&gt; 或 int[] 且长度正好 4（画面 4 张卡）。
    /// 判据：_size/长度 == 4，元素是 1~999999 的合理技能 id，且各不重复。
    /// 另外把附近「也是 List&lt;int&gt; 的小数组」一并列出，供人工判断。
    /// </summary>
    static void SkillHunt(WinMem mem)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        if (cands.Count == 0) { Console.WriteLine("没找到 wasm 内存"); return; }
        var (wbase, wsize) = cands[0];
        Console.WriteLine($"wasm {Hex(wbase)} {wsize / 1048576.0:N0} MB，找 length=4 的整型列表…");

        int found = 0;
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x40) { addr += 0x10000; continue; }

            for (int i = 0; i + 0x40 <= read; i += 4)
            {
                // List<int>: +0x08 _items(ptr)  +0x0C _size
                int size = BitConverter.ToInt32(buf, i + 0x0C);
                if (size != 4) continue;
                uint itemsOff = BitConverter.ToUInt32(buf, i + 0x08);
                if (itemsOff < 0x1000 || itemsOff > wsize - 0x40) continue;

                var arr = mem.Read(wbase + itemsOff, 0x20);
                if (arr == null) continue;
                int maxLen = BitConverter.ToInt32(arr, 0x0C);
                if (maxLen < 4 || maxLen > 16) continue;

                var vals = mem.Read(wbase + itemsOff + 0x10, 16);
                if (vals == null) continue;
                var ids = new int[4];
                bool ok = true;
                for (int k = 0; k < 4; k++)
                {
                    int v = BitConverter.ToInt32(vals, k * 4);
                    if (v < 1 || v > 999999) { ok = false; break; }
                    ids[k] = v;
                }
                if (!ok) continue;
                if (ids.Distinct().Count() != 4) continue;

                Console.WriteLine($"\n── 候选 {Hex(addr + i)}  size=4  items={Hex(wbase + itemsOff)}");
                Console.WriteLine($"   ids = {string.Join(", ", ids)}");
                if (++found >= _max) { Console.WriteLine($"…上限 {_max}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x40);
        }
        Console.WriteLine($"\n共 {found} 个候选");
    }

    /// <summary>
    /// 找长度为 N 的「对象指针数组」List&lt;T&gt;（T 是引用类型）。
    /// 判据：List._size == N，items 是合法偏移，且每个元素都指向一个合法对象（klass 是合法偏移）。
    /// 用来找「4 个技能图标」「技能对象列表」这类结构。
    /// </summary>
    static void ObjList(WinMem mem, int want)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];
        Console.WriteLine($"wasm {Hex(wbase)} {wsize / 1048576.0:N0} MB，找 size={want} 的对象列表…");

        int found = 0;
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int wantBytes = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, wantBytes, out int read) || read < 0x60) { addr += 0x10000; continue; }

            for (int i = 0; i + 0x40 <= read; i += 4)
            {
                int size = BitConverter.ToInt32(buf, i + 0x0C);
                if (size != want) continue;
                uint itemsOff = BitConverter.ToUInt32(buf, i + 0x08);
                if (itemsOff < 0x1000 || itemsOff > wsize - 0x200) continue;

                var arr = mem.Read(wbase + itemsOff, 0x20);
                if (arr == null) continue;
                int maxLen = BitConverter.ToInt32(arr, 0x0C);
                if (maxLen < want || maxLen > want * 4) continue;

                // 每个元素必须指向合法对象
                var ptrs = mem.Read(wbase + itemsOff + 0x10, want * 4);
                if (ptrs == null) continue;
                var elems = new List<long>();
                bool ok = true;
                for (int k = 0; k < want; k++)
                {
                    uint eo = BitConverter.ToUInt32(ptrs, k * 4);
                    if (eo < 0x1000 || eo > wsize - 0x100) { ok = false; break; }
                    long e = wbase + eo;
                    var head = mem.Read(e, 8);
                    if (head == null) { ok = false; break; }
                    uint klass = BitConverter.ToUInt32(head, 0);
                    if (klass < 0x1000 || klass > wsize - 0x100) { ok = false; break; }
                    elems.Add(e);
                }
                if (!ok) continue;

                Console.WriteLine($"\n── {Hex(addr + i)}  size={want}  items={Hex(wbase + itemsOff)}");
                for (int k = 0; k < elems.Count; k++)
                {
                    var body = mem.Read(elems[k], 0x30);
                    var ints = new List<string>();
                    if (body != null)
                        for (int q = 4; q + 4 <= body.Length && q < 0x20; q += 4)
                            ints.Add(BitConverter.ToInt32(body, q).ToString());
                    Console.WriteLine($"     [{k}] {Hex(elems[k])}  ints[1..7]= {string.Join(",", ints)}");
                }
                if (++found >= _max) { Console.WriteLine($"…上限 {_max}"); return; }
            }
            if (read < wantBytes) { addr += read; continue; }
            addr += Math.Max(1, read - 0x40);
        }
        Console.WriteLine($"\n共 {found} 个");
    }

    /// <summary>
    /// 精确导出某个字典：从 entries 起点开始，按「每 3 条一组」的实测结构遍历，
    /// 直到 klass 不再是已知值为止。输出「技能名 → 条目地址」。
    /// </summary>
    static void DictExport(WinMem mem, long start)
    {
        Console.WriteLine($"{Hex(start)} 起精确遍历：");
        int n = 0;
        var names = new List<(string Name, long At, int Hash)>();
        long at = start;
        while (n < 5000)
        {
            var b = mem.Read(at, 0x20);
            if (b == null) break;
            uint klass = BitConverter.ToUInt32(b, 0x00);
            if (klass != 0x0E055F90 && klass != 0x0E05D578) break;
            if (BitConverter.ToInt32(b, 0x04) != 0) break;

            int hash = BitConverter.ToInt32(b, 0x08);
            uint valOff = BitConverter.ToUInt32(b, 0x10);
            string text = "";
            if (valOff > 0x1000)
            {
                var sv = mem.Read(WASM_BASE + valOff, 0x60);
                if (sv != null && BitConverter.ToUInt32(sv, 0) == 0x0349FD10)
                {
                    int len = BitConverter.ToInt32(sv, 0x08);
                    if (len is > 0 and < 80)
                    {
                        int avail = Math.Min(len * 2, sv.Length - 0x0C);
                        if (avail > 0) text = Encoding.Unicode.GetString(sv, 0x0C, avail);
                    }
                }
            }
            if (text.Length > 0) names.Add((text, at, hash));
            at += 0x60;      // 实测：每 3 个 0x20 单元一组 = 0x60
            n++;
        }
        Console.WriteLine($"遍历 {n} 条，解出 {names.Count} 个名字：");
        foreach (var (name, a, h) in names)
            Console.WriteLine($"  hash=0x{h:X8}  @{Hex(a)}  \"{name}\"");
    }

    /// <summary>
    /// 导出「技能名字典」：扫描 wasm 内存里所有
    ///   klass(0xE05D578 / 0xE055F90) → 0 → hash → 0 → value(字符串指针)
    /// 形状的条目，把技能名解出来去重，输出成表。
    /// </summary>
    static void Skills(WinMem mem, int minLen)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];
        Console.WriteLine($"wasm {Hex(wbase)} {wsize / 1048576.0:N0} MB，扫描技能名条目…");

        var found = new Dictionary<string, long>();
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x20) { addr += 0x10000; continue; }

            for (int i = 0; i + 0x20 <= read; i += 4)
            {
                uint klass = BitConverter.ToUInt32(buf, i);
                if (klass != 0x0E055F90 && klass != 0x0E05D578) continue;
                // +0x04 应为 0，+0x08 应是「像哈希」的值，+0x10 是字符串指针
                if (BitConverter.ToInt32(buf, i + 4) != 0) continue;
                uint strOff = BitConverter.ToUInt32(buf, i + 0x10);
                if (strOff < 0x1000 || strOff > wsize - 0x100) continue;

                var sv = mem.Read(wbase + strOff, 0x60);
                if (sv == null) continue;
                if (BitConverter.ToUInt32(sv, 0) != 0x0349FD10) continue;   // 必须是 string 对象
                int len = BitConverter.ToInt32(sv, 0x08);
                if (len < Math.Max(1, minLen) || len > 60) continue;
                int avail = Math.Min(len * 2, sv.Length - 0x0C);
                if (avail <= 0) continue;
                var s = Encoding.Unicode.GetString(sv, 0x0C, avail);
                if (s.Length == 0 || s.Any(c => c < 0x20)) continue;
                if (!found.ContainsKey(s)) found[s] = addr + i;
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x20);
        }

        Console.WriteLine($"共 {found.Count} 个技能名：");
        foreach (var kv in found.OrderBy(k => k.Key, StringComparer.Ordinal))
            Console.WriteLine($"  {kv.Key,-24} @ {Hex(kv.Value)}");
    }

    /// <summary>
    /// 读「(hashCode, valuePtr) 交替」的数组（每条 0x20），value 指向字符串时解码出来。
    /// 用于读「技能 id → 名字」这种映射表。
    /// </summary>
    static void Pairs(WinMem mem, long addr, int count)
    {
        Console.WriteLine($"{Hex(addr)} 起，{count} 条（每条 0x20）：");
        for (int k = 0; k < count; k++)
        {
            long at = addr + k * 0x20L;
            var b = mem.Read(at, 0x20);
            if (b == null) break;
            // 实测布局：+0x00 klass, +0x08 hashCode, +0x10 value(字符串对象指针)
            int hash = BitConverter.ToInt32(b, 0x08);
            uint valOff = BitConverter.ToUInt32(b, 0x10);
            string text = "";
            if (valOff > 0x1000)
            {
                var sv = mem.Read(WASM_BASE + valOff, 0x40);
                if (sv != null)
                {
                    int len = BitConverter.ToInt32(sv, 0x08);
                    if (len is > 0 and < 100)
                    {
                        int avail = Math.Min(len * 2, sv.Length - 0x0C);
                        if (avail > 0) text = Encoding.Unicode.GetString(sv, 0x0C, avail);
                    }
                }
            }
            Console.WriteLine($"  [{k,3}] {Hex(at)}  hash=0x{hash:X8}({hash,11})  \"{text}\"");
        }
    }

    /// <summary>
    /// 把一片内存按「il2cpp 字符串对象」逐条解码（每条 32 字节对齐）。
    /// 字符串对象布局：+0x00 klass, +0x04 monitor, +0x08 length, +0x0C UTF-16 起。
    /// 用来读「技能名/描述」这类字符串数组。
    /// </summary>
    static void StrArr(WinMem mem, long addr, int count)
    {
        var buf = mem.Read(addr, count * 0x20);
        if (buf == null) { Console.WriteLine("读不出来"); return; }
        Console.WriteLine($"{Hex(addr)} 起，{count} 条：");
        for (int k = 0; k < count; k++)
        {
            int off = k * 0x20;
            if (off + 0x0C > buf.Length) break;
            uint klass = BitConverter.ToUInt32(buf, off);
            int len = BitConverter.ToInt32(buf, off + 0x08);
            if (len <= 0 || len > 200) { Console.WriteLine($"  [{k}] +0x{off:X3} len={len} (跳过)"); continue; }
            int avail = Math.Min(len * 2, buf.Length - off - 0x0C);
            var s = Encoding.Unicode.GetString(buf, off + 0x0C, avail);
            Console.WriteLine($"  [{k}] +0x{off:X3} len={len,3}  klass=0x{klass:X}  \"{s}\"");
        }
    }

    /// <summary>找所有「值等于目标地址（wasm 偏移形式）」的 4 字节位置 —— 反向引用。</summary>
    static void Refs(WinMem mem, long target)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];
        if (target < wbase) { Console.WriteLine($"目标 {Hex(target)} 不在 wasm 内存内"); return; }
        uint off = (uint)(target - wbase);
        var needle = BitConverter.GetBytes(off);
        Console.WriteLine($"反查指向 {Hex(target)}（wasm+0x{off:X}）的引用…");

        int hits = 0;
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 8) { addr += 0x10000; continue; }
            int idx = 0;
            while (idx <= read - 4)
            {
                int at = buf.AsSpan(idx, read - idx).IndexOf(needle);
                if (at < 0) break;
                long holder = addr + idx + at;
                Console.WriteLine($"  {Hex(holder)}  （持有位置 +0x{holder - target:X} 相对目标）");
                if (++hits >= _max) { Console.WriteLine($"…上限 {_max}"); return; }
                idx = at + 4;
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 4);
        }
        Console.WriteLine($"共 {hits} 处引用");
    }

    /// <summary>
    /// 找「以某个技能 id 为 key」的字典条目，并尝试把 value 指向的对象挖出来。
    /// 用于：拿到技能 id 后，找它的配置对象（里面有名字、图标、描述）。
    /// Il2Cpp Dictionary.IntEntry（wasm32，无自定义比较器时 20 字节）：
    ///   +0x00 hashCode  +0x04 next  +0x08 key  +0x0C value
    /// </summary>
    static void DictFind(WinMem mem, int key, int maxHits)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];
        var needle = BitConverter.GetBytes(key);
        Console.WriteLine($"在 wasm 内存里找 key={key} 的字典条目…");

        int hits = 0;
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x30) { addr += 0x10000; continue; }

            for (int i = 0; i + 0x14 <= read; i += 4)
            {
                if (buf[i + 8] != needle[0] || buf[i + 9] != needle[1] ||
                    buf[i + 10] != needle[2] || buf[i + 11] != needle[3]) continue;

                int hashCode = BitConverter.ToInt32(buf, i);
                int next = BitConverter.ToInt32(buf, i + 4);
                uint valueOff = BitConverter.ToUInt32(buf, i + 0x0C);

                // 合理性：next 在 -1..大数之间，value 是合法 wasm 偏移或 0
                if (next < -1 || next > 100000) continue;
                if (valueOff != 0 && (valueOff < 0x1000 || valueOff > wsize - 0x100)) continue;

                long entry = addr + i;
                Console.Write($"{Hex(entry),-16} hash={hashCode,12} next={next,6} key={key} value=");
                if (valueOff == 0) { Console.WriteLine("null"); continue; }

                uint v = valueOff;
                // 值可能直接是小整数，也可能是指针
                if (v > 0x100000)
                {
                    Console.WriteLine($"{Hex(wbase + v)}  (对象)");
                    var body = mem.Read(wbase + v, 0x40);
                    if (body != null)
                    {
                        for (int q = 4; q + 4 <= body.Length; q += 4)
                        {
                            uint vv = BitConverter.ToUInt32(body, q);
                            if (vv < 0x1000 || vv > wsize - 0x100) continue;
                            var s = ReadCStr(mem, wbase + vv, 48);
                            if (s.Length >= 2) Console.WriteLine($"        +0x{q:X2} → \"{s}\"");
                        }
                    }
                }
                else Console.WriteLine($"{v} (整数)");

                if (++hits >= maxHits) { Console.WriteLine($"…上限 {maxHits}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x14);
        }
        Console.WriteLine($"共 {hits} 处");
    }

    /// <summary>
    /// 沿着对象指针往下走，把整棵「对象树」里所有 List/int 都打出来。
    /// 用来从某个已知对象（比如 UI 实例）往下挖技能列表。
    /// </summary>
    static void SkillNear(WinMem mem, long obj, int maxDepth)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];
        var seen = new HashSet<long>();
        WalkLists(mem, wbase, wsize, obj, 0, maxDepth, seen, "");
    }

    static void WalkLists(WinMem mem, long wbase, long wsize, long obj, int depth, int maxDepth,
                          HashSet<long> seen, string indent)
    {
        if (depth > maxDepth || obj < wbase || obj >= wbase + wsize) return;
        if (!seen.Add(obj) || seen.Count > 400) return;

        var b = mem.Read(obj, 0x40);
        if (b == null) return;

        // 先看这个对象本身像不像 List<int>
        uint itemsOff = BitConverter.ToUInt32(b, 0x08);
        int size = BitConverter.ToInt32(b, 0x0C);
        if (size is >= 1 and <= 20 && itemsOff > 0x1000 && itemsOff < wsize - 0x100)
        {
            var arr = mem.Read(wbase + itemsOff, 0x20);
            if (arr != null)
            {
                int maxLen = BitConverter.ToInt32(arr, 0x0C);
                if (maxLen >= size && maxLen <= 64)
                {
                    var vals = mem.Read(wbase + itemsOff + 0x10, Math.Min(size, 12) * 4);
                    if (vals != null)
                    {
                        var ints = new List<int>();
                        for (int k = 0; k * 4 + 4 <= vals.Length; k++) ints.Add(BitConverter.ToInt32(vals, k * 4));
                        bool allSmall = ints.All(v => v >= 0 && v <= 999999);
                        if (allSmall && ints.Any(v => v > 0))
                            Console.WriteLine($"{indent}List<int> @ {Hex(obj)} size={size} → [{string.Join(", ", ints)}]");
                    }
                }
            }
        }

        // 再往下走指针字段
        for (int q = 0; q + 4 <= b.Length; q += 4)
        {
            uint v = BitConverter.ToUInt32(b, q);
            if (v < 0x1000 || v > wsize - 0x100) continue;
            long t = wbase + v;
            if (seen.Contains(t)) continue;
            var inner = mem.Read(t, 0x10);
            if (inner == null) continue;
            uint klass = BitConverter.ToUInt32(inner, 0);
            if (klass < 0x1000 || klass > wsize - 0x100) continue;
            Console.WriteLine($"{indent}+0x{q:X2} → {Hex(t)}  obj");
            WalkLists(mem, wbase, wsize, t, depth + 1, maxDepth, seen, indent + "   ");
        }
    }

    // ───────────────────────── uidetect ─────────────────────────

    /// <summary>
    /// 检测当前打开的是哪个迷宫 UI（用于「点一下 → 看弹哪个界面」的实验）。
    /// 原理：迷宫 UI 打开时，场景里的 GameObject 名字会出现在内存里；
    /// 统计各个已知 UI 名在当前内存里出现次数，出现多的那个就是正在显示的。
    /// </summary>
    static readonly string[] MazeUiNames =
    {
        "MazeShopUI", "MazeSupplyEventUI", "MazeNormalEventUI", "MazeRandomSkillSelectUI",
        "MazeConfirmUI", "MazeMonsterShowUI", "MazeBagUI", "MazeGetDrugUI",
        "MazeSelectDrugUI", "MazeGetCurrencyUI", "MazeFinalUI", "MazeRankUI",
        "MazeExchangeShopUI", "MazeUI",
    };

    static void UiDetect(WinMem mem)
    {
        // 先定位 wasm 内存
        var cands = MazeLocator.FindWasmCandidates(mem);
        if (cands.Count == 0) { Console.WriteLine("没找到 wasm 内存"); return; }
        var (wbase, wsize) = cands[0];

        // 一次性把整块读进来做统计（768MB 放内存里可以，但为省内存分块累计）
        var counts = new Dictionary<string, int>();
        foreach (var n in MazeUiNames) counts[n] = 0;

        var buf = new byte[8 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 32) { addr += 0x10000; continue; }
            var span = buf.AsSpan(0, read);
            foreach (var n in MazeUiNames)
            {
                var needle = Encoding.ASCII.GetBytes(n);
                int idx = 0, c = 0;
                while (idx <= read - needle.Length)
                {
                    int at = span[idx..].IndexOf(needle);
                    if (at < 0) break;
                    // 后面必须是 \0 或非标识符字符，避免 MazeUI 命中 MazeUIXxx
                    int after = idx + at + needle.Length;
                    if (after >= read || !(buf[after] == 0 || buf[after] == '_' || char.IsLetterOrDigit((char)buf[after]) == false))
                        c++;
                    idx += at + needle.Length;
                }
                counts[n] += c;
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 32);
        }

        Console.WriteLine("各迷宫 UI 名在当前内存里的出现次数：");
        foreach (var kv in counts.OrderByDescending(k => k.Value))
            Console.WriteLine($"  {kv.Key,-26} {kv.Value}");
        var top = counts.OrderByDescending(k => k.Value).First();
        Console.WriteLine($"\n→ 最可能正在显示：{top.Key}（{top.Value} 次）");

        // 追加写入快照文件，供前后对比
        var snap = System.IO.Path.Combine(AppContext.BaseDirectory, "ui-counts.txt");
        File.WriteAllLines(snap, counts.Select(kv => $"{kv.Key}|{kv.Value}"));
        Console.WriteLine($"计数已存 {snap}");
    }

    // ───────────────────────── cellcfg ─────────────────────────

    /// <summary>
    /// 从迷宫格子对象里挖配置：每个 CSMessMapData 后面往往跟着它引用的配置对象指针。
    /// 把整格前后 0x60 字节按 4 字节展开，并尝试把每个「像 wasm 偏移」的值当对象头读出来，
    /// 找里面的字符串（配置表里的名字/图标名）。
    /// </summary>
    static void CellCfg(WinMem mem)
    {
        var st = MazeLocator.Locate(mem, out var why);
        if (st == null) { Console.WriteLine("定位失败：" + why); return; }
        Console.WriteLine($"迷宫对象 {Hex(st.Obj)}，格子 {st.Cells.Count} 个");

        var head = mem.Read(st.ListAddr, 0x10);
        uint itemsOff = BitConverter.ToUInt32(head, 0x08);
        long itemsAddr = st.WBase + itemsOff;

        Console.WriteLine("\n格子按列表原始顺序（不是排序后）：");
        Console.WriteLine($"{"#",-4}{"类型",-6}{"事件",-8}{"row",-6}{"col",-6}{"标志",-6}地址");
        for (int k = 0; k < st.Cells.Count; k++)
        {
            var c = st.Cells[k];
            var p = mem.Read(itemsAddr + 0x10 + k * 4, 4);
            uint off = p != null ? BitConverter.ToUInt32(p, 0) : 0;
            Console.WriteLine($"{c.Index,-4}{c.Type,-6}{c.EventId,-8}{c.Row,-6}{c.Col,-6}{c.Flag,-6}{Hex(st.WBase + off)}");
        }

        // 检查同一 row 内列表顺序与 col 顺序是否一致
        Console.WriteLine("\n同一 row 内的列表顺序 vs col 值：");
        foreach (var g in st.Cells.GroupBy(c => c.Row).OrderBy(x => x.Key))
        {
            var inListOrder = g.OrderBy(c => c.Index).Select(c => c.Col).ToList();
            var sortedByCol = g.OrderBy(c => c.Col).Select(c => c.Col).ToList();
            bool same = inListOrder.SequenceEqual(sortedByCol);
            Console.WriteLine($"  row={g.Key,-3} 列表序=[{string.Join(",", inListOrder)}]  col序=[{string.Join(",", sortedByCol)}]  {(same ? "一致" : "★不一致")}");
        }

        // 关键：同一 row 内 col 相同的格子，差异在哪？（找真正的列位置字段）
        Console.WriteLine("\n══ 同一 row 内 col 相同的格子，完整 40 字节对比 ══");
        foreach (var g in st.Cells.GroupBy(c => c.Row).OrderBy(x => x.Key))
        {
            if (g.Count() < 2) continue;
            var cols = g.Select(c => c.Col).Distinct().Count();
            if (cols != 1) continue;      // 只看 col 全相同的那一行

            Console.WriteLine($"\nrow={g.Key}  全部 col={g.First().Col}，共 {g.Count()} 格：");
            foreach (var c in g.OrderBy(x => x.Index))
            {
                var p = mem.Read(itemsAddr + 0x10 + c.Index * 4, 4);
                uint off = p != null ? BitConverter.ToUInt32(p, 0) : 0;
                long cell = st.WBase + off;
                var body = mem.Read(cell, 0x28);
                if (body == null) continue;
                var words = new List<string>();
                for (int w = 0; w + 4 <= body.Length; w += 4)
                    words.Add($"{BitConverter.ToInt32(body, w)}");
                Console.WriteLine($"  #{c.Index} 类型={c.Type} 事件={c.EventId}  [w0..w9] {string.Join(", ", words)}");
            }
        }
    }

    /// <summary>递归走对象指针，把能读成字符串的都打出来（限深度、限访问次数）。</summary>
    static void Walk(WinMem mem, long wbase, long wsize, long obj, int depth, int maxDepth,
                     HashSet<long> seen, string indent)
    {
        if (depth > maxDepth || obj < wbase || obj >= wbase + wsize) return;
        if (!seen.Add(obj)) return;
        if (seen.Count > 300) return;

        var b = mem.Read(obj, 0x40);
        if (b == null) return;

        for (int q = 0; q + 4 <= b.Length; q += 4)
        {
            uint v = BitConverter.ToUInt32(b, q);
            if (v < 0x1000 || v > wsize - 0x100) continue;
            long t = wbase + v;

            var s = ReadCStr(mem, t, 60);
            if (s.Length >= 2)
            {
                Console.WriteLine($"{indent}+0x{q:X2} → {Hex(t)}  \"{s}\"");
                continue;
            }

            var inner = mem.Read(t, 0x10);
            if (inner == null) continue;
            uint klass = BitConverter.ToUInt32(inner, 0);
            // 只有像对象头（klass 是合法偏移）才继续下钻
            if (klass < 0x1000 || klass > wsize - 0x100) continue;
            Console.WriteLine($"{indent}+0x{q:X2} → {Hex(t)}  obj(klass=0x{klass:X})");
            Walk(mem, wbase, wsize, t, depth + 1, maxDepth, seen, indent + "   ");
        }
    }

    /// <summary>尝试把某地址当 UTF-8 字符串读（遇到不可打印就停）。</summary>
    static string ReadCStr(WinMem mem, long addr, int max)
    {
        var b = mem.Read(addr, max);
        if (b == null) return "";
        var sb = new System.Text.StringBuilder();
        foreach (var c in b)
        {
            if (c == 0) break;
            if (c >= 0x20 && c < 0x7F) sb.Append((char)c);
            else return "";
        }
        return sb.ToString();
    }

    // ───────────────────────── cfghunt ─────────────────────────

    /// <summary>
    /// 找迷宫事件配置字典：Dictionary&lt;int, *Cfg&gt;。
    /// Il2Cpp Dictionary（wasm32）实测布局：
    ///   +0x00 klass  +0x04 monitor
    ///   +0x08 buckets(ptr)  +0x0C entries(ptr)  +0x10 count  +0x14 freeList  +0x18 freeCount
    ///   +0x1C keyCount  +0x20 比较器引用
    /// Entry（24 字节）：+0x00 hashCode  +0x04 next  +0x08 key  +0x0C value(ptr，4 字节)
    /// 判据：count∈[10,500]、keyCount≈count、buckets/entries 都是合法 wasm 偏移，
    ///       且 keys 严格递增、落在迷宫事件 id 区间（1000~99999）。
    /// </summary>
    static void CfgHunt(WinMem mem, int minKey, int minCount)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        if (cands.Count == 0) { Console.WriteLine("没找到 wasm 内存"); return; }
        var (wbase, wsize) = cands[0];
        Console.WriteLine($"wasm {Hex(wbase)} {wsize / 1048576.0:N0} MB，找事件配置字典…");

        int found = 0;
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x30) { addr += 0x10000; continue; }

            for (int i = 0; i + 0x30 <= read; i += 4)
            {
                int count = BitConverter.ToInt32(buf, i + 0x10);
                if (count < Math.Max(1, minCount) || count > 500) continue;
                int keyCount = BitConverter.ToInt32(buf, i + 0x1C);
                if (keyCount != count) continue;                 // 强烈约束
                int freeCount = BitConverter.ToInt32(buf, i + 0x18);
                if (freeCount is < 0 or > 500) continue;

                uint entriesOff = BitConverter.ToUInt32(buf, i + 0x0C);
                uint bucketsOff = BitConverter.ToUInt32(buf, i + 0x08);
                if (entriesOff < 0x1000 || entriesOff > wsize - 0x100) continue;
                if (bucketsOff < 0x1000 || bucketsOff > wsize - 0x100) continue;

                long entriesAddr = wbase + entriesOff;
                var e = mem.Read(entriesAddr, 24 * Math.Min(count, 10));
                if (e == null || e.Length < 48) continue;

                var keys = new List<int>();
                int prev = int.MinValue;
                bool ok = true;
                for (int k = 0; k < Math.Min(count, 10); k++)
                {
                    int off = k * 24;
                    if (off + 24 > e.Length) break;
                    int key = BitConverter.ToInt32(e, off + 0x08);
                    if (key <= 0 || key > 9999999) { ok = false; break; }
                    if (key <= prev) { ok = false; break; }     // 必须严格递增
                    prev = key;
                    keys.Add(key);
                }
                if (!ok || keys.Count < 5) continue;
                if (minKey > 0 && keys[0] < minKey) continue;

                long dictAddr = addr + i;
                Console.WriteLine($"\n── 候选字典 {Hex(dictAddr)}  count={count} free={freeCount} buckets={Hex(wbase + bucketsOff)} entries={Hex(entriesAddr)}");
                Console.WriteLine($"   keys: {string.Join(", ", keys)}");
                if (++found >= _max) { Console.WriteLine($"…上限 {_max}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x30);
        }
        Console.WriteLine($"\n共 {found} 个候选");
    }

    // ───────────────────────── abs / abfind ─────────────────────────

    /// <summary>看一个 .ab 的头信息。</summary>
    static void Abs(string path)
    {
        var data = File.ReadAllBytes(path);
        Console.WriteLine($"{Path.GetFileName(path)}  {data.Length / 1024.0:N1} KB");

        // 先手工走一遍头部，定位各字段真实偏移
        int p = 0;
        var magic = System.Text.Encoding.ASCII.GetString(data, 0, 8);
        p = 8;
        uint ver = (uint)(data[p] << 24 | data[p + 1] << 16 | data[p + 2] << 8 | data[p + 3]);
        p += 4;
        int verStrStart = p;
        while (p < data.Length && data[p] != 0) p++;
        var verStr = System.Text.Encoding.ASCII.GetString(data, verStrStart, p - verStrStart);
        p++;
        int revStart = p;
        while (p < data.Length && data[p] != 0) p++;
        var revStr = System.Text.Encoding.ASCII.GetString(data, revStart, p - revStart);
        p++;
        Console.WriteLine($"  magic={magic} version={ver} unity={verStr} rev={revStr}");
        Console.WriteLine($"  size 字段起点 offset={p}");

        long size = 0;
        for (int i = 0; i < 8; i++) size = (size << 8) | data[p + i];
        int ciOff = p + 8, uiOff = p + 12, flOff = p + 16, infoOff = p + 20;
        uint ci = (uint)(data[ciOff] << 24 | data[ciOff + 1] << 16 | data[ciOff + 2] << 8 | data[ciOff + 3]);
        uint ui = (uint)(data[uiOff] << 24 | data[uiOff + 1] << 16 | data[uiOff + 2] << 8 | data[uiOff + 3]);
        uint fl = (uint)(data[flOff] << 24 | data[flOff + 1] << 16 | data[flOff + 2] << 8 | data[flOff + 3]);
        Console.WriteLine($"  size={size}  ciSize={ci}  uiSize={ui}  flags=0x{fl:X}");
        Console.WriteLine($"  blocksInfo 起点 offset={infoOff}");
        Console.WriteLine($"  文件长={data.Length}");

        if (infoOff + ci <= data.Length)
        {
            Console.WriteLine("  暴力搜索 blocksInfo 起点：");
            for (int tryOff = 40; tryOff < 80; tryOff++)
            {
                if (tryOff + ci > data.Length) break;
                var raw = new byte[ci];
                Buffer.BlockCopy(data, tryOff, raw, 0, (int)ci);
                var dst = new byte[ui];
                int n = Lz4.DecompressBlock(raw, dst);
                if (n == ui)
                {
                    Console.WriteLine($"    ✓ 起点 {tryOff} → LZ4 解出 {n} 字节");
                    int q = 0;
                    uint count = (uint)(dst[q] << 24 | dst[q + 1] << 16 | dst[q + 2] << 8 | dst[q + 3]);
                    Console.WriteLine($"      blockCount(前4大端)={count}");
                    for (int q2 = 0; q2 < Math.Min(24, dst.Length); q2 += 4)
                    {
                        uint v = (uint)(dst[q2] << 24 | dst[q2 + 1] << 16 | dst[q2 + 2] << 8 | dst[q2 + 3]);
                        Console.WriteLine($"      +0x{q2:X}: 0x{v:X8} ({v})");
                    }
                    break;
                }
            }
        }
    }

    /// <summary>
    /// 解析「技能描述表」：实测结构为
    ///   +0x00 u32 标记(0x02000001)
    ///   +0x04 u32 字符串字节长度
    ///   +0x08 UTF-8 字符串 + 0x00
    ///   之后 8 字节（可能是 id / 偏移）
    /// 输出「名字 → 后续数值」，供建立映射。
    /// </summary>
    static void AbTable(string rawPath, long start)
    {
        var data = File.ReadAllBytes(rawPath);
        int p = (int)(start > 0 ? start : 0);
        int n = 0;
        var rows = new List<(string Name, long Key, int At)>();
        while (p + 12 < data.Length && n < 5000)
        {
            // 找「u32 长度 + 紧跟的合法 UTF-8」
            uint len = BitConverter.ToUInt32(data, p);
            if (len == 0 || len > 500 || p + 4 + len > data.Length) { p += 1; continue; }
            var s = Encoding.UTF8.GetString(data, p + 4, (int)len);
            if (s.Length == 0 || s.Any(c => c < 0x20 || c == 0xFFFD)) { p += 1; continue; }
            // 必须至少有 2 个可读字符，且不含控制字符
            if (s.Count(c => char.IsLetterOrDigit(c) || c > 0x7F) < 2) { p += 1; continue; }

            int after = p + 4 + (int)len;
            if (after < data.Length && data[after] == 0) after++;
            long key = 0;
            if (after + 8 <= data.Length) key = BitConverter.ToInt64(data, after);
            rows.Add((s, key, p));
            n++;
            p = after + 8;
        }
        Console.WriteLine($"解出 {rows.Count} 条：");
        foreach (var (name, key, at) in rows.Take(300))
            Console.WriteLine($"  +0x{at:X6}  {name,-30} key=0x{key:X16}({key})");
    }

    /// <summary>
    /// 找「当前可选卡」：扫描连续指针，每个指针指向的对象内部含「整卡」名。
    /// 与 FindCardObjList 的区别：不要求 List 结构，直接找任意位置的连续指针组。
    /// </summary>
    static void FindCardPtr(WinMem mem, int count)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];

        // 整卡字符串偏移 → 名字
        var cardStr = new Dictionary<uint, string>();
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x40) { addr += 0x10000; continue; }
            for (int i = 0; i + 0x40 <= read; i += 4)
            {
                if (BitConverter.ToUInt32(buf, i) != 0x0349FD10) continue;
                int len = BitConverter.ToInt32(buf, i + 8);
                if (len is < 2 or > 40) continue;
                int avail = Math.Min(len * 2, read - i - 0x0C);
                if (avail <= 0) continue;
                var s = Encoding.Unicode.GetString(buf, i + 0x0C, avail);
                if (!s.EndsWith("整卡", StringComparison.Ordinal)) continue;
                cardStr[(uint)(addr + i - wbase)] = s;
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x40);
        }
        Console.WriteLine($"整卡字符串 {cardStr.Count} 个");

        // 扫全部可读内存，找「连续 count 个指针，每个指向含整卡名的对象」
        int found = 0;
        addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < count * 4) { addr += 0x10000; continue; }
            for (int i = 0; i + count * 4 <= read; i += 4)
            {
                var names = new List<string>();
                bool ok = true;
                for (int k = 0; k < count; k++)
                {
                    uint eo = BitConverter.ToUInt32(buf, i + k * 4);
                    if (eo < 0x1000 || eo > wsize - 0x100) { ok = false; break; }
                    var body = mem.Read(wbase + eo, 0x40);
                    if (body == null) { ok = false; break; }
                    string hit = null;
                    for (int q = 0; q + 4 <= body.Length; q += 4)
                    {
                        uint vv = BitConverter.ToUInt32(body, q);
                        if (cardStr.TryGetValue(vv, out var nm)) { hit = nm; break; }
                    }
                    if (hit == null) { ok = false; break; }
                    names.Add(hit);
                }
                if (!ok || names.Distinct().Count() != count) continue;
                Console.WriteLine($"\n★ {Hex(addr + i)}");
                for (int k = 0; k < count; k++) Console.WriteLine($"    [{k}] {names[k]}");
                if (++found >= _max) { Console.WriteLine($"…上限 {_max}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - count * 4);
        }
        Console.WriteLine($"\n共 {found} 组");
    }

    /// <summary>
    /// 找「当前可选卡列表」的另一种形态：N 个元素的对象数组，
    /// 每个元素对象里（+0x08 ~ +0x30 范围）引用了某个「整卡」字符串。
    /// </summary>
    static void FindCardObjList(WinMem mem, int count)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];

        // 整卡字符串：偏移 → 名字
        var cardStr = new Dictionary<uint, string>();
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x40) { addr += 0x10000; continue; }
            for (int i = 0; i + 0x40 <= read; i += 4)
            {
                if (BitConverter.ToUInt32(buf, i) != 0x0349FD10) continue;
                int len = BitConverter.ToInt32(buf, i + 8);
                if (len is < 2 or > 40) continue;
                int avail = Math.Min(len * 2, read - i - 0x0C);
                if (avail <= 0) continue;
                var s = Encoding.Unicode.GetString(buf, i + 0x0C, avail);
                if (!s.EndsWith("整卡", StringComparison.Ordinal)) continue;
                cardStr[(uint)(addr + i - wbase)] = s;
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x40);
        }
        Console.WriteLine($"整卡字符串 {cardStr.Count} 个；找「{count} 个对象的列表，每个含整卡名」…");

        // 扫 List<T>：_items(4) _size(4)，size == count
        int found = 0;
        addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x20) { addr += 0x10000; continue; }
            for (int i = 0; i + 0x14 <= read; i += 4)
            {
                int size = BitConverter.ToInt32(buf, i + 0x0C);
                if (size != count) continue;
                uint itemsOff = BitConverter.ToUInt32(buf, i + 0x08);
                if (itemsOff < 0x1000 || itemsOff > wsize - 0x100) continue;

                // 读 count 个元素指针，逐个看对象内是否引用整卡名
                var names = new List<string>();
                bool ok = true;
                for (int k = 0; k < count; k++)
                {
                    var p = mem.Read(wbase + itemsOff + 0x10 + k * 4, 4);
                    if (p == null) { ok = false; break; }
                    uint eo = BitConverter.ToUInt32(p, 0);
                    if (eo < 0x1000 || eo > wsize - 0x100) { ok = false; break; }
                    var body = mem.Read(wbase + eo, 0x40);
                    if (body == null) { ok = false; break; }
                    string hit = null;
                    for (int q = 0; q + 4 <= body.Length; q += 4)
                    {
                        uint vv = BitConverter.ToUInt32(body, q);
                        if (cardStr.TryGetValue(vv, out var nm)) { hit = nm; break; }
                    }
                    if (hit == null) { ok = false; break; }
                    names.Add(hit);
                }
                if (!ok || names.Count != count || names.Distinct().Count() != count) continue;

                Console.WriteLine($"\n★ List @ {Hex(addr + i)}  items={Hex(wbase + itemsOff)}");
                for (int k = 0; k < count; k++) Console.WriteLine($"    [{k}] {names[k]}");
                if (++found >= _max) { Console.WriteLine($"…上限 {_max}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x14);
        }
        Console.WriteLine($"\n共 {found} 组");
    }

    /// <summary>
    /// 找「恰好 N 个连续字符串指针、且都指向『整卡』名字」的数组 —— 就是当前可选卡列表。
    /// </summary>
    static void FindCardList(WinMem mem, int count)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];

        // 先收集「整卡」字符串对象地址 → 名字
        var cardStr = new Dictionary<uint, string>();
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x40) { addr += 0x10000; continue; }
            for (int i = 0; i + 0x40 <= read; i += 4)
            {
                if (BitConverter.ToUInt32(buf, i) != 0x0349FD10) continue;
                int len = BitConverter.ToInt32(buf, i + 8);
                if (len is < 2 or > 40) continue;
                int avail = Math.Min(len * 2, read - i - 0x0C);
                if (avail <= 0) continue;
                var s = Encoding.Unicode.GetString(buf, i + 0x0C, avail);
                if (!s.EndsWith("整卡", StringComparison.Ordinal)) continue;
                cardStr[(uint)(addr + i - wbase)] = s;
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x40);
        }
        Console.WriteLine($"「整卡」字符串 {cardStr.Count} 个，找连续 {count} 个指针的数组…");

        int found = 0;
        addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < count * 4 + 4) { addr += 0x10000; continue; }
            for (int i = 0; i + count * 4 <= read; i += 4)
            {
                var names = new List<string>();
                for (int k = 0; k < count; k++)
                {
                    uint v = BitConverter.ToUInt32(buf, i + k * 4);
                    if (!cardStr.TryGetValue(v, out var nm)) { names = null; break; }
                    names.Add(nm);
                }
                if (names == null || names.Count != count) continue;
                // 名字必须互不相同
                if (names.Distinct().Count() != count) continue;

                Console.WriteLine($"\n★ {Hex(addr + i)}  (wasm+0x{addr + i - wbase:X})");
                for (int k = 0; k < count; k++)
                    Console.WriteLine($"    [{k}] {names[k]}");
                if (++found >= _max) { Console.WriteLine($"…上限 {_max}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - count * 4);
        }
        Console.WriteLine($"\n共 {found} 组");
    }

    /// <summary>
    /// 找「当前可选技能卡」容器。
    ///
    /// 思路：把 wasm 内存里所有「字符串对象指针」引用位置收集起来，
    /// 找出那些「指向的技能名以『整卡』结尾」的指针；
    /// 这些指针如果成组出现（4 个左右、地址相近），那一组就是本次可选卡。
    ///
    /// 参数：可选传入技能名过滤（只关心含这些关键字的卡）。
    /// </summary>
    static void FindCards(WinMem mem, string[] filter)
    {
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];
        Console.WriteLine($"wasm {Hex(wbase)} {wsize / 1048576.0:N0} MB，找「当前可选技能卡」…");

        // ① 把所有「整卡」字符串对象的地址记下来（含名字）
        var cardStr = new Dictionary<long, string>();
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x40) { addr += 0x10000; continue; }
            for (int i = 0; i + 0x40 <= read; i += 4)
            {
                if (BitConverter.ToUInt32(buf, i) != 0x0349FD10) continue;
                int len = BitConverter.ToInt32(buf, i + 8);
                if (len is < 2 or > 40) continue;
                int avail = Math.Min(len * 2, read - i - 0x0C);
                if (avail <= 0) continue;
                var s = Encoding.Unicode.GetString(buf, i + 0x0C, avail);
                if (!s.EndsWith("整卡", StringComparison.Ordinal)) continue;
                long at = addr + i;
                if (!cardStr.ContainsKey(at)) cardStr[at] = s;
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x40);
        }
        Console.WriteLine($"① 找到 {cardStr.Count} 个「整卡」字符串对象");

        // ② 扫全内存找引用这些字符串的 4 字节指针
        var hits = new Dictionary<long, List<(long Holder, string Name)>>();
        var needleSet = new Dictionary<uint, string>();
        foreach (var (a, s) in cardStr) needleSet[(uint)(a - wbase)] = s;

        addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 8) { addr += 0x10000; continue; }
            for (int i = 0; i + 4 <= read; i += 4)
            {
                uint v = BitConverter.ToUInt32(buf, i);
                if (!needleSet.TryGetValue(v, out var name)) continue;
                // 记录「持有位置所在的 0x40 对齐块」，同一块里的算一组
                long holder = addr + i;
                long block = holder & ~0x3FL;
                if (!hits.TryGetValue(block, out var list)) hits[block] = list = new();
                if (!list.Any(x => x.Name == name)) list.Add((holder, name));
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 4);
        }

        // ③ 输出「同一块内出现 2 个以上不同卡名」的组
        Console.WriteLine("\n② 可能的分组（同一 0x40 块内出现多个不同卡名）：");
        var groups = hits.Where(kv => kv.Value.Count >= 2)
                         .OrderByDescending(kv => kv.Value.Count)
                         .Take(20).ToList();
        foreach (var kv in groups)
        {
            Console.WriteLine($"\n── 块 {Hex(kv.Key)}  含 {kv.Value.Count} 个卡名：");
            foreach (var (holder, name) in kv.Value)
                Console.WriteLine($"     +0x{holder - kv.Key:X2}  {name}");
        }
        if (groups.Count == 0) Console.WriteLine("   （没有；说明引用分散在不同块）");
    }

    /// <summary>
    /// 在 wasm 内存里按「指定的 int32 序列」搜索，允许中间有间隔（默认每项间隔 stride 字节）。
    /// 用于找「技能等级数组」这种 11,7,2,2 的特征。
    /// </summary>
    static void Pattern(WinMem mem, int[] vals)
    {
        if (vals.Length < 2) { Console.WriteLine("至少给两个数"); return; }
        var cands = MazeLocator.FindWasmCandidates(mem);
        var (wbase, wsize) = cands[0];
        Console.WriteLine($"在 wasm 里找序列 [{string.Join(",", vals)}]（允许 4 字节间隔）…");

        int hits = 0;
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x40) { addr += 0x10000; continue; }

            for (int i = 0; i + vals.Length * 4 <= read; i += 4)
            {
                bool ok = true;
                for (int k = 0; k < vals.Length; k++)
                    if (BitConverter.ToInt32(buf, i + k * 4) != vals[k]) { ok = false; break; }
                if (!ok) continue;

                long at2 = addr + i;
                Console.WriteLine($"\n── {Hex(at2)} (wasm+0x{at2 - wbase:X})");
                Console.Write(Preview(buf, Math.Max(0, i - 24), Math.Min(read, i + vals.Length * 4 + 32)));
                if (++hits >= _max) { Console.WriteLine($"…上限 {_max}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - vals.Length * 4);
        }
        Console.WriteLine($"命中 {hits} 处");
    }

    /// <summary>把 .ab 解出来的数据存成文件。</summary>
    static void AbDump(string path, string outPath)
    {
        var data = File.ReadAllBytes(path);
        var info = UnityFs.ReadInfo(data);
        var all = UnityFs.ReadAllData(data, info);
        outPath ??= Path.Combine(AppContext.BaseDirectory, Path.GetFileNameWithoutExtension(path) + ".raw");
        File.WriteAllBytes(outPath, all);
        Console.WriteLine($"解出 {all.Length / 1024.0:N1} KB → {outPath}");
    }

    /// <summary>
    /// 扫描一个目录下所有 .ab，找含指定关键字的包。
    /// 用于「哪个包里有技能配置表」。
    /// </summary>
    static void AbScan(string dir, string[] keys)
    {
        var files = Directory.GetFiles(dir, "*.ab");
        Console.WriteLine($"扫描 {files.Length} 个包，找 {string.Join(", ", keys)}…");
        foreach (var f in files)
        {
            try
            {
                var data = File.ReadAllBytes(f);
                var info = UnityFs.ReadInfo(data);
                if (info.Blocks.Count == 0) continue;
                var all = UnityFs.ReadAllData(data, info);
                var hitKeys = new List<string>();
                foreach (var k in keys)
                {
                    var n8 = Encoding.UTF8.GetBytes(k);
                    var n16 = Encoding.Unicode.GetBytes(k);
                    if (all.AsSpan().IndexOf(n8) >= 0 || all.AsSpan().IndexOf(n16) >= 0) hitKeys.Add(k);
                }
                if (hitKeys.Count > 0)
                    Console.WriteLine($"  ✓ {Path.GetFileName(f)}  ({all.Length / 1024.0:N0} KB)  命中: {string.Join(", ", hitKeys)}");
            }
            catch { }
        }
    }

    /// <summary>
    /// 在 .ab 解出来的数据里找关键字，打印命中处的可读上下文。
    /// 用来确认某个配置表里有没有我们要的技能名。
    /// </summary>
    static void AbFind(string path, string[] keys)
    {
        var data = File.ReadAllBytes(path);
        var info = UnityFs.ReadInfo(data);
        var all = UnityFs.ReadAllData(data, info, m => Console.WriteLine(m));
        Console.WriteLine($"{Path.GetFileName(path)} → 解出 {all.Length / 1024.0:N1} KB，找 {string.Join(", ", keys)}");

        foreach (var k in keys)
        {
            var needles = new[] { Encoding.UTF8.GetBytes(k), Encoding.Unicode.GetBytes(k) };
            foreach (var needle in needles)
            {
                bool wide = needle.Length > 0 && needle.Length % 2 == 0 && needle[1] == 0;
                int idx = 0, hits = 0;
                while (idx <= all.Length - needle.Length && hits < 3)
                {
                    int at = all.AsSpan(idx).IndexOf(needle);
                    if (at < 0) break;
                    int abs = idx + at;
                    hits++;
                    Console.WriteLine($"  [{k}] {(wide ? "UTF16" : "UTF8")} +0x{abs:X}");
                    int s = Math.Max(0, abs - 40), e = Math.Min(all.Length, abs + needle.Length + 80);
                    Console.WriteLine("     " + Printable(all, s, e - s));
                    idx = abs + needle.Length;
                }
                if (hits == 0) Console.WriteLine($"  [{k}] {(wide ? "UTF16" : "UTF8")} 未命中");
            }
        }
    }

    static string Printable(byte[] b, int off, int len)
    {
        var sb = new StringBuilder();
        for (int i = off; i < off + len && i < b.Length; i++)
        {
            byte c = b[i];
            sb.Append(c >= 0x20 && c < 0x7F ? (char)c : c == 0 ? ' ' : '.');
        }
        return sb.ToString();
    }

    // ───────────────────────── ocr ─────────────────────────

    /// <summary>截图游戏窗口并识别 4 张可选技能卡的名字。</summary>
    static void Ocr(long hwnd)
    {
        if (!SkillOcr.Available) { Console.WriteLine("找不到 tesseract.exe"); return; }

        Bitmap shot = null;
        // 优先用窗口截图
        if (hwnd > 0) shot = CaptureWindow(new IntPtr(hwnd));
        if (shot == null)
        {
            Console.WriteLine("窗口截图失败，改用全屏截图");
            var b = new Bitmap(System.Windows.Forms.SystemInformation.VirtualScreen.Width,
                               System.Windows.Forms.SystemInformation.VirtualScreen.Height);
            using (var g = Graphics.FromImage(b))
                g.CopyFromScreen(System.Windows.Forms.SystemInformation.VirtualScreen.Left,
                                 System.Windows.Forms.SystemInformation.VirtualScreen.Top,
                                 0, 0, b.Size);
            shot = b;
        }
        using var _ = shot;
        Console.WriteLine($"截图 {shot.Width}x{shot.Height}，开始识别…");
        var cards = SkillOcr.ReadCards(shot, s => Console.WriteLine("  " + s));
        Console.WriteLine();
        if (cards.Count == 0) { Console.WriteLine("没识别出技能卡"); return; }
        Console.WriteLine($"识别到 {cards.Count} 张可选技能：");
        for (int i = 0; i < cards.Count; i++)
            Console.WriteLine($"  [{i + 1}] {cards[i].Name}");
    }

    static Bitmap CaptureWindow(IntPtr hwnd)
    {
        try
        {
            // 用 ClientToScreen 定位客户区，避免 GetWindowRect 在部分环境失效
            if (GetClientRect(hwnd, out var cr) && ClientToScreen(hwnd, ref __origin))
            {
                int w = cr.Right - cr.Left, h = cr.Bottom - cr.Top;
                if (w > 0 && h > 0)
                {
                    var b = new Bitmap(w, h);
                    using var g = Graphics.FromImage(b);
                    g.CopyFromScreen(__origin.X, __origin.Y, 0, 0, new Size(w, h));
                    return b;
                }
            }
        }
        catch (Exception ex) { Console.WriteLine("  ClientToScreen 截图失败：" + ex.Message); }

        try
        {
            if (GetWindowRect(hwnd, out var r))
            {
                int w = r.Right - r.Left, h = r.Bottom - r.Top;
                if (w > 0 && h > 0)
                {
                    var b = new Bitmap(w, h);
                    using var g = Graphics.FromImage(b);
                    g.CopyFromScreen(r.Left, r.Top, 0, 0, new Size(w, h));
                    return b;
                }
            }
        }
        catch (Exception ex) { Console.WriteLine("  GetWindowRect 截图失败：" + ex.Message); }
        return null;
    }

    static WPOINT __origin = new WPOINT();
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct WPOINT { public int X; public int Y; }
    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    static extern bool GetClientRect(IntPtr h, out WRECT r);
    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    static extern bool ClientToScreen(IntPtr h, ref WPOINT p);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct WRECT { public int Left; public int Top; public int Right; public int Bottom; }
    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    static extern bool GetWindowRect(IntPtr h, out WRECT r);
    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);

    // ───────────────────────── maze（全自动定位） ─────────────────────────

    static void Maze(WinMem mem)
    {
        var st = MazeLocator.Locate(mem, out var why, s => Console.WriteLine("  " + s));
        if (st == null) { Console.WriteLine("定位失败：" + why); return; }
        Console.WriteLine();
        Console.Write(MazeLocator.Describe(st));
    }

    // ───────────────────────── mazehunt ─────────────────────────

    /// <summary>
    /// 按 MazeDataMgr 的字段声明顺序找实例：
    ///   ... m_curLevel, m_curType, m_curRow, m_curCol, m_mazeCoin, m_mazeScore,
    ///       NeedJumpUI, m_nextRow, m_nextCol, m_preRow, m_preCol, m_highestMazeScore ...
    /// 特征：连续 12 个 int32，其中 curLevel 与最高分、行/列都在合理范围。
    /// 参数：当前层 curLevel、最高积分 highestScore（都可给 -1 表示不限定）。
    /// </summary>
    static void MazeHunt(WinMem mem, int curLevel, int highest)
    {
        Console.WriteLine($"在 wasm 内存里找迷宫实例（层={curLevel} 最高分={highest}）…");
        int hits = 0;
        var buf = new byte[4 << 20];

        // 从 0x3C480000000 起（wasm 线性内存）
        long start = 0x3C480000000L, end = 0x3C480000000L + (768L << 20);
        long addr = start;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read)) { addr += 0x10000; continue; }

            for (int i = 0; i + 64 <= read; i += 4)
            {
                // 布局：+0x00 curLevel, +0x04 curType, +0x08 curRow, +0x0C curCol,
                //       +0x10 mazeCoin, +0x14 mazeScore, +0x18 needJump, +0x1C nextRow,
                //       +0x20 nextCol, +0x24 preRow, +0x28 preCol, +0x2C highest
                int lvl = BitConverter.ToInt32(buf, i);
                int typ = BitConverter.ToInt32(buf, i + 4);
                int row = BitConverter.ToInt32(buf, i + 8);
                int col = BitConverter.ToInt32(buf, i + 12);
                int coin = BitConverter.ToInt32(buf, i + 16);
                int score = BitConverter.ToInt32(buf, i + 20);
                int nrow = BitConverter.ToInt32(buf, i + 28);
                int ncol = BitConverter.ToInt32(buf, i + 32);
                int prow = BitConverter.ToInt32(buf, i + 36);
                int pcol = BitConverter.ToInt32(buf, i + 40);
                int high = BitConverter.ToInt32(buf, i + 44);

                if (lvl is < 1 or > 20) continue;
                if (curLevel > 0 && lvl != curLevel) continue;
                if (typ is < 0 or > 20) continue;
                if (row is < 0 or > 40 || col is < 0 or > 40) continue;
                if (coin is < 0 or > 100000) continue;
                if (score is < 0 or > 100000) continue;
                if (nrow is < 0 or > 40 || ncol is < 0 or > 40) continue;
                if (prow is < 0 or > 40 || pcol is < 0 or > 40) continue;
                if (high is < 0 or > 100000) continue;
                if (highest >= 0 && high != highest) continue;

                long a = addr + i;
                Console.WriteLine($"\n── 候选 {Hex(a)}  (wasm+0x{a - start:X})");
                Console.WriteLine($"   层={lvl} 类型={typ} 当前格=({row},{col}) 迷宫币={coin} 积分={score}");
                Console.WriteLine($"   下一格=({nrow},{ncol})  上一格=({prow},{pcol})  最高分={high}");
                Console.Write(Preview(buf, Math.Max(0, i - 32), Math.Min(read, i + 96)));
                Console.WriteLine();
                if (++hits >= _max) { Console.WriteLine($"…已达上限 {_max}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 64);
        }
        Console.WriteLine($"命中 {hits} 处");
    }

    // ───────────────────────── types ─────────────────────────

    /// <summary>列出 metadata 里所有类型名（可给子串过滤）。</summary>
    static void Types(string path)
    {
        var m = Il2CppMeta.Load(path, 0);
        Console.WriteLine($"类型 {m.TypeDefinitionsCount} 个：");
        foreach (var n in m.AllTypeNames().Take(_max)) Console.WriteLine("  " + n);
    }

    /// <summary>按子串找类型名。</summary>
    static void FindTypes(string path, string substr)
    {
        var m = Il2CppMeta.Load(path, 0);
        var hits = m.AllTypeNames().Where(n => n.Contains(substr, StringComparison.OrdinalIgnoreCase)).ToList();
        Console.WriteLine($"含 \"{substr}\" 的类型 {hits.Count} 个：");
        foreach (var n in hits.Take(_max)) Console.WriteLine("  " + n);
    }

    // ───────────────────────── metadump ─────────────────────────

    /// <summary>
    /// 把内存里的 IL2CPP metadata 段整块读到本地文件，然后用 Il2CppMeta 解析。
    /// 用法：MemProbe metadump 0xmetadata地址 [字节数] [类名]
    /// </summary>
    static void MetaDump(WinMem mem, long addr, long size, string className)
    {
        // size=0 → 按段表推算总长度
        if (size <= 0)
        {
            var hdr = mem.Read(addr, 200);
            if (hdr == null || hdr.Length < 192) { Console.WriteLine("读不到 metadata 头"); return; }
            // 段表里最后一个有效段（windowsRuntimeTypeNames 附近）推末尾
            long maxEnd = 0;
            for (int i = 8; i + 8 <= 184; i += 8)
            {
                int off = BitConverter.ToInt32(hdr, i);
                int len = BitConverter.ToInt32(hdr, i + 4);
                if (off < 0 || len < 0) continue;
                long end = (long)off + len;
                if (end > maxEnd && end < 128L << 20) maxEnd = end;
            }
            size = (maxEnd + 0x10000) & ~0xFFFFL;
            Console.WriteLine($"按段表推算 metadata 长度 = {size / 1048576.0:N1} MB");
        }

        var all = new byte[size];
        long got = 0;
        const int chunk = 4 << 20;
        var buf = new byte[chunk];
        while (got < size)
        {
            int want = (int)Math.Min(chunk, size - got);
            if (!mem.TryReadInto(addr + got, buf, want, out int read) || read <= 0)
            {
                Console.WriteLine($"  在 +0x{got:X} 处读取失败（区域边界），已停");
                break;
            }
            Buffer.BlockCopy(buf, 0, all, (int)got, read);
            got += read;
        }
        var path = System.IO.Path.Combine(AppContext.BaseDirectory, "metadata-mem.dat");
        System.IO.File.WriteAllBytes(path, all.AsSpan(0, (int)got).ToArray());
        Console.WriteLine($"已保存 {got / 1048576.0:N1} MB → {path}");

        var m = Il2CppMeta.Load(path, 0);
        Console.WriteLine($"解析：version={m.Version}  类型 {m.TypeDefinitionsCount} 个  字段 {m.FieldsCount} 个");

        if (string.IsNullOrEmpty(className)) return;
        var hits = m.FindType(className);
        Console.WriteLine($"\n查类 \"{className}\" → 命中 {hits.Count} 个");
        foreach (var idx in hits)
        {
            Console.WriteLine($"\n=== 类型 #{idx} ===");
            foreach (var f in m.FieldsOfType(idx)) Console.WriteLine($"  字段[{f.DeclOrder,2}] {f.Name}");
            var ms = m.MethodsOfType(idx);
            if (ms.Count > 0) Console.WriteLine("  方法：" + string.Join(", ", ms.Take(30)));
        }
    }

    // ───────────────────────── metamem ─────────────────────────

    /// <summary>在进程内存里找 IL2CPP metadata 魔数（AF 1B B1 FA + version 20~40）。</summary>
    static void MetaMem(WinMem mem)
    {
        var magic = new byte[] { 0xAF, 0x1B, 0xB1, 0xFA };
        Console.WriteLine("在内存里找 IL2CPP metadata 头…");
        int hits = 0;
        mem.Scan(chunk: 4 << 20, onChunk: (baseAddr, buf, len) =>
        {
            int idx = 0;
            while (idx <= len - 8)
            {
                int at = buf.AsSpan(idx, Math.Min(len, buf.Length) - idx).IndexOf(magic);
                if (at < 0) break;
                int abs = idx + at;
                if (abs + 8 <= len && abs + 4 <= buf.Length - 4)
                {
                    int ver = BitConverter.ToInt32(buf, abs + 4);
                    if (ver is >= 20 and <= 40)
                    {
                        long addr = baseAddr + abs;
                        // 读一下段表前几项做校验
                        var hdr = mem.Read(addr, 192);
                        if (hdr != null && hdr.Length >= 168)
                        {
                            int strLitOff = BitConverter.ToInt32(hdr, 8);
                            int typeOff = BitConverter.ToInt32(hdr, 160);
                            int typeBytes = BitConverter.ToInt32(hdr, 164);
                            if (typeBytes <= 0 || typeBytes > 64 << 20) { idx = abs + 4; continue; }
                            Console.WriteLine($"  {Hex(addr)}  version={ver}  stringsOff={strLitOff}  typesOff=0x{typeOff:X} typesBytes=0x{typeBytes:X} ({typeBytes / 0x5C} 个类型)");
                            hits++;
                        }
                    }
                }
                idx = abs + 4;
                if (hits >= _max) return true;
            }
            return false;
        }, privateOnly: !_withModules);
        Console.WriteLine($"命中 {hits} 处");
    }

    // ───────────────────────── unpack ─────────────────────────

    static void WxList(string path)
    {
        var list = Wxapkg.ReadIndex(path);
        Console.WriteLine($"{path}");
        Console.WriteLine($"共 {list.Count} 个文件：");
        foreach (var e in list.OrderByDescending(x => x.Size).Take(40))
            Console.WriteLine($"  {e.Size,12:N0}  {e.Name}");
    }

    static void Unpack(string path, string outDir)
    {
        outDir ??= Path.Combine(Path.GetDirectoryName(path) ?? ".", Path.GetFileNameWithoutExtension(path) + "-out");
        int n = Wxapkg.Extract(path, outDir);
        Console.WriteLine($"解出 {n} 个文件 → {outDir}");
    }

    // ───────────────────────── meta ─────────────────────────

    /// <summary>meta 文件 0x偏移 [类名]  —— 解析 IL2CPP metadata，列类型或某类型的字段。</summary>
    static void Meta(List<string> pos)
    {
        if (pos.Count < 3) { Console.WriteLine("用法：MemProbe meta 文件路径 0xmetadata偏移 [类名]"); return; }
        var path = pos[1];
        long off = Addr(pos[2]);
        var m = Il2CppMeta.Load(path, off);
        Console.WriteLine($"IL2CPP metadata  version={m.Version}");
        Console.WriteLine($"类型定义 {m.TypeDefinitionsCount} 个 / 0x{m.TypeDefinitionsBytes:X} 字节");
        Console.WriteLine($"字段 {m.FieldsCount} 个 / 0x{m.FieldsBytes:X} 字节");
        Console.WriteLine($"方法 0x{m.MethodsBytes:X} 字节   字符串 0x{m.StringsBytes:X} 字节");

        if (pos.Count < 4) return;
        var wanted = pos[3];
        var hits = m.FindType(wanted);
        Console.WriteLine($"\n查类 \"{wanted}\" → 命中 {hits.Count} 个");
        foreach (var idx in hits)
        {
            Console.WriteLine($"\n=== 类型 #{idx} ===");
            foreach (var f in m.FieldsOfType(idx)) Console.WriteLine($"  字段[{f.DeclOrder,2}] {f.Name}");
            var ms = m.MethodsOfType(idx);
            if (ms.Count > 0) Console.WriteLine("  方法：" + string.Join(", ", ms.Take(40)));
        }
    }

    // ───────────────────────── hunt ─────────────────────────

    /// <summary>
    /// 从候选根对象出发，按「指针 + 偏移」逐层下行，打印每一层读到的值。
    /// 用法：MemProbe hunt 0x根指针 0x偏移1 0x偏移2 ...
    /// 用来把 il2cpp 对象链（根 → 管理器 → 列表 → 元素）一路读到底。
    /// </summary>
    static void Hunt(WinMem mem, long root, int[] offsets)
    {
        var path = new List<(string Where, long Addr, long Value)>();
        long cur = root;
        Console.WriteLine($"根 {Hex(cur)}");
        var head = mem.Read(cur, 32);
        if (head == null) { Console.WriteLine("根读不出来"); return; }
        Console.Write(Preview(head, 0, head.Length));

        foreach (var off in offsets)
        {
            var b8 = mem.Read(cur + off, 8);
            if (b8 == null) { Console.WriteLine($"{Hex(cur + off)} 读不出来，停下"); break; }
            long v = BitConverter.ToInt64(b8, 0);
            Console.WriteLine($"  [{Hex(cur)} + 0x{off:X}] = {Hex(v)}   (int32={BitConverter.ToInt32(b8, 0)})");
            if (v < 0x10000 || v > 0x7FFFFFFF0000L) { Console.WriteLine("  ↑ 不像指针，停下"); break; }
            cur = v;
            var nb = mem.Read(cur, 48);
            if (nb == null) { Console.WriteLine($"  {Hex(cur)} 读不出来，停下"); break; }
            Console.Write(Preview(nb, 0, nb.Length));
        }
    }

    // ───────────────────────── cells / diff ─────────────────────────

    /// <summary>
    /// 找「一组连续小整数记录」：适合找格子表/节点表。
    /// 判据：同一区域里连续 N 条结构体，每条都含 row/col 量级的小整数和 1~999 的事件 id。
    /// 这里只是把候选区域里形如「int 序列」的片段列出来，供人工判断。
    /// </summary>
    static void Cells(WinMem mem)
    {
        Console.WriteLine("扫描形如「(小整数, 小整数, 事件id, 标志)」的连续记录组…");
        int groups = 0;
        var buf = new byte[1 << 20];
        foreach (var m in mem.Regions())
        {
            if (!WinMem.IsReadable(m) || m.Type != 0x20000) continue;
            long b = m.BaseAddress.ToInt64();
            long size = (long)m.RegionSize;
            if (size < 256) continue;
            for (long off = 0; off + buf.Length < size; off += buf.Length)
            {
                if (!mem.TryReadInto(b + off, buf, Math.Min(buf.Length, (int)(size - off)), out int read)) break;
                int best = 0, bestAt = -1;
                for (int i = 0; i + 32 <= read; i += 4)
                {
                    // 起手：3 个连续小正整数（0..64），后面跟 1..999
                    int a = BitConverter.ToInt32(buf, i), bb = BitConverter.ToInt32(buf, i + 4);
                    int c = BitConverter.ToInt32(buf, i + 8), d = BitConverter.ToInt32(buf, i + 12);
                    if (a is < 0 or > 64 || bb is < 0 or > 64) continue;
                    if (c is < 0 or > 40 || d is < 1 or > 9999) continue;
                    best = i; bestAt = i;
                    break;
                }
                if (bestAt < 0) continue;
                groups++;
                Console.WriteLine($"── 区域 {Hex(b + off)} 命中 +0x{bestAt:X}");
                Console.Write(Preview(buf, Math.Max(0, bestAt - 16), Math.Min(read, bestAt + 96)));
                Console.WriteLine();
                if (groups >= _max) { Console.WriteLine($"…已达上限 {_max}"); return; }
            }
        }
        Console.WriteLine($"共 {groups} 组");
    }

    /// <summary>把一块内存按 4 字节解析成 int 列表，便于前后对比。</summary>
    static void Diff(WinMem mem, long addr, string[] extra)
    {
        int len = extra.Length > 0 && int.TryParse(extra[0], out var n) ? n : 256;
        var buf = mem.Read(addr, len);
        if (buf == null) { Console.WriteLine($"{Hex(addr)} 读不出来"); return; }
        for (int i = 0; i + 4 <= buf.Length; i += 4)
            Console.WriteLine($"  {Hex(addr + i)}  int={BitConverter.ToInt32(buf, i),-12} u32=0x{BitConverter.ToUInt32(buf, i):X8} f={BitConverter.ToSingle(buf, i),12:0.####}");
    }

    // ───────────────────────── multi ─────────────────────────

    /// <summary>在同一个 256 字节窗口里同时出现多个关键词 —— 用来找「真实的数据结构」而不是散落的符号。</summary>
    static void Multi(WinMem mem, string[] keys)
    {
        if (keys.Length < 2) { Console.WriteLine("至少给两个关键词：MemProbe multi 词1 词2 ..."); return; }
        Console.WriteLine($"找同一窗口内同时含：{string.Join(" + ", keys)}");
        var needles = keys.Select(Encoding.UTF8.GetBytes).ToArray();
        int hits = 0;
        const int window = 256;

        mem.Scan(chunk: 4 << 20, onChunk: (baseAddr, buf, len) =>
        {
            for (int i = 0; i <= len - needles[0].Length; i++)
            {
                if (buf[i] != needles[0][0]) continue;
                int at = buf.AsSpan(i, len - i).IndexOf(needles[0]);
                if (at < 0) break;
                int pos0 = i + at;
                i = pos0;                     // 跳到这一处
                long addr = baseAddr + pos0;
                if (InRange(addr))
                {
                    int s = Math.Max(0, pos0 - window), e = Math.Min(len, pos0 + window);
                    bool all = true;
                    foreach (var n in needles.Skip(1))
                        if (buf.AsSpan(s, e - s).IndexOf(n) < 0) { all = false; break; }
                    if (all)
                    {
                        Console.WriteLine($"── {Hex(addr)}");
                        Console.Write(Preview(buf, s, e));
                        Console.WriteLine();
                        if (++hits >= _max) return true;
                    }
                }
                i = pos0 + needles[0].Length - 1;
            }
            return false;
        }, privateOnly: !_withModules);
        Console.WriteLine($"命中 {hits} 处");
    }

    // ───────────────────────── nearby ─────────────────────────

    /// <summary>在 [from,to) 里找某个 int32（按 4 字节对齐），带范围限制，用于 WASM 线性内存。</summary>
    static void Nearby(WinMem mem, long value, int unused, long from, long to)
    {
        var needle = BitConverter.GetBytes(value);
        Console.WriteLine($"在 {Hex(from)}..{Hex(to)} 内找 int32 = {value}");
        int hits = 0;
        var buf = new byte[4 << 20];
        long addr = from;
        while (addr < to)
        {
            int want = (int)Math.Min(buf.Length, to - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read)) { addr += 0x10000; continue; }
            for (int i = 0; i + 4 <= read; i += 4)
            {
                if (buf[i] != needle[0] || buf[i + 1] != needle[1] || buf[i + 2] != needle[2] || buf[i + 3] != needle[3]) continue;
                long a = addr + i;
                Console.WriteLine($"  {Hex(a)}   (基址+0x{a - from:X})");
                if (++hits >= _max) { Console.WriteLine($"…已达上限 {_max}"); return; }
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x1000);
        }
        Console.WriteLine($"命中 {hits} 处");
    }

    // ───────────────────────── region ─────────────────────────

    static void Region(WinMem mem, long addr)
    {
        var list = mem.Regions().ToList();
        foreach (var m in list)
        {
            long b = m.BaseAddress.ToInt64();
            long e = b + (long)m.RegionSize;
            if (addr < b || addr >= e) continue;
            Console.WriteLine($"地址 {Hex(addr)} 属于区域 {Hex(b)}");
            Console.WriteLine($"  大小 {m.RegionSize / 1048576.0:N2} MB   State=0x{m.State:X} Protect=0x{m.Protect:X} Type=0x{m.Type:X}");
            Console.WriteLine($"  区域内偏移 +0x{addr - b:X}  剩余 {e - addr:N0} 字节");
            var head = mem.Read(b, 64);
            if (head != null) Console.WriteLine("  开头：" + BitConverter.ToString(head).Replace("-", " "));
            return;
        }
        Console.WriteLine($"{Hex(addr)} 不在任何区域里");
    }

    /// <summary>列出最大的可读 MEM_PRIVATE 区域（WASM 线性内存通常是单个 GB 级大块）。</summary>
    static void BigRegions(WinMem mem)
    {
        var rows = mem.Regions().Where(m => WinMem.IsReadable(m))
            .Select(m => (Base: m.BaseAddress.ToInt64(), Size: (long)m.RegionSize, m.Type, m.Protect))
            .OrderByDescending(r => r.Size).Take(20).ToList();
        Console.WriteLine($"{"基址",-18}{"大小",-14}{"Type",-12}Protect");
        foreach (var r in rows)
            Console.WriteLine($"{Hex(r.Base),-18}{r.Size / 1048576.0,-14:N1}{"0x" + r.Type.ToString("X"),-12}0x{r.Protect:X}");
    }

    // ───────────────────────── json ─────────────────────────

    static void Json(WinMem mem)
    {
        var all = JsonExtract.All(mem, _max);
        Console.WriteLine($"找到 {all.Count} 段含 role_name 的 JSON：");
        int n = 0;
        foreach (var (addr, json) in all)
        {
            n++;
            Console.WriteLine();
            Console.WriteLine($"── #{n}  {Hex(addr)}  长度 {json.Length}");
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                var pretty = System.Text.Json.JsonSerializer.Serialize(doc.RootElement,
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                Console.WriteLine(pretty);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"(解析失败 {ex.Message}，原文如下)");
                Console.WriteLine(json);
            }
        }
    }

    // ───────────────────────── procs ─────────────────────────

    /// <summary>列出游戏渲染进程候选：WeChatAppEx renderer，按工作集排序。</summary>
    static void Procs()
    {
        Console.WriteLine($"{"PID",-8}{"PPID",-8}{"Type",-6}{"WS(MB)",-10}{"AppId",-26}");
        var rows = new List<(int Pid, int PPid, string Kind, long Ws, string AppId)>();
        using var searcher = new System.Management.ManagementObjectSearcher(
            "SELECT ProcessId, ParentProcessId, CommandLine FROM Win32_Process WHERE Name='WeChatAppEx.exe'");
        foreach (var mo in searcher.Get())
        {
            var cmd = mo["CommandLine"] as string ?? "";
            if (!cmd.Contains("--type=renderer")) continue;
            int pid = Convert.ToInt32(mo["ProcessId"]);
            int ppid = Convert.ToInt32(mo["ParentProcessId"]);
            long ws = 0;
            try { using var p = Process.GetProcessById(pid); ws = p.WorkingSet64; } catch { }
            rows.Add((pid, ppid, Between(cmd, "--wmpf-render-type=", " "), ws, Between(cmd, "--wmpf-appid=", " ")));
        }
        foreach (var r in rows.OrderByDescending(r => r.Ws))
            Console.WriteLine($"{r.Pid,-8}{r.PPid,-8}{r.Kind,-6}{r.Ws / 1048576.0,-10:N1}{r.AppId,-26}");
    }

    static string Between(string s, string a, string b)
    {
        int i = s.IndexOf(a, StringComparison.Ordinal);
        if (i < 0) return "";
        i += a.Length;
        int j = s.IndexOf(b, i, StringComparison.Ordinal);
        return j < 0 ? s[i..].Trim('"') : s[i..j].Trim('"');
    }

    // ───────────────────────── near ─────────────────────────

    static void Near(WinMem mem, long addr, int radius)
    {
        long start = (addr - radius) & ~0x3L;
        var buf = mem.Read(start, radius * 2);
        if (buf == null) { Console.WriteLine($"{Hex(start)} 读不出来"); return; }
        for (int i = 0; i + 4 <= buf.Length; i += 4)
        {
            int v = BitConverter.ToInt32(buf, i);
            long a = start + i;
            string mark = a == addr ? "  <== 目标" : "";
            if (v == 0) continue;
            Console.WriteLine($"  {Hex(a)}  int={v,-12} 0x{(uint)v:X8}  f={(v is > 0 and < 100000000 ? BitConverter.ToSingle(buf, i) : 0):0.###}{mark}");
        }
    }
}
