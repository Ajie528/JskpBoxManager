using System.Text;

namespace MemProbe;

/// <summary>
/// 迷宫（雾境迷宫）自动定位器 —— 不依赖任何硬编码地址或魔法数值。
///
/// 定位思路（每一步都只依赖结构特征，重启后依然成立）：
///   1. 动态找 wasm 线性内存（最大的 MEM_PRIVATE 可读区域，768MB 那块的起点每次都会变）
///   2. 在 wasm 内存里扫「格子列表」：List&lt;CSMessMapData&gt;
///        要求 _size ∈ [8,80]，_items 是合法 wasm 偏移，且每个元素都是
///        类型 ∈ 1..5、事件 id ∈ 0..99999、row 单调不减 —— 这套组合几乎不可能误命中
///   3. 反查引用：在内存里找值为「该 List 偏移」的 4 字节，命中位置减去 +0x58
///        就是 MazeDataMgr 的基址；再用「当前层 1..20、迷宫币/积分合理」验证一遍
///   4. 从基址读出当前层、币、积分、最高分、完成数，以及当前层的全部格子
///
/// 全程只读：ReadProcessMemory，不写目标进程。
/// </summary>
public static class MazeLocator
{
    // MazeDataMgr 里格子列表字段的偏移（IL2CPP 元数据声明的固定顺序）
    const int OBJ_LIST_OFF = 0x58;

    // CSMessMapData 内部字段偏移（实测每格 40 字节）
    const int CELL_TYPE_OFF = 0x08;    // 类型 = 行内第几列（1-based）
    const int CELL_EVENT_OFF = 0x0C;   // 事件 id
    const int CELL_ROW_OFF = 0x10;     // 行号
    const int CELL_COL_OFF = 0x14;     // 美术/样式 id（不是位置！同行可重复）
    const int CELL_FLAG_OFF = 0x18;    // 标志 0/3

    /// <summary>
    /// (类型, 事件id) → 界面名称。已实测确认的几组。
    /// 用「类型+事件」做键，因为同一个事件 id 在不同类型下界面不同
    /// （事件0/类型1=商店，事件0/类型2=本层怪物）。
    /// </summary>
    static readonly Dictionary<(int Type, int Event), string> UiNames = new()
    {
        [(1, 0)] = "商店",
        [(2, 1000)] = "安全区",
        [(2, 0)] = "本层怪物",
        [(3, 1090)] = "随机事件",
    };

    /// <summary>查界面名；没确认过的返回「事件xxxx(未确认)」。</summary>
    public static string UiNameOf(int type, int eventId) =>
        UiNames.TryGetValue((type, eventId), out var n) ? n : $"事件{eventId}(未确认)";

    public sealed record Cell(int Index, int Type, int EventId, int Row, int Col, int Flag)
    {
        /// <summary>
        /// 选项序号（1 = 最左）。
        /// 由「该格在同一 row 内、按列表原始顺序排第几」决定。
        /// 实测：点左箭头 → CurSelectCol=1，弹出第 1 个格子的界面；点右箭头 → 2。
        /// </summary>
        public int OptionNo { get; init; }
    }

    public sealed record State(
        long WBase, long WSize, long Obj,
        int CurLevel, int PreLevel, int Coin, int Score, int Highest, int FinCnt,
        int CurRow, int CurCol, int NextRow, int NextCol,
        int SelRow, int SelCol,
        long ListAddr, List<Cell> Cells)
    {
        /// <summary>
        /// 下一步可选的格子 —— 画面上的黄色箭头目标。
        ///
        /// 实测规则（三次点击验证）：
        ///   从当前列（CurCol）出发，只能走到上一行里
        ///     · 类型 == CurCol      （直行，画面上是「左箭头」）
        ///     · 类型 == CurCol + 1  （右移一列，画面上是「右箭头」）
        ///   其它列走不到，所以 row 有 3 格时箭头只有 2 个。
        /// </summary>
        public List<Cell> Options =>
            Cells.Where(c => c.Row == CurRow + 1 && (c.Type == CurCol || c.Type == CurCol + 1))
                 .OrderBy(c => c.Type)
                 .Select((c, i) => c with { OptionNo = i + 1 })
                 .ToList();

        /// <summary>当前所在行（角色站的那一格）。</summary>
        public List<Cell> HereRow => Cells.Where(c => c.Row == CurRow).OrderBy(c => c.Type).ToList();

        /// <summary>已走过的上一行。</summary>
        public List<Cell> PrevRow => Cells.Where(c => c.Row == CurRow - 1).OrderBy(c => c.Type).ToList();

        /// <summary>
        /// 玩家此刻在界面上选中的是哪一个选项。
        /// 注意：CurSelectCol 存的是「格子类型值」，所以要按 Type 匹配，不是按序号。
        /// 返回 1 = 第 1 个（左），2 = 第 2 个（右），0 = 没选。
        /// </summary>
        public int SelectedOptionNo
        {
            get
            {
                var opts = Options;
                var hit = opts.FirstOrDefault(o => o.Type == SelCol);
                return hit?.OptionNo ?? 0;
            }
        }

        /// <summary>当前选中的格子。</summary>
        public Cell SelectedCell => Options.FirstOrDefault(o => o.Type == SelCol);
    }

    /// <summary>
    /// 找 wasm 线性内存的候选区域。
    /// 不能死认「最大的那一块」—— 有的沙箱里 wasm 内存会被拆成多段，或有更大的缓存区。
    /// 这里返回所有 ≥32MB 的可读区域（大的在前），由调用方逐个尝试。
    /// </summary>
    public static List<(long Base, long Size)> FindWasmCandidates(WinMem mem)
    {
        var list = new List<(long Base, long Size)>();
        foreach (var m in mem.Regions())
        {
            if (!WinMem.IsReadable(m)) continue;
            long size = (long)m.RegionSize;
            if (size < 32L << 20) continue;
            // MEM_PRIVATE 优先（wasm 内存一定是私有匿名映射），但 MEM_MAPPED 也留作后备
            list.Add((m.BaseAddress.ToInt64(), size));
        }
        return list.OrderByDescending(x => x.Size).ToList();
    }

    // ─────────────────────────── 定位 ───────────────────────────

    /// <summary>完整定位；失败时 why 说明卡在哪一步。</summary>
    public static State Locate(WinMem mem, out string why, Action<string> log = null)
    {
        why = "";
        log ??= _ => { };

        var cands = FindWasmCandidates(mem);
        if (cands.Count == 0) { why = "没有可读的大块内存（游戏还没起？）"; return null; }
        log($"大块可读内存 {cands.Count} 个：" + string.Join("，", cands.Take(4).Select(c => $"{Hex(c.Base)}({c.Size / 1048576.0:N0}MB)")));

        foreach (var (wbase, wsize) in cands)
        {
            // ① 找候选格子列表
            var lists = FindCellLists(mem, wbase, wsize, log);
            if (lists.Count == 0) continue;

            // ② 反查引用，得到 MazeDataMgr 基址
            foreach (var (listAddr, size, items) in lists.OrderByDescending(x => x.Size))
            {
                long listOff = listAddr - wbase;
                foreach (long holder in FindRefs(mem, wbase, wsize, (uint)listOff))
                {
                    long obj = holder - OBJ_LIST_OFF;
                    if (obj < wbase) continue;
                    var st = ReadObject(mem, wbase, wsize, obj, listAddr, size);
                    if (st != null) return st;
                }
            }
        }
        why = "没定位到迷宫数据（雾境迷宫界面没打开？）";
        return null;
    }

    /// <summary>扫 wasm 内存找 List&lt;CSMessMapData&gt; 候选。</summary>
    static List<(long Addr, int Size, long Items)> FindCellLists(WinMem mem, long wbase, long wsize, Action<string> log)
    {
        var hits = new List<(long, int, long)>();
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        long scanned = 0;

        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 0x20)
            {
                addr += 0x10000;
                continue;
            }
            scanned += read;

            for (int i = 0; i + 0x20 <= read; i += 4)
            {
                int size = BitConverter.ToInt32(buf, i + 0x0C);
                if (size < 8 || size > 80) continue;          // 绝大多数位置在这里被刷掉

                uint itemsOff = BitConverter.ToUInt32(buf, i + 0x08);
                if (itemsOff < 0x1000 || itemsOff > wsize - 0x100) continue;

                long listAddr = addr + i;
                long itemsAddr = wbase + itemsOff;
                if (LooksLikeCellList(mem, wbase, wsize, itemsAddr, size))
                    hits.Add((listAddr, size, itemsAddr));
            }

            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 0x100);                // 少量重叠，避免跨块截断
        }

        log($"扫过 {scanned / 1048576.0:N0} MB，格子列表候选 {hits.Count} 个");
        if (hits.Count > 1)
            foreach (var h in hits.Take(8))
                log($"  候选 List {Hex(h.Item1)}  size={h.Item2}");
        return hits;
    }

    /// <summary>验证一段内存像不像 CSMessMapData 数组：元素指针有效、类型/事件/row 都合理且 row 单调。</summary>
    static bool LooksLikeCellList(WinMem mem, long wbase, long wsize, long itemsAddr, int size)
    {
        var arr = mem.Read(itemsAddr, 0x20);
        if (arr == null) return false;
        int maxLen = BitConverter.ToInt32(arr, 0x0C);
        if (maxLen < size || maxLen > 4096) return false;

        // 头几个元素必须完全合规；后面允许个别异常但不允许倒退
        int prevRow = int.MinValue;
        int checkedOk = 0;
        for (int k = 0; k < size; k++)
        {
            var p = mem.Read(itemsAddr + 0x10 + k * 4, 4);
            if (p == null) return false;
            uint off = BitConverter.ToUInt32(p, 0);
            if (off < 0x1000 || off > wsize - 0x40) return false;

            var body = mem.Read(wbase + off, 0x20);
            if (body == null) return false;

            int type = BitConverter.ToInt32(body, CELL_TYPE_OFF);
            int ev = BitConverter.ToInt32(body, CELL_EVENT_OFF);
            int row = BitConverter.ToInt32(body, CELL_ROW_OFF);
            int col = BitConverter.ToInt32(body, CELL_COL_OFF);

            if (type is < 1 or > 5) return false;
            if (ev is < 0 or > 99999) return false;
            if (row is < 0 or > 200) return false;
            if (col is < 0 or > 100000) return false;
            if (row < prevRow) return false;      // 按 row 升序排好
            prevRow = row;

            if (++checkedOk >= 6 && k >= size / 2) break;   // 前一半够可信就收
        }
        return checkedOk >= Math.Min(6, size);
    }

    /// <summary>在内存里找值为 value 的 4 字节（wasm32 指针）。</summary>
    static IEnumerable<long> FindRefs(WinMem mem, long wbase, long wsize, uint value)
    {
        var needle = BitConverter.GetBytes(value);
        var buf = new byte[4 << 20];
        long end = wbase + wsize;
        long addr = wbase;
        while (addr < end)
        {
            int want = (int)Math.Min(buf.Length, end - addr);
            if (!mem.TryReadInto(addr, buf, want, out int read) || read < 8)
            {
                addr += 0x10000;
                continue;
            }
            int idx = 0;
            while (idx <= read - 4)
            {
                int at = buf.AsSpan(idx, read - idx).IndexOf(needle);
                if (at < 0) break;
                yield return addr + idx + at;
                idx += at + 4;
            }
            if (read < want) { addr += read; continue; }
            addr += Math.Max(1, read - 4);
        }
    }

    /// <summary>按已知字段布局读一个候选 MazeDataMgr，字段不合理返回 null。</summary>
    static State ReadObject(WinMem mem, long wbase, long wsize, long obj, long listAddr, int listSize)
    {
        var b = mem.Read(obj, OBJ_LIST_OFF + 8);
        if (b == null || b.Length < OBJ_LIST_OFF + 8) return null;

        int I(int off) => BitConverter.ToInt32(b, off);

        int selRow = I(0x00), selCol = I(0x04);
        int preLevel = I(0x08), curLevel = I(0x10);
        int curRow = I(0x18), curCol = I(0x1C);
        int coin = I(0x20), score = I(0x24);
        int nextRow = I(0x2C), nextCol = I(0x30);
        int highest = I(0x3C), finCnt = I(0x44);
        uint listRef = BitConverter.ToUInt32(b, OBJ_LIST_OFF);

        // 校验：列表指针必须真的是我们找到的这个 List
        if (wbase + listRef != listAddr) return null;
        if (curLevel is < 0 or > 20) return null;
        if (coin is < 0 or > 10_000_000) return null;
        if (score is < 0 or > 100_000_000) return null;
        if (highest is < 0 or > 100_000_000) return null;

        var cells = ReadCells(mem, wbase, wsize, listAddr, listSize);
        if (cells.Count == 0) return null;

        return new State(wbase, wsize, obj, curLevel, preLevel, coin, score, highest, finCnt,
                         curRow, curCol, nextRow, nextCol, selRow, selCol, listAddr, cells);
    }

    static List<Cell> ReadCells(WinMem mem, long wbase, long wsize, long listAddr, int size)
    {
        var list = new List<Cell>();
        var head = mem.Read(listAddr, 0x10);
        if (head == null) return list;
        uint itemsOff = BitConverter.ToUInt32(head, 0x08);
        long itemsAddr = wbase + itemsOff;

        for (int k = 0; k < size; k++)
        {
            var p = mem.Read(itemsAddr + 0x10 + k * 4, 4);
            if (p == null) break;
            uint off = BitConverter.ToUInt32(p, 0);
            if (off < 0x1000 || off > wsize - 0x40) continue;
            var body = mem.Read(wbase + off, 0x20);
            if (body == null) continue;
            list.Add(new Cell(k,
                BitConverter.ToInt32(body, CELL_TYPE_OFF),
                BitConverter.ToInt32(body, CELL_EVENT_OFF),
                BitConverter.ToInt32(body, CELL_ROW_OFF),
                BitConverter.ToInt32(body, CELL_COL_OFF),
                BitConverter.ToInt32(body, CELL_FLAG_OFF))
            {
                });
        }
        return list;
    }

    static string Hex(long v) => "0x" + v.ToString("X");

    /// <summary>把定位结果排成人读的文本。</summary>
    public static string Describe(State s)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"wasm 线性内存  {Hex(s.WBase)}  {s.WSize / 1048576.0:N0} MB");
        sb.AppendLine($"MazeDataMgr     {Hex(s.Obj)}   （wasm 内偏移 0x{s.Obj - s.WBase:X}）");
        sb.AppendLine($"格子列表        {Hex(s.ListAddr)}   {s.Cells.Count} 格");
        sb.AppendLine();
        sb.AppendLine($"当前层 {s.CurLevel}   迷宫币 {s.Coin}   积分 {s.Score}   最高分 {s.Highest}   完成 {s.FinCnt}");
        sb.AppendLine($"当前位置 行={s.CurRow} 列={s.CurCol}（列 = 行内第几格）");
        sb.AppendLine($"当前选中 CurSelectRow={s.SelRow} CurSelectCol={s.SelCol}（= 选中格子的类型）");
        sb.AppendLine();

        var opts = s.Options;
        sb.AppendLine($"── 下一步可选格子（画面黄色箭头）共 {opts.Count} 个 ──");
        if (opts.Count == 0)
            sb.AppendLine("   （没有可选项：可能已到顶层、或界面还没刷新）");
        foreach (var c in opts)
        {
            string side = opts.Count == 1 ? "唯一" : c.OptionNo == 1 ? "左  " : c.OptionNo == opts.Count ? "右  " : $"第{c.OptionNo}个";
            string picked = c.Type == s.SelCol ? "  ★当前选中" : "";
            sb.AppendLine($"   [{c.OptionNo}] {side} 列{c.Type}  行{c.Row}  →  【{UiNameOf(c.Type, c.EventId)}】   (类型{c.Type},事件{c.EventId},美术{c.Col}){picked}");
        }
        sb.AppendLine();

        var here = s.HereRow;
        if (here.Count > 0)
        {
            sb.AppendLine($"── 当前所在行 row={s.CurRow} ──");
            foreach (var c in here)
                sb.AppendLine($"   列{c.Type}  【{UiNameOf(c.Type, c.EventId)}】  (事件{c.EventId},美术{c.Col})");
            sb.AppendLine();
        }

        sb.AppendLine("── 全部格子按 row 分组 ──");
        foreach (var g in s.Cells.GroupBy(c => c.Row).OrderBy(g => g.Key))
        {
            string mark = g.Key == s.CurRow + 1 ? "  ← 可选"
                        : g.Key == s.CurRow ? "  ← 当前位置"
                        : g.Key < s.CurRow ? "  ← 已走过" : "";
            var ordered = g.OrderBy(c => c.Type).ToList();
            var parts = ordered.Select(c => $"列{c.Type}:{UiNameOf(c.Type, c.EventId)}");
            sb.AppendLine($"   row={g.Key,-3} " + string.Join("  ", parts) + mark);
        }
        return sb.ToString();
    }
}
