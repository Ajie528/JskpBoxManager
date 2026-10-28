using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// 从游戏渲染进程（沙箱里的 WeChatAppEx）读角色名和攻击力，只读不写。
/// 角色：界面 JSON 文本里的 role_name / role_id / role_level。
/// 攻击力：用 role_id 当锚点找「当前角色」属性块（D 型 +0xB8；找不到再用 C 型 +0x28 取最新时间戳）。
/// 不扫历史战斗记录（A 型），那些会残留旧攻击力。
/// </summary>
public static class RoleReader
{
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ = 0x0010;
    /// <summary>C 型块里 +0x64 的特征常量大致落在这个区间（游戏版本会变，不能写死某一个值）。</summary>
    const uint AttackMarkerMin = 0x02000000;
    const uint AttackMarkerMax = 0x0FFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    struct MBI
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
    [DllImport("kernel32.dll", SetLastError = true)] static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, uint len);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("psapi.dll", SetLastError = true)] static extern bool QueryWorkingSet(IntPtr h, IntPtr buf, int size);

    public sealed record RoleText(int Pid, long Addr, string Text);
    public sealed record AttackHit(int Pid, int Value, long Addr, long Heap, int Copies);

    /// <summary>本沙箱里「向僵尸开炮」的渲染进程：命令行带游戏 appid 的优先，其次是游戏窗口进程树上的渲染进程（按内存从大到小）。</summary>
    public static List<int> GameRenderers(string box)
    {
        var view = new BoxView(box);
        var cmds = ProcessUtil.CommandLines(view.Pids);
        var hwnd = view.GameHwnd;
        int gamePid = hwnd != IntPtr.Zero ? Win32.PidOf(hwnd) : 0;
        var parents = ProcessUtil.ParentPids(view.Pids);
        var game = new List<int>();
        var rest = new List<(int Pid, long Ws)>();
        foreach (var (pid, (name, cmd)) in cmds)
        {
            if (!name.Equals("WeChatAppEx.exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (!cmd.Contains("--type=renderer")) continue;
            if (cmd.Contains(AppInfo.GameAppId)) { game.Add(pid); continue; }
            parents.TryGetValue(pid, out var parent);
            if (gamePid > 0 && (pid == gamePid || parent == gamePid))
            {
                long ws = 0;
                try { using var p = System.Diagnostics.Process.GetProcessById(pid); ws = p.WorkingSet64; } catch { }
                rest.Add((pid, ws));
            }
        }
        var list = new List<int>(game);
        list.AddRange(rest.OrderByDescending(r => r.Ws).Select(r => r.Pid).Where(p => !list.Contains(p)));
        if (gamePid > 0 && !list.Contains(gamePid)) list.Add(gamePid);
        return list;
    }

    public static string Field(string text, string key)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var m = Regex.Match(text, "\"" + Regex.Escape(key) + "\"\\s*:\\s*\"([^\"\\\\]{0,80})\"");
        if (m.Success) return m.Groups[1].Value;
        m = Regex.Match(text, "\"" + Regex.Escape(key) + "\"\\s*:\\s*(\\d{1,12})");
        return m.Success ? m.Groups[1].Value : "";
    }

    /// <summary>按驻留页顺序扫，连续页合并读（每次最多 maxRun 页），避免长时间占住游戏进程。</summary>
    static void ScanResident(IntPtr h, int cap, int maxRun, Func<long, byte[], int, bool> onChunk)
    {
        int bytes = 8 + cap * 8;
        IntPtr mem = Marshal.AllocHGlobal(bytes);
        try
        {
            if (!QueryWorkingSet(h, mem, bytes)) return;
            long count = Marshal.ReadInt64(mem);
            var pages = new List<long>((int)Math.Min(count, cap));
            for (long i = 0; i < count && i < cap; i++)
                pages.Add((long)(((ulong)Marshal.ReadInt64(mem, 8 + (int)i * 8) >> 12) << 12));
            pages.Sort();
            int idx = 0;
            var buf = new byte[maxRun * 4096];
            while (idx < pages.Count)
            {
                long page = pages[idx];
                int run = 1;
                while (idx + run < pages.Count && pages[idx + run] == page + run * 4096L && run < maxRun) run++;
                if (ReadProcessMemory(h, new IntPtr(page), buf, run * 4096, out int read) && read > 0)
                    if (onChunk(page, buf, read)) return;
                idx += run;
            }
        }
        finally { Marshal.FreeHGlobal(mem); }
    }

    static int Find(byte[] buf, int len, byte[] needle)
    {
        int n = needle.Length, last = len - n;
        if (n <= 0 || last < 0) return -1;
        return buf.AsSpan(0, len).IndexOf(needle);
    }

    static long AllocBase(IntPtr h, long addr) =>
        VirtualQueryEx(h, new IntPtr(addr), out var mbi, (uint)Marshal.SizeOf<MBI>()) != 0 ? mbi.AllocationBase.ToInt64() : 0;

    /// <summary>找含 role_name 的角色信息文本。</summary>
    public static RoleText ProbeRole(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var u8 = Encoding.UTF8.GetBytes("role_name\":\"");
            var u16 = Encoding.Unicode.GetBytes("role_name\":\"");
            RoleText hit = null;
            ScanResident(h, 700000, 32, (page, buf, read) =>
            {
                if (read < u16.Length) return false;
                int i8 = Find(buf, read, u8), i16 = Find(buf, read, u16);
                bool is16 = i16 >= 0 && (i8 < 0 || i16 <= i8);
                int pick = is16 ? i16 : i8;
                if (pick < 0) return false;
                int nlen = is16 ? u16.Length : u8.Length;
                int start = Math.Max(0, pick - (is16 ? 180 : 100));
                int end = Math.Min(read, pick + nlen + (is16 ? 420 : 260));
                string text;
                if (is16)
                {
                    if (((pick - start) & 1) != 0) start++;
                    int bl = end - start;
                    if ((bl & 1) != 0) bl--;
                    text = bl > 0 ? Encoding.Unicode.GetString(buf, start, bl) : "";
                }
                else text = Encoding.UTF8.GetString(buf, start, end - start);
                hit = new RoleText(pid, page + pick, text);
                return true;
            });
            return hit;
        }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// 按角色 ID 定位当前攻击力（换装备立刻变的那一格）。
    /// D 型：角色 ID 后 +0x1C/+0x20=等级、+0xB4=小正整数、+0xB8=攻击 —— 通常只有 1 份，优先用。
    ///      （+0xB4 实测可为 1 或 2，不能写死 ==1，否则部分号读不到。）
    /// C 型：+0x1C=小正整数、+0x20=等级、+0x28=攻击、+0x64≈特征常量 —— 可能有旧副本，取 +0x4C 时间戳最新的。
    /// 旧的 A 型（战斗/历史记录，+0x48）会残留旧攻击力，不再用来取当前值。
    /// </summary>
    public static AttackHit ProbeAttack(int pid, int level, ulong roleId)
    {
        if (level < 1 || level > 1000 || roleId == 0) return null;
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            AttackHit dHit = null;
            AttackHit cHit = null;
            int cGen = 0;
            var needle = BitConverter.GetBytes(roleId);
            ScanRegions(h, (baseAddr, buf, read) =>
            {
                for (int i = 0; i + 0xBC <= read; i += 4)
                {
                    if (buf[i] != needle[0] || buf[i + 7] != needle[7]) continue;
                    bool eq = true;
                    for (int q = 1; q < 7; q++) if (buf[i + q] != needle[q]) { eq = false; break; }
                    if (!eq) continue;

                    int At(int off) => BitConverter.ToInt32(buf, i + off);
                    int lv1C = At(0x1C), lv20 = At(0x20);
                    int flagB4 = At(0xB4);

                    // D：唯一的「当前角色」块（+0x1C/+0x20 同时等于等级即可唯一定位）
                    if (lv1C == level && lv20 == level && flagB4 is >= 1 and <= 255)
                    {
                        int atk = At(0xB8);
                        if (atk is >= 100 and <= 5000000)
                        {
                            long addr = baseAddr + i + 0xB8;
                            dHit = new AttackHit(pid, atk, addr, AllocBase(h, addr), 1);
                            return true; // 找到 D 即可停
                        }
                    }

                    // C：可能有一份旧的；用 +0x4C 时间戳挑最新
                    // +0x1C 和 +0x64 随角色/版本会变（见过 1 / 2，以及 0x034020C0 / 0x03464FC0），只要求落在合理区间
                    uint marker = unchecked((uint)At(0x64));
                    if (lv1C is >= 1 and <= 255 && lv20 == level && marker is >= AttackMarkerMin and <= AttackMarkerMax)
                    {
                        int atk = At(0x28);
                        if (atk is >= 100 and <= 5000000)
                        {
                            int gen = At(0x4C);
                            if (gen > cGen)
                            {
                                cGen = gen;
                                long addr = baseAddr + i + 0x28;
                                cHit = new AttackHit(pid, atk, addr, AllocBase(h, addr), 1);
                            }
                        }
                    }
                }
                return false;
            });
            return dHit ?? cHit;
        }
        finally { CloseHandle(h); }
    }

    /// <summary>按 VirtualQueryEx 扫整个可读私有内存（角色属性块不一定全在工作集里）。</summary>
    static void ScanRegions(IntPtr h, Func<long, byte[], int, bool> onChunk)
    {
        long addr = 0;
        var buf = new byte[4 << 20];
        while (addr < 0x7FFFFFFF0000L)
        {
            if (VirtualQueryEx(h, new IntPtr(addr), out var mbi, (uint)Marshal.SizeOf<MBI>()) == 0) break;
            long b = mbi.BaseAddress.ToInt64(), size = mbi.RegionSize.ToInt64();
            bool ok = mbi.State == 0x1000 && (mbi.Protect & 0x101) == 0 && (mbi.Protect & 0xEE) != 0;
            if (ok)
            {
                for (long off = 0; off < size; )
                {
                    int want = (int)Math.Min(buf.Length, size - off);
                    if (!ReadProcessMemory(h, new IntPtr(b + off), buf, want, out int read) || read <= 0) break;
                    if (onChunk(b + off, buf, read)) return;
                    // 块末尾可能截断一条记录，回退 0x100 再读下一段
                    int step = read < want ? read : Math.Max(1, read - 0x100);
                    off += step;
                    if (read < want) break;
                }
            }
            addr = b + size;
            if (size <= 0) break;
        }
    }
}
