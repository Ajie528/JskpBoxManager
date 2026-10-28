using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// 从游戏渲染进程（沙箱里的 WeChatAppEx）的驻留内存读角色名和攻击力，只读不写。
/// 读法与旧版 tools\game-memory\read-role-attack.ps1 相同：
///   角色：界面上已显示的角色信息以 JSON 文本 role_name":"… 留在内存里；
///   攻击力：前面 0x2C 是本号等级，后面 0x0C、0x14 是固定值 0x034020C0；
///           改过攻击后旧值会残留且份数更多，取写入时间最新的一份（时间在 -0xC4 或 -0x64）。
/// </summary>
public static class RoleReader
{
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ = 0x0010;
    const int AttackMarker = 0x034020C0;

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

    public static AttackHit ProbeAttack(int pid, int level)
    {
        if (level < 1 || level > 1000) return null;
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var tally = new Dictionary<int, int>();
            var where = new Dictionary<int, long>();
            var found = new List<(int Gen, int Atk, long Addr)>();
            ScanResident(h, 900000, 8, (page, buf, read) =>
            {
                if (read < 0x100) return false;
                for (int i = 0xD0; i <= read - 24; i += 4)
                {
                    int atk = BitConverter.ToInt32(buf, i);
                    if (atk < 100 || atk > 5000000) continue;
                    if (BitConverter.ToInt32(buf, i + 12) != AttackMarker) continue;
                    if (BitConverter.ToInt32(buf, i + 20) != AttackMarker) continue;
                    if (BitConverter.ToInt32(buf, i - 44) != level) continue;
                    long at = page + i;
                    if (!tally.ContainsKey(atk)) { tally[atk] = 0; where[atk] = at; }
                    tally[atk]++;
                    if (at < where[atk]) where[atk] = at;
                    int rear = BitConverter.ToInt32(buf, i - 0xC4);
                    int front = BitConverter.ToInt32(buf, i - 0x64);
                    int gen = rear is > 1600000000 and < 2100000000 ? rear : front is > 1600000000 and < 2100000000 ? front : 0;
                    if (gen != 0) found.Add((gen, atk, at));
                }
                return false;
            });

            int chosen = 0, chosenGen = 0, chosenNear = 0;
            long chosenAddr = 0;
            foreach (var g in found.GroupBy(f => f.Atk))
            {
                int maxGen = g.Max(f => f.Gen);
                var near = g.Where(f => f.Gen >= maxGen - 3000).ToList();
                if (near.Count < 3) continue;
                if (maxGen > chosenGen || (maxGen == chosenGen && near.Count > chosenNear))
                {
                    chosen = g.Key;
                    chosenGen = maxGen;
                    chosenNear = near.Count;
                    chosenAddr = near.Min(f => f.Addr);
                }
            }
            if (chosen <= 0 && tally.Count > 0)
            {
                var ranked = tally.OrderByDescending(kv => kv.Value).ToList();
                int second = ranked.Count > 1 ? ranked[1].Value : 0;
                if (ranked[0].Value >= 8 && ranked[0].Value >= second * 5)
                {
                    chosen = ranked[0].Key;
                    chosenNear = ranked[0].Value;
                    chosenAddr = where[chosen];
                }
            }
            if (chosen <= 0 || chosenAddr <= 0) return null;
            long heap = AllocBase(h, chosenAddr);
            if (heap <= 0 || chosenAddr <= heap) return null;
            return new AttackHit(pid, chosen, chosenAddr, heap, chosenNear);
        }
        finally { CloseHandle(h); }
    }
}
