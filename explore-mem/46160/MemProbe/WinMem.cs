using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace MemProbe;

/// <summary>
/// 只读内存访问层：OpenProcess + VirtualQueryEx + ReadProcessMemory。
/// 不写、不注入、不挂线程，纯粹把别的进程的内存读出来。
/// </summary>
public sealed class WinMem : IDisposable
{
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ = 0x0010;

    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_GUARD = 0x100;
    const uint PAGE_NOACCESS = 0x01;

    [StructLayout(LayoutKind.Sequential)]
    public struct MBI
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ModuleEntry
    {
        public IntPtr Base;
        public ulong Size;
        public string Path;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern ulong VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    static extern bool IsWow64Process(IntPtr h, out bool wow64);

    public IntPtr Handle { get; }
    public int Pid { get; }
    public bool Is64Bit { get; }

    WinMem(IntPtr h, int pid, bool is64)
    {
        Handle = h;
        Pid = pid;
        Is64Bit = is64;
    }

    public static WinMem Open(int pid)
    {
        var h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero)
            throw new InvalidOperationException($"OpenProcess({pid}) 失败，Win32 错误 {Marshal.GetLastWin32Error()}");
        IsWow64Process(h, out bool wow64);
        return new WinMem(h, pid, !wow64);
    }

    public void Dispose() => CloseHandle(Handle);

    public byte[] Read(long addr, int size)
    {
        var buf = new byte[size];
        if (!ReadProcessMemory(Handle, new IntPtr(addr), buf, new IntPtr(size), out var read) || read.ToInt64() <= 0)
            return null;
        long n = read.ToInt64();
        return n == size ? buf : buf[..(int)n];
    }

    public bool TryReadInto(long addr, byte[] buf, int size, out int read)
    {
        read = 0;
        if (!ReadProcessMemory(Handle, new IntPtr(addr), buf, new IntPtr(size), out var got)) return false;
        read = (int)got.ToInt64();
        return read > 0;
    }

    public bool Query(long addr, out MBI mbi) =>
        VirtualQueryEx(Handle, new IntPtr(addr), out mbi, Marshal.SizeOf<MBI>()) != 0;

    /// <summary>可读、已提交、非 Guard 的区域。</summary>
    public static bool IsReadable(in MBI m) =>
        m.State == MEM_COMMIT && (m.Protect & PAGE_GUARD) == 0 && (m.Protect & PAGE_NOACCESS) == 0
        && m.Protect != 0;

    public IEnumerable<MBI> Regions(long maxAddr = 0x7FFFFFFF_0000L)
    {
        long addr = 0;
        while (addr < maxAddr)
        {
            if (!Query(addr, out var m)) yield break;
            ulong size = m.RegionSize;
            yield return m;
            if (size == 0) yield break;
            addr = m.BaseAddress.ToInt64() + (long)size;
            if (addr <= m.BaseAddress.ToInt64()) yield break;
        }
    }

    /// <summary>模块列表（走 Process.Modules，只读）。</summary>
    public List<ModuleEntry> Modules()
    {
        var list = new List<ModuleEntry>();
        try
        {
            using var p = Process.GetProcessById(Pid);
            foreach (ProcessModule m in p.Modules)
            {
                try { list.Add(new ModuleEntry { Base = m.BaseAddress, Size = (ulong)m.ModuleMemorySize, Path = m.FileName }); }
                catch { }
            }
        }
        catch { }
        return list;
    }

    /// <summary>整片扫描可读区域，逐块回调。返回 false 继续，true 提前结束。</summary>
    public void Scan(int chunk = 4 << 20, Func<long, byte[], int, bool> onChunk = null,
                     bool privateOnly = true, Action<MBI> onRegion = null)
    {
        var buf = new byte[chunk];
        foreach (var m in Regions())
        {
            onRegion?.Invoke(m);
            if (!IsReadable(m)) continue;
            if (privateOnly && m.Type != 0x20000 /*MEM_PRIVATE*/) continue;
            long b = m.BaseAddress.ToInt64();
            long size = (long)m.RegionSize;
            for (long off = 0; off < size;)
            {
                int want = (int)Math.Min(buf.Length, size - off);
                if (!TryReadInto(b + off, buf, want, out int read)) break;
                // 块尾可能截断记录：重叠 1KB 再读下一段
                if (onChunk != null && onChunk(b + off, buf, read)) return;
                if (read < want) break;
                off += Math.Max(1, read - 0x400);
            }
        }
    }

    public static string Printable(byte[] b, int len)
    {
        var sb = new StringBuilder(len);
        for (int i = 0; i < len; i++)
        {
            byte c = b[i];
            if (c == 0) sb.Append('\u0000');
            else if (c >= 0x20 && c < 0x7F) sb.Append((char)c);
            else if (c == '\r' || c == '\n' || c == '\t') sb.Append((char)c);
            else sb.Append('.');
        }
        return sb.ToString();
    }
}
