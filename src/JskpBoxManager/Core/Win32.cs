using System.Runtime.InteropServices;
using System.Text;

namespace JskpBoxManager.Core;

[ComImport, Guid("56FDF342-FD6D-11d0-958A-006097C9A090"), ClassInterface(ClassInterfaceType.None)]
class CoTaskbarList { }

[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("56FDF342-FD6D-11d0-958A-006097C9A090")]
interface ITaskbarList
{
    void HrInit();
    void AddTab(IntPtr hwnd);
    void DeleteTab(IntPtr hwnd);
    void ActivateTab(IntPtr hwnd);
    void SetActiveAlt(IntPtr hwnd);
}

[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("886d8eeb-8cf2-4446-8d02-cdba1dbdcf99")]
interface IPropertyStore
{
    void GetCount(out uint c);
    void GetAt(uint i, out PropertyKey key);
    void GetValue(ref PropertyKey key, out PropVariant pv);
    void SetValue(ref PropertyKey key, ref PropVariant pv);
    void Commit();
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
struct PropertyKey { public Guid fmtid; public uint pid; }

[StructLayout(LayoutKind.Explicit, Size = 24)]
struct PropVariant
{
    [FieldOffset(0)] public ushort vt;
    [FieldOffset(8)] public IntPtr ptr;
}

public static class Win32
{
    public const int SW_HIDE = 0, SW_SHOWNOACTIVATE = 4, SW_SHOW = 5, SW_SHOWMINNOACTIVE = 7, SW_RESTORE = 9, SW_FORCEMINIMIZE = 11;
    const int GWL_EXSTYLE = -20;
    const long WS_EX_TOOLWINDOW = 0x80, WS_EX_APPWINDOW = 0x40000;
    public const uint WM_CLOSE = 0x0010;
    const uint SWP_NOSIZE = 1, SWP_NOMOVE = 2, SWP_NOZORDER = 4, SWP_NOACTIVATE = 0x10, SWP_FRAMECHANGED = 0x20, SWP_HIDEWINDOW = 0x80;
    static readonly IntPtr HWND_MESSAGE = new(-3);

    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] static extern IntPtr GetWindowLongPtr(IntPtr h, int i);
    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW")] static extern IntPtr SetWindowLongPtr(IntPtr h, int i, IntPtr v);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint f);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int i);
    [DllImport("user32.dll")] static extern IntPtr SetParent(IntPtr child, IntPtr parent);
    [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr h);
    [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] static extern void mouse_event(int f, int dx, int dy, int d, IntPtr e);
    [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint flags, IntPtr extra);
    [DllImport("psapi.dll")] public static extern bool EmptyWorkingSet(IntPtr process);
    [DllImport("shell32.dll")] static extern int SHGetPropertyStoreForWindow(IntPtr h, ref Guid iid, out IPropertyStore ps);
    [DllImport("kernel32.dll")] public static extern bool AttachConsole(int pid);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    public static string Title(IntPtr h)
    {
        var sb = new StringBuilder(512);
        GetWindowText(h, sb, 512);
        return sb.ToString();
    }

    public static string ClassOf(IntPtr h)
    {
        var sb = new StringBuilder(256);
        GetClassName(h, sb, 256);
        return sb.ToString();
    }

    public static int PidOf(IntPtr h)
    {
        GetWindowThreadProcessId(h, out var pid);
        return (int)pid;
    }

    public static List<IntPtr> TopWindows()
    {
        var list = new List<IntPtr>();
        EnumWindows((h, _) => { list.Add(h); return true; }, IntPtr.Zero);
        return list;
    }

    static ITaskbarList _tb;
    static ITaskbarList Tb
    {
        get
        {
            if (_tb == null)
            {
                _tb = (ITaskbarList)new CoTaskbarList();
                _tb.HrInit();
            }
            return _tb;
        }
    }

    static long ExStyle(IntPtr h) => GetWindowLongPtr(h, GWL_EXSTYLE).ToInt64();
    static void SetExStyle(IntPtr h, long v) => SetWindowLongPtr(h, GWL_EXSTYLE, new IntPtr(v));

    public static void RemoveTaskbarTab(IntPtr h)
    {
        if (h == IntPtr.Zero) return;
        try { Tb.DeleteTab(h); } catch { }
    }

    public static void RestoreTopLevel(IntPtr h)
    {
        if (h == IntPtr.Zero) return;
        try { SetParent(h, IntPtr.Zero); } catch { }
    }

    public static void SetAppUserModelId(IntPtr h, string id)
    {
        if (h == IntPtr.Zero || string.IsNullOrEmpty(id)) return;
        try
        {
            var iid = new Guid("886d8eeb-8cf2-4446-8d02-cdba1dbdcf99");
            if (SHGetPropertyStoreForWindow(h, ref iid, out var store) != 0) return;
            var pv = new PropVariant { vt = 31, ptr = Marshal.StringToCoTaskMemUni(id) };
            var key = new PropertyKey { fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"), pid = 5 };
            store.SetValue(ref key, ref pv);
            store.Commit();
            Marshal.FreeCoTaskMem(pv.ptr);
        }
        catch { }
    }

    /// <summary>Chrome 假最小化会把窗停在 x≈-32000，任务栏点了也看不见。拖回虚拟桌面。</summary>
    public static bool RescueIfOffscreen(IntPtr h)
    {
        if (h == IntPtr.Zero) return false;
        try { if (IsIconic(h)) return false; } catch { }
        if (!GetWindowRect(h, out var r)) return false;
        int w = r.Right - r.Left, ht = r.Bottom - r.Top;
        if (w < 80 || ht < 80) return false;
        int vx = GetSystemMetrics(76), vy = GetSystemMetrics(77), vw = GetSystemMetrics(78), vh = GetSystemMetrics(79);
        if (vw <= 0 || vh <= 0) { vx = 0; vy = 0; vw = GetSystemMetrics(0); vh = GetSystemMetrics(1); }
        bool fakeMin = r.Left <= -10000 || r.Top <= -10000;
        bool noOverlap = r.Right <= vx || r.Bottom <= vy || r.Left >= vx + vw || r.Top >= vy + vh;
        if (!fakeMin && !noOverlap) return false;
        if (w > vw - 16) w = vw - 16;
        if (ht > vh - 48) ht = vh - 48;
        MoveWindow(h, vx + 8, vy + 8, w, ht, true);
        ShowWindow(h, SW_SHOWNOACTIVATE);
        return true;
    }

    /// <summary>游戏窗独立出现在任务栏。最小化保持不动；被藏进消息窗时恢复成最小化按钮。</summary>
    public static bool EnsureGameTaskbarButton(IntPtr h, string appId)
    {
        if (h == IntPtr.Zero) return false;
        SetAppUserModelId(h, appId);
        try
        {
            bool swallowed = GetParent(h) == HWND_MESSAGE;
            bool hidden = !IsWindowVisible(h) && !IsIconic(h);
            if (swallowed || hidden)
            {
                if (swallowed) SetParent(h, IntPtr.Zero);
                long v = ExStyle(h), nv = (v | WS_EX_APPWINDOW) & ~WS_EX_TOOLWINDOW;
                if (nv != v) SetExStyle(h, nv);
                ShowWindow(h, SW_SHOWMINNOACTIVE);
                try { Tb.AddTab(h); } catch { }
                return true;
            }
        }
        catch { }
        if (IsIconic(h))
        {
            try
            {
                long v = ExStyle(h), nv = (v | WS_EX_APPWINDOW) & ~WS_EX_TOOLWINDOW;
                if (nv != v) SetExStyle(h, nv);
            }
            catch { }
            return false;
        }
        try { RescueIfOffscreen(h); } catch { }
        try { if (GetParent(h) != IntPtr.Zero) SetParent(h, IntPtr.Zero); } catch { }
        bool changed = false;
        try
        {
            long v = ExStyle(h), nv = (v | WS_EX_APPWINDOW) & ~WS_EX_TOOLWINDOW;
            if (nv != v)
            {
                SetExStyle(h, nv);
                changed = true;
                SetWindowPos(h, IntPtr.Zero, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
                try { Tb.AddTab(h); } catch { }
            }
        }
        catch { }
        return changed;
    }

    public static void ForceHideBrowserChrome(IntPtr h)
    {
        if (h == IntPtr.Zero) return;
        RemoveTaskbarTab(h);
        try { SetParent(h, HWND_MESSAGE); } catch { }
        ForceHide(h);
    }

    public static void ForceHide(IntPtr h)
    {
        if (h == IntPtr.Zero) return;
        try
        {
            ShowWindow(h, SW_FORCEMINIMIZE);
            SetExStyle(h, (ExStyle(h) | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW);
            SetWindowPos(h, IntPtr.Zero, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_HIDEWINDOW);
        }
        catch { }
        ShowWindow(h, SW_HIDE);
        ShowWindowAsync(h, SW_HIDE);
        SetWindowPos(h, IntPtr.Zero, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW);
        RemoveTaskbarTab(h);
    }

    /// <summary>让窗口出现在任务栏并还原显示（扫码页用）。</summary>
    public static void ShowAsAppWindow(IntPtr h)
    {
        if (h == IntPtr.Zero) return;
        RestoreTopLevel(h);
        try { SetExStyle(h, (ExStyle(h) | WS_EX_APPWINDOW) & ~WS_EX_TOOLWINDOW); } catch { }
        ShowWindow(h, SW_RESTORE);
        ShowWindowAsync(h, SW_SHOW);
    }

    public static void ClickScreen(int x, int y)
    {
        SetCursorPos(x, y);
        mouse_event(0x0002, 0, 0, 0, IntPtr.Zero);
        Thread.Sleep(40);
        mouse_event(0x0004, 0, 0, 0, IntPtr.Zero);
    }

    public static bool ClickWindowRatio(IntPtr h, double rx, double ry)
    {
        if (h == IntPtr.Zero || !GetWindowRect(h, out var r)) return false;
        int x = (int)(r.Left + (r.Right - r.Left) * rx);
        int y = (int)(r.Top + (r.Bottom - r.Top) * ry);
        SetForegroundWindow(h);
        Thread.Sleep(200);
        ClickScreen(x, y);
        return true;
    }

    public static void PressEnter()
    {
        keybd_event(0x0D, 0, 0, IntPtr.Zero);
        Thread.Sleep(30);
        keybd_event(0x0D, 0, 2, IntPtr.Zero);
    }
}
