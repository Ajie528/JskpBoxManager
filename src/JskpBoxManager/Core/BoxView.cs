using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;

namespace JskpBoxManager.Core;

/// <summary>
/// 某一时刻沙箱里的进程和顶层窗口快照。启动/看门循环每轮取一次，各种判断都基于这份快照，
/// 不必每个判断都重新枚举一遍全桌面窗口。
/// </summary>
public sealed class BoxView
{
    public sealed record Win(IntPtr Hwnd, int Pid, string Proc, string Title, string Class, bool Visible);

    public string Box { get; }
    public List<int> Pids { get; }
    readonly HashSet<int> _set;
    readonly Dictionary<int, string> _names = new();
    readonly List<(int Pid, string Name, string MainTitle, IntPtr MainHwnd)> _procs = new();
    List<Win> _wins;
    Dictionary<int, (string Name, string Cmd)> _cmds;

    static IntPtr _lastGameHwnd;

    public BoxView(string box) : this(box, Sandboxie.Pids(box)) { }

    public BoxView(string box, List<int> pids)
    {
        Box = box;
        Pids = pids;
        _set = new HashSet<int>(pids);
        foreach (var id in pids)
        {
            try
            {
                using var p = Process.GetProcessById(id);
                _names[id] = p.ProcessName;
                _procs.Add((id, p.ProcessName, p.MainWindowTitle ?? "", p.MainWindowHandle));
            }
            catch { }
        }
    }

    public string NameOf(int pid) => _names.TryGetValue(pid, out var n) ? n : "";

    public List<Win> Windows
    {
        get
        {
            if (_wins != null) return _wins;
            _wins = new List<Win>();
            foreach (var h in Win32.TopWindows())
            {
                int pid = Win32.PidOf(h);
                if (!_set.Contains(pid)) continue;
                _wins.Add(new Win(h, pid, NameOf(pid), Win32.Title(h), Win32.ClassOf(h), Win32.IsWindowVisible(h)));
            }
            return _wins;
        }
    }

    Dictionary<int, (string Name, string Cmd)> Cmds => _cmds ??= ProcessUtil.CommandLines(Pids);

    static bool IsQq(string n) => n == "QQBrowser";
    static bool IsWx(string n) => n is "WeChatAppEx" or "WeChatAppHost";

    public bool HasQqOrGame => _names.Values.Any(n => IsQq(n) || IsWx(n));
    public bool HasWeChat => _names.Values.Any(IsWx);
    public bool Empty => !HasQqOrGame;

    public IntPtr FindTitle(Func<string, bool> match, bool includeHidden)
    {
        foreach (var p in _procs)
            if (match(p.MainTitle) && p.MainHwnd != IntPtr.Zero) return p.MainHwnd;
        foreach (var w in Windows)
        {
            if (!includeHidden && !w.Visible) continue;
            if (!string.IsNullOrWhiteSpace(w.Title) && match(w.Title)) return w.Hwnd;
        }
        return IntPtr.Zero;
    }

    public IntPtr GameHwnd
    {
        get
        {
            foreach (var p in _procs)
                if (IsWx(p.Name) && Titles.IsGameForBox(p.MainTitle, Box) && p.MainHwnd != IntPtr.Zero)
                    return _lastGameHwnd = p.MainHwnd;
            foreach (var w in Windows)
                if (Titles.IsGameForBox(w.Title, Box)) return _lastGameHwnd = w.Hwnd;
            var last = _lastGameHwnd;
            if (last != IntPtr.Zero && Win32.IsWindow(last) && _set.Contains(Win32.PidOf(last)) && Titles.IsGameForBox(Win32.Title(last), Box))
                return last;
            return IntPtr.Zero;
        }
    }

    public bool HasGameWindow => GameHwnd != IntPtr.Zero;

    public bool HasStrictQr => FindTitle(Titles.IsStrictQr, true) != IntPtr.Zero || Cdp.HasQrTab(Box);
    public bool HasWmpfSetup => FindTitle(Titles.IsWmpfSetup, true) != IntPtr.Zero;
    public bool HasGameUpdateDialog => FindTitle(Titles.IsGameUpdateRestart, true) != IntPtr.Zero;

    /// <summary>微信运行时主进程已起（扫码阶段也会起，不能当成登录成功）。</summary>
    public bool WeChatRuntimeUp
    {
        get
        {
            if (HasGameWindow) return true;
            foreach (var (pid, (name, cmd)) in Cmds)
            {
                if (!name.Equals("WeChatAppEx.exe", StringComparison.OrdinalIgnoreCase)) continue;
                if (cmd.Contains("--type=")) continue;
                if (cmd.Contains("product-id=3000") || System.Text.RegularExpressions.Regex.IsMatch(cmd, "WeChatAppEx\\.exe\"\\s+--log-level")) return true;
            }
            return false;
        }
    }

    public bool HasVisibleUi
    {
        get
        {
            foreach (var p in _procs)
            {
                if (p.MainHwnd == IntPtr.Zero || string.IsNullOrWhiteSpace(p.MainTitle)) continue;
                var t = p.MainTitle;
                if (Titles.IsRestorePage(t) || Titles.IsStrictQr(t)) continue;
                if (!t.Contains("游戏中心") && Titles.IsJunk(t, "")) continue;
                return true;
            }
            return false;
        }
    }

    public string TitlesSample(int max = 8)
    {
        var list = _procs.Where(p => !string.IsNullOrWhiteSpace(p.MainTitle)).Select(p => p.Name + ":" + p.MainTitle).ToList();
        if (list.Count == 0) list = Windows.Where(w => !string.IsNullOrWhiteSpace(w.Title)).Select(w => w.Title).ToList();
        return string.Join(" | ", list.Distinct().Take(max));
    }

    // ---------- 动作 ----------

    public bool CloseRestorePage()
    {
        var h = FindTitle(Titles.IsRestorePage, false);
        if (h == IntPtr.Zero) return false;
        Win32.PostMessage(h, Win32.WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
        return true;
    }

    /// <summary>只拉出真正的授权扫码页，不强制置顶。</summary>
    public bool ShowQrWindow()
    {
        var h = FindTitle(Titles.IsStrictQr, true);
        if (h == IntPtr.Zero) return false;
        Win32.ShowAsAppWindow(h);
        return true;
    }

    public bool ShowGameWindow()
    {
        var h = GameHwnd;
        if (h == IntPtr.Zero) return false;
        Win32.EnsureGameTaskbarButton(h, "JskpGame." + Box);
        Win32.ShowWindow(h, Win32.SW_RESTORE);
        Win32.SetForegroundWindow(h);
        return true;
    }

    public bool ShowBrowser()
    {
        foreach (var p in _procs)
        {
            if (!IsQq(p.Name) || Titles.IsGame(p.MainTitle) || p.MainHwnd == IntPtr.Zero) continue;
            Win32.RestoreTopLevel(p.MainHwnd);
            Win32.ShowWindow(p.MainHwnd, Win32.SW_RESTORE);
            Win32.SetForegroundWindow(p.MainHwnd);
            return true;
        }
        return false;
    }

    /// <summary>
    /// 「暂无法打开小程序」画在小程序页面里，标题仍是「向僵尸开炮」。按钮是页面中上部一条浅灰横条（约窗口高度 39%）。
    /// 找到返回屏幕坐标。
    /// </summary>
    public Point? MiniProgramRetryPoint()
    {
        var h = GameHwnd;
        if (h == IntPtr.Zero || !Win32.GetWindowRect(h, out var r)) return null;
        int width = r.Right - r.Left, height = r.Bottom - r.Top;
        if (width < 120 || height < 200 || r.Left <= -10000) return null;
        try
        {
            using var bmp = new Bitmap(width, height, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp)) g.CopyFromScreen(r.Left, r.Top, 0, 0, new Size(width, height));
            int minX = width, maxX = 0, minY = height, maxY = 0, count = 0;
            int y0 = (int)(height * 0.30), y1 = (int)(height * 0.50);
            for (int y = y0; y < y1; y += 2)
                for (int x = 0; x < width; x += 2)
                {
                    var c = bmp.GetPixel(x, y);
                    int spread = Math.Max(c.R, Math.Max(c.G, c.B)) - Math.Min(c.R, Math.Min(c.G, c.B));
                    if (spread > 14 || c.R < 228 || c.R > 250) continue;
                    count++;
                    minX = Math.Min(minX, x); maxX = Math.Max(maxX, x);
                    minY = Math.Min(minY, y); maxY = Math.Max(maxY, y);
                }
            int barW = maxX - minX, barH = maxY - minY;
            if (count < 80 || barW < width * 0.28 || barW > width * 0.62 || barH < 8 || barH > height * 0.12) return null;
            return new Point(r.Left + (minX + maxX) / 2, r.Top + (minY + maxY) / 2);
        }
        catch { return null; }
    }

    public bool HasMiniProgramFail(out Point? point)
    {
        point = null;
        if (FindTitle(Titles.IsMiniProgramFail, false) != IntPtr.Zero) return true;
        if (!HasGameWindow) return false;
        point = MiniProgramRetryPoint();
        return point != null;
    }

    public bool ClickMiniProgramRetry(Point? point)
    {
        if (point != null)
        {
            Win32.ClickScreen(point.Value.X, point.Value.Y);
            return true;
        }
        var h = FindTitle(Titles.IsMiniProgramFail, false);
        if (h != IntPtr.Zero)
        {
            Win32.ShowWindow(h, Win32.SW_RESTORE);
            Win32.SetForegroundWindow(h);
            Thread.Sleep(200);
            Win32.PressEnter();
            return true;
        }
        return Win32.ClickWindowRatio(GameHwnd, 0.50, 0.39);
    }

    static DateTime _lastRendererSweep = DateTime.MinValue;
    static DateTime _lastTrim = DateTime.MinValue;

    /// <summary>
    /// 隐藏 QQ 浏览器窗口和空白微信壳，只留游戏窗和输入法窗。
    /// 绝不关闭 QQ 浏览器（会话挂在浏览器上，关了游戏会掉线），也不 WM_CLOSE 微信壳（会连游戏一起关）。
    /// </summary>
    public int HideBrowserKeepGame(bool gameRunning)
    {
        int hidden = 0;
        var game = gameRunning ? GameHwnd : IntPtr.Zero;
        foreach (var w in Windows)
        {
            if (w.Hwnd == game || Titles.IsGame(w.Title)) continue;
            if (!gameRunning && (!w.Visible || Win32.IsIconic(w.Hwnd) || Titles.IsStrictQr(w.Title))) continue;
            if (Titles.IsIme(w.Title, w.Class, w.Proc)) continue;
            bool isQq = IsQq(w.Proc), isWx = IsWx(w.Proc);
            bool wxShell = isWx && (string.IsNullOrWhiteSpace(w.Title) || Titles.IsWeChatShell(w.Title));
            if (gameRunning && wxShell)
            {
                if (w.Class.Contains("Chrome_WidgetWin") || string.IsNullOrWhiteSpace(w.Title) || Titles.IsWeChatShell(w.Title))
                {
                    Win32.ForceHide(w.Hwnd);
                    hidden++;
                }
                continue;
            }
            bool junk = Titles.IsJunk(w.Title, w.Class);
            if (!(junk || isQq || (isWx && string.IsNullOrWhiteSpace(w.Title)))) continue;
            if (isQq && Titles.IsRestorePage(w.Title)) Win32.PostMessage(w.Hwnd, Win32.WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
            if (isQq && gameRunning)
            {
                if (!w.Class.Contains("Chrome_WidgetWin") && !w.Visible) continue;
                Win32.ForceHideBrowserChrome(w.Hwnd);
            }
            else Win32.ForceHide(w.Hwnd);
            hidden++;
        }
        if (gameRunning)
        {
            try { Cdp.CloseQrTabs(Box); } catch { }
            if (game != IntPtr.Zero)
            {
                if (Win32.RescueIfOffscreen(game)) Log.Box(Box, "rescued game window from off-screen");
                Win32.EnsureGameTaskbarButton(game, "JskpGame." + Box);
            }
            if ((DateTime.Now - _lastRendererSweep).TotalMinutes >= 3)
            {
                _lastRendererSweep = DateTime.Now;
                KillBrowserRenderers();
            }
            if ((DateTime.Now - _lastTrim).TotalMinutes >= 10)
            {
                _lastTrim = DateTime.Now;
                TrimBrowserMemory();
            }
        }
        if (hidden > 0) Log.Box(Box, $"hide windows={hidden}");
        return hidden;
    }

    /// <summary>杀掉 QQ 浏览器的页面渲染/助手进程；保留主进程和扩展链（WeChatAppEx 挂在上面）。</summary>
    public int KillBrowserRenderers()
    {
        int killed = 0;
        foreach (var (pid, (name, cmd)) in Cmds)
        {
            if (!name.Equals("QQBrowser.exe", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(cmd)) continue;
            bool drop = cmd.Contains("--type=assistant") ||
                        (cmd.Contains("--type=renderer") && !cmd.Contains("--extension-process") && !cmd.Contains("--type=dll-extension") && !cmd.Contains("-host=extension"));
            if (!drop) continue;
            ProcessUtil.Kill(pid);
            killed++;
        }
        return killed;
    }

    /// <summary>只回收 QQ 浏览器的工作集。WeChatAppEx 就是游戏本体，清了会卡。</summary>
    public (long Before, long After) TrimBrowserMemory()
    {
        long before = 0, after = 0;
        foreach (var p in _procs.Where(p => IsQq(p.Name)))
        {
            try
            {
                using var proc = Process.GetProcessById(p.Pid);
                before += proc.WorkingSet64;
                Win32.EmptyWorkingSet(proc.Handle);
                proc.Refresh();
                after += proc.WorkingSet64;
            }
            catch { }
        }
        return (before, after);
    }
}
