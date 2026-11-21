# 迷宫事件 id → UI 语义 的实验采集脚本
#
# 做什么：
#   1. 读当前可选格子（左/右）
#   2. 点左箭头 → 截图 + 记录 CurSelect + 提示你看到什么弹窗
#   3. 关掉弹窗
#   4. 点右箭头 → 同样记录
#   5. 把「事件 id / 类型」和「弹窗标题」配对，输出对照表
#
# 需要你配合：每次弹窗出现后，看一眼标题（脚本会截图，你也可以直接看画面）。
# 脚本会把截图存在 explore-mem\46160\ 下，文件名带事件 id。

param(
    [int]$RendererPid = 0,
    [string]$Box = 'qb1'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$exe = Join-Path $root '46160\MemProbe\bin\Release\net8.0\MemProbe.exe'
if (-not (Test-Path $exe)) { Write-Host "先编译 MemProbe" -ForegroundColor Red; exit 2 }

# ---------- 窗口 / 点击 ----------
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class MazeClick {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, int dx, int dy, uint d, IntPtr e);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  public static void Click(int x, int y) {
    SetCursorPos(x, y); System.Threading.Thread.Sleep(220);
    mouse_event(0x0002, 0, 0, 0, IntPtr.Zero); System.Threading.Thread.Sleep(70);
    mouse_event(0x0004, 0, 0, 0, IntPtr.Zero);
  }
}
"@
Add-Type -AssemblyName System.Drawing

function Get-GameWindow {
    Get-Process | Where-Object {
        $_.MainWindowTitle -eq '向僵尸开炮' -and $_.ProcessName -eq 'WeChatAppEx'
    } | Select-Object -First 1
}

function Save-Shot([IntPtr]$hwnd, [string]$path) {
    $r = New-Object MazeClick+RECT
    [void][MazeClick]::GetWindowRect($hwnd, [ref]$r)
    $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    [void][MazeClick]::PrintWindow($hwnd, $hdc, 2)
    $g.ReleaseHdc($hdc); $g.Dispose()
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return @{ Left = $r.Left; Top = $r.Top; W = $w; H = $h }
}

# ---------- 找游戏窗口 ----------
$win = Get-GameWindow
if (-not $win) { Write-Host "找不到「向僵尸开炮」窗口" -ForegroundColor Red; exit 3 }
$hwnd = $win.MainWindowHandle
Write-Host "窗口句柄 $hwnd  PID $($win.Id)" -ForegroundColor Cyan
if ($RendererPid -le 0) { $RendererPid = 38200 }

# ---------- 读当前状态 ----------
function Get-Maze {
    $out = & $exe maze --pid $RendererPid 2>&1
    $txt = $out -join "`n"
    if ($txt -notmatch '下一步可选格子') { return $null }
    return $txt
}

$state = Get-Maze
if (-not $state) { Write-Host "读不到迷宫状态（界面没开？）" -ForegroundColor Red; exit 4 }
Write-Host "`n$state`n"

# ---------- 取两个选项的事件 id ----------
$optLines = $state -split "`n" | Where-Object { $_ -match '^\s+\[\d\]' }
$options = @()
foreach ($l in $optLines) {
    if ($l -match '\[(\d)\].*类型=(\d+)\s+事件=(\d+)') {
        $options += [pscustomobject]@{ No = [int]$matches[1]; Type = [int]$matches[2]; Event = [int]$matches[3] }
    }
}
if ($options.Count -eq 0) { Write-Host "没有可选项" -ForegroundColor Yellow; exit 5 }

Write-Host "可选项：" -ForegroundColor Cyan
$options | Format-Table -AutoSize | Out-String | Write-Host

# ---------- 逐个点击实验 ----------
$results = @()
foreach ($o in $options) {
    Write-Host "───── 测试选项 [$($o.No)] 类型=$($o.Type) 事件=$($o.Event) ─────" -ForegroundColor Yellow

    [void][MazeClick]::SetForegroundWindow($hwnd)
    Start-Sleep -Milliseconds 400

    # 左箭头 x=211, 右箭头 x=372（相对窗口），y=745
    $relX = if ($o.No -eq 1) { 211 } else { 372 }
    $relY = 745
    $shot0 = Save-Shot $hwnd (Join-Path $root "46160\exp-$($o.No)-before.png")
    [MazeClick]::Click(($shot0.Left + $relX), ($shot0.Top + $relY))
    Start-Sleep -Milliseconds 1800

    $shot1 = Save-Shot $hwnd (Join-Path $root "46160\exp-$($o.No)-e$($o.Event).png")
    Write-Host "  截图：46160\exp-$($o.No)-e$($o.Event).png" -ForegroundColor Gray
    Write-Host "  ★ 请看一眼画面，告诉我弹窗标题是什么（商店/安全区/问号事件…）" -ForegroundColor Cyan

    # 记录 CurSelect
    $sel = & $exe diff 0x3C483D008FC 0x8 --pid $RendererPid 2>&1 | Select-String 'int=' | ForEach-Object {
        if ($_ -match 'int=(-?\d+)') { [int]$matches[1] }
    }
    $results += [pscustomobject]@{
        选项 = $o.No; 类型 = $o.Type; 事件 = $o.Event
        CurSelectRow = ($sel | Select-Object -First 1)
        CurSelectCol = ($sel | Select-Object -Skip 1 -First 1)
    }

    # 关弹窗：点「返回」（相对窗口 218,602）
    Start-Sleep -Milliseconds 300
    [MazeClick]::SetForegroundWindow($hwnd)
    Start-Sleep -Milliseconds 300
    [MazeClick]::Click(($shot1.Left + 218), ($shot1.Top + 602))
    Start-Sleep -Milliseconds 1200
}

Write-Host "`n===== 实验结果 =====" -ForegroundColor Green
$results | Format-Table -AutoSize | Out-String | Write-Host

$csv = Join-Path $root '46160\exp-results.csv'
$results | Export-Csv $csv -NoTypeInformation -Encoding UTF8
Write-Host "已保存 $csv"
Write-Host "`n把这些截图对应的弹窗标题告诉我，就能建立「事件 id → 界面」的对照表。"
