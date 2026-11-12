# 移动到窗口指定坐标并截图（验证 ToolTip 弹出效果）
param([int]$ProcId, [string]$Out, [int]$RelX, [int]$RelY, [int]$WaitMs = 2500)
$sig = @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
[DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
public delegate bool EnumProc(IntPtr hWnd, IntPtr p);
public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
'@
Add-Type -MemberDefinition $sig -Name U -Namespace Shot2
Add-Type -AssemblyName System.Drawing

$script:hwnd = [IntPtr]::Zero
$cb = [Shot2.U+EnumProc]{
    param($h, $lp)
    $p = 0
    [Shot2.U]::GetWindowThreadProcessId($h, [ref]$p) | Out-Null
    if ([int]$p -eq $ProcId -and [Shot2.U]::IsWindowVisible($h)) {
        $r = New-Object Shot2.U+RECT
        [Shot2.U]::GetWindowRect($h, [ref]$r) | Out-Null
        if (($r.Right - $r.Left) -gt 500 -and ($r.Bottom - $r.Top) -gt 400) { $script:hwnd = $h }
    }
    return $true
}
[Shot2.U]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
if ($script:hwnd -eq [IntPtr]::Zero) { Write-Host "没找到窗口"; exit 1 }

[Shot2.U]::ShowWindow($script:hwnd, 9) | Out-Null
[Shot2.U]::SetForegroundWindow($script:hwnd) | Out-Null
Start-Sleep -Milliseconds 800

$r = New-Object Shot2.U+RECT
[Shot2.U]::GetWindowRect($script:hwnd, [ref]$r) | Out-Null
# 悬停到窗口内相对坐标（触发 ToolTip）
[Shot2.U]::SetCursorPos($r.Left + $RelX, $r.Top + $RelY) | Out-Null
Start-Sleep -Milliseconds $WaitMs

$w = $r.Right - $r.Left
$h2 = $r.Bottom - $r.Top
$bmp = New-Object Drawing.Bitmap $w, $h2
$g = [Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
$bmp.Save($Out, [Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "窗口 ${w}x${h2}  悬停@($RelX,$RelY) -> $Out"
