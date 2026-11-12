# 把窗口调整到指定尺寸并截图，验证自适应布局
param([int]$ProcId, [string]$Out, [int]$W, [int]$H)
$sig = @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int w, int h, bool repaint);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
public delegate bool EnumProc(IntPtr hWnd, IntPtr p);
public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
'@
Add-Type -MemberDefinition $sig -Name U -Namespace Resize
Add-Type -AssemblyName System.Drawing

$script:hwnd = [IntPtr]::Zero
$cb = [Resize.U+EnumProc]{
    param($h, $lp)
    $p = 0
    [Resize.U]::GetWindowThreadProcessId($h, [ref]$p) | Out-Null
    if ([int]$p -eq $ProcId -and [Resize.U]::IsWindowVisible($h)) {
        $r = New-Object Resize.U+RECT
        [Resize.U]::GetWindowRect($h, [ref]$r) | Out-Null
        if (($r.Right - $r.Left) -gt 400 -and ($r.Bottom - $r.Top) -gt 300) { $script:hwnd = $h }
    }
    return $true
}
[Resize.U]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
if ($script:hwnd -eq [IntPtr]::Zero) { Write-Host "没找到窗口"; exit 1 }

[Resize.U]::ShowWindow($script:hwnd, 9) | Out-Null
[Resize.U]::MoveWindow($script:hwnd, 40, 40, $W, $H, $true) | Out-Null
[Resize.U]::SetForegroundWindow($script:hwnd) | Out-Null
Start-Sleep -Milliseconds 1600

$r = New-Object Resize.U+RECT
[Resize.U]::GetWindowRect($script:hwnd, [ref]$r) | Out-Null
$aw = $r.Right - $r.Left
$ah = $r.Bottom - $r.Top
$bmp = New-Object Drawing.Bitmap $aw, $ah
$g = [Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
$bmp.Save($Out, [Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "请求 ${W}x${H} -> 实际 ${aw}x${ah} -> $Out"
