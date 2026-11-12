# 截图指定进程的主窗口（用于验证 GUI 布局）。用法：powershell -File shot.ps1 <pid> <输出png>
param([int]$ProcId, [string]$Out)
$sig = @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, System.Text.StringBuilder s, int n);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
public delegate bool EnumProc(IntPtr hWnd, IntPtr p);
public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
'@
Add-Type -MemberDefinition $sig -Name U -Namespace Shot
Add-Type -AssemblyName System.Drawing

$script:hwnd = [IntPtr]::Zero
$cb = [Shot.U+EnumProc]{
    param($h, $lp)
    $p = 0
    [Shot.U]::GetWindowThreadProcessId($h, [ref]$p) | Out-Null
    if ([int]$p -eq $ProcId -and [Shot.U]::IsWindowVisible($h)) {
        $r = New-Object Shot.U+RECT
        [Shot.U]::GetWindowRect($h, [ref]$r) | Out-Null
        if (($r.Right - $r.Left) -gt 500 -and ($r.Bottom - $r.Top) -gt 400) { $script:hwnd = $h }
    }
    return $true
}
[Shot.U]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
if ($script:hwnd -eq [IntPtr]::Zero) { Write-Host "没找到窗口"; exit 1 }

[Shot.U]::ShowWindow($script:hwnd, 9) | Out-Null
[Shot.U]::SetForegroundWindow($script:hwnd) | Out-Null
Start-Sleep -Seconds 2

$r = New-Object Shot.U+RECT
[Shot.U]::GetWindowRect($script:hwnd, [ref]$r) | Out-Null
$w = $r.Right - $r.Left
$h2 = $r.Bottom - $r.Top
$bmp = New-Object Drawing.Bitmap $w, $h2
$g = [Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
$bmp.Save($Out, [Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "窗口 ${w}x${h2} -> $Out"
