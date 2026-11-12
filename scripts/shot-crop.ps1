# 截图并裁剪指定区域放大，用于检查某一列是否真的空白
param([int]$ProcId, [string]$Out, [int]$X, [int]$Y, [int]$W, [int]$H, [double]$Scale = 2.0)
$sig = @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
public delegate bool EnumProc(IntPtr hWnd, IntPtr p);
public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
'@
Add-Type -MemberDefinition $sig -Name U -Namespace Crop
Add-Type -AssemblyName System.Drawing

$script:hwnd = [IntPtr]::Zero
$cb = [Crop.U+EnumProc]{
    param($h, $lp)
    $p = 0
    [Crop.U]::GetWindowThreadProcessId($h, [ref]$p) | Out-Null
    if ([int]$p -eq $ProcId -and [Crop.U]::IsWindowVisible($h)) {
        $r = New-Object Crop.U+RECT
        [Crop.U]::GetWindowRect($h, [ref]$r) | Out-Null
        if (($r.Right - $r.Left) -gt 500 -and ($r.Bottom - $r.Top) -gt 400) { $script:hwnd = $h }
    }
    return $true
}
[Crop.U]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
if ($script:hwnd -eq [IntPtr]::Zero) { Write-Host "没找到窗口"; exit 1 }

[Crop.U]::ShowWindow($script:hwnd, 9) | Out-Null
[Crop.U]::SetForegroundWindow($script:hwnd) | Out-Null
Start-Sleep -Milliseconds 900

$r = New-Object Crop.U+RECT
[Crop.U]::GetWindowRect($script:hwnd, [ref]$r) | Out-Null

# 先抓整个窗口
$full = New-Object Drawing.Bitmap ($r.Right - $r.Left), ($r.Bottom - $r.Top)
$g = [Drawing.Graphics]::FromImage($full)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, $full.Size)
$g.Dispose()

# 裁剪
$rect = New-Object Drawing.Rectangle $X, $Y, $W, $H
$crop = $full.Clone($rect, $full.PixelFormat)
$nw = [int]($W * $Scale); $nh = [int]($H * $Scale)
$big = New-Object Drawing.Bitmap $nw, $nh
$g2 = [Drawing.Graphics]::FromImage($big)
$g2.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
$g2.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::Half
$g2.DrawImage($crop, 0, 0, $nw, $nh)
$g2.Dispose()
$big.Save($Out, [Drawing.Imaging.ImageFormat]::Png)
$full.Dispose(); $crop.Dispose(); $big.Dispose()
Write-Host "裁剪 ($X,$Y) ${W}x${H} x${Scale} -> $Out"
