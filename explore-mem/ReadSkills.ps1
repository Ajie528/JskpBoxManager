# 技能选择界面：OCR 读取当前 4 张可选技能
#
# 为什么用 PowerShell 而不是 C#：
#   C# 里 user32 的 GetWindowRect / GetClientRect 在这个工程里返回 false
#   （UseWindowsForms + InvariantGlobalization 的组合问题），
#   PowerShell 这边调用完全正常，所以截图交给这里做。
#
# 用法：
#   .\ReadSkills.ps1                 # 自动找游戏窗口
#   .\ReadSkills.ps1 -Hwnd 54399820
#   .\ReadSkills.ps1 -Save          # 额外保存裁切图，便于调试

param(
    [long]$Hwnd = 0,
    [switch]$Save,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class SkillCap {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
  [DllImport("user32.dll", SetLastError=true)] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
}
"@

$tess = 'C:\Program Files\Tesseract-OCR\tesseract.exe'
if (-not (Test-Path $tess)) { Write-Host "找不到 tesseract" -ForegroundColor Red; exit 2 }

# ── 找游戏窗口 ──
if ($Hwnd -le 0) {
    $p = Get-Process WeChatAppEx -ErrorAction SilentlyContinue |
         Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -eq '向僵尸开炮' } |
         Select-Object -First 1
    if (-not $p) { Write-Host "找不到「向僵尸开炮」窗口" -ForegroundColor Red; exit 3 }
    $Hwnd = [long]$p.MainWindowHandle
}
$h = [IntPtr]$Hwnd
if (-not [SkillCap]::IsWindow($h)) { Write-Host "句柄无效: $Hwnd" -ForegroundColor Red; exit 3 }

# ── 把游戏窗口拉到前台（否则截到的是遮挡在它上面的窗口） ──
[void][SkillCap]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 600

# ── 截图（客户区，避开标题栏） ──
$cr = New-Object SkillCap+RECT
if (-not [SkillCap]::GetClientRect($h, [ref]$cr)) { Write-Host "GetClientRect 失败" -ForegroundColor Red; exit 4 }
$pt = New-Object SkillCap+POINT
if (-not [SkillCap]::ClientToScreen($h, [ref]$pt)) { Write-Host "ClientToScreen 失败" -ForegroundColor Red; exit 4 }
$w = $cr.Right - $cr.Left
$hh = $cr.Bottom - $cr.Top
if ($w -le 0 -or $hh -le 0) { Write-Host "窗口尺寸异常 ${w}x${hh}" -ForegroundColor Red; exit 4 }

$bmp = New-Object System.Drawing.Bitmap($w, $hh)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok = [SkillCap]::PrintWindow($h, $hdc, 2)
$g.ReleaseHdc($hdc)
$g.Dispose()
if (-not $ok) {
    Write-Host "PrintWindow 失败，退回屏幕抓取" -ForegroundColor Yellow
    $bmp.Dispose()
    $bmp = New-Object System.Drawing.Bitmap($w, $hh)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($pt.X, $pt.Y, 0, 0, (New-Object System.Drawing.Size($w, $hh)))
    $g.Dispose()
} else {
    # PrintWindow 抓的是整个窗口（含标题栏），裁掉标题栏
    $wr = New-Object SkillCap+RECT
    if ([SkillCap]::GetWindowRect($h, [ref]$wr)) {
        $capH = $hh + 8      # 估算标题栏高度
        if ($bmp.Height -gt $hh) {
            $crop = New-Object System.Drawing.Bitmap($w, $hh)
            $gc = [System.Drawing.Graphics]::FromImage($crop)
            $gc.DrawImage($bmp, (New-Object System.Drawing.Rectangle(0,0,$w,$hh)),
                (New-Object System.Drawing.Rectangle(0, $bmp.Height - $hh, $w, $hh)), [System.Drawing.GraphicsUnit]::Pixel)
            $gc.Dispose()
            $bmp.Dispose()
            $bmp = $crop
        }
    }
}
Write-Host "窗口 ${w}x${hh}  截图完成 (PrintWindow=$ok)" -ForegroundColor Cyan

# ── 找标题文字行（卡牌上部） ──
$y0 = [int]($hh * 0.42)
$y1 = [int]($hh * 0.80)
$rows = @{}
for ($y = $y0; $y -lt $y1; $y++) {
    $cnt = 0
    for ($x = 0; $x -lt $w; $x += 2) {
        $c = $bmp.GetPixel($x, $y)
        if ($c.R -gt 185 -and $c.G -gt 185 -and $c.B -gt 185) { $cnt++ }
    }
    # 只要「有少量亮字但不占满整行」的行（横幅会占很宽）
    if ($cnt -ge 4 -and $cnt -le ($w / 3)) { $rows[$y] = $cnt }
}
if ($rows.Count -eq 0) { Write-Host "卡牌区没找到文字" -ForegroundColor Yellow; $bmp.Dispose(); exit 5 }

# 聚成带（间隔 > 3 行才算断开）
$ys = @($rows.Keys | Sort-Object)
$bands = @()
$s = $ys[0]; $pv = $ys[0]
foreach ($y in $ys) {
    if ($y - $pv -gt 3) { $bands += [pscustomobject]@{From=$s; To=$pv}; $s = $y }
    $pv = $y
}
$bands += [pscustomobject]@{From=$s; To=$pv}

# 统计每个带的列分组数（只认白字，卡牌标题都是白字）
function Get-ColGroups($bmpObj, $bandObj, $width) {
    $cc = @{}
    for ($x = 0; $x -lt $width; $x++) {
        $n2 = 0
        for ($y = $bandObj.From; $y -le $bandObj.To; $y++) {
            $c2 = $bmpObj.GetPixel($x, $y)
            if ($c2.R -gt 185 -and $c2.G -gt 185 -and $c2.B -gt 185) { $n2++ }
        }
        if ($n2 -gt 0) { $cc[$x] = $n2 }
    }
    if ($cc.Count -eq 0) { return @() }
    $xxs = @($cc.Keys | Sort-Object)
    $out = @()
    $gs = $xxs[0]; $gp = $xxs[0]
    foreach ($x in $xxs) {
        if ($x - $gp -gt 17) { if (($gp - $gs) -ge 8) { $out += [pscustomobject]@{From=$gs; To=$gp} }; $gs = $x }
        $gp = $x
    }
    if (($gp - $gs) -ge 8) { $out += [pscustomobject]@{From=$gs; To=$gp} }
    return $out
}

Write-Host "所有文字带：" -ForegroundColor DarkGray
$bandInfo = @()
foreach ($b in $bands) {
    $gg = @(Get-ColGroups $bmp $b $w)
    $bandInfo += [pscustomobject]@{ Band = $b; Groups = $gg }
    Write-Host ("  y={0,4}..{1,-4} h={2,-3} 列组={3}" -f $b.From, $b.To, ($b.To - $b.From), $gg.Count)
}

# 选标题带：列组数最多者优先（4 张卡 → 3~6 组），高度放宽到 60（标题 + 图标常连在一起）
$cands = @($bandInfo | Where-Object {
    $_.Groups.Count -ge 2 -and ($_.Band.To - $_.Band.From) -ge 4 -and ($_.Band.To - $_.Band.From) -le 60
})
if ($cands.Count -eq 0) {
    Write-Host "没找到可用的标题带" -ForegroundColor Yellow
    $bmp.Dispose(); exit 5
}
# 列组最多者优先；并列时取靠上的
$picked = $cands | Sort-Object @{E={-$_.Groups.Count}}, @{E={$_.Band.From}} | Select-Object -First 1
$band = $picked.Band

# 在带内找「亮像素最密集」的一行，作为标题行中心（避免把横幅/图标一起裁进去）
$bestRow = $band.From; $bestCnt = -1
for ($y = $band.From; $y -le $band.To; $y++) {
    $cnt2 = 0
    for ($x = 0; $x -lt $w; $x++) {
        $c3 = $bmp.GetPixel($x, $y)
        if ($c3.R -gt 185 -and $c3.G -gt 185 -and $c3.B -gt 185) { $cnt2++ }
    }
    if ($cnt2 -gt $bestCnt) { $bestCnt = $cnt2; $bestRow = $y }
}
$ty = [Math]::Max(0, $bestRow - 9)
$th2 = [Math]::Min($hh - $ty, 20)
Write-Host "带 y=$($band.From)..$($band.To) → 标题行 y=$bestRow (亮=$bestCnt)，裁切 y=$ty..$($ty+$th2)" -ForegroundColor Cyan

$rawGroups = @($picked.Groups | Where-Object { ($_.To - $_.From) -lt ($w * 0.6) })
# ── 按 4 等分裁切（卡牌在界面上等宽排列，最稳） ──
# 用卡牌区（y=567..744 那条带）的实际左右边界确定总宽度
$cardLeft = 0; $cardRight = $w
$contentBand = $bandInfo | Where-Object { ($_.Band.To - $_.Band.From) -gt 100 } | Select-Object -First 1
if ($contentBand) {
    $allGroups = @(Get-ColGroups $bmp $contentBand.Band $w)
    if ($allGroups.Count -gt 0) {
        $cardLeft = ($allGroups | Measure-Object From -Minimum).Minimum
        $cardRight = ($allGroups | Measure-Object To -Maximum).Maximum
    }
}
$totalW = $cardRight - $cardLeft
Write-Host "卡牌区 x=$cardLeft..$cardRight (总宽 $totalW)" -ForegroundColor DarkGray

$groups = @()
$n = 4
$slot = $totalW / $n
for ($i = 0; $i -lt $n; $i++) {
    $groups += [pscustomobject]@{
        From = [int]($cardLeft + $slot * $i)
        To   = [int]($cardLeft + $slot * ($i + 1))
    }
}
Write-Host "按 4 等分裁切：" -ForegroundColor Cyan
$groups | ForEach-Object { Write-Host ("  [{0}] x={1}..{2} 宽 {3}" -f ($groups.IndexOf($_) + 1), $_.From, $_.To, ($_.To-$_.From)) }



# ── 逐组 OCR ──
$names = @()
$tmpDir = Join-Path $env:TEMP ("jskp-skill-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

# ── 已知技能名词典（从内存卡牌表导出 + 人工核对），用于纠正 OCR 误差 ──
$knownSkills = @(
  '干冰弹增伤','火焰侵袭','爆炸增伤','齐射+','燃料改良','猛烈震荡','散射小冰弹','制导激光',
  '增伤利刃','旋转利刃','风力加强','增伤电子','冰暴地带','冰暴增伤','激光增伤',
  '轰炸震荡','轰炸增伤','致残碾压','增伤装置','射线增伤','电磁爆炸扩张','电磁爆炸增伤',
  '低温贯穿','温压冲击','热能爆炸','通路污染','坍塌增幅','时空聚变','低维增伤',
  '多重冲击','汲能','矩阵裂变','多重坍塌','多重裂隙','弹珠雨','高维连发','弹射裂变',
  '硫化火焰','无人机气刃','闪电加农','永动电子','冰暴加农','连环冰暴','聚焦',
  '乱流刃','焦土策略','高能光波','核能电磁','电磁分流','干冰弹连发',
  '双重爆燃','温压弹连发','热能焚身','超爆弹','冰锥震荡','绝对零度'
)

function Fix-Name([string]$raw) {
    if ([string]::IsNullOrEmpty($raw)) { return $raw }
    foreach ($k in $knownSkills) { if ($raw -eq $k) { return $k } }
    # 用「共同字符数 / 较长长度」做相似度（避开 PowerShell 数组索引坑）
    $best = $null; $bestScore = 0.0
    foreach ($k in $knownSkills) {
        if ([Math]::Abs($raw.Length - $k.Length) -gt 3) { continue }
        $chH = @{}
        foreach ($ch in $k.ToCharArray()) {
            $key = [int]$ch
            if ($chH.ContainsKey($key)) { $chH[$key]++ } else { $chH[$key] = 1 }
        }
        $common = 0
        foreach ($ch in $raw.ToCharArray()) {
            $key = [int]$ch
            if ($chH.ContainsKey($key) -and $chH[$key] -gt 0) { $common++; $chH[$key]-- }
        }
        $maxLen = [Math]::Max($raw.Length, $k.Length)
        $score = $common / $maxLen
        if ($score -gt $bestScore) { $bestScore = $score; $best = $k }
    }
    if ($bestScore -ge 0.45) { return "$best" }
    return $raw
}

for ($i = 0; $i -lt $groups.Count -and $i -lt 8; $i++) {
    $gr = $groups[$i]
    $gx = [Math]::Max(0, $gr.From - 8)
    $gw = [Math]::Min($w - $gx, ($gr.To - $gr.From) + 17)
    $gy = $ty
    $gh = $th2
    if ($gw -lt 20 -or $gh -lt 8) { continue }

    # 放大 12 倍 + 二值化
    $sc = 12
    $big = New-Object System.Drawing.Bitmap([int]($gw*$sc), [int]($gh*$sc))
    $g2 = [System.Drawing.Graphics]::FromImage($big)
    $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g2.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g2.DrawImage($bmp, (New-Object System.Drawing.Rectangle(0,0,$big.Width,$big.Height)),
        (New-Object System.Drawing.Rectangle($gx,$gy,$gw,$gh)), [System.Drawing.GraphicsUnit]::Pixel)
    $g2.Dispose()
    # 二值化（阈值按亮度自适应）
    for ($yy=0; $yy -lt $big.Height; $yy++) {
        for ($xx=0; $xx -lt $big.Width; $xx++) {
            $c = $big.GetPixel($xx,$yy)
            $lum = ($c.R*299 + $c.G*587 + $c.B*114) / 1000
            $big.SetPixel($xx,$yy, $(if ($lum -gt 150) { [System.Drawing.Color]::Black } else { [System.Drawing.Color]::White }))
        }
    }
    $f = Join-Path $tmpDir "card$i.png"
    $big.Save($f, [System.Drawing.Imaging.ImageFormat]::Png)
    if ($Save) { Copy-Item $f "d:\a_game_scrpit\JskpBoxManager\explore-mem\46160\ocr-card$i.png" -Force }
    $big.Dispose()

    $raw = & $tess $f stdout -l chi_sim --psm 7 2>&1
    $txt = ($raw -join '').Trim()
    # 只保留中文/字母/数字/加号
    $clean = -join ($txt.ToCharArray() | Where-Object { ($_ -ge [char]0x4E00 -and $_ -le [char]0x9FFF) -or [char]::IsLetterOrDigit($_) -or $_ -eq '+' })
    # 原图里若明显有「+」而 OCR 没给出，补上（技能名常见后缀）
    if ($clean -notmatch '\+' -and $txt -match '\+') { $clean += '+' }
    if ($clean.Length -ge 2) {
        $fixed = Fix-Name $clean
        $names += [pscustomobject]@{ Index = $i+1; Raw = $clean; Name = $fixed; X = $gx; W = $gw }
    }
}
Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
$bmp.Dispose()

Write-Host ""
if ($names.Count -eq 0) { Write-Host "没识别出技能卡" -ForegroundColor Yellow; exit 5 }

if ($Json) {
    $out = @{ ok = $true; count = $names.Count; skills = @($names | ForEach-Object { @{ index = $_.Index; name = $_.Name; raw = $_.Raw } }) }
    $out | ConvertTo-Json -Depth 5 -Compress
    exit 0
}

Write-Host "当前可选技能 $($names.Count) 个：" -ForegroundColor Green
foreach ($n in $names) {
    if ($n.Raw -ne $n.Name) { Write-Host ("  [{0}] {1}   (OCR: {2})" -f $n.Index, $n.Name, $n.Raw) }
    else { Write-Host ("  [{0}] {1}" -f $n.Index, $n.Name) }
}
