# 把新构建的程序部署到现役安装目录，**只换程序、绝不动运行数据**。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File deploy.ps1              # 构建 + 部署
#   powershell -ExecutionPolicy Bypass -File deploy.ps1 -SkipBuild   # 部署 dist 里现有产物
#
# 为什么需要这个脚本：现役安装目录（默认 D:\a_game_scrpit\JskpBoxManager-exe）
# 里程序和运行数据混在一起——profiles（16 个号的登录凭证、游戏包）、logs、
# keepalive.json 等。直接把 dist 覆盖过去会把这些全删掉。
# 所以这里按「程序产物白名单」只写这几样：
#     JskpBoxManager.exe / CHANGELOG.md / README.md / tools\lean-refresh\*.py,*.js,*.md
# 其余一律不碰。
param(
    [string]$Target = 'D:\a_game_scrpit\JskpBoxManager-exe',
    [switch]$SkipBuild,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

[xml]$props = Get-Content (Join-Path $root 'Directory.Build.props') -Encoding UTF8
$version = $props.Project.PropertyGroup.Version
$src = Join-Path $root "dist\JskpBoxManager-$version"

if (-not $SkipBuild) {
    & (Join-Path $root 'build.ps1')
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'build.ps1 失败' }
}
if (-not (Test-Path $src)) { throw "没有构建产物：$src（先跑 build.ps1，或去掉 -SkipBuild）" }

if (-not (Test-Path $Target)) {
    if (-not $Force) { throw "目标目录不存在：$Target（确实要新建请加 -Force）" }
    New-Item -ItemType Directory -Force -Path $Target | Out-Null
}

# 目标里这个 exe 正在跑就不能换：文件被占用，且半套替换会留下不一致状态
$running = Get-Process -Name 'JskpBoxManager' -ErrorAction SilentlyContinue |
           Where-Object { $_.Path -and $_.Path.StartsWith($Target, [StringComparison]::OrdinalIgnoreCase) }
if ($running) {
    throw "目标程序正在运行（pid $(($running | ForEach-Object { $_.Id }) -join ', ')），请先关闭窗口再部署。"
}

Write-Host "部署 $version"
Write-Host "  来源 $src"
Write-Host "  目标 $Target"

# ---- 1. 备份旧 exe（只留一份，够回滚） ----
$exeDst = Join-Path $Target 'JskpBoxManager.exe'
$hadOld = Test-Path $exeDst
if ($hadOld) {
    Copy-Item $exeDst (Join-Path $Target 'JskpBoxManager.exe.bak') -Force
    Write-Host "  旧 exe -> JskpBoxManager.exe.bak"
}

# ---- 2. 只拷程序产物 ----
$files = @('JskpBoxManager.exe', 'CHANGELOG.md', 'README.md')
$n = 0
foreach ($f in $files) {
    $p = Join-Path $src $f
    if (Test-Path $p) { Copy-Item $p (Join-Path $Target $f) -Force; $n++ }
    elseif ($f -eq 'JskpBoxManager.exe') { throw "构建产物里没有 $f" }
}

# hook/观测用的 Frida 脚本属于程序的一部分，但它在 tools\ 下（该目录也放用户数据），
# 所以只按扩展名精确更新，不整目录覆盖。
$toolSrc = Join-Path $src 'tools\lean-refresh'
$toolDst = Join-Path $Target 'tools\lean-refresh'
if (Test-Path $toolSrc) {
    New-Item -ItemType Directory -Force -Path $toolDst | Out-Null
    Get-ChildItem $toolSrc -File -Include *.py, *.js, *.md | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $toolDst $_.Name) -Force
        $n++
    }
}
Write-Host "  写入 $n 个程序文件"

# ---- 3. 清掉历史残留（旧版本升级留下的大文件） ----
Get-ChildItem $Target -Filter '*.tmp' -File -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item $_.FullName -Force
    Write-Host "  清掉残留 $($_.Name)（$([math]::Round($_.Length/1MB,1)) MB）"
}

# ---- 4. 校验 ----
$exe = Get-Item $exeDst
$sha = (Get-FileHash $exeDst -Algorithm SHA256).Hash.ToLowerInvariant()

# 注意：这个程序是 WPF 应用，直接 & 调用时控制台输出会被吞掉（不是同步可捕获的），
# 必须走 cmd 重定向拿回 stdout。
$ver = (& cmd /c "`"$exeDst`" version 2>&1") -join ' '
$fileVer = $exe.VersionInfo.FileVersion

Write-Host ""
Write-Host "完成  $($exe.LastWriteTime)  $([math]::Round($exe.Length/1MB,1)) MB"
Write-Host "  文件版本 $fileVer"
Write-Host "  运行输出 $(if ($ver.Trim().Length) { $ver.Trim() } else { '(无输出)' })"
Write-Host "  sha256  $sha"
if (-not $fileVer.StartsWith($version)) {
    Write-Host "  ⚠ 文件版本不是 $version，请核对" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "运行数据未改动："
foreach ($d in @('profiles', 'logs')) {
    $p = Join-Path $Target $d
    if (Test-Path $p) {
        $cnt = (Get-ChildItem $p -Force -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host ("  {0}\  {1} 项  最后改动 {2}" -f $d, $cnt, (Get-Item $p).LastWriteTime)
    }
}
