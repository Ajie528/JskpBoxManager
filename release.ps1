# 发版：打包 → 打标签 → 在 GitHub 创建 Release 并上传 exe / sha256 / zip
# 用法：powershell -ExecutionPolicy Bypass -File release.ps1
# 前提：代码已提交并推送；CHANGELOG.md 里有本版本的一节；已 gh auth login
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location $root

$gh = (Get-Command gh -ErrorAction SilentlyContinue).Source
if (-not $gh) { $gh = 'C:\Program Files\GitHub CLI\gh.exe' }
if (-not (Test-Path $gh)) { throw '没找到 GitHub CLI：winget install GitHub.cli，然后 gh auth login' }

[xml]$props = Get-Content (Join-Path $root 'Directory.Build.props') -Encoding UTF8
$version = $props.Project.PropertyGroup.Version
$tag = "v$version"

if (git status --porcelain) { throw '还有没提交的改动，先提交再发版' }
if (git tag -l $tag) { throw "标签 $tag 已存在：先改 Directory.Build.props 的版本号" }

$changelog = Get-Content (Join-Path $root 'CHANGELOG.md') -Encoding UTF8
$start = -1; $end = $changelog.Count
for ($i = 0; $i -lt $changelog.Count; $i++) {
    if ($changelog[$i] -match '^## \[') {
        if ($start -ge 0) { $end = $i; break }
        if ($changelog[$i] -match ('^## \[' + [regex]::Escape($version) + '\]')) { $start = $i + 1 }
    }
}
if ($start -lt 0) { throw "CHANGELOG.md 里没有 ## [$version] 这一节" }
$notes = ($changelog[$start..($end - 1)] -join "`n").Trim()
$notesFile = Join-Path $env:TEMP "jskp-release-$version.md"
[IO.File]::WriteAllText($notesFile, $notes, (New-Object Text.UTF8Encoding $false))

& (Join-Path $root 'build.ps1')
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'build.ps1 失败' }

$out = Join-Path $root "dist\JskpBoxManager-$version"
$assets = @(
    (Join-Path $out 'JskpBoxManager.exe'),
    (Join-Path $root 'dist\JskpBoxManager.exe.sha256'),
    "$out.zip"
)
foreach ($a in $assets) { if (-not (Test-Path $a)) { throw "缺少发布文件 $a" } }

git tag -a $tag -m "向僵多开管家 $tag"
git push origin $tag
& $gh release create $tag @assets --title "向僵多开管家 $tag" --notes-file $notesFile
if ($LASTEXITCODE -ne 0) { throw 'gh release create 失败' }
"已发布 $tag"
