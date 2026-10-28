# 打包：生成 dist\JskpBoxManager-<版本>\JskpBoxManager.exe 和同名 zip
# 用法：powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if (-not $dotnet) { $dotnet = 'C:\Program Files\dotnet\dotnet.exe' }
if (-not (Test-Path $dotnet)) { throw '没找到 .NET SDK：winget install Microsoft.DotNet.SDK.8' }

[xml]$props = Get-Content (Join-Path $root 'Directory.Build.props') -Encoding UTF8
$version = $props.Project.PropertyGroup.Version
$commit = ''
try { $commit = (git -C $root rev-parse --short HEAD 2>$null) } catch {}
$info = if ($commit) { "$version+$commit" } else { $version }

$out = Join-Path $root "dist\JskpBoxManager-$version"
if (Test-Path $out) { Remove-Item $out -Recurse -Force }

& $dotnet publish (Join-Path $root 'src\JskpBoxManager\JskpBoxManager.csproj') -c Release -o $out "-p:InformationalVersion=$info" --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish 失败（$LASTEXITCODE）" }

Get-ChildItem $out -Filter *.pdb | Remove-Item -Force
Copy-Item (Join-Path $root 'CHANGELOG.md'), (Join-Path $root 'README.md') $out

$zip = "$out.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zip
$exe = Get-Item (Join-Path $out 'JskpBoxManager.exe')
"{0}  {1:N1} MB" -f $exe.FullName, ($exe.Length / 1MB)
"{0}" -f $zip
