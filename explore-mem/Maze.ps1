# 雾境迷宫：自动定位当前位置与下一步可选格子
#
# 不需要任何硬编码地址。脚本自己做这几件事：
#   1. 找游戏渲染进程（WeChatAppEx --type=renderer --wmpf-render-type=2），
#      并用命令行 / 父进程里的 C:\Sandbox\<用户>\qbN 路径确认它属于哪个沙箱
#   2. 扫 wasm 线性内存找格子列表（结构特征判定，不认地址）
#   3. 反查引用得到 MazeDataMgr 基址
#   4. 输出当前行 / 当前层 / 两个可选格子
#
# 用法：
#   .\Maze.ps1                   # 自动找唯一在跑的游戏
#   .\Maze.ps1 -Box qb1          # 指定沙箱
#   .\Maze.ps1 -RendererPid 38200  # 直接指定渲染进程

param(
    [string]$Box = '',
    [int]$RendererPid = 0
)

$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot '46160\MemProbe\bin\Release\net8.0\MemProbe.exe'
if (-not (Test-Path $exe)) {
    Write-Host "找不到 MemProbe.exe，先编译：" -ForegroundColor Yellow
    Write-Host "  cd `"$PSScriptRoot\46160\MemProbe`"; dotnet build -c Release" -ForegroundColor Yellow
    exit 2
}

if ($RendererPid -le 0) {
    # 父进程链上会有 --wmpf_root_dir="C:\Sandbox\<用户>\qbN\..."
    $all = Get-CimInstance Win32_Process -Filter "Name='WeChatAppEx.exe'" |
        Where-Object { $_.CommandLine -match '--type=renderer' -and $_.CommandLine -match '--wmpf-render-type=2' }

    $rows = foreach ($p in $all) {
        $box = ''
        # 自身命令行
        if ($p.CommandLine -match 'C:\\Sandbox\\[^\\]+\\(qb\d+)') { $box = $matches[1] }
        # 往上找父进程（QQBrowser 的命令行带 --wmpf_root_dir=...\qbN\...）
        if (-not $box) {
            $cur = $p
            for ($i = 0; $i -lt 4 -and $cur; $i++) {
                $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($cur.ParentProcessId)" -ErrorAction SilentlyContinue
                if (-not $parent) { break }
                if ($parent.CommandLine -match 'C:\\Sandbox\\[^\\]+\\(qb\d+)') { $box = $matches[1]; break }
                $cur = $parent
            }
        }
        $ws = 0
        try { $ws = (Get-Process -Id $p.ProcessId -ErrorAction Stop).WorkingSet64 } catch { }
        [pscustomobject]@{ Pid = [int]$p.ProcessId; Box = $box; MemMB = [math]::Round($ws / 1MB, 1) }
    }

    if (-not $rows) {
        Write-Host "没有运行中的游戏渲染进程（游戏没开？）" -ForegroundColor Red
        exit 3
    }

    if ($Box) {
        $rows = @($rows | Where-Object { $_.Box -eq $Box })
        if (-not $rows) { Write-Host "$Box 里没有运行中的游戏" -ForegroundColor Red; exit 3 }
    }

    $pick = $rows | Sort-Object MemMB -Descending | Select-Object -First 1
    $RendererPid = $pick.Pid
    $label = if ($pick.Box) { $pick.Box } else { '(未知沙箱)' }
    Write-Host "沙箱 $label   渲染进程 PID $RendererPid   $($pick.MemMB) MB" -ForegroundColor Cyan
    if ($rows.Count -gt 1) {
        Write-Host "  （同时有 $($rows.Count) 个游戏在跑，用 -Box 指定）" -ForegroundColor DarkGray
    }
}

& $exe maze --pid $RendererPid
exit $LASTEXITCODE
