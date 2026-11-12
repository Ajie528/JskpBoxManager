# 用 UI Automation 读取 DataGrid 每行每列的实际文本（定位「列空白」是数据问题还是渲染问题）
param([int]$ProcId)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcId)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Write-Host "没找到窗口"; exit 1 }
Write-Host ("窗口: " + $win.Current.Name)

# 找 DataGrid
$gridCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::DataGrid)
$grid = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $gridCond)
if (-not $grid) { Write-Host "没找到 DataGrid"; exit 1 }

# 表头
$hdrCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::Header)
$hdr = $grid.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $hdrCond)
$headers = @()
if ($hdr) {
    $items = $hdr.FindAll([System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($it in $items) { $headers += $it.Current.Name }
}
Write-Host ("表头: " + ($headers -join ' | '))
Write-Host ""

# 前 3 行
$rowCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::DataItem)
$rows = $grid.FindAll([System.Windows.Automation.TreeScope]::Children, $rowCond)
Write-Host ("行数: " + $rows.Count)
for ($i = 0; $i -lt [Math]::Min(3, $rows.Count); $i++) {
    $cells = $rows[$i].FindAll([System.Windows.Automation.TreeScope]::Children,
        (New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Custom)))
    $vals = @()
    foreach ($c in $cells) { $vals += ($c.Current.Name -replace "`r?`n", " ") }
    Write-Host ("行{0}: {1}" -f $i, ($vals -join ' || '))
}
