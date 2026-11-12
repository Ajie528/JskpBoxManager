# 精确读取 DataGrid 每列的 Header 与 ActualWidth
param([int]$ProcId)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcId)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Write-Host "没找到窗口"; exit 1 }

$gridCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::DataGrid)
$grid = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $gridCond)
if (-not $grid) { Write-Host "没找到 DataGrid（WPF 需要开启 Accessibility）"; exit 1 }

$hdrCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::Header)
$hdr = $grid.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $hdrCond)
if ($hdr) {
    $items = $hdr.FindAll([System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition)
    $i = 0
    foreach ($it in $items) {
        $r = $it.Current.BoundingRectangle
        Write-Host ("[{0,2}] {1,-16} 实际宽 {2,6:N0}px" -f $i, $it.Current.Name, $r.Width)
        $i++
    }
}
