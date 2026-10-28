# 以角色 ID（8 字节）为锚点，把游戏渲染进程里每一处出现位置前后的 int32 存成快照，用来对比换装备前后哪些格子变了。只读。
# 用法：
#   拍快照：powershell -ExecutionPolicy Bypass -File tools\probe-anchor.ps1 -RoleId 4170728974166104000 -Save before.json
#   对比：  powershell -ExecutionPolicy Bypass -File tools\probe-anchor.ps1 -Diff before.json,after.json -Old 80625 -New 81000
param(
    [UInt64]$RoleId = 0,
    [string]$Box = 'qb1',
    [int]$ProcessId = 0,
    [string]$Save = '',
    [string[]]$Diff = @(),
    [long]$Old = 0,
    [long]$New = 0
)
$ErrorActionPreference = 'Stop'

if ($Diff.Count -eq 2) {
    $a = Get-Content $Diff[0] -Raw -Encoding UTF8 | ConvertFrom-Json
    $b = Get-Content $Diff[1] -Raw -Encoding UTF8 | ConvertFrom-Json
    $map = @{}
    foreach ($r in $b.records) { $map[$r.addr] = $r }
    "before anchors {0}, after anchors {1}" -f @($a.records).Count, @($b.records).Count
    foreach ($r in $a.records) {
        $o = $map[$r.addr]
        if (-not $o) { "anchor {0} gone in after" -f $r.addr; continue }
        for ($i = 0; $i -lt $r.v.Count; $i++) {
            if ($r.v[$i] -eq $o.v[$i]) { continue }
            $rel = ($i * 4) + $a.from
            $tag = if ($Old -and $r.v[$i] -eq $Old -and $o.v[$i] -eq $New) { '  <== ATTACK' } else { '' }
            "{0} {1}{2:X3}: {3} -> {4}{5}" -f $r.addr, $(if ($rel -lt 0) { '-' } else { '+' }), [Math]::Abs($rel), $r.v[$i], $o.v[$i], $tag
        }
    }
    $newOnly = @($b.records | Where-Object { -not ($a.records.addr -contains $_.addr) })
    if ($newOnly.Count) { "new anchors in after: " + (($newOnly | ForEach-Object addr) -join ', ') }
    return
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class AnchorProbe {
  [StructLayout(LayoutKind.Sequential)]
  public struct MBI { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State, Protect, Type; }
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
  [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public static List<KeyValuePair<long, int[]>> Scan(int pid, ulong id, int from, int to) {
    var res = new List<KeyValuePair<long, int[]>>();
    IntPtr h = OpenProcess(0x0410, false, pid);
    if (h == IntPtr.Zero) return res;
    byte[] k = BitConverter.GetBytes(id);
    try {
      long addr = 0;
      byte[] buf = new byte[4 << 20];
      while (addr < 0x7FFFFFFF0000L) {
        MBI m;
        if (VirtualQueryEx(h, new IntPtr(addr), out m, (IntPtr)Marshal.SizeOf(typeof(MBI))) == IntPtr.Zero) break;
        long b = m.BaseAddress.ToInt64(), size = m.RegionSize.ToInt64();
        if (m.State == 0x1000 && (m.Protect & 0x101) == 0 && (m.Protect & 0xEE) != 0) {
          for (long off = 0; off < size; off += buf.Length - 1024) {
            long want = Math.Min(buf.Length, size - off);
            IntPtr got;
            if (!ReadProcessMemory(h, new IntPtr(b + off), buf, (IntPtr)want, out got)) continue;
            int n = (int)got.ToInt64();
            for (int i = 0; i + 8 <= n; i += 4) {
              if (buf[i] != k[0] || buf[i + 7] != k[7]) continue;
              bool eq = true;
              for (int q = 1; q < 7; q++) if (buf[i + q] != k[q]) { eq = false; break; }
              if (!eq) continue;
              if (i + from < 0 || i + to > n) continue;
              var v = new int[(to - from) / 4];
              for (int q = 0; q < v.Length; q++) v[q] = BitConverter.ToInt32(buf, i + from + q * 4);
              res.Add(new KeyValuePair<long, int[]>(b + off + i, v));
            }
            if (want < buf.Length) break;
          }
        }
        addr = b + size;
      }
    } finally { CloseHandle(h); }
    return res;
  }
}
'@ -Language CSharp

$sbie = 'E:\Program Files\Sandboxie-Plus\Start.exe'
if ($ProcessId -le 0) {
    $boxPids = @(& $sbie "/box:$Box" /listpids | Select-Object -Skip 1 | ForEach-Object { [int]$_ })
    $ProcessId = @(Get-CimInstance Win32_Process -Filter "Name='WeChatAppEx.exe'" | Where-Object { $boxPids -contains [int]$_.ProcessId -and $_.CommandLine -match '--type=renderer' } |
        Sort-Object { (Get-Process -Id $_.ProcessId).WorkingSet64 } -Descending | ForEach-Object { [int]$_.ProcessId })[0]
}
$from = -0x80; $to = 0x180
$sw = [Diagnostics.Stopwatch]::StartNew()
$hits = [AnchorProbe]::Scan($ProcessId, $RoleId, $from, $to)
$recs = foreach ($h in $hits) { [pscustomobject]@{ addr = ('0x{0:X}' -f $h.Key); v = $h.Value } }
"pid {0}  role-id hits {1}  {2:N1}s" -f $ProcessId, $hits.Count, $sw.Elapsed.TotalSeconds
if ($Save) {
    [pscustomobject]@{ pid = $ProcessId; at = (Get-Date).ToString('s'); from = $from; records = @($recs) } | ConvertTo-Json -Depth 4 -Compress | Set-Content $Save -Encoding UTF8
    "saved $Save"
}
