# 在沙箱游戏渲染进程里找一个数值（如攻击力）的所有存放形式，打印上下文，用来找稳定的读取特征。只读。
# 用法：powershell -ExecutionPolicy Bypass -File tools\probe-value.ps1 -Value 80625 [-ProcessId N] [-Box qb1]
param(
    [Parameter(Mandatory = $true)][long]$Value,
    [string]$Box = 'qb1',
    [int]$ProcessId = 0,
    [int]$MaxShow = 30,
    [string]$Out = ''
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class MemProbe {
  [StructLayout(LayoutKind.Sequential)]
  public struct MBI { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State, Protect, Type; }
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
  [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public class Hit { public string Kind; public long Addr; public long RegionBase; public long AllocBase; public uint Type; public byte[] Ctx; public int CtxBefore; }
  public static long TotalBytes;
  public static List<Hit> Scan(int pid, long value, int ctxBefore, int ctxAfter) {
    var hits = new List<Hit>();
    IntPtr h = OpenProcess(0x0410, false, pid);
    if (h == IntPtr.Zero) return hits;
    var needles = new List<KeyValuePair<string, byte[]>>();
    needles.Add(new KeyValuePair<string, byte[]>("i32", BitConverter.GetBytes((int)value)));
    needles.Add(new KeyValuePair<string, byte[]>("smi", BitConverter.GetBytes((int)(value << 1))));
    needles.Add(new KeyValuePair<string, byte[]>("f64", BitConverter.GetBytes((double)value)));
    needles.Add(new KeyValuePair<string, byte[]>("f32", BitConverter.GetBytes((float)value)));
    needles.Add(new KeyValuePair<string, byte[]>("a8", Encoding.ASCII.GetBytes(value.ToString())));
    needles.Add(new KeyValuePair<string, byte[]>("u16", Encoding.Unicode.GetBytes(value.ToString())));
    TotalBytes = 0;
    try {
      long addr = 0;
      byte[] buf = new byte[4 << 20];
      while (addr < 0x7FFFFFFF0000L) {
        MBI m;
        if (VirtualQueryEx(h, new IntPtr(addr), out m, (IntPtr)Marshal.SizeOf(typeof(MBI))) == IntPtr.Zero) break;
        long b = m.BaseAddress.ToInt64(), size = m.RegionSize.ToInt64();
        bool ok = m.State == 0x1000 && (m.Protect & 0x101) == 0 && (m.Protect & 0xEE) != 0;
        if (ok) {
          for (long off = 0; off < size; off += buf.Length - 64) {
            long want = Math.Min(buf.Length, size - off);
            IntPtr got;
            if (!ReadProcessMemory(h, new IntPtr(b + off), buf, (IntPtr)want, out got)) continue;
            int n = (int)got.ToInt64();
            TotalBytes += n;
            foreach (var nd in needles) {
              byte[] k = nd.Value;
              bool aligned = nd.Key == "i32" || nd.Key == "smi" || nd.Key == "f32" || nd.Key == "f64";
              int step = aligned ? (nd.Key == "f64" ? 8 : 4) : 1;
              int i = 0;
              while (i <= n - k.Length) {
                int at = Array.IndexOf(buf, k[0], i, n - k.Length + 1 - i);
                if (at < 0) break;
                bool eq = true;
                for (int q = 1; q < k.Length; q++) if (buf[at + q] != k[q]) { eq = false; break; }
                if (!eq) { i = at + 1; continue; }
                if (!aligned || ((b + off + at) % step) == 0) {
                  // a8 文本：前后不能是数字，避免 806250 之类
                  bool boundary = true;
                  if (nd.Key == "a8") {
                    if (at > 0 && buf[at - 1] >= '0' && buf[at - 1] <= '9') boundary = false;
                    if (at + k.Length < n && buf[at + k.Length] >= '0' && buf[at + k.Length] <= '9') boundary = false;
                  }
                  if (boundary) {
                    int s = Math.Max(0, at - ctxBefore);
                    int e = Math.Min(n, at + k.Length + ctxAfter);
                    var ctx = new byte[e - s];
                    Array.Copy(buf, s, ctx, 0, ctx.Length);
                    hits.Add(new Hit { Kind = nd.Key, Addr = b + off + at, RegionBase = b, AllocBase = m.AllocationBase.ToInt64(), Type = m.Type, Ctx = ctx, CtxBefore = at - s });
                  }
                }
                i = at + 1;
              }
            }
            if (want < buf.Length) break;
          }
        }
        addr = b + size;
      }
    } finally { CloseHandle(h); }
    return hits;
  }
}
'@ -Language CSharp

$sbie = 'E:\Program Files\Sandboxie-Plus\Start.exe'
$pids = @()
if ($ProcessId -gt 0) { $pids = @($ProcessId) } else {
    $boxPids = @(& $sbie "/box:$Box" /listpids | Select-Object -Skip 1 | ForEach-Object { [int]$_ })
    $pids = @(Get-CimInstance Win32_Process -Filter "Name='WeChatAppEx.exe'" | Where-Object { $boxPids -contains [int]$_.ProcessId -and $_.CommandLine -match '--type=renderer' } |
        Sort-Object { (Get-Process -Id $_.ProcessId).WorkingSet64 } -Descending | ForEach-Object { [int]$_.ProcessId })
}
$lines = New-Object System.Collections.Generic.List[string]
foreach ($procId in $pids) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $hits = [MemProbe]::Scan($procId, $Value, 0x80, 0x80)
    $lines.Add(("== pid {0}  扫描 {1:N0} MB 用时 {2:N1}s  命中 {3}" -f $procId, ([MemProbe]::TotalBytes / 1MB), $sw.Elapsed.TotalSeconds, $hits.Count))
    foreach ($g in ($hits | Group-Object Kind)) { $lines.Add(("   {0}: {1}" -f $g.Name, $g.Count)) }
    foreach ($kind in 'a8', 'u16', 'f64', 'i32', 'smi', 'f32') {
        $shown = 0
        foreach ($hit in ($hits | Where-Object Kind -eq $kind)) {
            if ($shown -ge $MaxShow) { break }
            $shown++
            $lines.Add(("-- {0} @0x{1:X}  region=0x{2:X}+0x{3:X} alloc=0x{4:X} type=0x{5:X}" -f $hit.Kind, $hit.Addr, $hit.RegionBase, ($hit.Addr - $hit.RegionBase), $hit.AllocBase, $hit.Type))
            if ($kind -in 'a8', 'u16') {
                $enc = if ($kind -eq 'u16') { [Text.Encoding]::Unicode } else { [Text.Encoding]::UTF8 }
                $txt = $enc.GetString($hit.Ctx) -replace '[\x00-\x1F]', '.'
                $lines.Add('   ' + $txt)
            } else {
                $c = $hit.Ctx; $base = $hit.CtxBefore - ($hit.CtxBefore % 4)
                $row = New-Object System.Text.StringBuilder
                for ($o = $base % 4; $o + 4 -le $c.Length; $o += 4) {
                    $rel = $o - $hit.CtxBefore
                    $v = [BitConverter]::ToInt32($c, $o)
                    [void]$row.AppendFormat('{0}{1:X3}:{2} ', $(if ($rel -lt 0) { '-' } else { '+' }), [Math]::Abs($rel), $v)
                }
                $lines.Add('   ' + $row.ToString())
            }
        }
    }
}
if ($Out) { $lines | Set-Content -Path $Out -Encoding UTF8; "已写入 $Out" } else { $lines }
