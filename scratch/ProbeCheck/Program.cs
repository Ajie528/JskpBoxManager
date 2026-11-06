using JskpBoxManager.Core;

var box = args.Length > 0 ? args[0] : "qb16";
var pids = Sandboxie.Pids(box);
Console.WriteLine($"{box} Pids.Count={pids.Count}: {string.Join(",", pids)}");
var view = new BoxView(box);
Console.WriteLine($"HasQqOrGame={view.HasQqOrGame} WeChatRuntimeUp={view.WeChatRuntimeUp} HasGameWindow={view.HasGameWindow}");
Console.WriteLine($"HasWeChat={view.HasWeChat}");
foreach (var pid in view.Pids)
{
    try { Console.WriteLine($"  pid={pid} {ProcessUtil.NameOf(pid)}"); } catch { }
}
var (ok, why) = ProtocolRenew.CheckRenewable(box);
Console.WriteLine($"CheckRenewable ok={ok} why={why.Replace("\n", " ")}");
Console.WriteLine($"BusyState={ProtocolRenew.BusyState(box)}");
