using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using JskpBoxManager.Core;

namespace JskpBoxManager.UI;

/// <summary>
/// 历史凭证恢复窗口：列出当前金库 + 历史快照的 key，支持「试这把」单试和「自动逐个试」（调 recover 子命令）。
/// </summary>
public partial class RecoverWindow : Window
{
    readonly string _box;
    Process _proc;

    public sealed class Row
    {
        public CredCandidate Cand { get; init; }
        public string Title { get; init; }
        public string Sub { get; init; }
        public bool CanTry { get; init; }
    }

    public RecoverWindow(string box)
    {
        InitializeComponent();
        _box = box;
        Title = $"历史凭证恢复 - {box}";
        TxtTitle.Text = $"历史凭证恢复 · {box}";
        TxtSub.Text = Notes.Load().GetValueOrDefault(box) ?? "";
        LoadList();
    }

    bool Busy => _proc != null && !_proc.HasExited;

    void LoadList()
    {
        var cands = Ilink.CredentialHistory(_box);
        var rows = cands.Select(c => new Row
        {
            Cand = c,
            Title = $"{c.SavedAt:MM-dd HH:mm} · key {c.KeyShort}{(c.IsVault ? " · 当前金库" : "")}{(c.Revoked ? " · 已作废" : "")}",
            Sub = $"uin …{Tail(c.Uin)}" + (c.Tag.Length > 0 ? $" · {c.Tag}" : ""),
            CanTry = !c.Revoked,
        }).ToList();
        List.ItemsSource = rows;
        TxtStatus.Text = rows.Count == 0
            ? "没有历史凭证（这个号可能从没成功登录过）"
            : $"共 {rows.Count} 份凭证，可试 {rows.Count(r => r.CanTry)} 份";
    }

    static string Tail(string uin) => string.IsNullOrEmpty(uin) ? "?" : (uin.Length <= 5 ? uin : uin[^5..]);

    // ---------- 自动逐个试：跑 recover 子命令 ----------

    void Auto_Click(object sender, RoutedEventArgs e)
    {
        if (Busy) { SetStatus("已经在跑了"); return; }
        if (MessageBox.Show(this, $"将自动用历史 key 逐个冷启测试 {_box}，直到某把免扫成功或全部失败。\n每把约 1~2 分钟，期间会反复重启沙箱。继续？",
                "自动逐个试", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        TxtOut.Clear();
        Append($"$ JskpBoxManager.exe recover {_box}\r\n");
        var exe = Environment.ProcessPath ?? AppInfo.ExePath;
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("recover");
        psi.ArgumentList.Add(_box);
        psi.ArgumentList.Add("--appdir");
        psi.ArgumentList.Add(AppPaths.AppDir);
        try
        {
            _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _proc.OutputDataReceived += (_, ev) => OnLine(ev.Data);
            _proc.ErrorDataReceived += (_, ev) => OnLine(ev.Data);
            _proc.Exited += (_, _) => Dispatcher.BeginInvoke(() => OnExit());
            _proc.Start();
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();
            SetBusy(true);
            SetStatus("自动逐个试运行中…");
        }
        catch (Exception ex)
        {
            Append("启动失败：" + ex.Message + "\r\n");
            _proc = null;
        }
    }

    void OnLine(string line)
    {
        if (line == null) return;
        Dispatcher.BeginInvoke(() => Append(line + "\r\n"));
    }

    void OnExit()
    {
        int code = -1;
        try { code = _proc?.ExitCode ?? -1; } catch { }
        SetBusy(false);
        SetStatus(code == 0 ? "成功：某把历史 key 免扫恢复了" : code == 2 ? "都失败：真被顶/过期，需要重新扫码" : $"结束（退出码 {code}）");
        _proc = null;
        LoadList();
    }

    void Stop_Click(object sender, RoutedEventArgs e)
    {
        try { if (Busy) { _proc.Kill(true); Append("\r\n[已终止]\r\n"); } } catch { }
    }

    // ---------- 单试：试这把 ----------

    async void TryRow_Click(object sender, RoutedEventArgs e)
    {
        if (Busy) { SetStatus("自动逐个试在跑，先停止再手动试"); return; }
        if (sender is not Button { Tag: Row row }) return;
        if (MessageBox.Show(this, $"将停箱、写入 key {row.Cand.KeyShort}，先试协议续期（不开浏览器、0.5 秒）；\n"
                + "不通再回退冷启动验证。进了游戏或续期成功就是这把能用。继续？",
                "试这把", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        SetStatus($"正在写入 {row.Cand.KeyShort} 并验证…");
        Append($"\r\n== 手动试 key {row.Cand.KeyShort}（{row.Cand.SavedAt:MM-dd HH:mm}）==\r\n");

        // 先走协议续期：这是最快、也最接近「当初救回 qb10/qb12」的方式
        var pr = await Task.Run(() =>
        {
            var s = new RecoverSession(_box);
            return s.TryOneByProtocol(row.Cand);
        });
        Append((pr.Ok ? "协议续期：成功，新 key " + pr.NewKeyHash : "协议续期：" + pr.Message) + "\r\n");
        if (pr.Ok)
        {
            SetStatus("协议续期成功，已恢复");
            Append("这个号已恢复免扫，直接点「启动游戏」即可进入，不需要扫码。\r\n");
            LoadList();
            return;
        }
        if (pr.Rejected)
        {
            SetStatus("这把已被服务端拒绝，换一把");
            Append($"服务端明确拒绝（{pr.Code}），这把不行。\r\n");
            return;
        }

        Append("回退冷启动验证…\r\n");
        var (ok, msg) = await Task.Run(() => BoxRuntime.TryHistoryKey(_box, row.Cand.Dir, row.Cand.KeyHash));
        Append(msg + "\r\n");
        if (!ok) { SetStatus(msg); return; }
        BoxStatusFile.Write(_box, BoxPhase.Starting, $"试历史 key {row.Cand.KeyShort}…");
        try { ProcessUtil.StartDetached(Environment.ProcessPath ?? AppInfo.ExePath, new[] { "launch", _box, "--appdir", AppPaths.AppDir }, true); } catch { }
        Append("已冷启动，请看是否进游戏或弹扫码；进了游戏就是这把 key 能用。\r\n");
        SetStatus("已写入并冷启动，观察游戏窗/扫码页");
    }

    void Refresh_Click(object sender, RoutedEventArgs e) => LoadList();
    void Close_Click(object sender, RoutedEventArgs e) => Close();

    void Append(string text) { TxtOut.AppendText(text); TxtOut.ScrollToEnd(); }
    void SetStatus(string m) => TxtStatus.Text = m;
    void SetBusy(bool busy) { BtnStop.IsEnabled = busy; BtnAuto.IsEnabled = !busy; }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        base.OnClosing(e);
    }
}
