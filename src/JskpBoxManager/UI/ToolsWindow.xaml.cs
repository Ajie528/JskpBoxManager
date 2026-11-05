using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Threading;
using JskpBoxManager.Core;
using Microsoft.Win32;

namespace JskpBoxManager.UI;

/// <summary>
/// 高级工具窗口：把命令行子命令（token/keylog/capture/unpack/hook/lean/observe/status/role/cred-*/clear/delbox）
/// 包装成按钮，子进程运行并实时显示输出。复用已测通的 CLI 代码路径。
/// </summary>
public partial class ToolsWindow : Window
{
    readonly string _box;
    Process _proc;
    string _tokenJson = "";

    public ToolsWindow(string box)
    {
        InitializeComponent();
        _box = box;
        Title = $"高级工具 - {box}";
        TxtTitle.Text = $"高级工具 · {box}";
        TxtSub.Text = Notes.Load().GetValueOrDefault(box) ?? "";
    }

    // ---------- 运行子进程 ----------

    bool Busy => _proc != null && !_proc.HasExited;

    void Run(string label, bool cold, params string[] cmdArgs)
    {
        if (Busy) { SetStatus("有命令在运行，先停止或等它结束"); return; }
        if (cold && !Confirm($"「{label}」会冷启动/重启沙箱 {_box}。继续？")) return;

        _tokenJson = "";
        BtnCopyToken.Visibility = Visibility.Collapsed;
        TxtResult.Text = "";
        TxtOut.Clear();
        Append($"$ JskpBoxManager.exe {string.Join(" ", cmdArgs)}\r\n");

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
        foreach (var a in cmdArgs) psi.ArgumentList.Add(a);
        psi.ArgumentList.Add("--appdir");
        psi.ArgumentList.Add(AppPaths.AppDir);

        try
        {
            _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _proc.OutputDataReceived += (_, e) => OnLine(e.Data, stdout: true);
            _proc.ErrorDataReceived += (_, e) => OnLine(e.Data, stdout: false);
            _proc.Exited += (_, _) => Dispatcher.BeginInvoke(() => OnExit(label));
            _proc.Start();
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();
            SetBusy(true);
            SetStatus($"正在运行：{label} …");
        }
        catch (Exception ex)
        {
            Append("启动失败：" + ex.Message + "\r\n");
            SetStatus("启动失败");
            _proc = null;
        }
    }

    void OnLine(string line, bool stdout)
    {
        if (line == null) return;
        // token 命令 stdout 的 JSON 结果
        if (stdout && line.TrimStart().StartsWith("{\"ok\"", StringComparison.Ordinal))
            _tokenJson = line.Trim();
        Dispatcher.BeginInvoke(() => Append(line + "\r\n"));
    }

    void OnExit(string label)
    {
        int code = -1;
        try { code = _proc?.ExitCode ?? -1; } catch { }
        SetBusy(false);
        if (_tokenJson.Length > 0)
        {
            ShowTokenResult(_tokenJson);
            SetStatus($"{label} 完成（已取到 Token）");
        }
        else
        {
            SetStatus($"{label} 结束（退出码 {code}）");
            if (label == "删除沙箱" && code != 0)
                MessageBox.Show(this,
                    $"沙箱 {_box} 的数据已清除，但 Sandboxie 配置段没有确认删除。\n\n" +
                    "如果本程序列表里仍能看到它，请到 Sandboxie 管理器里删除，或重启 Sandboxie 服务后重试。\n\n" +
                    $"详细日志：logs\\{_box}.log",
                    "删除未完全成功", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        _proc = null;
    }

    void ShowTokenResult(string json)
    {
        try
        {
            var o = System.Text.Json.Nodes.JsonNode.Parse(json) as System.Text.Json.Nodes.JsonObject;
            var token = JsonFile.Str(o, "token");
            var uin = JsonFile.Str(o, "uin");
            if (token.Length > 0)
            {
                _tokenJson = json;
                BtnCopyToken.Visibility = Visibility.Visible;
                TxtResult.Text = $"✓ Token 已取到（uin={uin}）";
                Append($"\r\n==> uin={uin}  token 长度={token.Length}，点右下「复制 Token」\r\n");
            }
        }
        catch { }
    }

    // ---------- 按钮 ----------

    string[] Sec() => int.TryParse(TxtSeconds.Text.Trim(), out var v) && v > 0
        ? new[] { "--seconds", v.ToString() } : Array.Empty<string>();

    void Launch_Click(object s, RoutedEventArgs e) => Run("启动游戏", true, "launch", _box);
    void Refresh_Click(object s, RoutedEventArgs e) => Run("静默保活", true, "refresh", _box);
    void Token_Click(object s, RoutedEventArgs e) => Run("取业务 Token", true, Concat(new[] { "token", _box }, Sec()));
    void Keylog_Click(object s, RoutedEventArgs e) => Run("导出 TLS 密钥", true, Concat(new[] { "keylog", _box }, Sec()));
    void Capture_Click(object s, RoutedEventArgs e) => Run("抓 wx.request", true, Concat(new[] { "capture", _box }, Sec()));
    void Hook_Click(object s, RoutedEventArgs e) => Run("Frida 观测", true, Concat(new[] { "hook", _box }, Sec()));
    void Lean_Click(object s, RoutedEventArgs e) => Run("精简启动实验", true, Concat(new[] { "lean", _box }, Sec()));
    void Observe_Click(object s, RoutedEventArgs e) => Run("窗口/凭证观测", true, Concat(new[] { "observe", _box, "--launch" }, Sec()));
    void Unpack_Click(object s, RoutedEventArgs e) => Run("解包 wxapkg", false, "unpack", _box);
    void Status_Click(object s, RoutedEventArgs e) => Run("状态", false, "status", _box);
    void Role_Click(object s, RoutedEventArgs e) => Run("读角色", false, "role", _box);
    void Stop_Click(object s, RoutedEventArgs e) => Run("停止沙箱", false, "stop", _box);

    void CredSave_Click(object s, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "选择导出凭证到的目录" };
        if (dlg.ShowDialog(this) == true) Run("导出凭证", false, "cred-save", _box, "--dir", dlg.FolderName);
    }

    void CredLoad_Click(object s, RoutedEventArgs e)
    {
        if (!Confirm("导入会覆盖沙箱当前凭证，需先停箱。继续选择目录？")) return;
        var dlg = new OpenFolderDialog { Title = "选择要写回的凭证目录" };
        if (dlg.ShowDialog(this) == true) Run("导入凭证", true, "cred-load", _box, "--dir", dlg.FolderName);
    }

    void Clear_Click(object s, RoutedEventArgs e)
    {
        if (Confirm($"确定清除 {_box} 的登录？下次启动要重新扫码（游戏包和备注保留）。"))
            Run("清除登录", true, "clear", _box);
    }

    void Delbox_Click(object s, RoutedEventArgs e)
    {
        if (Confirm($"彻底删除沙箱 {_box}？登录、游戏包、备注、保活任务、配置全部清除，不可恢复！"))
            Run("删除沙箱", true, "delbox", _box);
    }

    // ---------- 底栏 ----------

    void StopRun_Click(object s, RoutedEventArgs e)
    {
        try { if (Busy) { _proc.Kill(true); Append("\r\n[已终止]\r\n"); } } catch { }
    }

    void CopyOut_Click(object s, RoutedEventArgs e)
    {
        if (Win32.SetClipboardText(TxtOut.Text)) SetStatus("已复制输出");
        else SetStatus("复制失败（剪贴板被占用）");
    }

    void CopyToken_Click(object s, RoutedEventArgs e)
    {
        try
        {
            var o = System.Text.Json.Nodes.JsonNode.Parse(_tokenJson) as System.Text.Json.Nodes.JsonObject;
            var token = JsonFile.Str(o, "token");
            if (Win32.SetClipboardText(token)) SetStatus("已复制 Token");
            else SetStatus("复制失败（剪贴板被占用）");
        }
        catch { SetStatus("没有可复制的 Token"); }
    }

    void CloseWin_Click(object s, RoutedEventArgs e) => Close();

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        try { if (Busy && !_proc.HasExited) { /* 让子进程自己收尾（可能在停箱）*/ } } catch { }
        base.OnClosing(e);
    }

    // ---------- 工具 ----------

    static string[] Concat(string[] a, string[] b) => a.Concat(b).ToArray();

    bool Confirm(string msg) =>
        MessageBox.Show(this, msg, "确认", MessageBoxButton.OKCancel, MessageBoxImage.Question) == MessageBoxResult.OK;

    void Append(string text)
    {
        TxtOut.AppendText(text);
        TxtOut.ScrollToEnd();
    }

    void SetStatus(string m) => TxtStatus.Text = m;

    void SetBusy(bool busy)
    {
        BtnStop.IsEnabled = busy;
    }
}
