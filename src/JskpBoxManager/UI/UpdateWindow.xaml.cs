using System.Diagnostics;
using System.Windows;
using JskpBoxManager.Core;

namespace JskpBoxManager.UI;

public partial class UpdateWindow : Window
{
    readonly UpdateInfo _info;
    CancellationTokenSource _cts;

    public UpdateWindow(UpdateInfo info)
    {
        InitializeComponent();
        _info = info;
        TxtTitle.Text = $"新版本 v{info.Version} 可以更新了";
        TxtSub.Text = $"当前 {AppInfo.VersionLabel}，新版发布于 {info.Published:yyyy-MM-dd HH:mm}，大小约 {info.ExeSize / 1024.0 / 1024.0:N0} MB。\n" +
                      "更新只替换程序本身，金库、备注、保活设置都不动；正在玩的游戏不受影响。";
        MarkdownView.Fill(TxtNotes, string.IsNullOrWhiteSpace(info.Notes) ? "（这个版本没有写更新说明）" : info.Notes);
    }

    async void Update_Click(object sender, RoutedEventArgs e)
    {
        BtnUpdate.IsEnabled = BtnSkip.IsEnabled = false;
        BtnLater.Content = "取消";
        Bar.Visibility = Visibility.Visible;
        _cts = new CancellationTokenSource();
        var progress = new Progress<double>(p =>
        {
            Bar.Value = p;
            TxtProgress.Text = $"正在下载… {p * 100:N0}%";
        });
        try
        {
            var file = await Updater.DownloadAsync(_info, progress, _cts.Token);
            TxtProgress.Text = "下载完成，正在替换并打开新版…";
            App.ReleaseGuiLock();
            Updater.ApplyAndRestart(file);
            Application.Current.Shutdown();
            // 有后台任务拖着不退时兜底，保证新版能接手
            _ = Task.Delay(5000).ContinueWith(_ => Environment.Exit(0));
        }
        catch (OperationCanceledException)
        {
            TxtProgress.Text = "已取消下载。";
            Reset();
        }
        catch (Exception ex)
        {
            Log.App("update failed: " + ex);
            TxtProgress.Text = "更新失败：" + ex.Message + "\n可以点「在网页上查看」手动下载 zip，解压后覆盖程序目录里的 JskpBoxManager.exe。";
            Reset();
        }
    }

    void Reset()
    {
        _cts = null;
        BtnUpdate.IsEnabled = BtnSkip.IsEnabled = true;
        BtnLater.Content = "以后再说";
        Bar.Visibility = Visibility.Collapsed;
    }

    void Skip_Click(object sender, RoutedEventArgs e)
    {
        Updater.Skip(_info.Version);
        Close();
    }

    void Later_Click(object sender, RoutedEventArgs e)
    {
        if (_cts != null) { _cts.Cancel(); return; }
        Close();
    }

    void Page_Click(object sender, RoutedEventArgs e)
    {
        var url = string.IsNullOrEmpty(_info.PageUrl) ? Updater.ReleasesPage : _info.PageUrl;
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        _cts?.Cancel();
        base.OnClosing(e);
    }
}
