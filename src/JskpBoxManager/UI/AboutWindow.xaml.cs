using System.Diagnostics;
using System.Windows;
using JskpBoxManager.Core;

namespace JskpBoxManager.UI;

public partial class AboutWindow : Window
{
    readonly string _info;

    public AboutWindow()
    {
        InitializeComponent();
        TxtTitle.Text = $"{AppInfo.ProductName} {AppInfo.VersionLabel}";
        _info = $"版本：{AppInfo.VersionLabel}\n" +
                $"构建时间：{AppInfo.BuildTime:yyyy-MM-dd HH:mm}\n" +
                $"程序目录：{AppPaths.AppDir}\n" +
                $"Sandboxie：{EnvDetect.SbieStart} {EnvDetect.SbieVersion()}\n" +
                $"QQ 浏览器：{EnvDetect.QqCoreExe()}\n" +
                $"电脑：{Environment.MachineName}";
        TxtInfo.Text = _info;
        TxtLog.Text = AppInfo.ReadChangelog();
    }

    async void Check_Click(object sender, RoutedEventArgs e)
    {
        BtnCheck.IsEnabled = false;
        BtnCheck.Content = "正在检查…";
        try
        {
            var info = await Updater.CheckAsync();
            if (info == null)
            {
                MessageBox.Show(this, $"已经是最新版本（{AppInfo.VersionLabel}）。", "检查更新", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            (Owner as MainWindow)?.ShowNewVersion(info);
            new UpdateWindow(info) { Owner = this }.ShowDialog();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "连不上 GitHub：" + ex.Message + "\n\n可以稍后再试，或直接打开 " + Updater.ReleasesPage + " 下载。",
                "检查更新", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            BtnCheck.IsEnabled = true;
            BtnCheck.Content = "检查更新";
        }
    }

    void Copy_Click(object sender, RoutedEventArgs e) => Clipboard.SetText($"{AppInfo.ProductName}\n{_info}");
    void OpenDir_Click(object sender, RoutedEventArgs e) => Process.Start("explorer.exe", $"\"{AppPaths.AppDir}\"");
    void Close_Click(object sender, RoutedEventArgs e) => Close();
}
