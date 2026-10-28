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

    void Copy_Click(object sender, RoutedEventArgs e) => Clipboard.SetText($"{AppInfo.ProductName}\n{_info}");
    void OpenDir_Click(object sender, RoutedEventArgs e) => Process.Start("explorer.exe", $"\"{AppPaths.AppDir}\"");
    void Close_Click(object sender, RoutedEventArgs e) => Close();
}
