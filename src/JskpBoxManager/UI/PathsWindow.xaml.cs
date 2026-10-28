using System.Windows;
using JskpBoxManager.Core;
using Microsoft.Win32;

namespace JskpBoxManager.UI;

public partial class PathsWindow : Window
{
    public PathsWindow()
    {
        InitializeComponent();
        TxtQq.Text = EnvDetect.ConfigValue("qqExe");
        TxtSbie.Text = EnvDetect.ConfigValue("sbieStart");
        TxtRoot.Text = EnvDetect.ConfigValue("sandboxRoot");
        LblQq.Text = "当前使用：" + (EnvDetect.QqOk ? EnvDetect.QqCoreExe() : "未找到");
        LblSbie.Text = "当前使用：" + (EnvDetect.SbieOk ? EnvDetect.SbieStart : "未找到");
        LblRoot.Text = "当前使用：" + EnvDetect.SandboxRoot;
    }

    void BrowseQq_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "选择 QQBrowser.exe", Filter = "QQBrowser.exe|QQBrowser.exe|可执行文件|*.exe" };
        if (dlg.ShowDialog(this) == true) TxtQq.Text = dlg.FileName;
    }

    void BrowseSbie_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "选择 Sandboxie-Plus 的 Start.exe", Filter = "Start.exe|Start.exe" };
        if (dlg.ShowDialog(this) == true) TxtSbie.Text = dlg.FileName;
    }

    void Auto_Click(object sender, RoutedEventArgs e)
    {
        TxtQq.Text = TxtSbie.Text = TxtRoot.Text = "";
    }

    void Save_Click(object sender, RoutedEventArgs e)
    {
        foreach (var (box, path) in new[] { (TxtQq, TxtQq.Text.Trim()), (TxtSbie, TxtSbie.Text.Trim()) })
            if (path.Length > 0 && !File.Exists(path))
            {
                MessageBox.Show(this, "文件不存在：\n" + path, "路径设置", MessageBoxButton.OK, MessageBoxImage.Warning);
                box.Focus();
                return;
            }
        EnvDetect.SaveConfigValue("qqExe", TxtQq.Text.Trim());
        EnvDetect.SaveConfigValue("sbieStart", TxtSbie.Text.Trim());
        EnvDetect.SaveConfigValue("sandboxRoot", TxtRoot.Text.Trim());
        DialogResult = true;
    }
}
