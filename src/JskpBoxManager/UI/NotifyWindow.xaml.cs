using System.Windows;
using System.Windows.Controls;
using JskpBoxManager.Core;

namespace JskpBoxManager.UI;

/// <summary>
/// 过期提醒设置窗口：推送渠道、密钥、阈值、限流，以及测试/立即检查。
/// 独立成窗口是为了让说明文字有足够宽度，不被右侧窄面板截断。
/// </summary>
public partial class NotifyWindow : Window
{
    public NotifyWindow()
    {
        InitializeComponent();
        LoadFromConfig();
    }

    void LoadFromConfig()
    {
        var cfg = NotifyConfig.Load();
        ChkNotify.IsChecked = cfg.Enabled;
        foreach (var item in CmbChannel.Items.OfType<ComboBoxItem>())
            if (string.Equals(item.Tag?.ToString(), cfg.Channel, StringComparison.OrdinalIgnoreCase))
                CmbChannel.SelectedItem = item;
        if (CmbChannel.SelectedItem == null && CmbChannel.Items.Count > 0) CmbChannel.SelectedIndex = 0;
        TxtToken.Text = cfg.Token;
        TxtHours.Text = cfg.WarnHours.ToString("0.#");
        TxtRepeat.Text = cfg.RepeatHours.ToString("0.#");
        UpdateHelp();
    }

    string SelectedChannel
        => CmbChannel.SelectedItem is ComboBoxItem it && it.Tag is string tag ? tag : "pushplus";

    void Channel_Changed(object sender, SelectionChangedEventArgs e) => UpdateHelp();

    void UpdateHelp()
    {
        if (TxtChannelHelp == null) return;   // XAML 加载期间会先触发一次
        switch (SelectedChannel)
        {
            case "serverchan":
                TxtChannelHelp.Text = "Server酱：微信扫码登录 sct.ftqq.com，复制 SendKey 填到下面。";
                if (TxtTokenHelp != null) TxtTokenHelp.Text = "填 SendKey，形如 SCT123456Txxxxxxxx。也接受完整推送地址。";
                break;
            case "bark":
                TxtChannelHelp.Text = "Bark：iOS 用，在 App 里复制 key。";
                if (TxtTokenHelp != null) TxtTokenHelp.Text = "填 key 即可；也接受 https://api.day.app/xxx 这样的完整地址。";
                break;
            case "webhook":
                TxtChannelHelp.Text = "自定义 Webhook：任何能收 POST 的地址。";
                if (TxtTokenHelp != null) TxtTokenHelp.Text = "填完整 URL。请求体是 JSON：{\"title\":\"…\",\"content\":\"…\",\"text\":\"…\"}。";
                break;
            default:
                TxtChannelHelp.Text = "PushPlus：微信扫码登录 pushplus.plus，复制 token 填到下面。";
                if (TxtTokenHelp != null) TxtTokenHelp.Text = "填 PushPlus 的 token（32 位）。推送会发到该账号绑定的微信。";
                break;
        }
    }

    NotifyConfig ReadUi()
    {
        var cfg = NotifyConfig.Load();
        cfg.Enabled = ChkNotify.IsChecked == true;
        cfg.Channel = SelectedChannel;
        cfg.Token = TxtToken.Text.Trim();
        if (double.TryParse(TxtHours.Text.Trim(), out var h) && h >= 1) cfg.WarnHours = h;
        else cfg.WarnHours = ProtocolRenew.KeyMaxAgeHours;
        if (double.TryParse(TxtRepeat.Text.Trim(), out var r) && r >= 1) cfg.RepeatHours = r;
        else cfg.RepeatHours = 6;
        return cfg;
    }

    void Save_Click(object sender, RoutedEventArgs e)
    {
        var cfg = ReadUi();
        NotifyConfig.Save(cfg);
        TxtHours.Text = cfg.WarnHours.ToString("0.#");
        TxtRepeat.Text = cfg.RepeatHours.ToString("0.#");
        MessageBox.Show(this,
            cfg.Ready ? $"已保存。\n\n{cfg.Describe()}，凭证超过 {cfg.WarnHours:0.#} 小时没续期就会推送。"
                      : "已保存，但还没勾选启用或没填推送密钥，暂时不会推送。",
            "过期提醒", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    void Test_Click(object sender, RoutedEventArgs e)
    {
        var cfg = ReadUi();
        if (cfg.Token.Length == 0)
        {
            MessageBox.Show(this, "先填推送密钥。", "发送测试", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        NotifyConfig.Save(cfg);
        var err = Notifier.SendTest(cfg);
        if (err == null)
            MessageBox.Show(this, "测试消息已发出，请查收微信。\n\n如果没收到，检查该渠道的公众号是否被屏蔽。",
                "发送成功", MessageBoxButton.OK, MessageBoxImage.Information);
        else
            MessageBox.Show(this, err, "发送失败", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    void Check_Click(object sender, RoutedEventArgs e)
    {
        var cfg = ReadUi();
        if (!cfg.Ready)
        {
            MessageBox.Show(this, "先勾选启用并填写推送密钥。", "立即检查", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        NotifyConfig.Save(cfg);
        var boxes = Sandboxie.QueryBoxes();
        var res = Notifier.Check(boxes, cfg);
        if (res.Overdue == 0)
            MessageBox.Show(this, $"检查了 {boxes.Count} 个沙箱，没有凭证超过 {cfg.WarnHours:0.#} 小时未续期。",
                "检查完成", MessageBoxButton.OK, MessageBoxImage.Information);
        else if (res.Failed)
            MessageBox.Show(this, $"发现 {res.Overdue} 个超期账号，但推送失败：\n\n{res.Error}",
                "推送失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(this, $"已推送 {res.Sent} 个超期账号的提醒，请查收微信。",
                "已发送", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    void Close_Click(object sender, RoutedEventArgs e) => Close();
}
