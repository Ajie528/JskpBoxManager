using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using JskpBoxManager.Core;
using Microsoft.Win32;

namespace JskpBoxManager.UI;

public partial class MainWindow : Window
{
    readonly ObservableCollection<BoxRow> _rows = new();
    readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(5) };
    bool _refreshing;
    int _busy;
    string _detailBox;
    Action _bannerAction;

    public MainWindow()
    {
        InitializeComponent();
        Title = $"{AppInfo.ProductName} {AppInfo.VersionLabel}";
        TxtVersion.Text = AppInfo.VersionLabel;
        Grid.ItemsSource = _rows;
        ChkGlobalKeep.IsChecked = Keepalive.Load().Enabled;
        _timer.Tick += async (_, _) => await RefreshAsync();
        Loaded += async (_, _) => await StartupAsync();
        UpdateDetail(true);
    }

    // ---------- 启动检查 ----------

    async Task StartupAsync()
    {
        SetStatus("正在识别 Sandboxie 和 QQ 浏览器…");
        await Task.Run(EnvDetect.Reload);
        UpdateEnvText();
        _ = CheckUpdateAsync();
        if (!CheckEnvBanner()) { _timer.Start(); SetStatus("缺少必要软件，见上方提示"); return; }

        await RefreshAsync();
        _timer.Start();
        if (_updatedFrom != null)
        {
            SetStatus($"已从 v{_updatedFrom} 更新到 {AppInfo.VersionLabel}");
            ShowBanner($"已从 v{_updatedFrom} 更新到 {AppInfo.VersionLabel}。", "看看更新了什么", () => { HideBanner(); About_Click(null, null); });
            return;
        }

        if (!Migration.AlreadyMigrated && !Migration.HasOwnData)
        {
            var cands = await Task.Run(Migration.FindCandidates);
            if (cands.Count > 0)
            {
                SetStatus("就绪");
                ShowBanner($"发现旧版程序的数据：{cands[0].Dir}（{cands[0].Boxes} 个沙箱）。导入后旧版保存的登录可以直接用，不用重新扫码。",
                    "导入旧版数据", () => Import_Click(null, null));
                return;
            }
        }
        await CheckTasksAsync();
        SetStatus("就绪");
    }

    void UpdateEnvText()
    {
        var sb = EnvDetect.SbieOk ? $"Sandboxie {EnvDetect.SbieVersion()}" : "Sandboxie 未找到";
        var qq = EnvDetect.QqOk ? $"QQ浏览器 {EnvDetect.QqVersion()}" : "QQ浏览器 未找到";
        TxtEnv.Text = $"{sb}  ·  {qq}";
        TxtEnv.ToolTip = $"Sandboxie：{EnvDetect.SbieStart}\nQQ 浏览器：{EnvDetect.QqCoreExe()}\n沙箱目录：{EnvDetect.SandboxRoot}\n程序目录：{AppPaths.AppDir}";
    }

    bool CheckEnvBanner()
    {
        if (!EnvDetect.SbieOk)
        {
            ShowBanner("没有找到 Sandboxie-Plus。请先安装 Sandboxie-Plus；已经装了的话，点右边手动选择它的 Start.exe。", "选择 Start.exe", () =>
            {
                var dlg = new OpenFileDialog { Title = "选择 Sandboxie-Plus 的 Start.exe", Filter = "Start.exe|Start.exe" };
                if (dlg.ShowDialog(this) != true) return;
                EnvDetect.SaveConfigValue("sbieStart", dlg.FileName);
                RecheckEnv();
            });
            return false;
        }
        if (!EnvDetect.QqOk)
        {
            ShowBanner("没有找到 QQ 浏览器。请先安装 QQ 浏览器；已经装了的话，点右边手动选择 QQBrowser.exe。", "选择 QQBrowser.exe", () =>
            {
                var dlg = new OpenFileDialog { Title = "选择 QQ 浏览器的 QQBrowser.exe", Filter = "QQBrowser.exe|QQBrowser.exe|可执行文件|*.exe" };
                if (dlg.ShowDialog(this) != true) return;
                EnvDetect.SaveConfigValue("qqExe", dlg.FileName);
                RecheckEnv();
            });
            return false;
        }
        HideBanner();
        return true;
    }

    async void RecheckEnv()
    {
        await Task.Run(EnvDetect.Reload);
        UpdateEnvText();
        if (CheckEnvBanner()) await RefreshAsync();
    }

    /// <summary>保活计划任务还指向旧版 PowerShell 或别的目录（比如程序被挪了位置）时提醒修复。</summary>
    async Task CheckTasksAsync()
    {
        var keep = Keepalive.Load();
        var boxes = _rows.Where(r => r.Summary != null && r.Summary.Login != LoginLevel.None && keep.EnabledFor(r.Box)).Select(r => r.Box).ToList();
        if (boxes.Count == 0) return;
        var wrong = await Task.Run(() => boxes.Where(b => !Keepalive.TaskPointsHere(b)).ToList());
        if (wrong.Count == 0) return;
        ShowBanner($"有 {wrong.Count} 个沙箱（{string.Join("、", wrong)}）的保活计划任务没有指向本程序（可能是旧版或程序换了位置），到点不会按新版执行。",
            "修复计划任务", async () =>
            {
                var errors = await RunBusy("正在更新计划任务…", () => Keepalive.SyncAll(wrong));
                if (errors.Count > 0) MessageBox.Show(this, string.Join("\n", errors), "部分计划任务没更新成功", MessageBoxButton.OK, MessageBoxImage.Warning);
                HideBanner();
                SetStatus("计划任务已更新");
            });
    }

    void ShowBanner(string text, string button, Action action)
    {
        BannerText.Text = text;
        BannerBtn.Content = button;
        _bannerAction = action;
        Banner.Visibility = Visibility.Visible;
    }

    void HideBanner()
    {
        Banner.Visibility = Visibility.Collapsed;
        _bannerAction = null;
    }

    void BannerBtn_Click(object sender, RoutedEventArgs e) => _bannerAction?.Invoke();

    // ---------- 列表刷新 ----------

    async Task RefreshAsync()
    {
        if (_refreshing || !EnvDetect.SbieOk) return;
        _refreshing = true;
        try
        {
            var list = await Task.Run(() =>
            {
                var boxes = Sandboxie.QueryBoxes();
                var notes = Notes.Load();
                var keep = Keepalive.Load();
                var ev = BoxSummary.LastRefreshEvents();
                var res = boxes.Select(b => BoxSummary.Build(b, notes, keep, ev)).ToList();
                BoxSummary.MarkDuplicates(res);
                return res;
            });
            var names = list.Select(s => s.Box).ToHashSet();
            foreach (var r in _rows.Where(r => !names.Contains(r.Box)).ToList()) _rows.Remove(r);
            for (int i = 0; i < list.Count; i++)
            {
                var row = _rows.FirstOrDefault(r => r.Box == list[i].Box);
                if (row == null)
                {
                    row = new BoxRow(list[i].Box);
                    _rows.Insert(Math.Min(i, _rows.Count), row);
                }
                row.Update(list[i]);
            }
            if (Grid.SelectedItems.Count == 0 && _rows.Count > 0) Grid.SelectedIndex = 0;
            UpdateDetail(false);
        }
        catch (Exception ex)
        {
            SetStatus("刷新失败：" + ex.Message);
        }
        finally { _refreshing = false; }
    }

    async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        await Task.Run(EnvDetect.Reload);
        UpdateEnvText();
        CheckEnvBanner();
        await RefreshAsync();
        SetStatus("已刷新");
    }

    List<BoxRow> Selected => Grid.SelectedItems.Cast<BoxRow>().OrderBy(r => Sandboxie.BoxNumber(r.Box)).ToList();
    BoxRow Current => Grid.SelectedItem as BoxRow;

    void Grid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e) => UpdateDetail(true);

    void Grid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (Current != null) Start_Click(null, null);
    }

    /// <summary>selectionChanged=true 时才重填可编辑的框（备注、保活设置），避免定时刷新冲掉正在输入的内容。</summary>
    void UpdateDetail(bool selectionChanged)
    {
        var sel = Selected;
        var cur = Current;
        bool any = sel.Count > 0;
        foreach (var b in new[] { BtnStart, BtnStop, BtnMem, BtnKeepSave }) b.IsEnabled = any && _busy == 0;
        BtnClear.IsEnabled = sel.Count == 1 && _busy == 0;
        BtnNote.IsEnabled = TxtNote.IsEnabled = sel.Count == 1;
        if (!any || cur == null)
        {
            DetailTitle.Text = "请选择一个沙箱";
            DetailSub.Text = "";
            TxtCred.Text = "";
            TxtLog.Text = "";
            _detailBox = null;
            return;
        }
        var s = cur.Summary;
        if (sel.Count > 1)
        {
            DetailTitle.Text = $"已选 {sel.Count} 个沙箱";
            DetailSub.Text = string.Join("、", sel.Select(r => r.Box)) + "\n启动 / 停止 / 保活设置会对它们一起生效";
        }
        else
        {
            DetailTitle.Text = s != null && s.Note.Length > 0 ? $"{cur.Box} · {s.Note}" : cur.Box;
            DetailSub.Text = s == null ? "" : s.PhaseText;
        }
        if (selectionChanged || _detailBox != cur.Box)
        {
            _detailBox = cur.Box;
            TxtNote.Text = sel.Count == 1 ? s?.Note ?? "" : "";
            var keep = Keepalive.Load();
            var pol = keep.For(cur.Box);
            ChkKeep.IsChecked = pol.Enabled;
            ChkLeanRefresh.IsChecked = pol.LeanRefresh;
            ChkProbeAuth.IsChecked = pol.ProbeAuth;
            TxtHours.Text = pol.IntervalHours.ToString();
            var hm = pol.DailyTime.Split(':');
            TxtHour.Text = hm[0];
            TxtMinute.Text = hm.Length > 1 ? hm[1] : "00";
            RadDaily.IsChecked = pol.Schedule == "daily";
            RadInterval.IsChecked = pol.Schedule != "daily";
            Sched_Changed(null, null);
        }
        TxtCred.Text = s == null ? "" : CredentialText(s);
        TxtRole.Text = s == null ? "" : RoleDetail(s);
        BtnRole.IsEnabled = sel.Count == 1 && s != null && s.InGame && _busy == 0;
        var lines = Log.Tail(AppPaths.BoxLog(cur.Box), 40);
        var text = string.Join("\n", lines.Select(l => l.Length > 20 ? l[11..] : l));
        if (TxtLog.Text != text)
        {
            TxtLog.Text = text;
            TxtLog.ScrollToEnd();
        }
    }

    static string RoleDetail(BoxSummary s)
    {
        var r = s.Role;
        if (r == null || !r.HasName)
            return s.InGame ? "正在从游戏里读取角色名和攻击力…（进入主界面后一般 1 分钟内出来）" : "还没读到。进一次游戏后自动读取。";
        var lines = new List<string> { $"{r.Name}" };
        var meta = new List<string>();
        if (r.Level.Length > 0) meta.Add($"等级 {r.Level}");
        if (r.ServerName.Length > 0) meta.Add(r.ServerName);
        if (meta.Count > 0) lines.Add(string.Join("  ·  ", meta));
        lines.Add(r.HasAttack ? $"攻击力 {r.Attack}（{r.AttackAt:MM-dd HH:mm} 读取）" : "攻击力：还没读到（进游戏后一般几十秒内出来）");
        return string.Join("\n", lines);
    }

    async void Role_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null) return;
        var msg = await RunBusy($"正在从 {cur.Box} 的游戏里读取角色和攻击力…", () =>
        {
            try { return RoleCapture.ReadOnce(cur.Box).Message; }
            catch (Exception ex) { return "读取失败：" + ex.Message; }
        });
        SetStatus($"{cur.Box}：{msg}");
    }

    static string CredentialText(BoxSummary s)
    {
        var lines = new List<string>();
        if (s.Live.Valid || s.Vault.Valid)
        {
            var best = s.Live.Valid && s.Live.WriteUtc >= s.Vault.WriteUtc ? s.Live : s.Vault;
            lines.Add($"微信身份：{best.Uin}");
            lines.Add($"最近一次免扫换新：{best.WriteLocal}（{BoxRow.Ago(best.WriteUtc)}）");
            lines.Add(s.Vault.Valid ? $"金库备份：{s.Vault.WriteLocal}" : "金库备份：还没有（进一次游戏后自动保存）");
            if (s.Live.Valid && s.Vault.Valid && s.Live.KeyHash != s.Vault.KeyHash && s.Live.WriteUtc > s.Vault.WriteUtc)
                lines.Add("沙箱里有更新的凭证，下次停止/保活时会存进金库");
        }
        else lines.Add("还没有登录过。点「启动游戏」后用微信扫码一次，之后都免扫。");
        if (s.Login == LoginLevel.NeedScan)
            lines.Add("⚠ 服务器要求重新扫码：通常是这个微信号在别的电脑/沙箱扫码登录过（后扫码的会顶掉先登录的）。点「启动游戏」扫一次即可恢复。");
        if (s.Warning.Length > 0) lines.Add("⚠ " + s.Warning);
        if (s.LastRefresh.Length > 0) lines.Add($"上次保活：{s.LastRefresh}");
        return string.Join("\n", lines);
    }

    // ---------- 操作 ----------

    void SetStatus(string text) => TxtStatus.Text = $"{DateTime.Now:HH:mm:ss}  {text}";

    async Task<T> RunBusy<T>(string message, Func<T> work)
    {
        _busy++;
        Busy.Visibility = Visibility.Visible;
        SetStatus(message);
        UpdateDetail(false);
        try { return await Task.Run(work); }
        finally
        {
            _busy--;
            if (_busy == 0) Busy.Visibility = Visibility.Collapsed;
            UpdateDetail(false);
            _ = RefreshAsync();
        }
    }

    async Task RunBusy(string message, Action work) => await RunBusy<int>(message, () => { work(); return 0; });

    void Start_Click(object sender, RoutedEventArgs e)
    {
        var boxes = Selected.Select(r => r.Box).ToList();
        if (boxes.Count == 0) return;
        var dup = Selected.Where(r => r.Summary?.Warning.Length > 0).Select(r => r.Box).ToList();
        if (dup.Count > 1 && MessageBox.Show(this, $"{string.Join("、", dup)} 登录的是同一个微信号，同时打开会互相顶掉。仍然启动？",
                "同一个微信号", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        _ = Task.Run(() =>
        {
            for (int i = 0; i < boxes.Count; i++)
            {
                // 多个沙箱同时冷启动容易触发 SBIE2112/1231，依次错开
                if (i > 0) Thread.Sleep(15000);
                LaunchProcess("launch", boxes[i]);
            }
        });
        SetStatus(boxes.Count == 1 ? $"正在启动 {boxes[0]}，几秒后会出现游戏窗口；需要扫码时会弹出二维码" : $"将依次启动 {boxes.Count} 个沙箱（每个间隔 15 秒）");
        foreach (var r in Selected) BoxStatusFile.Write(r.Box, BoxPhase.Starting, "正在启动…");
    }

    static void LaunchProcess(string verb, string box)
    {
        var psi = new ProcessStartInfo(AppInfo.ExePath) { UseShellExecute = false, WorkingDirectory = AppPaths.AppDir };
        psi.ArgumentList.Add(verb);
        psi.ArgumentList.Add(box);
        Process.Start(psi);
    }

    async void Stop_Click(object sender, RoutedEventArgs e)
    {
        var boxes = Selected.Select(r => r.Box).ToList();
        if (boxes.Count == 0) return;
        if (MessageBox.Show(this, $"将保存登录后关闭 {string.Join("、", boxes)} 里的所有程序（游戏会退出）。确定？", "停止沙箱",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await RunBusy($"正在停止 {string.Join("、", boxes)}…", () => { foreach (var b in boxes) BoxRuntime.StopForce(b, true); });
        SetStatus($"已停止 {string.Join("、", boxes)}");
    }

    async void Mem_Click(object sender, RoutedEventArgs e)
    {
        var boxes = Selected.Select(r => r.Box).ToList();
        var msgs = await RunBusy("正在释放浏览器内存…", () => boxes.Select(b => b + "：" + BoxRuntime.ReleaseBrowserMemory(b)).ToList());
        SetStatus(string.Join("  ", msgs));
    }

    async void Clear_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null || Selected.Count != 1) return;
        var who = cur.Summary?.Note is { Length: > 0 } n ? $"{cur.Box}（{n}）" : cur.Box;
        if (MessageBox.Show(this,
                $"将删除 {who} 保存的微信登录，下次启动需要重新扫码。\n\n适用于：换一个微信号登录，或登录一直出错。\n游戏包和账号备注会保留，保活计划任务会被关掉。\n\n确定清除？",
                "清除登录", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await RunBusy($"正在清除 {cur.Box} 的登录…", () => BoxRuntime.ClearLogin(cur.Box));
        SetStatus($"已清除 {cur.Box} 的登录，下次启动扫码即可");
    }

    async void Note_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null) return;
        var note = TxtNote.Text.Trim();
        await RunBusy("正在保存备注…", () =>
        {
            Notes.Set(cur.Box, note);
            try { BoxSetup.CreateShortcut(cur.Box, note); } catch { }
        });
        SetStatus($"{cur.Box} 的备注已保存，桌面快捷方式已更新");
    }

    void TxtNote_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Note_Click(null, null);
    }

    void Sched_Changed(object sender, RoutedEventArgs e)
    {
        bool daily = RadDaily.IsChecked == true;
        TxtHours.IsEnabled = !daily;
        TxtHour.IsEnabled = TxtMinute.IsEnabled = daily;
    }

    async void KeepSave_Click(object sender, RoutedEventArgs e)
    {
        var boxes = Selected.Select(r => r.Box).ToList();
        if (boxes.Count == 0) return;
        if (!int.TryParse(TxtHours.Text.Trim(), out var hours) || hours < 1 || hours > 24)
        {
            MessageBox.Show(this, "间隔小时数请填 1～24。", "保活设置", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!int.TryParse(TxtHour.Text.Trim(), out var hh) || hh < 0 || hh > 23 || !int.TryParse(TxtMinute.Text.Trim(), out var mm) || mm < 0 || mm > 59)
        {
            MessageBox.Show(this, "每天的时刻请填 0～23 点、0～59 分。", "保活设置", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        bool enabled = ChkKeep.IsChecked == true;
        bool lean = ChkLeanRefresh.IsChecked == true;
        bool probe = ChkProbeAuth.IsChecked == true;
        bool daily = RadDaily.IsChecked == true;
        var errors = await RunBusy("正在保存保活设置并同步计划任务…", () =>
        {
            var cfg = Keepalive.Load();
            foreach (var b in boxes)
                cfg.Boxes[b] = new KeepPolicy
                {
                    Enabled = enabled, Schedule = daily ? "daily" : "interval",
                    IntervalHours = hours, DailyTime = $"{hh:D2}:{mm:D2}", LeanRefresh = lean, ProbeAuth = probe,
                };
            Keepalive.Save(cfg);
            var errs = new List<string>();
            foreach (var b in boxes)
                try { Keepalive.SyncTask(b, cfg); } catch (Exception ex) { errs.Add(b + "：" + ex.Message); }
            return errs;
        });
        if (errors.Count > 0) MessageBox.Show(this, string.Join("\n", errors), "部分计划任务没更新成功", MessageBoxButton.OK, MessageBoxImage.Warning);
        else if (!(ChkGlobalKeep.IsChecked ?? false)) SetStatus("已保存。注意：顶部「静默保活总开关」是关着的，打开后才会执行");
        else SetStatus(enabled ? $"已为 {string.Join("、", boxes)} 开启保活（{(daily ? $"每天 {hh:D2}:{mm:D2} 起错开" : $"每 {hours} 小时")}）" : $"已关闭 {string.Join("、", boxes)} 的保活");
    }

    async void GlobalKeep_Click(object sender, RoutedEventArgs e)
    {
        bool on = ChkGlobalKeep.IsChecked == true;
        var boxes = _rows.Select(r => r.Box).ToList();
        var errors = await RunBusy(on ? "正在开启静默保活…" : "正在关闭静默保活…", () =>
        {
            var cfg = Keepalive.Load();
            cfg.Enabled = on;
            Keepalive.Save(cfg);
            return Keepalive.SyncAll(boxes);
        });
        if (errors.Count > 0) MessageBox.Show(this, string.Join("\n", errors), "部分计划任务没更新成功", MessageBoxButton.OK, MessageBoxImage.Warning);
        SetStatus(on ? "静默保活已开启（各沙箱按自己的计划执行）" : "静默保活已全部关闭");
    }

    async void NewBox_Click(object sender, RoutedEventArgs e)
    {
        var next = BoxSetup.NextBoxName(_rows.Select(r => r.Box));
        if (MessageBox.Show(this, $"将新建一个空沙箱 {next}，首次启动需要用微信扫码登录。\n\n提醒：一个微信号只登录在一个沙箱、一台电脑上，否则会互相顶掉。",
                "新建沙箱", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        var box = await RunBusy($"正在创建 {next}…", () => BoxSetup.CreateBox(_rows.Select(r => r.Box)));
        await RefreshAsync();
        var row = _rows.FirstOrDefault(r => r.Box == box);
        if (row != null) { Grid.SelectedItems.Clear(); Grid.SelectedItem = row; }
        SetStatus($"已创建 {box}，桌面已生成快捷方式 jskp-{box}；填上备注后会改成 jskp-备注");
    }

    void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null) return;
        var p = AppPaths.BoxLog(cur.Box);
        if (File.Exists(p)) Process.Start(new ProcessStartInfo("notepad.exe", $"\"{p}\"") { UseShellExecute = true });
        else SetStatus("这个沙箱还没有日志");
    }

    async void Import_Click(object sender, RoutedEventArgs e)
    {
        var cands = await Task.Run(Migration.FindCandidates);
        string from = null;
        if (cands.Count > 0)
        {
            var c = cands[0];
            var r = MessageBox.Show(this,
                $"找到旧版程序目录：\n{c.Dir}\n（{c.Boxes} 个沙箱，最近修改 {c.LastWrite:yyyy-MM-dd HH:mm}）\n\n" +
                "点「是」导入这个目录；点「否」手动选择别的目录。\n\n" +
                "导入会：复制登录金库（profiles）、账号备注、保活设置；把保活计划任务改为由新版执行；重建桌面快捷方式。旧目录不会被修改。\n" +
                "导入前请先关闭旧版的「QQ多开管理」窗口，导入后不要再用旧版启动，避免两边同时操作同一个沙箱。",
                "导入旧版数据", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (r == MessageBoxResult.Cancel) return;
            if (r == MessageBoxResult.Yes) from = c.Dir;
        }
        if (from == null)
        {
            var dlg = new OpenFolderDialog { Title = "选择旧版程序目录（里面有 launch-qb-game.ps1 和 profiles 文件夹）" };
            if (dlg.ShowDialog(this) != true) return;
            from = dlg.FolderName;
            if (!Migration.IsLegacyDir(from))
            {
                MessageBox.Show(this, "这个目录里没有 launch-qb-game.ps1 和 profiles 文件夹，不是旧版程序目录。", "导入旧版数据", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
        }
        var progress = new Progress<string>(SetStatus);
        var msg = await RunBusy("正在导入旧版数据…", () => Migration.Import(from, progress));
        HideBanner();
        ChkGlobalKeep.IsChecked = Keepalive.Load().Enabled;
        await RefreshAsync();
        UpdateDetail(true);
        MessageBox.Show(this, msg, "导入完成", MessageBoxButton.OK, MessageBoxImage.Information);
        SetStatus("旧版数据已导入");
    }

    void Paths_Click(object sender, RoutedEventArgs e)
    {
        var w = new PathsWindow { Owner = this };
        if (w.ShowDialog() == true) RecheckEnv();
    }

    async void Diag_Click(object sender, RoutedEventArgs e)
    {
        var list = _rows.Where(r => r.Summary != null).Select(r => r.Summary).ToList();
        var zip = await RunBusy("正在导出诊断包…", () => Diagnostics.Export(list));
        SetStatus("诊断包已保存到桌面：" + Path.GetFileName(zip));
        Process.Start("explorer.exe", $"/select,\"{zip}\"");
    }

    void About_Click(object sender, RoutedEventArgs e) => new AboutWindow { Owner = this }.ShowDialog();

    // ---------- 自动更新 ----------

    UpdateInfo _update;
    string _updatedFrom;

    public void ShowUpdatedNotice(string fromVersion) => _updatedFrom = fromVersion;

    async Task CheckUpdateAsync()
    {
        try
        {
            var info = await Updater.CheckAutoAsync();
            if (info != null) ShowNewVersion(info);
        }
        catch (Exception ex) { Log.App("update check failed: " + ex.Message); }
    }

    public void ShowNewVersion(UpdateInfo info)
    {
        _update = info;
        BtnNewVersion.Content = $"● 有新版本 v{info.Version}";
        BtnNewVersion.Visibility = Visibility.Visible;
    }

    void NewVersion_Click(object sender, RoutedEventArgs e)
    {
        if (_update == null) return;
        new UpdateWindow(_update) { Owner = this }.ShowDialog();
    }

    /// <summary>--snapshot 参数：界面加载并刷新一轮后把窗口存成 png（写说明文档、远程排查用）。</summary>
    public async void SnapshotAfterLoad(string png)
    {
        await Task.Delay(8000);
        var dpi = System.Windows.Media.VisualTreeHelper.GetDpi(this);
        var root = (FrameworkElement)Content;
        var bmp = new System.Windows.Media.Imaging.RenderTargetBitmap(
            (int)(root.ActualWidth * dpi.DpiScaleX), (int)(root.ActualHeight * dpi.DpiScaleY), dpi.PixelsPerInchX, dpi.PixelsPerInchY,
            System.Windows.Media.PixelFormats.Pbgra32);
        bmp.Render(root);
        var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
        enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bmp));
        using var fs = File.Create(png);
        enc.Save(fs);
    }
}
