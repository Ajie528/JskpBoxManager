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
        SyncProtocolUi();
        SyncNotifyUi();
        LoadTrimConfig();
        if (NotifyConfig.Load().ProbeEnabled) CredentialProbe.Start();
        RefreshProbePanel();
        _timer.Tick += async (_, _) => { await RefreshAsync(); MaybeAutoTrim(); MaybeCheckNotify(); MaybeRefreshProbePanel(); };
        Loaded += async (_, _) => await StartupAsync();
        Closed += (_, _) => { try { ProtocolServer.StopCurrent(); } catch { } };
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
        TryStartProtocolServer();
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
                var rev = BoxSummary.LastRevokeEvents();
                var chains = AuthChain.Load();
                // 首次运行：把现有证据（事件日志 / 旧版日志 / prevAt 回溯）固化成基准文件，
                // 之后即使事件日志滚掉，授权窗口也能一直算准。
                ScanBaseline.BackfillAll(boxes, chains);
                var res = boxes.Select(b => BoxSummary.Build(b, notes, keep, ev, chains, rev)).ToList();
                BoxSummary.MarkDuplicates(res);
                BoxSummary.MarkLongestChain(res);
                BoxSummary.MarkAuthRejects(res);
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
        foreach (var b in new[] { BtnStart, BtnStop, BtnMem, BtnDeepMem, BtnKeepSave }) b.IsEnabled = any && _busy == 0;
        BtnClear.IsEnabled = BtnDelete.IsEnabled = sel.Count == 1 && _busy == 0;
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
            ChkResidentKeep.IsChecked = pol.ResidentKeepalive;
            ChkProtocolRenew.IsChecked = pol.ProtocolRenew;
            TxtHours.Text = pol.IntervalHours.ToString();
            TxtMaxRotations.Text = pol.MaxRotationsPerDay.ToString();
            TxtForceHours.Text = pol.ForceRenewHours.ToString("0.#");
            TxtMinKeyAge.Text = pol.MinKeyAgeHours.ToString("0.#");
            SyncQuotaNow(pol);
            var hm = pol.DailyTime.Split(':');
            TxtHour.Text = hm[0];
            TxtMinute.Text = hm.Length > 1 ? hm[1] : "00";
            RadDaily.IsChecked = pol.Schedule != "interval";
            RadInterval.IsChecked = pol.Schedule == "interval";
            Sched_Changed(null, null);
        }
        TxtCred.Text = s == null ? "" : CredentialText(s);
        TxtRole.Text = s == null ? "" : RoleDetail(s);
        // 定时刷新只更新「今天换了几次」这行实时提示，不动用户正在编辑的输入框
        SyncQuotaNow();
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
            if (s.Chain != null) lines.Add("免扫链寿命：" + s.Chain.Text);
            if (s.ScanAgeTip.Length > 0) lines.Add("扫码授权窗口：" + s.ScanAgeTip.Replace("\n", "；"));
            lines.Add(s.Vault.Valid ? $"金库备份：{s.Vault.WriteLocal}" : "金库备份：还没有（进一次游戏后自动保存）");
            if (s.Live.Valid && s.Vault.Valid && s.Live.KeyHash != s.Vault.KeyHash && s.Live.WriteUtc > s.Vault.WriteUtc)
                lines.Add("沙箱里有更新的凭证，下次停止/保活时会存进金库");
        }
        else lines.Add("还没有登录过。点「启动游戏」后用微信扫码一次，之后都免扫。");
        if (s.Login == LoginLevel.NeedScan)
            lines.Add("⚠ 服务器要求重新扫码：通常是这个微信号在别的电脑/沙箱扫码登录过（后扫码的会顶掉先登录的）。点「启动游戏」扫一次即可恢复。");
        if (s.Warning.Length > 0) lines.Add("⚠ " + s.Warning);
        if (s.LastRevoke.Length > 0) lines.Add("上次被顶/失效：" + s.LastRevoke);
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

    async void DeepMem_Click(object sender, RoutedEventArgs e)
    {
        var boxes = Selected.Select(r => r.Box).ToList();
        if (boxes.Count == 0) return;
        var msgs = await RunBusy("正在深度压缩内存（含游戏）…", () => boxes.Select(b => b + "：" + BoxRuntime.DeepTrimMemory(b)).ToList());
        SetStatus(string.Join("  ", msgs));
    }

    // ---------- 自动深度压缩（仅界面开着时生效） ----------

    DateTime _lastAutoTrim = DateTime.Now;

    void LoadTrimConfig()
    {
        var c = JsonFile.ReadObject(AppPaths.TrimJson);
        ChkAutoTrim.IsChecked = JsonFile.Bool(c, "enabled") ?? false;
        TxtTrimMin.Text = (JsonFile.Int(c, "minutes") ?? 10).ToString();
    }

    void AutoTrim_Click(object sender, RoutedEventArgs e)
    {
        int m = int.TryParse(TxtTrimMin.Text.Trim(), out var v) && v >= 1 ? Math.Min(v, 240) : 10;
        TxtTrimMin.Text = m.ToString();
        JsonFile.WriteObject(AppPaths.TrimJson, new System.Text.Json.Nodes.JsonObject
        {
            ["enabled"] = ChkAutoTrim.IsChecked == true,
            ["minutes"] = m,
        });
        _lastAutoTrim = DateTime.Now;
        SetStatus(ChkAutoTrim.IsChecked == true ? $"自动压内存已开：每 {m} 分钟压一次在跑的沙箱（仅 QQ 浏览器，不含游戏）" : "自动压内存已关");
    }

    void MaybeAutoTrim()
    {
        if (ChkAutoTrim.IsChecked != true) return;
        if (!int.TryParse(TxtTrimMin.Text.Trim(), out var m) || m < 1) m = 10;
        if ((DateTime.Now - _lastAutoTrim).TotalMinutes < m) return;
        _lastAutoTrim = DateTime.Now;
        var boxes = _rows.Where(r => r.Summary != null && r.Summary.Running).Select(r => r.Box).ToList();
        if (boxes.Count == 0) return;
        _ = Task.Run(() => { foreach (var b in boxes) { try { BoxRuntime.AutoTrimMemory(b); } catch { } } });
        SetStatus($"自动压内存 {boxes.Count} 个在跑的沙箱（仅 QQ 浏览器，不含游戏，{DateTime.Now:HH:mm}）");
    }

    DateTime _lastNotifyCheck = DateTime.MinValue;

    /// <summary>
    /// 界面每 5 秒刷新一次，但过期提醒每 10 分钟才检查一次（同账号另有 RepeatHours 限流）。
    /// 保活计划任务也会调用 Notifier，两处都靠 notify-state.json 去重。
    /// </summary>
    void MaybeCheckNotify()
    {
        if ((DateTime.Now - _lastNotifyCheck).TotalMinutes < 10) return;
        var cfg = NotifyConfig.Load();
        if (!cfg.Ready) return;
        _lastNotifyCheck = DateTime.Now;
        var boxes = _rows.Select(r => r.Box).ToList();
        if (boxes.Count == 0) return;
        _ = Task.Run(() =>
        {
            var res = Notifier.Check(boxes, cfg);
            if (res.Sent > 0) Dispatcher.Invoke(() => SetStatus($"已推送 {res.Sent} 个超期未续期提醒（{cfg.Describe()}）"));
            else if (res.Failed) Dispatcher.Invoke(() => SetStatus("过期提醒推送失败：" + res.Error));
        });
    }

    void Tools_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null) { SetStatus("请先选择一个沙箱"); return; }
        var w = new ToolsWindow(cur.Box) { Owner = this };
        w.Show();
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

    async void ScanFree_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null || Selected.Count != 1) return;
        var (ok, msg) = await RunBusy($"正在清缓存并还原 {cur.Box} 的免扫凭证…", () => BoxRuntime.ScanFreeRelogin(cur.Box));
        if (!ok) { SetStatus(msg); return; }
        BoxStatusFile.Write(cur.Box, BoxPhase.Starting, "免扫重试：正在重新进入…");
        _ = Task.Run(() => LaunchProcess("launch", cur.Box));
        SetStatus(msg + "（若仍弹扫码，说明是真被顶/过期，只能重新扫码）");
    }

    void Recover_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null || Selected.Count != 1) { SetStatus("请先选择一个沙箱"); return; }
        new RecoverWindow(cur.Box) { Owner = this }.Show();
    }

    async void ProtoRenew_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null || Selected.Count != 1) { SetStatus("请先选择一个沙箱"); return; }

        var pending = ProtocolRenew.LastAttemptAt(cur.Box);
        var (renewable, blocked) = ProtocolRenew.CheckRenewable(cur.Box);
        if (!renewable)
        {
            SetStatus(blocked.Split('\n')[0]);
            MessageBox.Show(this, blocked, "纯协议续期", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var warn = "这个操作会直接连微信服务器换新密钥：\n\n"
                 + "· 不启动浏览器，几秒完成\n"
                 + "· **服务端会立刻作废旧 key**，所以结果必须成功，否则该号要重新扫码\n"
                 + "· 已做「发送前先落盘」保护，断网也会留下标记，不会悄悄丢凭证\n";
        if (pending != null)
            warn += $"\n⚠ 上次续期（{pending:MM-dd HH:mm}）结果未知，标记还在。\n"
                  + "   如果那个号现在还能免扫，说明服务端没换掉，可以继续；\n"
                  + "   如果已经要扫码了，那把 key 多半已经作废。\n";
        warn += "\n确定对 " + cur.Box + " 执行？";

        if (MessageBox.Show(this, warn, "纯协议续期", MessageBoxButton.YesNo,
                MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;

        var (ok, msg) = await RunBusy($"正在用协议给 {cur.Box} 续期…", () =>
        {
            var r = ProtocolRenew.Renew(cur.Box, afterRotate: () =>
            {
                // 运行中续期时，运行时可能立刻把旧 key 写回；这里立刻纠正一次再存金库
                Thread.Sleep(1500);
                ProtocolRenew.RestoreRotated(cur.Box, "after-protocol-renew");
                try { Ilink.Save(cur.Box, "protocol-renew"); } catch { }
            });
            return (r.Ok, r.Message);
        });
        await RefreshAsync();
        SetStatus(msg);
        if (ok) MessageBox.Show(this, msg, "续期成功", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    async void DeleteBox_Click(object sender, RoutedEventArgs e)
    {
        var cur = Current;
        if (cur == null || Selected.Count != 1) return;
        var who = cur.Summary?.Note is { Length: > 0 } n ? $"{cur.Box}（{n}）" : cur.Box;
        if (MessageBox.Show(this,
                $"将彻底删除沙箱 {who}：\n\n· 保存的微信登录\n· 下载的游戏包\n· 账号备注\n· 保活计划任务\n· Sandboxie 里的这个沙箱及其内容\n· 桌面快捷方式\n\n删除后无法恢复。确定删除？",
                "删除沙箱", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        var gone = await RunBusy($"正在删除 {cur.Box}…", () => BoxSetup.RemoveBox(cur.Box));
        await RefreshAsync();
        SetStatus(gone
            ? $"已删除沙箱 {cur.Box}"
            : $"已清除 {cur.Box} 的数据，但 Sandboxie 配置未确认删除；如列表中仍存在，请重启 Sandboxie 服务后重试");
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

    /// <summary>详情面板里那行「这个号今天已经换了几次」的实时说明。</summary>
    void SyncQuotaNow(KeepPolicy pol = null)
    {
        if (TxtQuotaNow == null || _detailBox == null) return;
        pol ??= Keepalive.Load().For(_detailBox);
        try
        {
            int quota = pol.EffectiveMaxRotations;
            int used = CredentialProbe.RotationsToday(_detailBox);
            var age = ProtocolRenew.KeyAgeHours(_detailBox);
            var parts = new List<string>
            {
                $"今天已换 {used}/{quota} 次",
                used >= quota ? "额度用完，今天不再轮换" : $"还剩 {quota - used} 次",
            };
            if (age is double h) parts.Add($"密钥 {h:F1} 小时");
            if (pol.EffectiveMinKeyAgeHours > 0 && age is double a && a < pol.EffectiveMinKeyAgeHours)
                parts.Add($"还不到 {pol.EffectiveMinKeyAgeHours:0.#} 小时，保活会先跳过它");
            TxtQuotaNow.Text = string.Join(" · ", parts);
        }
        catch { TxtQuotaNow.Text = ""; }
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
        // 轮换额度：0 = 用默认。上限 1～50，避免误填成 500 把授权链滚废。
        if (!int.TryParse(TxtMaxRotations.Text.Trim(), out var maxRot) || maxRot < 0 || maxRot > 50)
        {
            MessageBox.Show(this, "「每天最多换几次」请填 0～50。填 0 表示用默认 8 次。\n\n为什么要有上限：每次换 key 都是一次真实轮换，太频繁会被服务端把整条授权链判成异常。",
                "保活设置", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!double.TryParse(TxtForceHours.Text.Trim(), out var forceH) || forceH < 0 || forceH > 168)
        {
            MessageBox.Show(this, "「密钥满几小时强制续期」请填 0～168。填 0 表示用默认 20 小时。",
                "保活设置", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!double.TryParse(TxtMinKeyAge.Text.Trim(), out var minAgeH) || minAgeH < 0 || minAgeH > 168)
        {
            MessageBox.Show(this, "「密钥不到几小时就别动它」请填 0～168。填 0 表示用默认 6 小时。",
                "保活设置", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (forceH > 0 && minAgeH > 0 && minAgeH >= forceH)
        {
            MessageBox.Show(this, "「密钥不到 N 小时就别动它」必须小于「密钥满 M 小时强制续期」，否则永远都不会续。\n"
                + $"现在填的是 {minAgeH:0.#} ≥ {forceH:0.#}。",
                "保活设置", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        bool enabled = ChkKeep.IsChecked == true;
        bool resident = ChkResidentKeep.IsChecked == true;
        bool protoRenew = ChkProtocolRenew.IsChecked == true;
        bool daily = RadDaily.IsChecked == true;
        var errors = await RunBusy("正在保存保活设置并同步计划任务…", () =>
        {
            var cfg = Keepalive.Load();
            foreach (var b in boxes)
                cfg.Boxes[b] = new KeepPolicy
                {
                    Enabled = enabled, Schedule = daily ? "daily" : "interval",
                    IntervalHours = hours, DailyTime = $"{hh:D2}:{mm:D2}",
                    ResidentKeepalive = resident,
                    ProtocolRenew = protoRenew,
                    MaxRotationsPerDay = maxRot,
                    ForceRenewHours = Math.Round(forceH, 1),
                    MinKeyAgeHours = Math.Round(minAgeH, 1),
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

    // ---------- 过期提醒 ----------

    /// <summary>右侧只显示一行摘要，详细配置在「高级工具 → 过期提醒」窗口里。</summary>
    void SyncNotifyUi()
    {
        var cfg = NotifyConfig.Load();
        if (!cfg.Ready)
        {
            TxtNotifySummary.Text = $"未配置。凭证超过 {cfg.WarnHours:0.#} 小时没续期时推送到微信。"
                + (cfg.Enabled && cfg.Token.Length == 0 ? "（已启用但没填密钥）" : "");
        }
        else
        {
            TxtNotifySummary.Text = $"已启用：{cfg.Describe()}。超过 {cfg.WarnHours:0.#} 小时推送，"
                + $"同一账号 {cfg.RepeatHours:0.#} 小时内不重复。";
        }
    }

    DateTime _lastProbePanel = DateTime.MinValue;

    /// <summary>探测计划每 30 秒刷一次即可（时间数字在动，但不必每 5 秒重绘）。</summary>
    void MaybeRefreshProbePanel()
    {
        if ((DateTime.Now - _lastProbePanel).TotalSeconds < 30) return;
        _lastProbePanel = DateTime.Now;
        RefreshProbePanel();
    }

    async void NotifyOpen_Click(object sender, RoutedEventArgs e)
    {
        var w = new NotifyWindow { Owner = this };
        w.ShowDialog();
        SyncNotifyUi();
        if (NotifyConfig.Load().ProbeEnabled) CredentialProbe.Start(); else CredentialProbe.Stop();
        _lastProbePanel = DateTime.MinValue;   // 设置改过，立刻重画
        RefreshProbePanel();
        await RefreshAsync();
    }

    /// <summary>状态栏显示探测安排：每个号错开，不是同一时刻全发。</summary>
    string ProbeScheduleText()
    {
        try
        {
            var s = CredentialProbe.Schedule();
            if (s.Length == 0) return "";
            var next = s.First();
            return $"下次探测 {next.Due:HH:mm}（{next.Box}），共 {s.Length} 个号错开排队";
        }
        catch { return ""; }
    }

    /// <summary>渲染「探测计划」列表：每号一行，显示下次探测时间与距现在多久。</summary>
    void RefreshProbePanel()
    {
        if (ProbePanel == null) return;
        var cfg = NotifyConfig.Load();
        if (!cfg.ProbeEnabled)
        {
            ProbePanel.Visibility = Visibility.Collapsed;
            return;
        }
        ProbePanel.Visibility = Visibility.Visible;
        try
        {
            // 只补登记新号，不清掉已有的（_rows 在构造时还是空的，
            // 传空列表会把已排好的计划全删了，面板就永远显示「尚未排程」）
            var known = _rows.Select(r => r.Box).ToList();
            if (known.Count > 0) CredentialProbe.ReseedSchedule(known, cfg);
            var s = CredentialProbe.Schedule();
            TxtProbeSummary.Text = s.Length == 0
                ? "尚未排程"
                : $"间隔 {cfg.ProbeMinutes} 分 · 抖动 ±35%";
            ProbeList.Children.Clear();
            var now = DateTime.Now;
            foreach (var (box, due) in s)
            {
                var row = new System.Windows.Controls.DockPanel { Margin = new Thickness(0, 1, 0, 1) };
                var when = new System.Windows.Controls.TextBlock
                {
                    Text = due.ToString("HH:mm:ss"),
                    FontFamily = new System.Windows.Media.FontFamily("Consolas, Microsoft YaHei UI"),
                    FontSize = 11,
                    Width = 62,
                };
                var rel = new System.Windows.Controls.TextBlock
                {
                    Text = due <= now ? "已到期" : $"还有 {FormatGap(due - now)}",
                    Foreground = due <= now
                        ? (System.Windows.Media.Brush)FindResource("Warn")
                        : (System.Windows.Media.Brush)FindResource("Muted"),
                    FontSize = 11,
                    TextAlignment = System.Windows.TextAlignment.Right,
                    Width = 62,
                };
                System.Windows.Controls.DockPanel.SetDock(when, System.Windows.Controls.Dock.Left);
                System.Windows.Controls.DockPanel.SetDock(rel, System.Windows.Controls.Dock.Right);
                var name = new System.Windows.Controls.TextBlock
                {
                    Text = box,
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(4, 0, 4, 0),
                };
                row.Children.Add(when);
                row.Children.Add(rel);
                row.Children.Add(name);
                ProbeList.Children.Add(row);
            }
        }
        catch (Exception ex)
        {
            TxtProbeSummary.Text = "读取计划失败：" + ex.Message;
        }
    }

    static string FormatGap(TimeSpan t)
    {
        if (t.TotalMinutes >= 60) return $"{(int)t.TotalHours}h{t.Minutes:D2}m";
        if (t.TotalMinutes >= 1) return $"{(int)t.TotalMinutes} 分";
        return $"{(int)Math.Max(0, t.TotalSeconds)} 秒";
    }

    void SyncProtocolUi()
    {
        var cfg = ProtocolConfig.Load();
        ChkProtocol.IsChecked = cfg.Enabled;
        var cur = ProtocolServer.Current;
        if (cur != null && cur.Running)
            TxtProtocol.Text = cur.BaseUrl;
        else if (cfg.Enabled)
            TxtProtocol.Text = $"待启动 :{cfg.Port}";
        else
            TxtProtocol.Text = "未启用";
        TxtProtocol.ToolTip = ProtocolServer.StatusText()
            + "\n脚本取业务 token：GET " + cfg.BaseUrl + "/token?ref=qb1"
            + "\n请求头 Authorization: Bearer <令牌>（点「复制令牌」）";
    }

    void TryStartProtocolServer()
    {
        try
        {
            var cfg = ProtocolConfig.Load();
            if (!cfg.Enabled) { SyncProtocolUi(); return; }
            var srv = ProtocolServer.EnsureStarted();
            SyncProtocolUi();
            if (srv == null || !srv.Running)
                SetStatus("协议服务启用失败：" + (ProtocolServer.Current?.LastError ?? "未知错误"));
            else
                SetStatus($"协议服务已监听 {srv.BaseUrl}");
        }
        catch (Exception ex)
        {
            SyncProtocolUi();
            SetStatus("协议服务启动异常：" + ex.Message);
        }
    }

    void Protocol_Click(object sender, RoutedEventArgs e)
    {
        bool on = ChkProtocol.IsChecked == true;
        var cfg = ProtocolConfig.Load();
        cfg.Enabled = on;
        ProtocolConfig.EnsureToken(cfg);
        ProtocolConfig.Save(cfg);
        if (on) TryStartProtocolServer();
        else
        {
            ProtocolServer.StopCurrent();
            SyncProtocolUi();
            SetStatus("协议服务已关闭");
        }
    }

    void ProtocolToken_Click(object sender, RoutedEventArgs e)
    {
        var cfg = ProtocolConfig.EnsureToken(ProtocolConfig.Load());
        ProtocolConfig.Save(cfg);
        if (TrySetClipboard(cfg.Token))
            SetStatus("已复制协议令牌；脚本请设置 JSKP_PROTOCOL_TOKEN，请求头 Authorization: Bearer <令牌>");
        else
            ShowCopyableToken(cfg.Token);
    }

    /// <summary>
    /// 先走原生 Win32 剪贴板（输入法/剪贴板工具占用时更稳），失败再退回 WPF。
    /// 原因多为常驻的输入法（如搜狗）或剪贴板管理器长期占着剪贴板（CLIPBRD_E_CANT_OPEN）。
    /// </summary>
    bool TrySetClipboard(string text)
    {
        try { if (Win32.SetClipboardText(text)) return true; } catch { }
        for (int i = 0; i < 6; i++)
        {
            try { Clipboard.SetDataObject(text, false); return true; }
            catch { System.Threading.Thread.Sleep(80); }
        }
        return false;
    }

    /// <summary>复制失败时给一个只读可全选的框，方便手动复制。</summary>
    void ShowCopyableToken(string token)
    {
        var win = new Window
        {
            Title = "协议令牌（复制失败，请手动复制）",
            Owner = this,
            Width = 520,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
        };
        var panel = new System.Windows.Controls.StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = "剪贴板被其它程序占用，自动复制失败。请手动全选复制下面的令牌：",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10),
        });
        var box = new System.Windows.Controls.TextBox
        {
            Text = token, IsReadOnly = true, FontFamily = new System.Windows.Media.FontFamily("Consolas"),
            TextWrapping = TextWrapping.Wrap, Padding = new Thickness(6),
        };
        box.Loaded += (_, _) => { box.Focus(); box.SelectAll(); };
        panel.Children.Add(box);
        win.Content = panel;
        win.ShowDialog();
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

    /// <summary>采集一份「免扫状态截面」，方便横向对比哪个号先出问题。</summary>
    async void Samples_Click(object sender, RoutedEventArgs e)
    {
        var list = _rows.Where(r => r.Summary != null).Select(r => r.Summary).ToList();
        if (list.Count == 0) { SetStatus("还没有沙箱数据，等列表加载完再试"); return; }
        BoxSummary.MarkLongestChain(list);
        var cap = await RunBusy("正在采集数据样板…", () => Samples.Take(list));
        SetStatus($"数据样板已保存到 samples\\{Path.GetFileName(cap.Dir)}"
            + (cap.Findings.Count > 0 ? $"（体检发现 {cap.Findings.Count} 条，见摘要）" : ""));
        Process.Start("explorer.exe", $"/select,\"{Path.Combine(cap.Dir, "摘要.md")}\"");
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
