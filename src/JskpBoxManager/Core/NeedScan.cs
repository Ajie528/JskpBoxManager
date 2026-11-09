using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>「需要重新扫码」标记：保活/启动确认凭证失效时写入，之后的保活不再空跑冷启动。</summary>
public static class NeedScan
{
    public static bool Pending(string box) => File.Exists(BoxPaths.NeedScanFile(box));

    public static string Reason(string box)
    {
        try
        {
            if (!Pending(box)) return "";
            var parts = File.ReadAllText(BoxPaths.NeedScanFile(box)).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return parts.Length >= 4 ? parts[3] : "";
        }
        catch { return ""; }
    }

    public static void Set(string box, string reason)
    {
        Directory.CreateDirectory(BoxPaths.Vault(box));
        var stamp = BoxPaths.NeedScanStamp(box);
        var liveKey = "";
        try { liveKey = Ilink.Live(box).KeyHash; } catch { }
        var logged = "";
        try { if (File.Exists(stamp)) logged = File.ReadAllText(stamp).Trim(); } catch { }
        try { File.WriteAllText(BoxPaths.NeedScanFile(box), $"need-scan {DateTime.Now:yyyy-MM-dd HH:mm:ss} {reason}"); } catch { }
        if (logged == "k:" + liveKey) return;
        try { File.WriteAllText(stamp, "k:" + liveKey); } catch { }
        try
        {
            var live = Ilink.Live(box);
            var vault = Ilink.VaultState(box);
            Ilink.WriteEvent(box, "need-scan", new JsonObject
            {
                ["reason"] = reason, ["liveValid"] = live.Valid, ["uin"] = live.Uin, ["keySha"] = live.KeyHash,
                ["keyAgeHours"] = live.AgeHours, ["vaultKeySha"] = vault.KeyHash, ["vaultAgeHours"] = vault.AgeHours,
            });
        }
        catch { }
    }

    /// <summary>标记之后沙箱里又出现了有效的新凭证（扫码 / 电脑微信授权成功），标记就过时了。</summary>
    public static bool Superseded(string box, IlinkState live)
    {
        try
        {
            if (!Pending(box) || live == null || !live.Valid) return false;
            if (live.WriteUtc <= File.GetLastWriteTimeUtc(BoxPaths.NeedScanFile(box))) return false;
            return !Ilink.IsRevoked(box, live.KeyHash);
        }
        catch { return false; }
    }

    public static bool ClearIfRenewed(string box)
    {
        var live = Ilink.Live(box);
        if (!Superseded(box, live)) return false;
        Clear(box);
        ClearQrStreak(box);
        Log.Box(box, $"need-scan cleared: new credential at {live.WriteLocal}");
        return true;
    }

    public static void Clear(string box)
    {
        foreach (var p in new[] { BoxPaths.NeedScanFile(box), BoxPaths.NeedScanStamp(box) })
            try { if (File.Exists(p)) File.Delete(p); } catch { }
    }

    /// <summary>金库里有可用于免扫的凭证（有效、未作废、没被标记需扫码）。</summary>
    public static bool SavedLoginUsable(string box)
    {
        if (Pending(box)) return false;
        var v = Ilink.VaultState(box);
        return v.Valid && !Ilink.IsRevoked(box, v.KeyHash);
    }

    public static void RegisterQrFailure(string box)
    {
        var path = BoxPaths.QrStreakFile(box);
        int n = 0;
        try { if (File.Exists(path)) int.TryParse(File.ReadAllText(path).Trim(), out n); } catch { }
        n++;
        if (n >= 2)
        {
            Set(box, "qr-auth-confirmed");
            try { File.Delete(path); } catch { }
            Log.Box(box, "refresh: QR twice -> mark need-scan");
        }
        else
        {
            try { File.WriteAllText(path, n.ToString()); } catch { }
            Log.Box(box, "refresh: QR once -> next keepalive will retry");
        }
    }

    public static void ClearQrStreak(string box)
    {
        try { File.Delete(BoxPaths.QrStreakFile(box)); } catch { }
    }

    // ---------------- 失败退避（借上游 keepAliveRetryAt 的思路，但落盘） ----------------
    //
    // 没有这一层时，一次临时故障（网络抖动、Sandboxie 报 SBIE2203、代理断开）
    // 就要等到下一次计划任务——默认每天一次，等于白白浪费一整个窗口。
    // 退避按「上次失败时间 + 序号」算，落在文件里，进程重启不丢。

    static string RetryPath(string box) => Path.Combine(BoxPaths.Vault(box), "refresh-retry.json");

    public sealed record RetryState(int Failures, DateTime NextTryUtc, string LastError)
    {
        public double MinutesLeft => Math.Max(0, (NextTryUtc - DateTime.UtcNow).TotalMinutes);
    }

    public static RetryState Retry(string box)
    {
        var o = JsonFile.ReadObject(RetryPath(box));
        if (o == null) return null;
        var next = JsonFile.Str(o, "nextTry");
        if (!DateTime.TryParseExact(next, "yyyy-MM-dd HH:mm:ss",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var nextUtc))
            return null;
        return new RetryState(JsonFile.Int(o, "failures") ?? 0, nextUtc, JsonFile.Str(o, "lastError"));
    }

    /// <summary>还没到下次可试时间就返回 true（保活应跳过）。</summary>
    public static bool RetryPending(string box)
    {
        var r = Retry(box);
        return r != null && r.NextTryUtc > DateTime.UtcNow;
    }

    /// <summary>
    /// 记一次失败并按序号退避。<paramref name="definitive"/> 为真表示
    /// 「服务端已明确拒绝」（-13/-14），重试意义不大，用更长的间隔。
    /// <para>
    /// <paramref name="urgent"/> 为真表示密钥已过硬上限（20h），此时**不能**退避太久：
    /// 等 6 小时基本等于让密钥自然过期，必须换成「短间隔多试」，宁可多打几次上游也要救回来。
    /// </para>
    /// </summary>
    public static void RegisterFailure(string box, string error, bool definitive = false, bool urgent = false)
    {
        var prev = Retry(box);
        int n = (prev?.Failures ?? 0) + 1;
        // 30 分钟起步，逐次翻倍，封顶 6 小时；明确拒绝直接 6 小时（重试只会重复被拒）。
        double minutes = Math.Min(360, 30 * Math.Pow(2, Math.Min(n - 1, 4)));
        if (definitive) minutes = Math.Max(minutes, 360);
        // 密钥快过期时把退避压到 30 分钟：这时候「少打扰上游」要让位于「别让它过期」。
        if (urgent) minutes = Math.Min(minutes, 30);
        var next = DateTime.UtcNow.AddMinutes(minutes);
        try
        {
            JsonFile.WriteObject(RetryPath(box), new JsonObject
            {
                ["failures"] = n,
                ["nextTry"] = next.ToString("yyyy-MM-dd HH:mm:ss"),
                ["lastError"] = (error ?? "").Length > 300 ? error[..300] : (error ?? ""),
                ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            });
        }
        catch { }
        Log.Box(box, $"refresh retry: failure #{n} -> next attempt in {minutes:0} min{(definitive ? " (definitive rejection)" : "")}");
    }

    /// <summary>成功后续期成功，清掉退避与失败计数。</summary>
    public static void ClearRetry(string box)
    {
        try { if (File.Exists(RetryPath(box))) File.Delete(RetryPath(box)); } catch { }
    }
}
