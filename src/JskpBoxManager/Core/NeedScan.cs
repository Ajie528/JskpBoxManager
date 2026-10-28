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
}
