namespace JskpBoxManager.Core;

/// <summary>
/// 一个沙箱涉及的目录：
///   live  = 沙箱里 QQ 浏览器的 WXRuntime_Log（微信运行时真正读写的地方）
///   vault = 程序目录 profiles\qbN（金库：凭证、运行时状态、游戏包的备份）
/// </summary>
public static class BoxPaths
{
    public const string UserDataRel = @"AppData\Local\Tencent\QQBrowser\User Data";
    public const string RuntimeName = "WXRuntime_V22346514299";

    public static string SandboxBoxRoot(string box) => Path.Combine(EnvDetect.SandboxRoot, box);
    public static string UserData(string box) => Path.Combine(EnvDetect.SandboxRoot, box, "user", "current", UserDataRel);
    public static string WmpfLive(string box) => Path.Combine(UserData(box), "WXRuntime_Log");

    public static string Vault(string box) => Path.Combine(AppPaths.Profiles, box);
    public static string WmpfVault(string box) => Path.Combine(Vault(box), "wmpf");
    public static string BrowserVault(string box) => Path.Combine(Vault(box), "browser");
    public static string CredentialDir(string box) => Path.Combine(Vault(box), "credential");
    public static string RevokedFile(string box) => Path.Combine(CredentialDir(box), "revoked.txt");
    public static string NeedScanFile(string box) => Path.Combine(Vault(box), "refresh-need-scan.txt");
    public static string NeedScanStamp(string box) => Path.Combine(Vault(box), "refresh-need-scan.event");
    public static string QrStreakFile(string box) => Path.Combine(Vault(box), "refresh-qr-streak.txt");
    public static string LoginOkFile(string box) => Path.Combine(Vault(box), "login-ok.txt");

    public static int DebugPort(string box)
    {
        int n = Sandboxie.BoxNumber(box);
        return n > 0 ? 9300 + n : 9222;
    }
}
