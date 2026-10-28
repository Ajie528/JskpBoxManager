namespace JskpBoxManager.Core;

/// <summary>robocopy 封装。返回码 &lt; 8 视为成功；bit0 = 有文件被复制。</summary>
public static class Robo
{
    static readonly string[] Quiet = { "/NFL", "/NDL", "/NJH", "/NJS", "/nc", "/ns", "/np" };

    public static int Run(string src, string dst, params string[] options)
    {
        if (!Directory.Exists(src)) return 16;
        Directory.CreateDirectory(dst);
        var args = new List<string> { src, dst };
        args.AddRange(options);
        args.AddRange(Quiet);
        var (exit, _) = ProcessUtil.Run(ProcessUtil.System32("robocopy.exe"), args, 30 * 60 * 1000);
        return exit;
    }

    public static bool Copied(int code) => code >= 0 && code < 8 && (code & 1) != 0;

    /// <summary>完整复制（不删除目标多余文件）。</summary>
    public static int Mirror(string src, string dst) => Run(src, dst, "/E", "/COPY:DAT", "/R:2", "/W:2");

    /// <summary>只补目标缺的文件，已有的一律不动。</summary>
    public static int MergeMissing(string src, string dst) => Run(src, dst, "/E", "/COPY:DAT", "/XC", "/XN", "/XO", "/R:1", "/W:1");

    /// <summary>只用更新的覆盖更旧的（游戏包、热更新）。</summary>
    public static int MergeNewer(string src, string dst) => Run(src, dst, "/E", "/XO", "/COPY:DAT", "/FFT", "/R:2", "/W:1");
}
