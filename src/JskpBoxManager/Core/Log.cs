using System.IO;
using System.Text;

namespace JskpBoxManager.Core;

public static class Log
{
    static readonly object Gate = new();
    static readonly UTF8Encoding Utf8 = new(false);

    /// <summary>写 logs\qbN.log，格式与旧版一致：yyyy-MM-dd HH:mm:ss [qbN] msg</summary>
    public static void Box(string box, string msg)
    {
        Append(AppPaths.BoxLog(box), $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{box}] {msg}");
    }

    public static void App(string msg)
    {
        Append(Path.Combine(AppPaths.Logs, "app.log"), $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {msg}");
    }

    static void Append(string path, string line)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                for (int i = 0; i < 5; i++)
                {
                    try
                    {
                        using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                        var b = Utf8.GetBytes(line + "\r\n");
                        fs.Write(b, 0, b.Length);
                        return;
                    }
                    catch (IOException) { Thread.Sleep(50); }
                }
            }
        }
        catch { }
    }

    /// <summary>读日志末尾若干行（给界面显示）。</summary>
    public static string[] Tail(string path, int lines)
    {
        try
        {
            if (!File.Exists(path)) return Array.Empty<string>();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            long len = fs.Length;
            long start = Math.Max(0, len - 256 * 1024);
            fs.Seek(start, SeekOrigin.Begin);
            using var r = new StreamReader(fs, Encoding.UTF8);
            var all = r.ReadToEnd().Split('\n').Select(s => s.TrimEnd('\r')).Where(s => s.Length > 0).ToArray();
            return all.Length <= lines ? all : all[^lines..];
        }
        catch { return Array.Empty<string>(); }
    }
}
