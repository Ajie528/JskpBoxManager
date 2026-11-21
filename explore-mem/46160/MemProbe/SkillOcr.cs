using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Diagnostics;

namespace MemProbe;

/// <summary>
/// 技能选择界面的 OCR 识别（兜底方案）。
///
/// 流程：
///   1. 截图游戏窗口
///   2. 在卡牌区域里按「白色文字像素」自动定位每张卡的标题栏（不硬编码坐标）
///   3. 放大 + 二值化后交给 tesseract（chi_sim）识别
///   4. 输出 4 个技能名
///
/// 只读屏幕，不碰游戏内存。用于内存读不到时的兜底。
/// </summary>
public static class SkillOcr
{
    public sealed record Card(int Index, string Name, int Left, int Top, int Width, int Height);

    const string TesseractPath = @"C:\Program Files\Tesseract-OCR\tesseract.exe";

    public static bool Available => File.Exists(TesseractPath);

    /// <summary>从整张窗口截图里识别 4 张可选技能卡的名字。</summary>
    public static List<Card> ReadCards(Bitmap shot, Action<string> log = null)
    {
        log ??= _ => { };
        var result = new List<Card>();

        // ① 在「卡牌区」里找白色文字行（卡牌区约在窗口高度的 45%~75%）
        int y0 = (int)(shot.Height * 0.44);
        int y1 = (int)(shot.Height * 0.78);
        var textRows = new List<int>();
        for (int y = y0; y < y1; y++)
        {
            int cnt = 0;
            for (int x = 0; x < shot.Width; x += 2)
            {
                var c = shot.GetPixel(x, y);
                if (c.R > 195 && c.G > 195 && c.B > 195) cnt++;
            }
            if (cnt > shot.Width / 60) textRows.Add(y);
        }
        if (textRows.Count == 0) { log("没找到文字行"); return result; }

        // ② 把连续行聚成「标题带」
        var bands = new List<(int From, int To)>();
        int s = textRows[0], p = textRows[0];
        foreach (var y in textRows)
        {
            if (y - p > 4) { bands.Add((s, p)); s = y; }
            p = y;
        }
        bands.Add((s, p));
        // 标题带通常是最靠上的那一组
        log($"文字带 {bands.Count} 个：" + string.Join("，", bands.Select(b => $"{b.From}~{b.To}")));

        var titleBand = bands.OrderBy(b => b.From).First();
        int ty = Math.Max(0, titleBand.From - 4);
        int th = Math.Min(shot.Height - ty, titleBand.To - titleBand.From + 9);

        // ③ 在这一带里按列找空隙，分出 4 张卡
        var cols = new List<int>();
        for (int x = 0; x < shot.Width; x++)
        {
            int cnt = 0;
            for (int y = titleBand.From; y <= titleBand.To; y++)
            {
                var c = shot.GetPixel(x, y);
                if (c.R > 195 && c.G > 195 && c.B > 195) cnt++;
            }
            if (cnt > 0) cols.Add(x);
        }
        if (cols.Count == 0) { log("标题带里没有文字"); return result; }

        var groups = new List<(int From, int To)>();
        s = cols[0]; p = cols[0];
        foreach (var x in cols)
        {
            if (x - p > 12) { groups.Add((s, p)); s = x; }
            p = x;
        }
        groups.Add((s, p));
        // 合并过窄的碎片
        groups = groups.Where(g => g.To - g.From >= 12).ToList();
        log($"列分组 {groups.Count} 个：" + string.Join("，", groups.Select(g => $"{g.From}~{g.To}")));

        // ④ 对每组做 OCR
        for (int i = 0; i < groups.Count && i < 8; i++)
        {
            var g = groups[i];
            int gx = Math.Max(0, g.From - 6);
            int gw = Math.Min(shot.Width - gx, g.To - g.From + 13);
            if (gw < 20 || th < 8) continue;

            var name = OcrRegion(shot, gx, ty, gw, th);
            if (name.Length == 0) continue;
            result.Add(new Card(i, name, gx, ty, gw, th));
            log($"  [{i}] {name}   (x={gx} w={gw})");
        }
        return result;
    }

    /// <summary>裁一块、放大、二值化，交给 tesseract。</summary>
    static string OcrRegion(Bitmap shot, int x, int y, int w, int h)
    {
        const int scale = 6;
        using var big = new Bitmap(w * scale, h * scale);
        using (var g = Graphics.FromImage(big))
        {
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.DrawImage(shot, new Rectangle(0, 0, big.Width, big.Height),
                        new Rectangle(x, y, w, h), GraphicsUnit.Pixel);
        }

        // 二值化：白字留黑，其余留白（提高对比）
        for (int yy = 0; yy < big.Height; yy++)
            for (int xx = 0; xx < big.Width; xx++)
            {
                var c = big.GetPixel(xx, yy);
                int lum = (c.R * 299 + c.G * 587 + c.B * 114) / 1000;
                big.SetPixel(xx, yy, lum > 170 ? Color.Black : Color.White);
            }

        var tmp = Path.Combine(Path.GetTempPath(), "jskp-ocr-" + Guid.NewGuid().ToString("N") + ".png");
        big.Save(tmp, ImageFormat.Png);
        try
        {
            var psi = new ProcessStartInfo(TesseractPath)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
            };
            foreach (var a in new[] { tmp, "stdout", "-l", "chi_sim", "--psm", "7" }) psi.ArgumentList.Add(a);
            using var proc = Process.Start(psi);
            var outp = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(8000);
            return Clean(outp);
        }
        catch { return ""; }
        finally { try { File.Delete(tmp); } catch { } }
    }

    /// <summary>去掉空格/标点噪声，只留中文、字母、数字、加号。</summary>
    static string Clean(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        var sb = new System.Text.StringBuilder();
        foreach (var c in s.Trim())
        {
            if (c >= 0x4E00 && c <= 0x9FFF) sb.Append(c);
            else if (char.IsLetterOrDigit(c)) sb.Append(c);
            else if (c == '+') sb.Append('+');
        }
        var r = sb.ToString();
        return r.Length >= 2 ? r : "";
    }
}
