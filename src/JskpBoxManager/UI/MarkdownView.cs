using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

namespace JskpBoxManager.UI;

/// <summary>把 CHANGELOG 这类简单 Markdown 排成 FlowDocument，不显示 # ** ` 等源码符号。</summary>
public static class MarkdownView
{
    static readonly Brush Heading = Brush("#111827");
    static readonly Brush Body = Brush("#374151");
    static readonly Brush Muted = Brush("#6B7280");
    static readonly Brush Accent = Brush("#15803D");

    public static void Fill(RichTextBox box, string markdown)
    {
        var doc = new FlowDocument
        {
            FontFamily = new FontFamily("Microsoft YaHei UI"),
            FontSize = 13,
            PagePadding = new Thickness(10),
            TextAlignment = TextAlignment.Left,
        };
        foreach (var block in Parse(markdown ?? ""))
            doc.Blocks.Add(block);
        box.Document = doc;
        box.CaretPosition = doc.ContentStart;
    }

    public static IEnumerable<Block> Parse(string md)
    {
        var lines = md.Replace("\r\n", "\n").Split('\n');
        var i = 0;
        while (i < lines.Length)
        {
            var raw = lines[i];
            var line = raw.TrimEnd();
            i++;
            if (line.Length == 0) continue;

            if (line.StartsWith("### "))
            {
                yield return HeadingPara(InlineText(line[4..]), 14, FontWeights.SemiBold, Accent, 14, 4);
                continue;
            }
            if (line.StartsWith("## "))
            {
                yield return HeadingPara(InlineText(line[3..]), 16, FontWeights.Bold, Heading, 18, 6);
                continue;
            }
            if (line.StartsWith("# "))
            {
                yield return HeadingPara(InlineText(line[2..]), 18, FontWeights.Bold, Heading, 8, 8);
                continue;
            }
            if (Regex.IsMatch(line, @"^-{3,}\s*$"))
            {
                yield return new Paragraph { Margin = new Thickness(0, 8, 0, 8), BorderBrush = Brush("#E5E7EB"), BorderThickness = new Thickness(0, 0, 0, 1) };
                continue;
            }

            if (line.StartsWith("- ") || line.StartsWith("* "))
            {
                var items = new List<string> { line[2..] };
                while (i < lines.Length)
                {
                    var n = lines[i].TrimEnd();
                    if (n.StartsWith("- ") || n.StartsWith("* ")) { items.Add(n[2..]); i++; continue; }
                    // 续行：缩进两格或空行后缩进
                    if (n.Length > 0 && (n.StartsWith("  ") || n.StartsWith("\t"))) { items[^1] += " " + n.Trim(); i++; continue; }
                    break;
                }
                var list = new List { MarkerStyle = TextMarkerStyle.Disc, Margin = new Thickness(8, 2, 0, 8), Padding = new Thickness(4, 0, 0, 0) };
                foreach (var item in items)
                {
                    var p = new Paragraph { Margin = new Thickness(0, 1, 0, 3), LineHeight = 20, Foreground = Body };
                    foreach (var inl in InlineText(item)) p.Inlines.Add(inl);
                    list.ListItems.Add(new ListItem(p));
                }
                yield return list;
                continue;
            }

            var body = new Paragraph { Margin = new Thickness(0, 0, 0, 6), LineHeight = 20, Foreground = Body };
            foreach (var inl in InlineText(line)) body.Inlines.Add(inl);
            yield return body;
        }
    }

    static Paragraph HeadingPara(IEnumerable<Inline> inlines, double size, FontWeight weight, Brush color, double top, double bottom)
    {
        var p = new Paragraph { FontSize = size, FontWeight = weight, Foreground = color, Margin = new Thickness(0, top, 0, bottom) };
        foreach (var inl in inlines) p.Inlines.Add(inl);
        return p;
    }

    /// <summary>处理 **粗体**、`代码`、普通链接文字（去掉 [文字](url) 的括号部分只留文字）。</summary>
    static IEnumerable<Inline> InlineText(string text)
    {
        text = Regex.Replace(text, @"\[([^\]]+)\]\([^)]+\)", "$1");
        var rx = new Regex(@"(\*\*[^*]+\*\*|`[^`]+`)");
        int last = 0;
        foreach (Match m in rx.Matches(text))
        {
            if (m.Index > last) yield return new Run(text[last..m.Index]) { Foreground = Body };
            var t = m.Value;
            if (t.StartsWith("**"))
                yield return new Run(t[2..^2]) { FontWeight = FontWeights.SemiBold, Foreground = Heading };
            else
                yield return new Run(t[1..^1]) { FontFamily = new FontFamily("Consolas"), Background = Brush("#F3F4F6"), Foreground = Brush("#1F2937") };
            last = m.Index + m.Length;
        }
        if (last < text.Length) yield return new Run(text[last..]) { Foreground = Body };
        else if (text.Length == 0) yield return new Run("");
    }

    static SolidColorBrush Brush(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}
