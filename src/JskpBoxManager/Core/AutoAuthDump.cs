using System.Globalization;
using System.Text;

namespace JskpBoxManager.Core;

/// <summary>
/// 一次 AutoAuth（cmdid 3198）交换过程的完整抓取：请求参数、响应密文、解密后的
/// 每一层 protobuf 字段。
/// </summary>
public sealed class AutoAuthCapture
{
    public string At = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    public string Box = "";
    public string Via = "";                 // renew / probe / capture / dump
    public string Host = "";
    public int Port;

    public string Uin = "";
    public string OldKeySha = "";
    public string OldEncLen = "";

    // 请求
    public int PlainLen;
    public int HybridLen;
    public int BodyLen;
    public string RequestHex = "";

    // 响应（原样）
    public int RespCmdId;
    public int RespBodyLen;
    public string RespBodyHex = "";
    public int WpkgHeadLen = -1;
    public int CipherLen;
    public string CipherHex = "";

    // 解密后
    public int DecodedLen;
    public string DecodedHex = "";
    public string DecryptError = "";

    // 解析结果：顶层 / base 结果块 / unified / unified.session
    public Dictionary<int, (ulong Num, byte[] Bytes)> Top = new();
    public Dictionary<int, (ulong Num, byte[] Bytes)> Base = new();
    public Dictionary<int, (ulong Num, byte[] Bytes)> Unified = new();
    public Dictionary<int, (ulong Num, byte[] Bytes)> Session = new();

    public long Code = long.MaxValue;
    public string NewKeySha = "";
    public int NewKeyLen, NewEncLen, NewSrvLen;
    public string Why = "";

    public bool Ok => Code == 0 && !string.IsNullOrEmpty(NewKeySha);
}

/// <summary>
/// AutoAuth 响应的完整字段 dump。
///
/// <para>
/// 目的很具体：**确认服务端到底有没有回传「有效期 / 到期时间」之类的字段**。
/// 有，就能算出免扫的真实上限；没有，就说明寿命只能靠实测统计。
/// 之前的 `DumpUnknownFields` 写了却从没被调用（死代码），所以一次 dump 都没产生过。
/// </para>
///
/// <para>
/// 三种触发方式：
/// <list type="number">
/// <item><c>autoauth-dump qbN</c> 命令：显式抓一次（会真实轮换密钥，自动写回）；</item>
/// <item>环境变量 <c>JSKP_DUMP_AUTOAUTH=1</c>：让平时的续期 / 探测顺手留档；</item>
/// <item>程序目录下放一个 <c>autoauth-dump.on</c> 文件：等同环境变量，但不用每次设。</item>
/// </list>
/// </para>
///
/// <para>
/// 产物：<c>logs\qbN.autoauth-fields.txt</c>（追加，人读）+ <c>samples\autoauth\&lt;时间戳&gt;-qbN.txt</c>（单份，便于对比）。
/// 含密文与解密后明文的十六进制——**本地诊断用，不要外传**。
/// </para>
/// </summary>
public static class AutoAuthDump
{
    public const string EnvFlag = "JSKP_DUMP_AUTOAUTH";
    public const string MarkerName = "autoauth-dump.on";

    /// <summary>是否要顺手留档（环境变量或标记文件）。</summary>
    public static bool Enabled
    {
        get
        {
            try
            {
                var v = Environment.GetEnvironmentVariable(EnvFlag);
                if (!string.IsNullOrEmpty(v) && v != "0" && !v.Equals("false", StringComparison.OrdinalIgnoreCase))
                    return true;
                return File.Exists(Path.Combine(AppPaths.AppDir, MarkerName));
            }
            catch { return false; }
        }
    }

    public static string FieldsFile(string box) => Path.Combine(AppPaths.Logs, box + ".autoauth-fields.txt");

    /// <summary>写一份 dump，返回单份报告的路径。</summary>
    public static string Write(string box, AutoAuthCapture c)
    {
        var text = Render(c);
        string single = "";
        try
        {
            Directory.CreateDirectory(AppPaths.Logs);
            File.AppendAllText(FieldsFile(box),
                $"===== {c.At}  via={c.Via}  code={c.Code}{(c.Ok ? "  OK" : "")} =====\r\n{text}\r\n",
                new UTF8Encoding(false));
        }
        catch (Exception ex) { Log.Box(box, "autoauth dump: append failed " + ex.Message); }

        try
        {
            var dir = Path.Combine(AppPaths.Samples, "autoauth");
            Directory.CreateDirectory(dir);
            single = Path.Combine(dir, $"{DateTime.Now:yyyyMMdd-HHmmss}-{box}.txt");
            File.WriteAllText(single, text, new UTF8Encoding(false));
        }
        catch (Exception ex) { Log.Box(box, "autoauth dump: single file failed " + ex.Message); }

        Log.Box(box, $"autoauth dump written -> {single}");
        // 日志里给一行摘要，方便不打开文件也知道结果
        Log.Box(box, $"autoauth dump: " + Summary(c));
        return single;
    }

    /// <summary>一行摘要（日志 / 命令行用）。</summary>
    public static string Summary(AutoAuthCapture c)
    {
        var sb = new StringBuilder();
        sb.Append($"code={c.Code}");
        if (c.Ok) sb.Append($"  新key={c.NewKeySha} enc={c.NewEncLen} srv={c.NewSrvLen}");
        sb.Append($"  响应 {c.RespBodyLen}B → 解密 {c.DecodedLen}B");
        sb.Append($"  顶层字段=[{string.Join(",", c.Top.Keys.OrderBy(x => x))}]");
        if (c.Base.Count > 0) sb.Append($"  base字段=[{string.Join(",", c.Base.Keys.OrderBy(x => x))}]");
        if (c.Session.Count > 0) sb.Append($"  session字段=[{string.Join(",", c.Session.Keys.OrderBy(x => x))}]");
        return sb.ToString();
    }

    // ---------------- 渲染 ----------------

    static string Render(AutoAuthCapture c)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"时间      {c.At}   via={c.Via}   box={c.Box}");
        sb.AppendLine($"目标      {c.Host}:{c.Port}   uin={c.Uin}");
        sb.AppendLine($"旧 key    {c.OldKeySha}   encKey长度={c.OldEncLen}");
        sb.AppendLine($"请求      明文 {c.PlainLen}B → hybrid {c.HybridLen}B → body {c.BodyLen}B");
        if (c.RequestHex.Length > 0) sb.AppendLine($"          请求体前 96B: {Head(c.RequestHex)}");
        sb.AppendLine();
        sb.AppendLine($"响应      cmdid={c.RespCmdId}  body={c.RespBodyLen}B  wpkg头={c.WpkgHeadLen}B  密文={c.CipherLen}B");
        if (c.RespBodyHex.Length > 0) sb.AppendLine($"          响应体前 96B: {Head(c.RespBodyHex)}");
        if (c.CipherHex.Length > 0) sb.AppendLine($"          密文前 96B:   {Head(c.CipherHex)}");
        sb.AppendLine();
        sb.AppendLine($"解密      {c.DecodedLen}B" + (c.DecryptError.Length > 0 ? $"  失败：{c.DecryptError}" : ""));
        if (c.DecodedHex.Length > 0) sb.AppendLine($"          明文前 96B:   {Head(c.DecodedHex)}");
        sb.AppendLine($"结果      code={c.Code}" + (c.Why.Length > 0 ? $"（{c.Why}）" : ""));
        if (c.Ok) sb.AppendLine($"          新key={c.NewKeySha}  key长度={c.NewKeyLen}  enc长度={c.NewEncLen}  serverId长度={c.NewSrvLen}");
        sb.AppendLine();

        sb.AppendLine("─ protobuf 结构（逐层展开）─");
        sb.AppendLine("顶层:");
        Walk(sb, c.Top, "  ", 0);

        if (c.Base.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("base 结果块（field 1，code 在这里）:");
            Walk(sb, c.Base, "  ", 0);
        }
        if (c.Unified.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("unified（field 2）:");
            Walk(sb, c.Unified, "  ", 0);
        }
        if (c.Session.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("unified.session（field 2.2，新凭证在这里）:");
            Walk(sb, c.Session, "  ", 0);
        }

        sb.AppendLine();
        sb.AppendLine("─ 自动判读 ─");
        foreach (var line in Interpret(c)) sb.AppendLine("  " + line);

        // 完整报文原样留档：报告里的「前 96B」只够人眼扫一眼，
        // 要离线展开每一层（尤其是 base/统一体里那些还没搞清含义的块）必须有全量。
        sb.AppendLine();
        sb.AppendLine("─ 完整报文（十六进制，可离线复算）─");
        sb.AppendLine("请求体 body:");
        sb.AppendLine(c.RequestHex);
        sb.AppendLine();
        sb.AppendLine("响应体（含 wpkg 头）:");
        sb.AppendLine(c.RespBodyHex);
        sb.AppendLine();
        sb.AppendLine("响应密文（剥掉 wpkg 头）:");
        sb.AppendLine(c.CipherHex);
        sb.AppendLine();
        sb.AppendLine("解密后明文:");
        sb.AppendLine(c.DecodedHex);
        return sb.ToString();
    }

    static string Head(string hex) => hex.Length <= 192 ? hex : hex[..192] + "…";

    /// <summary>递归展开一层 protobuf。字节段依次尝试：空 / 可读文本 / 合法 protobuf / 十六进制。</summary>
    static void Walk(StringBuilder sb, Dictionary<int, (ulong Num, byte[] Bytes)> fields, string indent, int depth)
    {
        if (fields.Count == 0) { sb.AppendLine(indent + "(空)"); return; }
        foreach (var kv in fields.OrderBy(x => x.Key))
        {
            var (num, bytes) = kv.Value;
            if (bytes.Length == 0)
            {
                sb.AppendLine($"{indent}f{kv.Key} = varint {num}" + Timestamp(num));
                continue;
            }

            var text = AsText(bytes);
            if (text != null)
            {
                sb.AppendLine($"{indent}f{kv.Key} = 文本[{bytes.Length}] \"{text}\"");
                continue;
            }

            if (depth < 4 && LooksLikePb(bytes, out var sub))
            {
                sb.AppendLine($"{indent}f{kv.Key} = 嵌套[{bytes.Length}] {{");
                Walk(sb, sub, indent + "  ", depth + 1);
                sb.AppendLine(indent + "}");
                continue;
            }

            var hex = Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)));
            sb.AppendLine($"{indent}f{kv.Key} = bytes[{bytes.Length}] {hex}" + (bytes.Length > 48 ? "…" : ""));
        }
    }

    /// <summary>看起来是 UTF-8 可读字符串就返回它，否则 null。</summary>
    static string AsText(byte[] b)
    {
        if (b.Length == 0 || b.Length > 512) return null;
        int printable = 0;
        foreach (var x in b)
        {
            if (x == 9 || x == 10 || x == 13) { printable++; continue; }
            if (x >= 32 && x < 127) { printable++; continue; }
            if (x >= 0xC0) { printable++; continue; }   // 多字节 UTF-8 的前导/续字节，宽松放过
        }
        if (printable < b.Length * 0.95) return null;
        try
        {
            var s = new UTF8Encoding(false, true).GetString(b);
            if (s.Length == 0) return null;
            // 全是控制字符的也别当文本
            if (s.All(ch => ch < 32 || ch == 127)) return null;
            return s.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
        }
        catch { return null; }
    }

    /// <summary>能否完整解析成 protobuf（且字段数合理），能就返回解析结果。</summary>
    static bool LooksLikePb(byte[] b, out Dictionary<int, (ulong Num, byte[] Bytes)> parsed)
    {
        parsed = null;
        if (b.Length < 2) return false;
        var p = MmtlsProtocol.PbParse(b);
        if (p.Count == 0) return false;
        // 要求「解析出的字段几乎覆盖整段」，否则只是碰巧开头像 tag
        int covered = p.Sum(kv => kv.Value.Bytes.Length + 2);
        if (covered < b.Length * 0.6) return false;
        parsed = p;
        return true;
    }

    /// <summary>varint 在合理时间戳范围内就标注出来。</summary>
    static string Timestamp(ulong v)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (v > (ulong)(now - 5 * 365L * 86400) && v < (ulong)(now + 5 * 365L * 86400))
            return $"   ← 像 unix 秒（{DateTimeOffset.FromUnixTimeSeconds((long)v).ToLocalTime():yyyy-MM-dd HH:mm:ss}）";

        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (v > (ulong)(nowMs - 5 * 365L * 86400 * 1000) && v < (ulong)(nowMs + 5 * 365L * 86400 * 1000) && v > 1_000_000_000_000)
            return $"   ← 像 unix 毫秒（{DateTimeOffset.FromUnixTimeMilliseconds((long)v).ToLocalTime():yyyy-MM-dd HH:mm:ss}）";

        if (v > 0 && v <= 12) return "   ← 很小的值，更像枚举/标志位，不是时间";
        return "";
    }

    /// <summary>用现有知识判读这份响应，直接回答「有没有有效期」。重点是找出可疑的新字段。</summary>
    static List<string> Interpret(AutoAuthCapture c)
    {
        var lines = new List<string>();

        // 已知字段：session 里 3=AutoauthKey 4=AutoauthEncKey 9=ServerId
        var known = new[] { 3, 4, 9 };
        var sessionUnknown = c.Session.Keys.Where(k => !known.Contains(k)).OrderBy(x => x).ToList();
        var baseUnknown = c.Base.Keys.Where(k => k != 1).OrderBy(x => x).ToList();
        var topUnknown = c.Top.Keys.Where(k => k is not (1 or 2)).OrderBy(x => x).ToList();

        if (c.Session.Count > 0)
        {
            lines.Add(sessionUnknown.Count == 0
                ? "session 里只有已知字段（3=key 4=enc 9=serverId），**没有任何有效期/到期时间字段**。"
                : $"session 里有 {sessionUnknown.Count} 个未知字段：{string.Join(",", sessionUnknown.Select(k => "f" + k))}"
                  + " —— 逐个看上面展开内容，重点找像时间戳的 varint。");
        }
        if (CountIsZero(c)) lines.Add("base 只有 code 字段，服务端没附带任何说明。");
        else
        {
            var extra = baseUnknown.ToList();
            // f2 是 base 里唯一的 varint 且恒为 0，不是「说明文本」
            var texts = extra.Where(k => AsText(c.Base[k].Bytes) != null).ToList();
            if (texts.Count > 0)
                lines.Add($"base 里有文本字段：{string.Join(",", texts.Select(k => $"f{k}={AsText(c.Base[k].Bytes)}"))}"
                    + "（被拒时通常会有 error_msg 之类的说明）。");
            if (extra.Count > 0)
                lines.Add($"base 额外字段：{string.Join(",", extra.Select(k => "f" + k))}"
                    + $"（{string.Join("、", extra.Select(k => $"f{k}={Describe(c.Base[k])}"))}）。"
                    + "实测成功样本里 f2 恒为 0，暂无含义。");
        }
        if (topUnknown.Count > 0)
            lines.Add($"顶层还有 {topUnknown.Count} 个未分析的块：{string.Join(",", topUnknown.Select(k => "f" + k))}。");

        // 全树扫一遍 varint，看有没有落在时间窗里的——那才是「有效期」最可能的形态。
        // 注意 ilinkst_ 票据是 base64 嵌套 protobuf，必须单独钻进去（时间戳就藏在里面）。
        var stamps = new List<string>();
        var tickets = new List<string>();
        ScanStamps(c.Top, "top", stamps, tickets, 0);

        foreach (var t in tickets) lines.Add(t);

        if (stamps.Count > 0) lines.Add("树里像时间戳的 varint：" + string.Join("；", stamps.Take(12)));
        else lines.Add("树里**没有任何 varint 落在合理时间窗内**。");

        if (c.Code == -13) lines.Add("这是 -13（作废）样本：把 base 里的额外字段与成功样本对照，能看出服务端为什么判死。");
        if (c.Code == 0 && c.NewKeyLen > 0)
            lines.Add($"这是成功样本：旧 key {c.OldKeySha} → 新 key {c.NewKeySha}。");
        return lines;
    }

    /// <summary>把一个字段值描述成「varint 0」/「bytes[24]」这类简短形式。</summary>
    static string Describe((ulong Num, byte[] Bytes) f)
        => f.Bytes.Length > 0 ? $"bytes[{f.Bytes.Length}]" : $"varint {f.Num}";

    static bool CountIsZero(AutoAuthCapture c) => c.Base.Keys.All(k => k == 1) && c.Base.Count <= 1;

    static void ScanStamps(Dictionary<int, (ulong Num, byte[] Bytes)> f, string path, List<string> outList,
        List<string> tickets, int depth)
    {
        if (depth > 4 || f == null) return;
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (var kv in f)
        {
            var (num, bytes) = kv.Value;
            if (bytes.Length == 0)
            {
                if (num > (ulong)(now - 5 * 365L * 86400) && num < (ulong)(now + 5 * 365L * 86400))
                    outList.Add($"{path}.f{kv.Key} = {num}"
                        + $"（{DateTimeOffset.FromUnixTimeSeconds((long)num).ToLocalTime():yyyy-MM-dd HH:mm:ss}）");
                continue;
            }

            // ilinkst_ 票据：base64 里套着 protobuf，真实时间戳藏在最里层
            var txt = AsText(bytes);
            if (txt != null && txt.StartsWith("ilinkst_", StringComparison.Ordinal))
            {
                var note = DecodeTicket(txt, out var inner);
                tickets.Add($"{path}.f{kv.Key} 是 ilinkst_ 票据（{note}）");
                foreach (var kv2 in inner)
                {
                    var (n2, b2) = kv2.Value;
                    if (b2.Length == 0 && n2 > (ulong)(now - 5 * 365L * 86400) && n2 < (ulong)(now + 5 * 365L * 86400))
                        outList.Add($"  票据.f{kv2.Key} = {n2}"
                            + $"（{DateTimeOffset.FromUnixTimeSeconds((long)n2).ToLocalTime():yyyy-MM-dd HH:mm:ss}）");
                }
                continue;
            }

            if (bytes.Length > 2 && depth < 4 && LooksLikePb(bytes, out var sub))
                ScanStamps(sub, $"{path}.f{kv.Key}", outList, tickets, depth + 1);
        }
    }

    /// <summary>
    /// 解开 ilinkst_ 票据（urlsafe base64 → protobuf），返回人读摘要。
    /// 实测结构：f1=uin、f2=16B 固定头、f3=48B、f4=ilinkapp_xxx、f5=**签发时刻（unix 秒）**。
    /// 关键结论：里面**只有签发时刻，没有到期时间**。
    /// </summary>
    static string DecodeTicket(string text, out Dictionary<int, (ulong Num, byte[] Bytes)> inner)
    {
        inner = new();
        try
        {
            var b64 = text["ilinkst_".Length..].Replace('-', '+').Replace('_', '/');
            b64 += new string('=', (4 - b64.Length % 4) % 4);
            var raw = Convert.FromBase64String(b64);
            inner = MmtlsProtocol.PbParse(raw);
            if (!inner.TryGetValue(5, out var f5) || f5.Bytes.Length > 0) return $"{raw.Length}B，没有 f5 时间戳";
            var at = DateTimeOffset.FromUnixTimeSeconds((long)f5.Num).ToLocalTime();
            var delta = (at - DateTime.Now).TotalMinutes;
            return $"{raw.Length}B，f5={f5.Num} 即 {at:yyyy-MM-dd HH:mm:ss}"
                + (Math.Abs(delta) < 10 ? "，与本次请求同时刻 → 是**签发时间**，不是到期时间" : "");
        }
        catch (Exception ex) { return "解析失败：" + ex.Message; }
    }
}
