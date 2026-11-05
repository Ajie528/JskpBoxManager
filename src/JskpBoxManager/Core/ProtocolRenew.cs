using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace JskpBoxManager.Core;

/// <summary>
/// 纯协议续期（不启浏览器、不启微信运行时）：直接 mmtls 连 longcloud.weixin.com
/// 发 AutoAuth（cmdid 3198），拿回轮换后的 AutoauthKey / AutoauthEncKey / ServerId。
///
/// 实现放在 tools\mmtls_autoauth.py（Python + cryptography），这里只做编排与安全落盘。
///
/// **为什么必须先落盘再发送**：
/// AutoAuth 是「轮换」语义——请求一旦被服务端接受，旧 key 立即作废。
/// 如果先发送、成功后才写本地，中途断网/程序被杀就会变成
/// 「服务端已换新、本地还是旧的」→ 这把凭证永久报废，只能重新扫码。
/// 所以流程固定为：
///   1. 写 attempted 标记（含发送前的旧 key 指纹）
///   2. 发送并等响应
///   3. 成功 → 把新凭证写回，清掉 attempted
///      失败/超时 → attempted 保留（下次启动能看到「可能已轮换」的告警，不会盲目重放）
/// </summary>
public static class ProtocolRenew
{
    public static string ScriptPath => Path.Combine(AppPaths.AppDir, "tools", "mmtls_autoauth.py");

    static string AttemptFile(string box) => Path.Combine(AppPaths.Logs, box + ".renew-attempt");

    public sealed record Result(bool Ok, string Message, string NewKeyHash = "");

    /// <summary>是否具备运行条件（脚本 + python + cryptography）。</summary>
    public static (bool Ready, string Reason) Check()
    {
        if (!File.Exists(ScriptPath)) return (false, "缺少 tools\\mmtls_autoauth.py");
        var py = FindPython();
        if (py.Length == 0) return (false, "找不到 python（py -3 / python）");
        return (true, "");
    }

    static string FindPython()
    {
        foreach (var exe in new[] { "py", "python" })
        {
            try
            {
                var (code, _) = ProcessUtil.Run(exe, new[] { "-c", "import cryptography" }, 8000);
                if (code == 0) return exe;
            }
            catch { }
        }
        return "";
    }

    /// <summary>上一次续期是否留下了「已发送但结果未知」的标记。</summary>
    public static DateTime? PendingAttempt(string box)
    {
        try
        {
            var f = AttemptFile(box);
            if (!File.Exists(f)) return null;
            var o = JsonFile.ReadObject(f);
            return DateTime.TryParseExact(JsonFile.Str(o, "at"), "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var t) ? t : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// 纯协议续期一个沙箱。会真实向服务端发请求并轮换密钥。
    /// </summary>
    public static Result Renew(string box, bool dryRun = false)
    {
        var (ready, reason) = Check();
        if (!ready) return new Result(false, "协议续期不可用：" + reason);

        var vault = Ilink.VaultState(box);
        if (!vault.Valid) return new Result(false, "金库没有有效凭证，先扫码登录一次");

        // ---- 1. 发送前先落盘 attempted ----
        // 关键：这一步不成功就不发请求，否则可能丢掉服务端已轮换的密钥。
        var at = DateTime.Now;
        if (!dryRun)
        {
            try
            {
                Directory.CreateDirectory(AppPaths.Logs);
                JsonFile.WriteObject(AttemptFile(box), new JsonObject
                {
                    ["at"] = at.ToString("yyyy-MM-dd HH:mm:ss"),
                    ["uin"] = vault.Uin,
                    ["oldKeySha"] = vault.KeyHash,
                    ["oldPskSha"] = vault.PskHash,
                    ["stage"] = "sent",
                });
            }
            catch (Exception ex)
            {
                Log.Box(box, "protocol renew: cannot write attempt marker, abort before send: " + ex.Message);
                return new Result(false, "无法写续期标记，为避免丢密钥已放弃发送：" + ex.Message);
            }
            Log.Box(box, $"protocol renew: attempt marker written (old key {vault.KeyHash})");
        }

        // ---- 2. 发送 ----
        var args = new List<string> { ScriptPath, "--box", box, "--appdir", AppPaths.AppDir, "--send" };
        if (!dryRun) args.Add("--save");
        var (exit, output) = ProcessUtil.Run(FindPython(),
            new[] { "-3" }.Concat(args), 120000, System.Text.Encoding.UTF8);

        bool ok = output.Contains("base.code=0") && output.Contains("✅");
        // 日志里有两种写法：base.code=0（有符号 0） 或 base.code=18446744073709551614（有符号 -2）
        // 优先看括号里的有符号值，它才是业务码。
        long code = long.MinValue;
        var signed = Regex.Match(output, @"base\.code=\d+（有符号 (-?\d+)）");
        if (signed.Success && long.TryParse(signed.Groups[1].Value, out var sc)) code = sc;
        else
        {
            var raw = Regex.Match(output, @"base\.code=(-?\d+)");
            if (raw.Success && long.TryParse(raw.Groups[1].Value, out var rc))
                // 服务端用无符号 varint 表示负数，超过 long.MaxValue 的是补码
                code = rc > long.MaxValue / 2 ? unchecked((long)(ulong)rc) : rc;
        }

        // ---- 3. 收尾 ----
        if (ok && !dryRun)
        {
            try { File.Delete(AttemptFile(box)); } catch { }
            Log.Box(box, "protocol renew: rotated successfully");
            var fresh = Ilink.VaultState(box);
            return new Result(true, $"协议续期成功，新 key={fresh.KeyHash}", fresh.KeyHash);
        }

        if (dryRun)
            return new Result(ok || signed.Success, "演练：已构造并发送，结果见日志");

        var why = ok ? "未确认成功"
            : code == -2 ? "服务端拒绝（-2，通常是凭证已作废或设备信息不匹配）"
            : code == -13 ? "凭证已被服务端作废（-13），需要重新扫码"
            : $"业务层返回 {code}";
        Log.Box(box, $"protocol renew failed: {why}\n{Trim(output)}");
        // attempted 保留：下次启动会提示「上次续期结果未知」，不再自动重放
        return new Result(false, $"协议续期失败：{why}（上一次请求结果未知，标记已保留）");
    }

    static string Trim(string s) => s.Length <= 1200 ? s : s[..1200] + "…";

    /// <summary>续期成功后确认没问题（调用方可选择再用真实 AutoAuth 验证）。</summary>
    public static bool AttemptPending(string box) => PendingAttempt(box) != null;

    /// <summary>清掉 attempted 标记（人工确认后）。</summary>
    public static void ClearAttempt(string box)
    {
        try { File.Delete(AttemptFile(box)); } catch { }
    }
}
