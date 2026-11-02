using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>
/// 本机协议服务配置（protocol.json）。
/// 脚本用环境变量 JSKP_SERVER / YYB_SERVER 指向这里，再调 /wxapp/getCode 取本游戏的 wx.login code。
/// </summary>
public sealed class ProtocolConfig
{
    public bool Enabled;
    public string Host = "127.0.0.1";
    public int Port = 18000;
    public string Token = "";

    public string BaseUrl => $"http://{Host}:{Port}";

    public static ProtocolConfig Load()
    {
        var cfg = new ProtocolConfig();
        var raw = JsonFile.ReadObject(AppPaths.ProtocolJson);
        if (raw == null) return cfg;
        cfg.Enabled = JsonFile.Bool(raw, "enabled") ?? false;
        var host = JsonFile.Str(raw, "host");
        if (host.Length > 0) cfg.Host = host;
        cfg.Port = Math.Clamp(JsonFile.Int(raw, "port") ?? 18000, 1024, 65535);
        cfg.Token = JsonFile.Str(raw, "token");
        // 只允许本机；配置里写了别的也强制回退，避免误暴露
        if (!string.Equals(cfg.Host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(cfg.Host, "localhost", StringComparison.OrdinalIgnoreCase))
            cfg.Host = "127.0.0.1";
        return cfg;
    }

    public static void Save(ProtocolConfig cfg)
    {
        if (string.IsNullOrWhiteSpace(cfg.Token)) cfg.Token = NewToken();
        JsonFile.WriteObject(AppPaths.ProtocolJson, new JsonObject
        {
            ["enabled"] = cfg.Enabled,
            ["host"] = "127.0.0.1",
            ["port"] = Math.Clamp(cfg.Port, 1024, 65535),
            ["token"] = cfg.Token,
            ["appId"] = AppInfo.GameAppId,
            // 保持纯 ASCII：Windows PowerShell 5 的 Get-Content 默认按本地代码页读无 BOM 文件，中文会把引号吃掉
            ["note"] = "localhost only. set JSKP_SERVER=http://127.0.0.1:" + cfg.Port + " and JSKP_PROTOCOL_TOKEN=<token>",
        });
    }

    public static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();

    public static ProtocolConfig EnsureToken(ProtocolConfig cfg)
    {
        if (string.IsNullOrWhiteSpace(cfg.Token))
        {
            cfg.Token = NewToken();
            Save(cfg);
        }
        return cfg;
    }
}
