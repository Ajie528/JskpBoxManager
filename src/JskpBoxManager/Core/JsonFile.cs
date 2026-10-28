using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Unicode;

namespace JskpBoxManager.Core;

public static class JsonFile
{
    public static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
    };

    public static readonly JsonSerializerOptions Compact = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
    };

    /// <summary>读 JSON 对象；旧版 PowerShell 写的是带 BOM 的 UTF-8，也兼容。</summary>
    public static JsonObject ReadObject(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var text = File.ReadAllText(path, Encoding.UTF8).Trim().TrimStart('\uFEFF');
            if (text.Length == 0) return null;
            return JsonNode.Parse(text) as JsonObject;
        }
        catch { return null; }
    }

    public static void WriteObject(string path, JsonNode node)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, node.ToJsonString(Pretty), new UTF8Encoding(false));
        File.Move(tmp, path, true);
    }

    public static string Str(JsonObject o, string key)
    {
        if (o == null || !o.TryGetPropertyValue(key, out var v) || v == null) return "";
        try
        {
            if (v is JsonValue jv)
            {
                if (jv.TryGetValue<string>(out var s)) return s ?? "";
                return jv.ToJsonString().Trim('"');
            }
        }
        catch { }
        return v.ToJsonString();
    }

    public static bool? Bool(JsonObject o, string key)
    {
        if (o == null || !o.TryGetPropertyValue(key, out var v) || v == null) return null;
        try
        {
            if (v is JsonValue jv)
            {
                if (jv.TryGetValue<bool>(out var b)) return b;
                if (jv.TryGetValue<int>(out var i)) return i != 0;
                if (jv.TryGetValue<string>(out var s)) return s.Equals("true", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch { }
        return null;
    }

    public static int? Int(JsonObject o, string key)
    {
        if (o == null || !o.TryGetPropertyValue(key, out var v) || v == null) return null;
        try
        {
            if (v is JsonValue jv)
            {
                if (jv.TryGetValue<int>(out var i)) return i;
                if (jv.TryGetValue<double>(out var d)) return (int)d;
                if (jv.TryGetValue<string>(out var s) && int.TryParse(s, out var p)) return p;
            }
        }
        catch { }
        return null;
    }
}
