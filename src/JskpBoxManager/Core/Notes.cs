using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

/// <summary>账号备注（box-notes.json，格式与旧版相同）。只记在本机，清除登录不会删。</summary>
public static class Notes
{
    public static Dictionary<string, string> Load()
    {
        var d = new Dictionary<string, string>();
        var o = JsonFile.ReadObject(AppPaths.NotesJson);
        if (o == null) return d;
        foreach (var kv in o)
        {
            var t = JsonFile.Str(o, kv.Key).Trim();
            if (t.Length > 0) d[kv.Key] = t;
        }
        return d;
    }

    public static void Set(string box, string note)
    {
        var d = Load();
        note = (note ?? "").Trim();
        if (note.Length > 0) d[box] = note; else d.Remove(box);
        var o = new JsonObject();
        foreach (var kv in d.OrderBy(k => Sandboxie.BoxNumber(k.Key))) o[kv.Key] = kv.Value;
        JsonFile.WriteObject(AppPaths.NotesJson, o);
    }
}
