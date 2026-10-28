using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

public sealed class RoleInfo
{
    public string Box = "";
    public string Name = "";
    public string RoleId = "";
    public string Level = "";
    public string ServerName = "";
    public string Attack = "";
    public DateTime CapturedAt = DateTime.MinValue;
    public DateTime AttackAt = DateTime.MinValue;

    public bool HasName => Name.Length > 0;
    public bool HasAttack => Attack.Length > 0;
}

/// <summary>
/// 角色档案：roles\qbN.json + roles\index.json，与旧版格式相同（导入后旧版读到的角色直接可用）。
/// </summary>
public static class Roles
{
    public static string Dir => Path.Combine(AppPaths.AppDir, "roles");
    static string FileOf(string box) => Path.Combine(Dir, box + ".json");
    static string IndexPath => Path.Combine(Dir, "index.json");
    static readonly object Gate = new();

    public static RoleInfo Load(string box)
    {
        var doc = JsonFile.ReadObject(FileOf(box));
        var role = doc?["role"] as JsonObject;
        if (role == null) return null;
        var info = new RoleInfo
        {
            Box = box,
            Name = JsonFile.Str(role, "role_name").Trim(),
            RoleId = JsonFile.Str(role, "role_id"),
            Level = JsonFile.Str(role, "role_level"),
            ServerName = JsonFile.Str(role, "server_name"),
            Attack = JsonFile.Str(role, "attack").Trim(),
        };
        if (DateTime.TryParse(JsonFile.Str(doc, "captured_at"), out var at)) info.CapturedAt = at;
        if (DateTime.TryParse(JsonFile.Str(doc["source"] as JsonObject, "attack_at"), out var aat)) info.AttackAt = aat;
        else info.AttackAt = info.HasAttack ? info.CapturedAt : DateTime.MinValue;
        return info;
    }

    public static Dictionary<string, RoleInfo> LoadAll()
    {
        var d = new Dictionary<string, RoleInfo>();
        if (!Directory.Exists(Dir)) return d;
        foreach (var f in Directory.GetFiles(Dir, "qb*.json"))
        {
            var box = Path.GetFileNameWithoutExtension(f);
            if (!Sandboxie.IsBoxName(box)) continue;
            var r = Load(box);
            if (r != null && r.HasName) d[box] = r;
        }
        return d;
    }

    /// <summary>写入角色信息；attack 为空时保留档案里已有的攻击力。</summary>
    public static void Save(string box, RoleReader.RoleText text, RoleReader.AttackHit attack)
    {
        lock (Gate)
        {
            Directory.CreateDirectory(Dir);
            var path = FileOf(box);
            var doc = JsonFile.ReadObject(path) ?? new JsonObject();
            var role = doc["role"] as JsonObject ?? new JsonObject();
            var source = doc["source"] as JsonObject ?? new JsonObject();
            doc["box"] = box;
            doc["game"] = AppInfo.GameTitle;
            doc["appid"] = AppInfo.GameAppId;
            doc["captured_at"] = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:sszzz");
            if (text != null)
            {
                foreach (var key in new[] { "role_name", "role_id", "role_level", "server_id", "server_name" })
                {
                    var v = RoleReader.Field(text.Text, key);
                    if (v.Length > 0) role[key] = v;
                }
                source["renderer_pid"] = text.Pid;
                source["role_name_addr"] = $"0x{text.Addr:X}";
            }
            if (attack != null)
            {
                role["attack"] = attack.Value.ToString();
                source["attack_level_delta"] = "0x2C";
                source["attack_addr"] = $"0x{attack.Addr:X}";
                source["attack_heap_base"] = $"0x{attack.Heap:X}";
                source["attack_rva"] = $"0x{attack.Addr - attack.Heap:X}";
                source["attack_copies"] = attack.Copies;
                source["attack_at"] = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:sszzz");
            }
            doc["role"] = role;
            doc["source"] = source;
            JsonFile.WriteObject(path, doc);
            WriteIndex();
        }
    }

    static void WriteIndex()
    {
        var arr = new JsonArray();
        foreach (var r in LoadAll().Values.OrderBy(r => Sandboxie.BoxNumber(r.Box)))
        {
            var e = new JsonObject
            {
                ["box"] = r.Box, ["role_name"] = r.Name, ["role_id"] = r.RoleId,
                ["server_name"] = r.ServerName, ["file"] = r.Box + ".json",
            };
            if (r.HasAttack) e["attack"] = r.Attack;
            arr.Add(e);
        }
        JsonFile.WriteObject(IndexPath, new JsonObject { ["game"] = AppInfo.GameTitle, ["appid"] = AppInfo.GameAppId, ["roles"] = arr });
    }

    /// <summary>
    /// 读到角色名后写进账号备注（列表和桌面快捷方式能看到）。
    /// 备注是空的、或就是上次读到的角色名时才改；用户自己起的备注不覆盖。
    /// </summary>
    public static void SyncNote(string box, string roleName, string previousRoleName)
    {
        if (string.IsNullOrWhiteSpace(roleName)) return;
        Notes.Load().TryGetValue(box, out var current);
        current ??= "";
        if (current == roleName) return;
        if (current.Length > 0 && current != previousRoleName) return;
        Notes.Set(box, roleName);
        try { BoxSetup.CreateShortcut(box, roleName); } catch { }
        Log.Box(box, $"role name -> note: {roleName}");
    }

    public static void Clear(string box)
    {
        lock (Gate)
        {
            try { File.Delete(FileOf(box)); } catch { }
            try { WriteIndex(); } catch { }
        }
    }
}

/// <summary>读一次角色和攻击力（进游戏后后台调用，或界面上「重新读取」）。</summary>
public static class RoleCapture
{
    public sealed record Result(bool NameFound, bool AttackFound, string Message);

    public static Result ReadOnce(string box, bool wantAttack = true, bool write = true)
    {
        var pids = RoleReader.GameRenderers(box);
        if (pids.Count == 0) return new Result(false, false, "游戏没开着，读不到角色");
        var prev = Roles.Load(box);

        RoleReader.RoleText text = null;
        foreach (var pid in pids)
        {
            try { text = RoleReader.ProbeRole(pid); } catch { }
            if (text != null && RoleReader.Field(text.Text, "role_name").Length > 0) break;
            text = null;
        }
        var name = text != null ? RoleReader.Field(text.Text, "role_name") : "";
        var levelText = text != null ? RoleReader.Field(text.Text, "role_level") : "";
        if (levelText.Length == 0 && prev != null) levelText = prev.Level;
        if (name.Length == 0) return new Result(false, false, "游戏里的角色信息还没加载出来");

        RoleReader.AttackHit atk = null;
        if (wantAttack && int.TryParse(levelText, out var level) && level > 0)
        {
            var order = new List<int> { text.Pid };
            order.AddRange(pids.Where(p => p != text.Pid));
            foreach (var pid in order)
            {
                try { atk = RoleReader.ProbeAttack(pid, level); } catch { }
                if (atk != null) break;
            }
        }
        if (!write)
            return new Result(true, atk != null, $"{name} 等级={levelText} 区服={RoleReader.Field(text.Text, "server_name")} 攻击={(atk != null ? $"{atk.Value}（{atk.Copies} 份，pid {atk.Pid}）" : "未读到")}");
        Roles.Save(box, text, atk);
        Roles.SyncNote(box, name, prev?.Name ?? "");
        Log.Box(box, atk != null
            ? $"role read name={name} level={levelText} attack={atk.Value} copies={atk.Copies} pid={atk.Pid}"
            : $"role read name={name} level={levelText} (attack not in memory yet)");
        return new Result(true, atk != null, atk != null ? $"{name}  攻击 {atk.Value}" : $"{name}（攻击力还没出现在游戏界面上，稍后再读）");
    }
}
