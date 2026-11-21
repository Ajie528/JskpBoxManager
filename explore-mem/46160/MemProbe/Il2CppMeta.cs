using System.Text;

namespace MemProbe;

/// <summary>
/// 极简 IL2CPP metadata（version 29）解析器。
/// 目的只有一个：拿到某个类的字段名、类型、在对象里的偏移顺序。
/// 只读文件，不做任何修改。
/// </summary>
public sealed class Il2CppMeta
{
    public int Version;
    public long Base;                 // metadata 在文件里的绝对位置

    // 段表（相对 metadata 起点）—— header 里存的是「偏移 + 字节长度」
    public long StringLiteral, StringLiteralData, Strings, Events, Properties, Methods;
    public long ParameterDefaultValues, FieldDefaultValues, FieldAndParamDefaultData;
    public long FieldMarshaledSizes, Parameters, Fields, GenericParameters;
    public long GenericParameterConstraints, GenericContainers, NestedTypes, Interfaces;
    public long VTableMethods, InterfaceOffsets, TypeDefinitions, Images, Assemblies;
    public long FieldRefs, ReferencedAssemblies, AttributeData, AttributeDataRange;
    public long StringLiteralBytes, StringsBytes, EventsBytes, PropertiesBytes, MethodsBytes;
    public long ParametersBytes, FieldsBytes, GenericParametersBytes, InterfacesBytes;
    public long VTableMethodsBytes, InterfaceOffsetsBytes, TypeDefinitionsBytes;
    public long ImagesBytes;

    /// <summary>v29 结构体大小：字段定义 12 字节，类型定义 0x5C 字节。</summary>
    const int FIELD_DEF_SIZE = 12;
    const int TYPE_DEF_SIZE = 0x5C;

    public string TypeNameOf(int typeIndex)
    {
        long at = TypeDefinitions + (long)typeIndex * TYPE_DEF_SIZE;
        if (at + TYPE_DEF_SIZE > _buf.Length) return "";
        return Str(I32(at + TD_Name));
    }

    /// <summary>逐 32 位打印类型定义结构体，并把每个值尝试当字符串索引解释。</summary>
    public string DumpTypeFields(int typeIndex)
    {
        var sb = new StringBuilder();
        long at = TypeDefinitions + (long)typeIndex * TYPE_DEF_SIZE;
        if (at + TYPE_DEF_SIZE > _buf.Length) return "越界";
        for (int i = 0; i < TYPE_DEF_SIZE; i += 4)
        {
            int v = I32(at + i);
            string asStr = "";
            if (v >= 0 && v < StringsBytes)
            {
                var s = Str(v);
                if (s.Length is > 0 and < 44 && s.All(c => c >= 0x20 && c < 0x7F)) asStr = "  \"" + s + "\"";
            }
            sb.AppendLine($"  +0x{i:X2}  {v,12}  0x{v:X8}{asStr}");
        }
        return sb.ToString();
    }

    /// <summary>打印字段表某个区间，用来人工核对。</summary>
    public string DumpFieldRange(int from, int count)
    {
        var sb = new StringBuilder();
        for (int i = from; i < from + count && i < FieldsCount; i++)
        {
            long fat = Fields + (long)i * FIELD_DEF_SIZE;
            if (fat + FIELD_DEF_SIZE > _buf.Length) break;
            sb.AppendLine($"  field#{i,-7} {Str(I32(fat))}");
        }
        return sb.ToString();
    }

    public int FieldsCountPublic => FieldsCount;

    public int FieldsCount => (int)(FieldsBytes / FIELD_DEF_SIZE);
    public int TypeDefinitionsCount => (int)(TypeDefinitionsBytes / TYPE_DEF_SIZE);

    byte[] _buf;

    public static Il2CppMeta Load(string path, long metaOffset)
    {
        var m = new Il2CppMeta();
        using var fs = File.OpenRead(path);
        fs.Position = metaOffset;
        // metadata 通常几 MB ~ 几十 MB，先读 64MB 够用
        int len = (int)Math.Min(fs.Length - metaOffset, 128L << 20);
        m._buf = new byte[len];
        fs.ReadExactly(m._buf, 0, len);
        m.Base = metaOffset;
        m.ParseHeader();
        return m;
    }

    void ParseHeader()
    {
        uint sanity = U32(0);
        if (sanity != 0xFAB11BAF) throw new InvalidDataException($"不是 IL2CPP metadata（sanity=0x{sanity:X8}）");
        Version = I32(4);
        StringLiteral = I32(8);   StringLiteralBytes = I32(12);
        StringLiteralData = I32(16); StringLiteralDataCountBytes = I32(20);
        Strings = I32(24);        StringsBytes = I32(28);
        Events = I32(32);         EventsBytes = I32(36);
        Properties = I32(40);     PropertiesBytes = I32(44);
        Methods = I32(48);        MethodsBytes = I32(52);
        ParameterDefaultValues = I32(56);
        FieldDefaultValues = I32(64);
        FieldAndParamDefaultData = I32(72);
        FieldMarshaledSizes = I32(80);
        Parameters = I32(88);     ParametersBytes = I32(92);
        Fields = I32(96);         FieldsBytes = I32(100);
        GenericParameters = I32(104); GenericParametersBytes = I32(108);
        GenericParameterConstraints = I32(112);
        GenericContainers = I32(120);
        NestedTypes = I32(128);
        Interfaces = I32(136);    InterfacesBytes = I32(140);
        VTableMethods = I32(144); VTableMethodsBytes = I32(148);
        InterfaceOffsets = I32(152); InterfaceOffsetsBytes = I32(156);
        TypeDefinitions = I32(160); TypeDefinitionsBytes = I32(164);
        Images = I32(168);          ImagesBytes = I32(172);
        Assemblies = I32(176);      AssembliesBytes = I32(180);
    }

    public long StringLiteralDataCountBytes;
    public long AssembliesBytes;

    int I32(long off) => BitConverter.ToInt32(_buf, (int)off);
    uint U32(long off) => BitConverter.ToUInt32(_buf, (int)off);

    /// <summary>
    /// 字符串表（v29）：偏移处开始是一串以 0 结尾的 UTF-8 字符串，直接拼在一起。
    /// 索引即字节偏移。
    /// </summary>
    public string Str(int index)
    {
        if (index < 0) return "";
        long p = Strings + index;
        if (p < 0 || p >= _buf.Length) return "";
        int end = (int)p;
        while (end < _buf.Length && _buf[end] != 0) end++;
        if (end <= p) return "";
        return Encoding.UTF8.GetString(_buf, (int)p, end - (int)p);
    }

    /// <summary>类型名：typeDefinition 里存的是 typeIndex，低 29 位是索引。</summary>
    public string TypeName(int typeIndex)
    {
        if (typeIndex < 0) return "";
        int idx = typeIndex & 0x1FFFFFFF;
        // Il2CppTypeDefinition 在 v29 里 0x5C 字节一条（不同版本略有差异，这里按名索引读取）
        // nameIndex 相对结构体起点 +0x00（stringIndex 命名）
        long at = TypeDefinitions + (long)idx * 0x5C;
        if (at + 8 > _buf.Length) return "";
        return Str(I32(at));
    }

    /// <summary>v29 的 Il2CppTypeDefinition 布局（字节）。</summary>
    const int TD_Size = 0x5C;
    const int TD_Name = 0x00;
    const int TD_Namespace = 0x04;
    const int TD_FieldStart = 0x30;   // 实测：0x30 处是起始字段索引
    const int TD_FieldCount = 0x40;   // 实测：0x40 处是字段数（int，不是 short）

    public sealed record FieldDef(string Name, string TypeIndex, int DeclOrder);

    /// <summary>按类型名找所有匹配的类型索引（线性扫，约 3.8 万条，很快）。</summary>
    public List<int> FindType(string typeName, int limit = 8)
    {
        var hits = new List<int>();
        int count = TypeDefinitionsCount;
        for (int i = 0; i < count && hits.Count < limit; i++)
        {
            long at = TypeDefinitions + (long)i * TYPE_DEF_SIZE;
            if (at + TYPE_DEF_SIZE > _buf.Length) break;
            if (Str(I32(at + TD_Name)) == typeName) hits.Add(i);
        }
        return hits;
    }

    /// <summary>读某类型的字段表（名字 + 类型索引 + 声明顺序）。</summary>
    public List<FieldDef> FieldsOfType(int typeIndex)
    {
        var list = new List<FieldDef>();
        long at = TypeDefinitions + (long)typeIndex * TYPE_DEF_SIZE;
        if (at + TYPE_DEF_SIZE > _buf.Length) return list;

        // fieldStart 在 0x30 是 16 位（实测 0x3474=13428 这种量级），fieldCount 在 0x40 是 32 位
        int fieldStart = BitConverter.ToUInt16(_buf, (int)(at + TD_FieldStart));
        int fieldCount = I32(at + TD_FieldCount);
        if (fieldCount < 0 || fieldCount > 2000) fieldCount = 0;
        for (int f = 0; f < fieldCount; f++)
        {
            int fi = fieldStart + f;
            if (fi < 0 || fi >= FieldsCount) continue;
            long fat = Fields + (long)fi * FIELD_DEF_SIZE;
            if (fat + FIELD_DEF_SIZE > _buf.Length) break;
            var name = Str(I32(fat));
            int typeIdx = I32(fat + 4);
            list.Add(new FieldDef(name, "0x" + typeIdx.ToString("X8"), f));
        }
        return list;
    }

    /// <summary>读某类型的方法名（用来确认这个类是不是我们要找的那个）。</summary>
    public List<string> MethodsOfType(int typeIndex)
    {
        var names = new List<string>();
        long at = TypeDefinitions + (long)typeIndex * TYPE_DEF_SIZE;
        if (at + TYPE_DEF_SIZE > _buf.Length) return names;
        int methodStart = I32(at + 0x38);
        int methodCount = BitConverter.ToInt16(_buf, (int)(at + 0x3C));
        int methodEntries = methodsCount;
        for (int i = 0; i < methodCount && i < 200; i++)
        {
            int mi = methodStart + i;
            if (mi < 0 || mi >= methodEntries) continue;
            long mat = Methods + (long)mi * 4;
            if (mat + 4 > _buf.Length) break;
            int defIdx = I32(mat);
            long dat = MethodsData + (long)defIdx * 4;   // 名字索引在方法定义里
            int nameIdx = dat + 4 <= _buf.Length ? I32(dat) : -1;
            var s = Str(nameIdx);
            if (s.Length > 0) names.Add(s);
        }
        return names;
    }

    public int methodsCount => (int)(MethodsBytes / 4);
    public long MethodsData => Methods + MethodsBytes;

    /// <summary>枚举所有类型名（跳过空名与 &lt;Module&gt;）。</summary>
    public IEnumerable<string> AllTypeNames()
    {
        int count = TypeDefinitionsCount;
        for (int i = 0; i < count; i++)
        {
            long at = TypeDefinitions + (long)i * TYPE_DEF_SIZE;
            if (at + TYPE_DEF_SIZE > _buf.Length) yield break;
            var n = Str(I32(at + TD_Name));
            if (n.Length > 0 && n != "<Module>") yield return n;
        }
    }

    public sealed record FieldHit(int FieldIndex, string Name, string TypeName);

    /// <summary>某字段索引所属的类型（索引 + 名字）。</summary>
    public (int TypeIndex, string TypeName) OwnerOfField(int fieldIndex)
    {
        int tcount = TypeDefinitionsCount;
        for (int i = 0; i < tcount; i++)
        {
            long at = TypeDefinitions + (long)i * TYPE_DEF_SIZE;
            if (at + TYPE_DEF_SIZE > _buf.Length) break;
            int fs = BitConverter.ToUInt16(_buf, (int)(at + TD_FieldStart)), fc = I32(at + TD_FieldCount);
            if (fc < 0 || fc > 2000) continue;
            if (fieldIndex >= fs && fieldIndex < fs + fc)
            {
                var tn = Str(I32(at + TD_Name));
                if (tn.Length > 0) return (i, tn);
            }
        }
        return (-1, "");
    }

    /// <summary>全字段表按名子串搜索，并反查所属类型名。</summary>
    public List<FieldHit> FindFieldsByName(string substr, int limit)
    {
        // 先建「字段索引 → 所属类型」映射（只建立一次够用）
        var owner = new Dictionary<int, string>();
        int tcount = TypeDefinitionsCount;
        for (int i = 0; i < tcount; i++)
        {
            long at = TypeDefinitions + (long)i * TYPE_DEF_SIZE;
            if (at + TYPE_DEF_SIZE > _buf.Length) break;
            var tn = Str(I32(at + TD_Name));
            if (tn.Length == 0) continue;
            int fs = BitConverter.ToUInt16(_buf, (int)(at + TD_FieldStart)), fc = I32(at + TD_FieldCount);
            if (fc < 0 || fc > 2000) continue;
            for (int k = 0; k < fc; k++) owner[fs + k] = tn;
        }

        var hits = new List<FieldHit>();
        int n = FieldsCount;
        for (int i = 0; i < n && hits.Count < limit; i++)
        {
            long fat = Fields + (long)i * FIELD_DEF_SIZE;
            if (fat + FIELD_DEF_SIZE > _buf.Length) break;
            var name = Str(I32(fat));
            if (name.Length == 0 || !name.Contains(substr, StringComparison.OrdinalIgnoreCase)) continue;
            hits.Add(new FieldHit(i, name, owner.GetValueOrDefault(i, "?")));
        }
        return hits;
    }

    /// <summary>诊断：打印类型定义结构体原始字节，确认布局。</summary>
    public string DumpTypeRaw(int typeIndex, int bytes = 0x60)
    {
        long at = TypeDefinitions + (long)typeIndex * TD_Size;
        var sb = new StringBuilder();
        for (int i = 0; i < bytes && at + i < _buf.Length; i += 16)
        {
            sb.Append($"  +0x{i:X2}  ");
            for (int j = 0; j < 16 && i + j < bytes; j++) sb.Append($"{_buf[at + i + j]:X2} ");
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
