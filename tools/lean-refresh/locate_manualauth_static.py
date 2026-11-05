"""静态定位 ManualAuth 请求构造函数（扫码时走的那条路）。

思路同 locate_autoauth_static.py：找代码对 `/ilink/ilinkapp/sys/ilinkapp_manualauth`
这个 URL 的引用，再用 .pdata 归属到函数。

ManualAuth 的 cmdid 是 0x0d7d（3453）。

用法：
    py -3 locate_manualauth_static.py [ilink2.dll 路径]
"""
import struct
import sys
from pathlib import Path

import pefile

URL = b"/ilink/ilinkapp/sys/ilinkapp_manualauth"
CMDS = [(3453, "ManualAuth(3453)"), (0x0D7D, "ManualAuth(0x0d7d)")]


def main(dll_path):
    dll = Path(dll_path)
    data = dll.read_bytes()
    pe = pefile.PE(str(dll), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
        ents = [(e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION]
    except Exception:
        ents = []

    def func_of(rva):
        for b, e in ents:
            if b <= rva < e:
                return b, e - b
        return None

    off = data.find(URL)
    if off < 0:
        print("找不到 ManualAuth URL")
        return 1
    url_rva = pe.get_rva_from_offset(off)
    url_va = base + url_rva
    print("ManualAuth URL: fileoff=0x%X rva=0x%X" % (off, url_rva))

    secs = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize,
             s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData)
            for s in pe.sections if s.Characteristics & 0x20000000]

    refs = []
    for _a, _b, o, st in secs:
        p = o
        while p < st - 7:
            if data[p] == 0x48 and data[p + 1] == 0x8D and (data[p + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", data, p + 3)[0]
                r = pe.get_rva_from_offset(p)
                if r is not None and base + r + 7 + disp == url_va:
                    refs.append(r)
            p += 1
    # imm64 引用
    packed = struct.pack("<Q", url_va)
    j = data.find(packed)
    while j >= 0:
        r = pe.get_rva_from_offset(j - 2)
        if r:
            refs.append(r)
        j = data.find(packed, j + 1)

    print("引用点 %d 个" % len(refs))
    targets = {}
    for r in refs:
        f = func_of(r)
        if f:
            targets[f[0]] = f[1]
            print("  ref rva=0x%X -> func 0x%X (size %d)" % (r, f[0], f[1]))
        else:
            print("  ref rva=0x%X -> (no pdata)" % r)

    print()
    print("=== 候选函数里找 ManualAuth cmdid ===")
    for cmd_val, cmd_name in CMDS:
        pat = struct.pack("<I", cmd_val)
        for fn_rva, size in sorted(targets.items()):
            o = pe.get_offset_from_rva(fn_rva)
            body = data[o:o + size]
            pos = body.find(pat)
            if pos >= 0:
                print("  func 0x%X 含 %s @ +0x%X" % (fn_rva, cmd_name, pos))

    print()
    print("=== 谁调用这些函数 ===")
    for fn_rva, _size in sorted(targets.items()):
        callers = []
        for _a, _b, o, st in secs:
            p = o
            while p < st - 5:
                if data[p] == 0xE8:
                    rel = struct.unpack_from("<i", data, p + 1)[0]
                    r = pe.get_rva_from_offset(p)
                    if r is not None and r + 5 + rel == fn_rva:
                        callers.append(r)
                p += 1
        print("  func 0x%X 被 %d 处调用" % (fn_rva, len(callers)))
        for c in callers[:6]:
            f2 = func_of(c)
            print("    from 0x%X (in func %s)" % (c, ("0x%X" % f2[0]) if f2 else "?"))
    return 0


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else (
        r"C:\Sandbox\Ajie\qb15\user\current\AppData\Local\Tencent\QQBrowser\User Data"
        r"\WXRuntime_V22346514299\runtime\ilink2.dll")
    sys.exit(main(p))
