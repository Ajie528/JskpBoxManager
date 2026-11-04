"""定位真正的 AutoAuth 请求构造函数（静态）。

思路：不靠日志常量池，而是找**代码引用** `/ilink/ilinkapp/sys/ilinkapp_autoauth` 的地方
——这个 URL 在构造请求时一定会被引用，比日志字面量可靠。

用法：
    py -3 locate_autoauth_static.py <ilink2.dll 路径>
"""
import struct
import sys
from pathlib import Path

import pefile

AUTH_URL = b"/ilink/ilinkapp/sys/ilinkapp_autoauth"
AUTH_CMDIID = 3198  # 0xC7E


def main(dll_path):
    dll = Path(dll_path)
    data = dll.read_bytes()
    pe = pefile.PE(str(dll), fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
        ents = [(e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION]
    except Exception:
        ents = []
    base = pe.OPTIONAL_HEADER.ImageBase

    def func_of(rva):
        for b, e in ents:
            if b <= rva < e:
                return b, e - b
        return None

    def rva2off(r):
        return pe.get_offset_from_rva(r)

    # 1) 找 URL 字符串
    i = data.find(AUTH_URL)
    if i < 0:
        print("找不到 AutoAuth URL 字符串")
        return 1
    url_rva = pe.get_rva_from_offset(i)
    url_va = base + url_rva
    print(f"AutoAuth URL: fileoff=0x{i:X} rva=0x{url_rva:X}")

    # 2) 找代码里对它的 lea/mov 引用
    secs = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize,
             s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData)
            for s in pe.sections if s.Characteristics & 0x20000000]
    refs = []
    # lea reg, [rip+disp32]
    for _a, _b, off, stop in secs:
        p = off
        while p < stop - 7:
            if data[p] == 0x48 and data[p + 1] == 0x8D and (data[p + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", data, p + 3)[0]
                r = pe.get_rva_from_offset(p)
                if r is not None and base + r + 7 + disp == url_va:
                    refs.append(r)
            p += 1
    # mov reg, imm64
    packed = struct.pack("<Q", url_va)
    j = data.find(packed)
    while j >= 0:
        r = pe.get_rva_from_offset(j - 2)
        if r:
            refs.append(r)
        j = data.find(packed, j + 1)

    print(f"\n引用点 {len(refs)} 个：")
    targets = set()
    for r in refs:
        f = func_of(r)
        print(f"  ref rva=0x{r:X} -> func {('0x%X (size %d)' % f) if f else 'no pdata'}")
        if f:
            targets.add(f)

    # 3) 在每个候选函数里确认有没有 cmdid 3198
    print(f"\n=== 候选函数里查找 cmdid {AUTH_CMDIID} (0x{AUTH_CMDIID:X}) ===")
    pat = struct.pack("<I", AUTH_CMDIID)
    for fn_rva, size in sorted(targets):
        o = rva2off(fn_rva)
        body = data[o:o + size]
        has = pat in body
        print(f"  func 0x{fn_rva:X} (size {size}) 含 cmdid 3198: {has}")
        if has:
            pos = body.find(pat)
            print(f"    位于 func+0x{pos:X}")

    # 4) 谁调用这些函数（找上层入口）
    print(f"\n=== 谁 call 这些函数 ===")
    for fn_rva, _size in sorted(targets):
        callers = []
        for _a, _b, off, stop in secs:
            p = off
            while p < stop - 5:
                if data[p] == 0xE8:
                    rel = struct.unpack_from("<i", data, p + 1)[0]
                    r = pe.get_rva_from_offset(p)
                    if r is not None and r + 5 + rel == fn_rva:
                        callers.append(r)
                p += 1
        print(f"  func 0x{fn_rva:X} 被 {len(callers)} 处调用")
        for c in callers[:8]:
            f2 = func_of(c)
            print(f"    from 0x{c:X} (in func {('0x%X' % f2[0]) if f2 else '?'})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else
                  r"C:\Sandbox\Ajie\qb15\user\current\AppData\Local\Tencent\QQBrowser\User Data\WXRuntime_V22346514299\runtime\ilink2.dll"))
