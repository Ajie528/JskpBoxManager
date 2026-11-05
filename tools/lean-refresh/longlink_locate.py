"""Locate the ilink long-link / session-timeout functions in ilink2.dll (offline).

ilink2.dll exposes no export for these; each is only reachable through the string it logs.
Every ilink log line goes through `ilink::CustomAppender::append`, which formats
    "MM-DD HH:MM:SS.mmm tid/a/b L tag file.cc:line Func: message"
The `Func:` part is produced by the logging macro at the call site, which references a
string literal like "mars::stn::LongLink::__NoopResp: " in .rdata. That literal is used by
exactly one function, so `locate_by_log_tag` finds the function that references it.

Why we need these:
    __NoopResp            heartbeat handler (server -> client noop reply)
    __RunReadWrite        the long-link read/write loop that arms the noop alarm
    __OnAppSessionTimeout where "App layer sessiontimeout!" is handled
    TdiClearLoginStatus   wipes the login state right before the process exits
    Uninit / Stop         the teardown that ends the ilink process

Result cached next to this script, keyed by file size + mtime + tag.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pefile

CACHE = Path(__file__).with_name("longlink_rva_cache.json")


def _sections(pe: pefile.PE, data: bytes):
    """[(rva_start, rva_end, file_off_start, file_off_end)] for executable sections."""
    out = []
    for s in pe.sections:
        if not (s.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue
        out.append((s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize,
                    s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData))
    return out


def _string_va(pe: pefile.PE, data: bytes, needle: bytes):
    """Absolute virtual address of the first .rdata occurrence of `needle`."""
    off = data.find(needle)
    if off < 0:
        return None
    rva = pe.get_rva_from_offset(off)
    if rva is None:
        return None
    return pe.OPTIONAL_HEADER.ImageBase + rva


def _find_refs(pe: pefile.PE, data: bytes, abs_va: int):
    """Every x64 absolute reference to `abs_va` (mov reg, imm64 / lea rip-relative)."""
    hits = []
    packed = struct.pack("<Q", abs_va)

    # 1) plain imm64 operands (mov rcx, offset str)
    i = data.find(packed)
    while i >= 0:
        hits.append(i - 3)  # back up over the opcode, refined below
        i = data.find(packed, i + 1)

    # 2) lea reg, [rip+disp32] -> scan executable sections for 48 8D xx disp32
    for s_rva, s_end, s_off, s_stop in _sections(pe, data):
        p = s_off
        while p < s_stop - 7:
            if data[p] == 0x48 and data[p + 1] == 0x8D and (data[p + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", data, p + 3)[0]
                insn_rva = pe.get_rva_from_offset(p)
                if insn_rva is not None:
                    target = pe.OPTIONAL_HEADER.ImageBase + insn_rva + 7 + disp
                    if target == abs_va:
                        hits.append(p)
            p += 1
    return hits


def _containing_func(pe: pefile.PE, data: bytes, file_off: int):
    """RVA of the function that contains `file_off`, via the .pdata exception directory."""
    try:
        entries = pe.DIRECTORY_ENTRY_EXCEPTION
    except AttributeError:
        return None
    target_rva = pe.get_rva_from_offset(file_off)
    if target_rva is None:
        return None
    for e in entries:
        begin = e.struct.BeginAddress
        end = begin + e.struct.EndAddress - e.struct.BeginAddress
        if begin <= target_rva < end:
            return begin
    return None


def locate_by_log_tag(dll: Path, tag: str) -> int | None:
    """RVA of the function that logs `<tag>: ...` (the `Func:` field of the log line)."""
    pe = pefile.PE(str(dll), fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
    except Exception:
        pass
    data = dll.read_bytes()

    for needle in (f"{tag}: ".encode(), tag.encode()):
        va = _string_va(pe, data, needle)
        if va is None:
            continue
        for off in _find_refs(pe, data, va):
            if not (0 < off < len(data)):
                continue
            fn = _containing_func(pe, data, off)
            if fn:
                return fn
    return None


WANTED = {
    "noop_resp": "mars::stn::LongLink::__NoopResp",
    "run_read_write": "mars::stn::LongLinkWithMMTLS::__RunReadWrite",
    "on_session_timeout": "__OnAppSessionTimeout",
    "unpack_response": "UnPackResponse",
}

# 静态定位（推荐）：找代码引用 `/ilink/ilinkapp/sys/ilinkapp_autoauth` 的函数。
# 这个 URL 在构造请求时必被引用，比日志字面量可靠得多。
#
# 2026-11-04 用 locate_autoauth_static.py + 手工分析（WXRuntime_V22346514299）：
#   0xD7710  (161B)  构造 AutoAuth 请求：引用 AutoAuth URL + `mov dword [rbx+10h], 0xC7E`（cmdid 3198）
#   0xD4390  (895B)  0xD7710 的唯一调用者，是**完整的 AutoAuth 流程**：
#                    构造(0xD7710) -> 设置凭证(0xB41C0) -> 发送(0x224F60) …
#                    只被上层调用 1 次，符合 AutoAuth 特征
#
# 对比：早前误判的 0x229B70 被 37 个 this 调用共 638 次、且不含 cmdid 3198，
#       已改名为 auth_chain_leaf（通用发送包装，不是 AutoAuth）。
#
# ⚠️ 换 WXRuntime 版本必须重新跑 locate_autoauth_static.py 确认。
DYN_RVA = {
    "auto_auth": 0xD4390,          # 完整 AutoAuth 流程（推荐 hook / 调用这个）
    "auto_auth_build": 0xD7710,    # 其中的请求构造（写 cmdid 3198 + URL）
    "manual_auth": 0xD4710,        # 完整 ManualAuth 流程（扫码）
    "manual_auth_build": 0xD77C0,  # 其中的请求构造（写 cmdid 3453 + URL）
    "auth_chain_leaf": 0x229B70,   # 通用发送包装（不是 AutoAuth，勿用）
    "auto_auth_switch": 0x222FF0,  # 日志名为 __SendAutoAuthRequestWithIDCSwitch（未验证）
}

# 说明：TdiClearLoginStatus / OnAppSessionTimeout 在 ilink2.dll 里只以「字符串表」形式出现
# （紧挨着 TdiClearSession / TdiLogoutAsync），不是日志宏字面量，按引用定位到的是数据表而非函数。
# 因此这两个不列为可拦截目标：清登录态的时机改为从日志流里观测（TdiClearLoginStatus 行）。


def locate_all(dll: Path) -> dict:
    st = dll.stat()
    # 缓存键要带上 WANTED 的指纹：改了 tag 列表后旧缓存必须失效，
    # 否则会拿到上一版算出的 rva（实测踩过：on_session_timeout 一直是旧的 null）。
    want_key = "|".join(f"{k}={v}" for k, v in sorted(WANTED.items()))
    key = f"{dll.name}|{st.st_size}|{int(st.st_mtime)}|{hash(want_key) & 0xFFFFFFFF:x}"
    try:
        cache = json.loads(CACHE.read_text(encoding="utf-8"))
    except Exception:
        cache = {}
    if key in cache and cache[key]:
        return cache[key]

    out = {}
    for name, tag in WANTED.items():
        try:
            rva = locate_by_log_tag(dll, tag)
        except Exception as exc:
            rva = None
            out[name + "_error"] = str(exc)
        out[name] = rva
        if rva is not None:
            out[name + "_tag"] = tag   # 记录这次用的是哪个 tag，便于排查
    # 动态定位的那几个（换版本必须重新采栈确认，见 DYN_RVA 注释）
    out.update(DYN_RVA)
    # 只有全部定位成功才缓存：部分失败多为版本差异或探测 bug，下次应该重算而不是沿用空值
    if all(isinstance(v, int) and v > 0 for k, v in out.items() if not k.endswith(("_error", "_tag"))):
        cache[key] = out
        try:
            CACHE.write_text(json.dumps(cache, indent=1), encoding="utf-8")
        except Exception:
            pass
    return out


if __name__ == "__main__":
    for p in sys.argv[1:]:
        res = locate_all(Path(p))
        print(p)
        for k, v in res.items():
            print("  %-20s %s" % (k, hex(v) if isinstance(v, int) else v))
