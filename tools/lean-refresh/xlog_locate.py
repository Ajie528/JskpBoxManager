"""Locate ilink's log sink in ilink2.dll (offline, via MSVC RTTI).

ilink hands every formatted log line to `ilink::CustomAppender`, a subclass of `v8::zlog::log_appender_base`.
Its vtable slot 4 overrides the base's pure virtual append:
    void append(this, const record*, const std::string& line, int)
`line` is the full plaintext, e.g.
    "10-29 11:04:37.713 1597988/1598700/0 I mars::mmext longlink_with_mmtls.cc:839 ...: ... /ilink/base/ilinksyncmsg ..."
The host (flue.dll) encrypts it into ilink_YYYYMMDD.xlog, so this is the last point where it is readable.

Result is cached next to this script, keyed by file size + mtime.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pefile

CLASS = b".?AVCustomAppender@ilink@@"
BASE = b".?AVlog_appender_base@v8@zlog@@"
SLOT = 4
CACHE = Path(__file__).with_name("xlog_rva_cache.json")


def _vtable(pe: pefile.PE, data: bytes, type_name: bytes) -> list[int]:
    off = data.find(type_name)
    if off < 0:
        return []
    td_rva = pe.get_rva_from_offset(off) - 16
    image_base = pe.OPTIONAL_HEADER.ImageBase
    size = pe.OPTIONAL_HEADER.SizeOfImage
    pat = struct.pack("<I", td_rva)
    i = 0
    while True:
        i = data.find(pat, i)
        if i < 0:
            return []
        col = i - 12
        i += 1
        if col < 0 or struct.unpack_from("<I", data, col)[0] != 1:
            continue
        col_rva = pe.get_rva_from_offset(col)
        if col_rva is None:
            continue
        ref = data.find(struct.pack("<Q", image_base + col_rva))
        if ref < 0:
            continue
        entries = []
        for k in range(16):
            v = struct.unpack_from("<Q", data, ref + 8 + 8 * k)[0] - image_base
            if not 0x1000 < v < size:
                break
            entries.append(v)
        return entries


def locate(dll: Path) -> int | None:
    pe = pefile.PE(str(dll), fast_load=True)
    data = dll.read_bytes()
    derived = _vtable(pe, data, CLASS)
    base = _vtable(pe, data, BASE)
    if len(derived) <= SLOT:
        return None
    # sanity: slot 4 must be the one CustomAppender overrides (base has a purecall stub there)
    if len(base) > SLOT and base[SLOT] == derived[SLOT]:
        return None
    return derived[SLOT]


def locate_cached(dll: Path) -> int | None:
    st = dll.stat()
    key = f"{dll.name}|{st.st_size}|{int(st.st_mtime)}|append"
    cache = {}
    try:
        cache = json.loads(CACHE.read_text(encoding="utf-8"))
    except Exception:
        pass
    if key in cache:
        return cache[key]
    rva = locate(dll)
    cache[key] = rva
    try:
        CACHE.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    except Exception:
        pass
    return rva


if __name__ == "__main__":
    for p in sys.argv[1:]:
        r = locate_cached(Path(p))
        print(p, hex(r) if r is not None else None)
