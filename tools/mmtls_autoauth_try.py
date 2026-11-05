"""AutoAuth 参数试错：找出服务端接受的 (appVersion, device, wpkg变体) 组合。

每次尝试都会真的向微信服务器发 AutoAuth 请求（不修改本地凭证，除非成功）。
失败码 -2 表示服务端拒绝，我们通过遍历候选找能通过的那组。

用法：
    py -3 mmtls_autoauth_try.py --box qb15
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import mmtls_autoauth as M  # noqa: E402


def try_one(host, port, uin, auto_key, enc_key, device_id, ilink_app_id, server_id,
            app_version, device_variant, head_variant, timeout=12):
    """发一次 AutoAuth，返回 (ok, code, note)"""
    inner = M.pb_len(1, device_variant)
    plaintext = M.pb_len(1, inner) + M.pb_var(2, app_version) + M.pb_len(3, auto_key)

    server_pub = bytes.fromhex(M.SERVER_PUB_HEX)
    hybrid, temp = M.hybrid_encrypt_with_key(plaintext, server_pub, enc_key)

    # 关键：wpkg 字段 24 必须是 ilinkAppId 字符串，不是 32 字节 DeviceId
    if head_variant == "appid17":
        body = M.session_wpkg_head(uin, server_id, ilink_app_id) + hybrid
    elif head_variant == "appid16":
        ints = {1: 1, 2: uin, 3: 0, 4: 0, 5: M.CLIENT_VERSION, 6: 11, 7: 0, 8: 0, 9: 0,
                10: 1, 11: 0, 12: 0, 13: 0, 17: 0, 18: 1, 20: 1504, 21: 0, 22: uin,
                23: 0, 25: 16, 26: 4, 28: 1, 29: 1, 30: 0}
        body = M.wpkg_head(ints, {14: b"", 24: ilink_app_id, 27: server_id}) + hybrid
    else:
        raise ValueError(head_variant)

    import socket as _s
    sock = _s.create_connection((_s.gethostbyname(host), port), timeout=timeout)
    try:
        m = M.Mmtls(sock, timeout)
        m.handshake(host, port)
        m.send_app(M.CMD_AUTOAUTH, body)
        pkt = m.recv_app()
        data = pkt["body"]
        ints = {}
        hlen = 0
        try:
            i = 0
            _, i = M.read_varint(data, i)
            while i < len(data):
                fn, i = M.read_varint(data, i)
                if fn == 0:
                    break
                v, i = M.read_varint(data, i)
                ints[fn] = v
            hlen = i
        except Exception:
            pass
        if ints.get(4):
            return False, ints[4], f"transport reject {ints[4]}"
        if ints.get(23):
            return False, ints[23], f"app reject {ints[23]}"

        marker = bytes([0x08, 0x9F, 0x03, 0x12, 0x41, 0x04])
        idx = data.find(marker)
        blob = data[idx - 2:] if idx >= 2 else data[hlen:]
        try:
            decoded = M.hybrid_decrypt(blob, temp)
        except Exception as e:
            return False, None, f"decrypt fail: {e}"
        fields = M.pb_parse(decoded)
        base = fields.get(1, b"")
        code = None
        if base:
            bf = M.pb_parse(base)
            c = bf.get(1)
            if isinstance(c, int):
                code = c - (1 << 64) if c >= (1 << 63) else c
        if code == 0:
            unified = fields.get(2, b"")
            if unified:
                uf = M.pb_parse(unified)
                sect = M.pb_parse(uf.get(2, b""))
                nk, ne = sect.get(3), sect.get(4)
                return True, 0, f"OK newKey={len(nk) if nk else 0} newEnc={len(ne) if ne else 0}"
            return True, 0, "OK(no unified)"
        return False, code, f"business code={code}"
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--box", default="qb15")
    ap.add_argument("--appdir", default=r"D:\a_game_scrpit\JskpBoxManager-exe")
    ap.add_argument("--host", default="longcloud.weixin.com")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()

    wmpf = Path(a.appdir) / "profiles" / a.box / "wmpf"
    acc = M.read_tdi_account(wmpf)
    kv = acc["kv"]
    auto_key = M.b64(kv["kTdiKeyAutoauthKey"])
    enc_key = M.b64(kv["kTdiKeyAutoauthEncKey"])
    device_id = M.b64(kv["kTdiKeyDeviceId"])
    server_id = M.b64(kv["kTdiKeyServerId"])
    uin = int(kv["kTdiKeyUin"])
    ilink_app_id = kv.get("kTdiKeyIlinkAppId", "").strip().encode()
    if not ilink_app_id:
        parts = [p for p in Path(acc["path"]).parts if p.startswith("ilinkapp_")]
        if parts:
            ilink_app_id = parts[-1].encode()

    print(f"uin={uin} autoKey={len(auto_key)} encKey={len(enc_key)} "
          f"dev={len(device_id)} f9={len(server_id)} appId={ilink_app_id.decode(errors='replace')}")
    print()

    if not ilink_app_id:
        print("找不到 kTdiKeyIlinkAppId，无法填 wpkg 字段 24")
        return 3

    # 候选：appVersion × device 变体 × head 变体
    app_versions = [1901, 524545, 1504, 1900, 2100]
    device_variants = [("dev32", device_id)]
    if len(server_id) >= 32:
        device_variants.append(("f9h32", server_id[:32]))
    heads = ["appid17"]

    results = []
    for av, (dvname, dv), hv in itertools.product(app_versions, device_variants, heads):
        label = f"app={av} dev={dvname} head={hv}"
        try:
            ok, code, note = try_one(a.host, a.port, uin, auto_key, enc_key,
                                     device_id, ilink_app_id, server_id, av, dv, hv)
            mark = "✅" if ok else "  "
            print(f"{mark} {label:44} -> {note}")
            results.append((ok, label, note))
            if ok:
                print("\n*** 找到可用组合 ***")
                break
        except Exception as e:
            print(f"   {label:44} -> EXC {type(e).__name__}: {str(e)[:60]}")
        time.sleep(1.2)   # 避免触发频控

    ok_any = any(r[0] for r in results)
    if not ok_any:
        print("\n所有组合都失败。可能需要抓真实的 Device/appVersion。")
    return 0 if ok_any else 1


if __name__ == "__main__":
    sys.exit(main())
