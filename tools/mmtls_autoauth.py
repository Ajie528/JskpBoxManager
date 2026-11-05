"""AutoAuth 自实现（第二步）：用已有凭证直接向微信服务器续期，不需要 QQ 浏览器。

协议参考：525815266/YYB-Go-Enhanced 的 internal/protocol/autoauth.go + ilink.go
本脚本是「只读验证」版本：默认 dry-run 只构造请求，加 --send 才真正发送。

用法：
    py -3 mmtls_autoauth.py --box qb15                 # 只构造，不发送（dry-run）
    py -3 mmtls_autoauth.py --box qb15 --send          # 真正发送并看响应
    py -3 mmtls_autoauth.py --box qb15 --send --save   # 成功后把新 key 写回沙箱与金库
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import struct
import sys
import time
from pathlib import Path

# ---------------- 协议常量 ----------------
RECORD_VERSION = 0xF103
CT_HANDSHAKE = 0x16
CT_APPDATA = 0x17

HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_NEW_SESSION_TICKET = 0x04
HS_CERT_VERIFY = 0x0F
HS_FINISHED = 0x14

CIPHER_ECDHE = 0xC02B
EXT_KEY_SHARE = 0x01
GROUP_P256 = 0x01
GROUP_2 = 0x02
KEY_LEN = 65

CMD_AUTOAUTH = 3198
CLIENT_VERSION = 524545
APP_VERSION = 1901

SHORTLINK_MAGIC = 0x1110
DEFAULT_VER = 0x076D

SERVER_PUB_HEX = (
    "04ef87876d6478b15f1796eab12068610541173b7176b67f1dcc86683e901acd44"
    "d18b4ac36938251d0812dd0cf842aa2d6cbb8115712d1c0087dcefc14a44cd58"
)

LABEL_EXPANDED_SECRET = b"expanded secret"
LABEL_HANDSHAKE_KEYS = b"handshake key expansion"
LABEL_APP_DATA_KEYS = b"application data key expansion"
LABEL_CLIENT_FINISHED = b"client finished"
LABEL_SERVER_FINISHED = b"server finished"
LABEL_PSK_ACCESS = b"PSK_ACCESS"
LABEL_PSK_REFRESH = b"PSK_REFRESH"
ILINK_HKDF_SALT = b"security hdkf expand"


def log(*a):
    print(*a, flush=True)


# ---------------- protobuf 基础 ----------------
def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint(data: bytes, i: int):
    n = 0
    shift = 0
    while i < len(data):
        b = data[i]
        i += 1
        n |= (b & 0x7F) << shift
        if not (b & 0x80):
            return n, i
        shift += 7
        if shift > 63:
            raise ValueError("varint overflow")
    raise ValueError("truncated varint")


def pb_len(field: int, data: bytes) -> bytes:
    return bytes([(field << 3) | 2]) + varint(len(data)) + data


def pb_var(field: int, n: int) -> bytes:
    return bytes([(field << 3) | 0]) + varint(n)


def pb_parse(data: bytes) -> dict:
    out = {}
    i = 0
    while i < len(data):
        try:
            tag, i = read_varint(data, i)
        except ValueError:
            break
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            try:
                v, i = read_varint(data, i)
            except ValueError:
                break
            out[fn] = v
        elif wt == 2:
            try:
                ln, i = read_varint(data, i)
            except ValueError:
                break
            if i + ln > len(data):
                break
            out[fn] = data[i:i + ln]
            i += ln
        else:
            break
    return out


# ---------------- HKDF / AEAD ----------------
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    c = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t
        c += 1
    return out[:length]


def expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    return hkdf_expand(secret, label + (context or b""), length)


def aes_gcm_encrypt_layout(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """与参考实现一致：body || iv(12) || tag(16)"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plaintext, aad)   # ct 尾部含 16 字节 tag
    body, tag = ct[:-16], ct[-16:]
    return body + iv + tag


def aes_gcm_decrypt_layout(key: bytes, aad: bytes, blob: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(blob) < 28:
        raise ValueError("GCM blob too short")
    ct, iv, tag = blob[:-28], blob[-28:-16], blob[-16:]
    return AESGCM(key).decrypt(iv, ct + tag, aad)


def lz4_all_literal(data: bytes) -> bytes:
    n = len(data)
    if n < 15:
        return bytes([n << 4]) + data
    out = bytearray([0xF0])
    rem = n - 15
    while rem >= 255:
        out.append(255)
        rem -= 255
    out.append(rem)
    out += data
    return bytes(out)


def lz4_decompress(data: bytes) -> bytes:
    from lz4.block import decompress as _lz4
    try:
        # 纯 literal 块：自己解析更可靠（避免 lz4 库的 header 探测）
        out = bytearray()
        i = 0
        while i < len(data):
            tok = data[i]; i += 1
            lit = tok >> 4
            if lit == 15:
                while i < len(data) and data[i] == 255:
                    lit += 255; i += 1
                if i >= len(data):
                    raise ValueError("truncated literal len")
                lit += data[i]; i += 1
            if i + lit > len(data):
                raise ValueError("truncated literals")
            out += data[i:i + lit]
            i += lit
            if i >= len(data):
                break
            if i + 2 > len(data):
                raise ValueError("truncated offset")
            off = struct.unpack("<H", data[i:i + 2])[0]; i += 2
            if off <= 0 or off > len(out):
                raise ValueError("bad offset")
            mlen = (tok & 0x0F) + 4
            if (tok & 0x0F) == 15:
                while i < len(data) and data[i] == 255:
                    mlen += 255; i += 1
                if i >= len(data):
                    raise ValueError("truncated match len")
                mlen += data[i]; i += 1
            start = len(out) - off
            for j in range(mlen):
                out.append(out[start + j])
        return bytes(out)
    except ImportError:
        raise


# ---------------- 记录层 ----------------
def build_record(ct: int, payload: bytes) -> bytes:
    return bytes([ct]) + struct.pack(">H", RECORD_VERSION) + struct.pack(">H", len(payload)) + payload


def parse_records(data: bytes):
    recs = []
    off = 0
    while off + 5 <= len(data):
        ct = data[off]
        ver = struct.unpack(">H", data[off + 1:off + 3])[0]
        ln = struct.unpack(">H", data[off + 3:off + 5])[0]
        if ver != RECORD_VERSION or ct not in (0x15, 0x16, 0x17, 0x19, 0x14):
            break
        end = off + 5 + ln
        if end > len(data):
            break
        recs.append((ct, data[off + 5:end]))
        off = end
    return recs, off


def build_handshake(t: int, body: bytes) -> bytes:
    total = 1 + len(body)
    return struct.pack(">I", total) + bytes([t]) + body


def split_handshake(payload: bytes):
    total = struct.unpack(">I", payload[:4])[0]
    inner = payload[4:4 + total]
    return inner[0], inner[1:]


def build_record_aad(seq: int, ct: int, cipher_len: int) -> bytes:
    return struct.pack(">Q", seq) + bytes([ct, 0xF1, 0x03]) + struct.pack(">H", cipher_len)


def nonce_for(iv: bytes, seq: int) -> bytes:
    s = struct.pack(">Q", seq)
    iv = bytearray(iv)
    for i in range(8):
        iv[len(iv) - 8 + i] ^= s[i]
    return bytes(iv)


def gcm_encrypt(key, iv, seq, plaintext, aad):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).encrypt(nonce_for(iv, seq), plaintext, aad)


def gcm_decrypt(key, iv, seq, ct, aad):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(nonce_for(iv, seq), ct, aad)


# ---------------- ECDH ----------------
def gen_ecdh():
    from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1())
    pub = k.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.X962,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PublicFormat.UncompressedPoint)
    return k, pub


def ecdh_secret(priv, peer_pub: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
    return hashlib.sha256(priv.exchange(ec.ECDH(), peer)).digest()


def build_client_hello(g1_pub: bytes, g2_pub: bytes, rnd: bytes, ts: int) -> bytes:
    body = bytearray([0x03, 0xF1, 1]) + struct.pack(">H", CIPHER_ECDHE) + rnd + struct.pack(">I", ts)
    ks = bytearray([0x00, 0x10, 2])
    for g, p in ((GROUP_P256, g1_pub), (GROUP_2, g2_pub)):
        one = struct.pack(">I", g) + struct.pack(">H", KEY_LEN) + p
        ks += struct.pack(">I", len(one)) + one
    ks += bytes([0, 0, 0, 1])
    ext = bytes([EXT_KEY_SHARE]) + struct.pack(">I", len(ks)) + bytes(ks)
    body += struct.pack(">I", len(ext)) + ext
    return build_handshake(HS_CLIENT_HELLO, bytes(body))


def parse_server_hello(body: bytes):
    o = 2
    cipher = struct.unpack(">H", body[o:o + 2])[0]; o += 2
    o += 32  # server random
    ext_len = struct.unpack(">I", body[o:o + 4])[0]; o += 4
    ext = body[o:o + ext_len]
    group, server_pub = GROUP_P256, b""
    if ext and ext[0] == EXT_KEY_SHARE:
        eo = 1 + 4 + 2
        group = struct.unpack(">I", ext[eo:eo + 4])[0]; eo += 4
        klen = struct.unpack(">H", ext[eo:eo + 2])[0]; eo += 2
        server_pub = ext[eo:eo + klen]
    return cipher, group, server_pub


def finished_vd(secret, is_client, hs_hash):
    label = LABEL_CLIENT_FINISHED if is_client else LABEL_SERVER_FINISHED
    key = expand_label(secret, label, b"", 32)
    return hmac.new(key, hs_hash, hashlib.sha256).digest()


def parse_nst(body: bytes):
    out = []
    if not body:
        return out
    count = body[0]
    o = 1
    for _ in range(count):
        if o + 4 > len(body):
            break
        elen = struct.unpack(">I", body[o:o + 4])[0]; o += 4
        if o + elen > len(body) or elen < 5:
            break
        e = body[o:o + elen]; o += elen
        out.append((e[0], struct.unpack(">I", e[1:5])[0], e))
    return out


# ---------------- wpkg 头 ----------------
def wpkg_head(ints: dict, byts: dict) -> bytes:
    out = bytearray(varint(1))
    for k in sorted(ints):
        out += varint(k) + varint(ints[k])
    out += varint(0)
    for k in sorted(byts):
        v = byts[k]
        out += varint(k) + varint(len(v)) + v
    prefix_len = len(out)
    out += b"\x00"
    out += varint(prefix_len + 1)
    return bytes(out)


def session_wpkg_head(uin: int, f9: bytes, device_id: bytes) -> bytes:
    ints = {
        1: 1, 2: uin, 3: 0, 4: 0, 5: CLIENT_VERSION, 6: 11, 7: 0, 8: 0, 9: 0,
        10: 1, 11: 0, 12: 0, 13: 0, 17: 0, 18: 1, 20: 1504, 21: 0, 22: uin,
        23: 0, 25: 16, 26: 4, 28: 1, 29: 1, 30: 0,
    }
    # AutoAuth 场景下参考实现把 ints[25] 改成 17（App instance clears IsAppAccount）
    ints[25] = 17
    return wpkg_head(ints, {14: b"", 24: device_id, 27: f9})


def build_shortlink(cmd: int, seq: int, body: bytes) -> bytes:
    out = struct.pack(">I", 16 + len(body)) + struct.pack(">H", SHORTLINK_MAGIC)
    out += struct.pack(">H", DEFAULT_VER) + struct.pack(">I", cmd) + struct.pack(">I", seq)
    return out + body


def parse_shortlink(pkt: bytes):
    total = struct.unpack(">I", pkt[:4])[0]
    magic = struct.unpack(">H", pkt[4:6])[0]
    ver = struct.unpack(">H", pkt[6:8])[0]
    cmd = struct.unpack(">I", pkt[8:12])[0]
    seq = struct.unpack(">I", pkt[12:16])[0]
    return {"total": total, "magic": magic, "ver": ver, "cmd": cmd, "seq": seq, "body": pkt[16:total]}


# ---------------- Hybrid ECDH ----------------
def hybrid_encrypt_with_key(plaintext: bytes, server_pub: bytes, enc_key: bytes):
    """返回 (cipher_blob, temp_state)"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    eph, eph_pub = gen_ecdh()
    srv = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub)
    secret = hashlib.sha256(eph.exchange(ec.ECDH(), srv)).digest()

    hash1 = hashlib.sha256(b"1" + b"415" + eph_pub).digest()
    cek = os.urandom(32)

    enc_cek = aes_gcm_encrypt_layout(secret[:24], hash1, cek)
    enc_session = b""
    if enc_key:
        if len(enc_key) != 24:
            raise ValueError(f"enc_key 长度必须 24，实际 {len(enc_key)}")
        enc_session = aes_gcm_encrypt_layout(enc_key, hash1, cek)

    prk = hkdf_extract(ILINK_HKDF_SALT, cek)
    okm = hkdf_expand(prk, hash1, 56)

    hash2 = hashlib.sha256(b"1" + b"415" + eph_pub + enc_cek + enc_session).digest()
    comp = lz4_all_literal(plaintext)
    enc_body = aes_gcm_encrypt_layout(okm[:24], hash2, comp)

    ecdh_key = pb_var(1, 415) + pb_len(2, eph_pub)
    out = pb_var(1, 1) + pb_len(2, ecdh_key) + pb_len(3, enc_cek) + pb_len(4, enc_session) + pb_len(5, enc_body)

    temp = {"eph": eph, "okm": okm, "comp": comp, "request_cipher": enc_body}
    return out, temp


def hybrid_decrypt(response: bytes, temp) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec
    F = pb_parse(response)
    f1 = F.get(1)
    if not isinstance(f1, (bytes, bytearray)):
        raise ValueError("HybridEcdhResponse 缺 field 1")
    key_fields = pb_parse(f1)
    server_resp_pub = key_fields.get(2)
    if not isinstance(server_resp_pub, (bytes, bytearray)):
        raise ValueError("缺 server pubkey")
    cred_type = F.get(2, 1)
    ct = F.get(3)
    if not isinstance(ct, (bytes, bytearray)):
        raise ValueError("缺 ciphertext")

    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(server_resp_pub))
    secret = hashlib.sha256(temp["eph"].exchange(ec.ECDH(), peer)).digest()
    aad_input = temp["okm"][24:56] + temp["comp"] + b"415" + bytes(server_resp_pub) + str(cred_type).encode()
    aad = hashlib.sha256(aad_input).digest()
    comp = aes_gcm_decrypt_layout(secret[:24], aad, bytes(ct))
    return lz4_decompress(comp)


# ---------------- 凭证读取 ----------------
def read_tdi_account(wmpf_root: Path) -> dict:
    tdi = wmpf_root / "ilink" / "default" / "tdi"
    cands = sorted(tdi.rglob("tdi_account.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not cands:
        raise FileNotFoundError(f"找不到 tdi_account.txt（在 {tdi}）")
    path = cands[0]
    kv = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return {"path": path, "kv": kv}


def b64(v: str) -> bytes:
    return base64.b64decode(v + "=" * (-len(v) % 4))


# ---------------- 主流程 ----------------
class Mmtls:
    def __init__(self, sock, timeout):
        self.sock = sock
        self.timeout = timeout
        self.tx = 0
        self.rx = 0
        self.transcript = b""
        self.rxbuf = b""
        self.recq = []
        self.app_tx = 0

    def send_raw(self, data: bytes):
        self.sock.sendall(data)

    def recv_rec(self):
        if self.recq:
            return self.recq.pop(0)
        while True:
            recs, off = parse_records(self.rxbuf)
            if recs:
                self.rxbuf = self.rxbuf[off:]
                self.recq.extend(recs)
                return self.recq.pop(0)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("peer closed")
            self.rxbuf += chunk

    def handshake(self, host, port):
        import socket as _s
        ip = _s.gethostbyname(host)
        log(f"[握手] {host} -> {ip}:{port}")
        g1, g1_pub = gen_ecdh()
        _, g2_pub = gen_ecdh()
        ch = build_client_hello(g1_pub, g2_pub, os.urandom(32), int(time.time()))
        self.transcript += ch
        self.send_raw(build_record(CT_HANDSHAKE, ch))
        self.tx += 1

        ct, payload = self.recv_rec(); self.rx += 1
        if ct != CT_HANDSHAKE:
            raise ValueError(f"期望 Handshake，收到 0x{ct:02x}")
        mt, body = split_handshake(payload)
        if mt != HS_SERVER_HELLO:
            raise ValueError(f"期望 ServerHello，收到 0x{mt:02x}")
        self.transcript += payload
        cipher, group, server_pub = parse_server_hello(body)
        log(f"[握手] ServerHello cipher=0x{cipher:04x} group={group}")

        secret = ecdh_secret(g1, server_pub)
        hs_hash = hashlib.sha256(self.transcript).digest()
        kb = expand_label(secret, LABEL_HANDSHAKE_KEYS, hs_hash, 56)
        hs_c_key, hs_s_key, hs_c_iv, hs_s_iv = kb[0:16], kb[16:32], kb[32:44], kb[44:56]

        h_certv = None
        h_final = None
        nst = []
        while True:
            ct, cp = self.recv_rec()
            seq = self.rx; self.rx += 1
            aad = build_record_aad(seq, ct, len(cp))
            pt = gcm_decrypt(hs_s_key, hs_s_iv, seq, cp, aad)
            mt, mbody = split_handshake(pt)
            if mt == HS_FINISHED:
                h_final = hashlib.sha256(self.transcript).digest()
                n = struct.unpack(">H", mbody[:2])[0]
                got = mbody[2:2 + n]
                want = finished_vd(secret, False, h_final)
                if got != want:
                    raise ValueError("ServerFinished 校验失败")
                self.transcript += pt
                break
            self.transcript += pt
            if mt == HS_CERT_VERIFY:
                h_certv = hashlib.sha256(self.transcript).digest()
            elif mt == HS_NEW_SESSION_TICKET:
                nst = parse_nst(mbody)

        master = expand_label(secret, LABEL_EXPANDED_SECRET, h_final, 32)
        ak = expand_label(master, LABEL_APP_DATA_KEYS, h_final, 56)
        self.app_c_key, self.app_s_key = ak[0:16], ak[16:32]
        self.app_c_iv, self.app_s_iv = ak[32:44], ak[44:56]

        vd = finished_vd(secret, True, h_final)
        cf = build_handshake(HS_FINISHED, struct.pack(">H", len(vd)) + vd)
        seq = self.tx
        aad = build_record_aad(seq, CT_HANDSHAKE, len(cf) + 16)
        enc = gcm_encrypt(hs_c_key, hs_c_iv, seq, cf, aad)
        self.send_raw(build_record(CT_HANDSHAKE, enc))
        self.tx += 1
        log("[握手] 完成")
        return {"secret": secret, "h_certv": h_certv, "nst": nst}

    def send_app(self, cmd: int, body: bytes):
        pkt = build_shortlink(cmd, self.app_tx, body)
        self.app_tx += 1
        seq = self.tx
        aad = build_record_aad(seq, CT_APPDATA, len(pkt) + 16)
        enc = gcm_encrypt(self.app_c_key, self.app_c_iv, seq, pkt, aad)
        self.send_raw(build_record(CT_APPDATA, enc))
        self.tx += 1

    def recv_app(self):
        ct, pt = self.recv_rec()
        seq = self.rx; self.rx += 1
        aad = build_record_aad(seq, ct, len(pt))
        plain = gcm_decrypt(self.app_s_key, self.app_s_iv, seq, pt, aad)
        return parse_shortlink(plain)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--box", default="qb15")
    ap.add_argument("--appdir", default=r"D:\a_game_scrpit\JskpBoxManager-exe")
    ap.add_argument("--host", default="longcloud.weixin.com")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--send", action="store_true", help="真正发送 AutoAuth（默认只构造）")
    ap.add_argument("--save", action="store_true", help="成功后把新 key 写回 tdi_account.txt")
    ap.add_argument("--device", default="", help="覆盖 AutoAuth.Device 的 hex（32 字节，默认用 kTdiKeyDeviceId）")
    ap.add_argument("--timeout", type=int, default=15)
    a = ap.parse_args()

    try:
        import cryptography  # noqa
    except ImportError:
        log("需要 cryptography：py -3 -m pip install cryptography")
        return 2

    appdir = Path(a.appdir)
    wmpf = appdir / "profiles" / a.box / "wmpf"
    if not wmpf.exists():
        log(f"金库不存在：{wmpf}")
        return 2

    acc = read_tdi_account(wmpf)
    kv = acc["kv"]
    log(f"=== 读取凭证 {acc['path']} ===")

    auto_key = b64(kv["kTdiKeyAutoauthKey"])
    enc_key = b64(kv["kTdiKeyAutoauthEncKey"])
    device_id = b64(kv["kTdiKeyDeviceId"])
    server_id = b64(kv["kTdiKeyServerId"])
    uin = int(kv["kTdiKeyUin"])

    # 参考实现 ilink.go：wpkg 头字段 24 是 ilink app id 字符串（如 ilinkapp_0600005ba4e935），
    # 不是 kTdiKeyDeviceId 那 32 字节。之前一直填错，服务端能解包但业务层回 -2。
    ilink_app_id = kv.get("kTdiKeyIlinkAppId", "").strip().encode()
    if not ilink_app_id:
        # tdi_account.txt 没写这项时，从目录名反推：...\tdi\ilinkapp_xxxx\0\6\tdi_account.txt
        parts = [p for p in Path(acc["path"]).parts if p.startswith("ilinkapp_")]
        if parts:
            ilink_app_id = parts[-1].encode()
    log(f"  uin={uin} keyLen={len(auto_key)} encKeyLen={len(enc_key)} "
        f"deviceLen={len(device_id)} f9Len={len(server_id)} "
        f"ilinkAppId={ilink_app_id.decode(errors='replace')}")

    if len(enc_key) != 24:
        log(f"encKey 长度 {len(enc_key)} != 24，参考实现要求 24，放弃")
        return 3
    if not ilink_app_id:
        log("找不到 kTdiKeyIlinkAppId，无法填 wpkg 字段 24，放弃")
        return 3

    # 构造 AutoAuth 明文（参考实现 buildAutoAuth）
    #   request = pbLen(1, pbLen(1, AutoAuth.Device)) + pbVar(2, appVersion) + pbLen(3, AutoAuth.Key)
    # AutoAuth.Device 在参考实现里就是 ManualAuth 时本地生成的 32 字节 appDeviceID，
    # 我们手上没有那个值；本地能对应上的是 kTdiKeyDeviceId（同样 32 字节）。
    if a.device:
        device_field = bytes.fromhex(a.device)
        log(f"=== 使用命令行指定的 Device ({len(device_field)} 字节) ===")
    else:
        device_field = device_id
    inner = pb_len(1, device_field)
    request = pb_len(1, inner) + pb_var(2, APP_VERSION) + pb_len(3, auto_key)
    log(f"=== AutoAuth 明文 {len(request)} 字节 ===")

    server_pub = bytes.fromhex(SERVER_PUB_HEX)
    hybrid, temp = hybrid_encrypt_with_key(request, server_pub, enc_key)
    log(f"=== Hybrid 加密后 {len(hybrid)} 字节 ===")

    body = session_wpkg_head(uin, server_id, ilink_app_id) + hybrid
    log(f"=== 完整请求体 {len(body)} 字节（含 wpkg 头）===")

    if not a.send:
        log("\n[dry-run] 未发送。要真正发送请加 --send")
        return 0

    import socket as _s
    sock = _s.create_connection((_s.gethostbyname(a.host), a.port), timeout=a.timeout)
    try:
        m = Mmtls(sock, a.timeout)
        hs = m.handshake(a.host, a.port)
        log(f"\n=== 发送 AutoAuth (cmdid {CMD_AUTOAUTH}) ===")
        m.send_app(CMD_AUTOAUTH, body)
        pkt = m.recv_app()
        log(f"响应 cmd={pkt['cmd']} seq={pkt['seq']} bodyLen={len(pkt['body'])}")

        # 解析响应
        ints = {}
        hlen = None
        # 尝试解析 wpkg 头条
        data = pkt["body"]
        try:
            i = 0
            _, i = read_varint(data, i)
            ints = {}
            while i < len(data):
                fn, i = read_varint(data, i)
                if fn == 0:
                    break
                v, i = read_varint(data, i)
                ints[fn] = v
            hlen = i
        except Exception:
            pass
        log(f"响应头 ints={ints} hlen={hlen}")
        if ints.get(4):
            log(f"❌ 传输层拒绝 code={ints[4]}")
            return 4
        if ints.get(23):
            log(f"❌ 应用层拒绝 code={ints[23]}")
            return 4

        # 解密响应体
        # 响应结构可能不完全等于参考实现的假设：先试 hlen 之后，再用参考实现的
        # 「找 HybridEcdhResponse 标记」兜底（0x08 0x9f 0x03 0x12 0x41 0x04）
        candidates = []
        if hlen is not None and hlen < len(data):
            candidates.append(("after-wpkg-head", data[hlen:]))
        marker = bytes([0x08, 0x9F, 0x03, 0x12, 0x41, 0x04])
        idx = data.find(marker)
        if idx >= 2:
            candidates.append(("marker", data[idx - 2:]))

        decoded = None
        used = None
        for label, blob in candidates:
            if not blob:
                continue
            try:
                decoded = hybrid_decrypt(blob, temp)
                used = label
                break
            except Exception as e:
                log(f"  [{label}] 解密失败: {type(e).__name__}: {e}")
        if decoded is None:
            log("所有候选解密均失败")
            log(f"  body hex(前80): {data[:80].hex()}")
            return 5

        log(f"=== 解密成功（{used}）{len(decoded)} 字节 ===")
        log(f"  密文 hex: {decoded.hex()}")
        fields = pb_parse(decoded)
        log(f"字段: {list(fields.keys())}")
        for k, v in fields.items():
            if isinstance(v, (bytes, bytearray)):
                log(f"  field {k}: bytes[{len(v)}] = {bytes(v)[:60].hex()}")
                sub = pb_parse(bytes(v))
                if sub:
                    for sk, sv in sub.items():
                        if isinstance(sv, (bytes, bytearray)):
                            log(f"    .{sk}: bytes[{len(sv)}] = {bytes(sv)[:48].hex()}")
                            sub2 = pb_parse(bytes(sv))
                            if sub2:
                                for sk2, sv2 in sub2.items():
                                    if isinstance(sv2, (bytes, bytearray)):
                                        log(f"      ..{sk2}: bytes[{len(sv2)}]")
                                    else:
                                        log(f"      ..{sk2}: {sv2}")
                        else:
                            log(f"    .{sk}: {sv}")
            else:
                log(f"  field {k}: {v}")

        base = fields.get(1, b"")
        unified = fields.get(2, b"")
        if base:
            bf = pb_parse(base)
            code = bf.get(1)
            # protobuf varint 是无符号；负数是补码。转成有符号看真实语义。
            signed = None
            if isinstance(code, int):
                signed = code - (1 << 64) if code >= (1 << 63) else code
            log(f"base.code={code}（有符号 {signed}）")
            for k, v in bf.items():
                if isinstance(v, (bytes, bytearray)):
                    log(f"  base.{k}: bytes[{len(v)}] = {bytes(v)[:80].hex()}")
                    txt = None
                    try:
                        txt = bytes(v).decode("utf-8")
                    except Exception:
                        pass
                    if txt and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in txt):
                        log(f"  base.{k} 文本: {txt[:120]}")
                else:
                    log(f"  base.{k}: {v}")
            if signed not in (None, 0):
                log(f"❌ 业务层拒绝 code={signed}")
                return 4
        if unified:
            uf = pb_parse(unified)
            sect = pb_parse(uf.get(2, b""))
            new_key = sect.get(3)
            new_enc = sect.get(4)
            new_f9 = sect.get(9)          # 新的 ServerId（wpkg 字段 27）
            log(f"🧩 新 key: len={len(new_key) if new_key else 0} "
                f"encKey: len={len(new_enc) if new_enc else 0} "
                f"serverId: len={len(new_f9) if new_f9 else 0}")
            if new_key and new_enc:
                log("✅ 拿到轮换后的新凭证！")
                if a.save:
                    save_new_credential(acc["path"], kv, new_key, new_enc, new_f9)
        return 0
    finally:
        sock.close()


def save_new_credential(path: Path, kv: dict, new_key: bytes, new_enc: bytes, new_f9: bytes = None):
    """把新 key 写回 tdi_account.txt（原地替换对应几行）。"""
    import base64 as _b64
    new_k = _b64.b64encode(new_key).decode()
    new_e = _b64.b64encode(new_enc).decode()
    new_s = _b64.b64encode(new_f9).decode() if new_f9 else None
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        if line.startswith("kTdiKeyAutoauthKey="):
            out.append("kTdiKeyAutoauthKey=" + new_k)
        elif line.startswith("kTdiKeyAutoauthEncKey="):
            out.append("kTdiKeyAutoauthEncKey=" + new_e)
        elif new_s and line.startswith("kTdiKeyServerId="):
            out.append("kTdiKeyServerId=" + new_s)
        else:
            out.append(line)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    log(f"[保存] 已写回 {path}")
    log(f"       newKey={new_k[:16]}… newEnc={new_e[:12]}…"
        + (f" newServerId={new_s[:16]}…" if new_s else ""))


if __name__ == "__main__":
    sys.exit(main())
