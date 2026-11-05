"""mmtls 握手可行性探测（第一步：只验证握手，不发 AutoAuth）。

目标：用我们从 tdi_account.txt / psk.key 拿到的数据，能否完成 mmtls 握手并拿到 PSK。
这一步不涉及任何凭证轮换，纯只读验证。

协议参考：525815266/YYB-Go-Enhanced 的 internal/protocol/mmtls_*.go
（recordVersion=0xf103, cipherECDHE=0xc02b, group=P-256）

用法：
    py -3 mmtls_probe.py --box qb15
    py -3 mmtls_probe.py --box qb15 --host longcloud.weixin.com --port 5000
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
import time
from pathlib import Path

# ---------------- 协议常量（与参考实现一致） ----------------
RECORD_VERSION = 0xF103
CT_ALERT = 0x15
CT_HANDSHAKE = 0x16
CT_APPDATA = 0x17
CT_PSK_HANDSHAKE = 0x19

HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_NEW_SESSION_TICKET = 0x04
HS_CERT_VERIFY = 0x0F
HS_FINISHED = 0x14

CIPHER_ECDHE = 0xC02B
CIPHER_PSK = 0x00A8
EXT_KEY_SHARE = 0x01
GROUP_P256 = 0x01
GROUP_2 = 0x02
KEY_LEN = 65

# 微信服务器静态公钥（参考实现里的 serverPubHex）
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


def log(*a):
    print(*a, flush=True)


# ---------------- HKDF / 加密 ----------------
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    return hkdf_expand(secret, label + (context or b""), length)


def build_record_aad(seq: int, content_type: int, cipher_len: int) -> bytes:
    return struct.pack(">Q", seq) + bytes([content_type, 0xF1, 0x03]) + struct.pack(">H", cipher_len)


def nonce_for(iv: bytes, seq: int) -> bytes:
    s = struct.pack(">Q", seq)
    iv = bytearray(iv)
    for i in range(8):
        iv[len(iv) - 8 + i] ^= s[i]
    return bytes(iv)


def gcm_encrypt(key: bytes, iv: bytes, seq: int, plaintext: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).encrypt(nonce_for(iv, seq), plaintext, aad)


def gcm_decrypt(key: bytes, iv: bytes, seq: int, ct: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(nonce_for(iv, seq), ct, aad)


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
        if ver != RECORD_VERSION or ct not in (CT_ALERT, CT_HANDSHAKE, CT_APPDATA, CT_PSK_HANDSHAKE, 0x14):
            break
        end = off + 5 + ln
        if end > len(data):
            break
        recs.append((ct, data[off + 5:end]))
        off = end
    return recs, off


def build_handshake(msg_type: int, body: bytes) -> bytes:
    total = 1 + len(body)
    return struct.pack(">I", total) + bytes([msg_type]) + body


def split_handshake(payload: bytes):
    if len(payload) < 5:
        raise ValueError("handshake too short")
    total = struct.unpack(">I", payload[:4])[0]
    inner = payload[4:4 + total]
    return inner[0], inner[1:]


# ---------------- ClientHello ----------------
def build_client_hello(g1_pub: bytes, g2_pub: bytes, client_random: bytes, timestamp: int) -> bytes:
    body = bytearray()
    body += bytes([0x03, 0xF1, 1])
    body += struct.pack(">H", CIPHER_ECDHE)
    body += client_random
    body += struct.pack(">I", timestamp)

    ks = bytearray()
    ks += bytes([0x00, 0x10, 2])
    for group, pub in ((GROUP_P256, g1_pub), (GROUP_2, g2_pub)):
        one = struct.pack(">I", group) + struct.pack(">H", KEY_LEN) + pub
        ks += struct.pack(">I", len(one)) + one
    ks += bytes([0, 0, 0, 1])

    ext = bytes([EXT_KEY_SHARE]) + struct.pack(">I", len(ks)) + bytes(ks)
    body += struct.pack(">I", len(ext)) + ext
    return build_handshake(HS_CLIENT_HELLO, bytes(body))


def parse_server_hello(body: bytes):
    o = 2  # 跳过版本
    cipher = struct.unpack(">H", body[o:o + 2])[0]; o += 2
    random = body[o:o + 32]; o += 32
    ext_len = struct.unpack(">I", body[o:o + 4])[0]; o += 4
    ext = body[o:o + ext_len]
    server_pub = b""
    group = GROUP_P256
    if ext and ext[0] == EXT_KEY_SHARE:
        eo = 1
        eo += 4  # 跳过总长
        eo += 2
        group = struct.unpack(">I", ext[eo:eo + 4])[0]; eo += 4
        klen = struct.unpack(">H", ext[eo:eo + 2])[0]; eo += 2
        server_pub = ext[eo:eo + klen]
    return cipher, random, group, server_pub


def finished_verify_data(secret: bytes, is_client: bool, hs_hash: bytes) -> bytes:
    label = LABEL_CLIENT_FINISHED if is_client else LABEL_SERVER_FINISHED
    key = expand_label(secret, label, b"", 32)
    return hmac.new(key, hs_hash, hashlib.sha256).digest()


def derive_psk(secret: bytes, h_certv: bytes, psk_type: int) -> bytes:
    label = LABEL_PSK_ACCESS if psk_type == 1 else LABEL_PSK_REFRESH
    return expand_label(secret, label, h_certv, 32)


def parse_new_session_ticket(body: bytes):
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
        entry = body[o:o + elen]; o += elen
        psk_type = entry[0]
        lifetime = struct.unpack(">I", entry[1:5])[0]
        out.append((psk_type, lifetime, entry))
    return out


# ---------------- 主流程 ----------------
def pexpect_ecdh():
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.X962,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).PublicFormat.UncompressedPoint)
    return priv, pub


def ecdh_secret(priv, peer_pub: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
    shared = priv.exchange(ec.ECDH(), peer)
    return hashlib.sha256(shared).digest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--box", default="qb15")
    ap.add_argument("--host", default="longcloud.weixin.com")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--timeout", type=int, default=15)
    a = ap.parse_args()

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except ImportError:
        log("需要 cryptography：py -3 -m pip install cryptography")
        return 2

    log(f"=== mmtls 握手探测 box={a.box} target={a.host}:{a.port} ===")

    # 1) 解析目标
    try:
        ip = socket.gethostbyname(a.host)
        log(f"DNS: {a.host} -> {ip}")
    except Exception as e:
        log("DNS 失败:", e)
        return 2

    # 2) TCP 连接
    sock = socket.create_connection((ip, a.port), timeout=a.timeout)
    log(f"TCP 已连接 {ip}:{a.port}")

    state = {"tx": 0, "rx": 0, "transcript": b"", "rxbuf": b"", "recq": []}

    def send(payload: bytes):
        sock.sendall(payload)
        state["tx"] += 1

    def recv_record():
        # 一次 recv 可能带回多条记录，必须排队逐条消费，不能只取第一条就丢掉其余
        if state["recq"]:
            return state["recq"].pop(0)
        while True:
            recs, off = parse_records(state["rxbuf"])
            if recs:
                state["rxbuf"] = state["rxbuf"][off:]
                state["recq"].extend(recs)
                return state["recq"].pop(0)
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("peer closed")
            state["rxbuf"] += chunk

    # 3) ClientHello
    g1_priv, g1_pub = pexpect_ecdh()
    _, g2_pub = pexpect_ecdh()
    client_random = os.urandom(32)
    ch = build_client_hello(g1_pub, g2_pub, client_random, int(time.time()))
    state["transcript"] += ch
    send(build_record(CT_HANDSHAKE, ch))
    log(f"已发 ClientHello ({len(ch)} 字节)")

    # 4) ServerHello
    ct, payload = recv_record()
    state["rx"] += 1
    log(f"收到记录 ct=0x{ct:02x} len={len(payload)}")
    if ct != CT_HANDSHAKE:
        log(f"期望 Handshake(0x16)，实际 0x{ct:02x}")
        return 3
    mt, body = split_handshake(payload)
    if mt != HS_SERVER_HELLO:
        log(f"期望 ServerHello，实际 0x{mt:02x}")
        return 3
    state["transcript"] += payload
    cipher, server_random, group, server_pub = parse_server_hello(body)
    log(f"ServerHello: cipher=0x{cipher:04x} group={group} serverPubLen={len(server_pub)}")
    if group != GROUP_P256:
        log("服务器选了非 P-256 组，本探测未实现")
        return 3

    # 5) 派生握手密钥
    secret = ecdh_secret(g1_priv, server_pub)
    hs_hash = hashlib.sha256(state["transcript"]).digest()
    kb = expand_label(secret, LABEL_HANDSHAKE_KEYS, hs_hash, 56)
    hs_c_key, hs_s_key = kb[0:16], kb[16:32]
    hs_c_iv, hs_s_iv = kb[32:44], kb[44:56]
    log("握手密钥已派生")

    # 6) 读服务端 flight（CertVerify / NewSessionTicket / Finished）
    nst_entries = []
    h_certv = None
    h_final = None
    while True:
        ct, ct_payload = recv_record()
        seq = state["rx"]; state["rx"] += 1
        aad = build_record_aad(seq, ct, len(ct_payload))
        try:
            pt = gcm_decrypt(hs_s_key, hs_s_iv, seq, ct_payload, aad)
        except Exception as e:
            log(f"解密失败 ct=0x{ct:02x} len={len(ct_payload)}: {e}")
            return 4
        mt, mbody = split_handshake(pt)
        log(f"  握手消息 0x{mt:02x} ({len(mbody)} 字节)")
        if mt == HS_FINISHED:
            h_final = hashlib.sha256(state["transcript"]).digest()
            got = struct.unpack(">H", mbody[:2])[0]
            verify = mbody[2:2 + got]
            want = finished_verify_data(secret, False, h_final)
            log(f"  ServerFinished 校验: {'通过' if verify == want else '失败'}")
            state["transcript"] += pt
            break
        state["transcript"] += pt
        if mt == HS_CERT_VERIFY:
            h_certv = hashlib.sha256(state["transcript"]).digest()
        elif mt == HS_NEW_SESSION_TICKET:
            nst_entries = parse_new_session_ticket(mbody)

    if h_final is None:
        log("没收到 Finished")
        return 4

    # 7) 应用密钥 + ClientFinished
    master = expand_label(secret, LABEL_EXPANDED_SECRET, h_final, 32)
    ak = expand_label(master, LABEL_APP_DATA_KEYS, h_final, 56)
    app_c_key, app_s_key = ak[0:16], ak[16:32]
    app_c_iv, app_s_iv = ak[32:44], ak[44:56]

    vd = finished_verify_data(secret, True, h_final)
    cf = build_finished(vd)
    seq = state["tx"]
    aad = build_record_aad(seq, CT_HANDSHAKE, len(cf) + 16)
    enc = gcm_encrypt(hs_c_key, hs_c_iv, seq, cf, aad)
    send(build_record(CT_HANDSHAKE, enc))
    log("已发 ClientFinished")

    # 8) 输出 PSK（不落盘，只显示数量与类型）
    log(f"\n=== 握手成功 ===")
    log(f"NewSessionTicket 数量: {len(nst_entries)}")
    for psk_type, lifetime, entry in nst_entries:
        label = "PSK_ACCESS" if psk_type == 1 else "PSK_REFRESH"
        psk = derive_psk(secret, h_certv, psk_type)
        log(f"  type={psk_type}({label}) lifetime={lifetime}s psk={psk.hex()[:16]}… ticketLen={len(entry)}")

    sock.close()
    log("\n结论：mmtls 握手可用 —— 说明我们有能力自实现协议发包。")
    return 0


def build_finished(verify_data: bytes) -> bytes:
    return build_handshake(HS_FINISHED, struct.pack(">H", len(verify_data)) + verify_data)


if __name__ == "__main__":
    sys.exit(main())
