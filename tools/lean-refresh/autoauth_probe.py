"""AutoAuth 主动续期实验（在沙箱内运行）。

做三件事：
  1. 找到 qbX 的 ilink 进程并 attach
  2. 挂 hook_ilink.js（含 autoAuthRva），等运行时自己发一次 AutoAuth 以抓 this 指针
  3. 抓到后（或强制）用该 this 主动调 SendAutoAuthRequestAsync，观察密钥是否换新

用法（箱内）：
    Start.exe /box:qb15 /wait python.exe autoauth_probe.py --box qb15 --mode wait
    ... --mode force   # 不等运行时自己发，直接用上次抓到的 this 调（危险）

输出：%TEMP%\\autoauth_probe.txt 与 %TEMP%\\autoauth_probe.jsonl
"""
import argparse
import ctypes
import json
import os
import sys
import time
import traceback
from pathlib import Path

import psutil


def out_txt():
    return Path(os.environ.get("TEMP", ".")) / "autoauth_probe.txt"


def out_jsonl():
    return Path(os.environ.get("TEMP", ".")) / "autoauth_probe.jsonl"


LINES = []


def log(*a):
    s = " ".join(str(x) for x in a)
    LINES.append(s)
    try:
        out_txt().write_text("\n".join(LINES), encoding="utf-8")
    except Exception:
        pass


class Sbie:
    def __init__(self):
        try:
            self.dll = ctypes.WinDLL("SbieDll.dll")
        except OSError:
            self.dll = ctypes.WinDLL(r"C:\Program Files\Sandboxie-Plus\SbieDll.dll")
        self.fn = self.dll.SbieApi_QueryProcess
        self.fn.restype = ctypes.c_long

    def box_of(self, pid):
        b = ctypes.create_unicode_buffer(64)
        i = ctypes.create_unicode_buffer(128)
        if self.fn(ctypes.c_void_p(pid), b, i, None, None) != 0:
            return ""
        return b.value


def find_ilink(box, sbie):
    for p in psutil.process_iter(["pid", "name"]):
        if (p.info["name"] or "").lower() != "wechatappex.exe":
            continue
        pid = p.info["pid"]
        if sbie.box_of(pid).lower() != box.lower():
            continue
        try:
            cmd = " ".join(p.cmdline())
        except Exception:
            continue
        if "ILinkServiceHost" in cmd:
            return pid
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--box", default="qb15")
    ap.add_argument("--mode", default="wait", choices=["wait", "force"])
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--auto-auth-rva", type=lambda x: int(x, 0), default=0x229B70)
    a = ap.parse_args()

    out_txt().write_text("", encoding="utf-8")
    out_jsonl().write_text("", encoding="utf-8")

    try:
        import frida
    except Exception:
        log("frida 不可用")
        return 1

    sbie = Sbie()
    pid = find_ilink(a.box, sbie)
    log(f"box={a.box} ilink pid={pid}")
    if not pid:
        log("找不到 ilink 进程（沙箱没在跑？）")
        return 2

    script_path = Path(__file__).with_name("hook_ilink.js")
    src = script_path.read_text(encoding="utf-8")

    dev = frida.get_local_device()
    sess = dev.attach(pid)
    sc = sess.create_script(src)
    state = {"thisPtr": None, "calls": 0}

    def on_msg(m, d):
        if m.get("type") != "send":
            return
        p = m.get("payload") or {}
        ev = p.get("ev")
        try:
            with out_jsonl().open("a", encoding="utf-8") as f:
                f.write(json.dumps(p, ensure_ascii=False) + "\n")
        except Exception:
            pass
        if ev == "autoauth-call":
            state["thisPtr"] = p.get("thisPtr")
            state["calls"] = p.get("n", state["calls"])
            log(f"[运行时自己发了 AutoAuth] this={state['thisPtr']} 第 {state['calls']} 次")
        elif ev == "autoauth-hooked":
            log(f"[已挂上 AutoAuth] rva={p.get('rva')}")
        elif ev == "auth-stack":
            log(f"[采栈] {p.get('msg','')[:90]}")

    sc.on("message", on_msg)
    sc.load()
    sc.exports_sync.init({"xlogRva": None, "role": "ilink", "autoAuthRva": a.auto_auth_rva,
                          "stackOnAuth": False})
    log("脚本已注入", sc.exports_sync.autoAuthState())

    # 等运行时自己发一次（拿到 this）
    deadline = time.time() + a.seconds
    while time.time() < deadline and not state["thisPtr"]:
        time.sleep(1)
    log("等待结束，state =", sc.exports_sync.autoAuthState())

    if not state["thisPtr"]:
        log("没抓到 this 指针：运行时在常驻态下不会主动发 AutoAuth，无法安全调用（会写坏内存）")
        log("结论：无法在本次会话内主动续期")
    else:
        log("抓到 this，准备主动调用")
        try:
            r = sc.exports_sync.invokeAutoAuth()
            log("invokeAutoAuth ->", r)
        except Exception as e:
            log("调用失败:", type(e).__name__, str(e)[:200])

    # 调完之后再观察一会，看有没有新 AutoAuth / 新凭证写入
    log("观察 20 秒…")
    time.sleep(20)
    log("最终 state =", sc.exports_sync.autoAuthState())

    for fn in (sc.unload, sess.detach):
        try:
            fn()
        except Exception:
            pass
    log("done")
    print("\n".join(LINES))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        log("EXCEPTION:\n" + traceback.format_exc())
        print(out_txt().read_text(encoding="utf-8") if out_txt().exists() else "")
        sys.exit(1)
