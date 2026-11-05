"""验证 spawn gating 能否在沙箱内捕获 ilink 进程创建（解决 4 秒窗口问题）。

背景：AutoAuth 在 ilink 进程创建后约 1 秒开始、约 4 秒完成，attach 现有进程来不及。
如果用 frida 的 spawn gating，可以在进程创建瞬间拿到它（挂起状态），
装好 hook 再 resume——这样 hook 在第一条指令前就位。

用法（箱内）：
    Start.exe /box:qb15 /wait python.exe spawn_gate_test.py --box qb15 --seconds 90

输出：%TEMP%\\spawn_gate_test.txt
"""
import argparse
import ctypes
import os
import time
import traceback
from pathlib import Path

import psutil

LOG = []


def log(*a):
    s = " ".join(str(x) for x in a)
    LOG.append(s)
    try:
        (Path(os.environ.get("TEMP", ".")) / "spawn_gate_test.txt").write_text(
            "\n".join(LOG), encoding="utf-8")
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--box", default="qb15")
    ap.add_argument("--seconds", type=int, default=90)
    a = ap.parse_args()

    (Path(os.environ.get("TEMP", ".")) / "spawn_gate_test.txt").write_text("", encoding="utf-8")
    sbie = Sbie()
    log("self box =", repr(sbie.box_of(os.getpid())))

    try:
        import frida
    except Exception:
        log("frida 不可用")
        return 1

    dev = frida.get_local_device()
    seen = []

    def on_spawned(spawn):
        try:
            name = Path(spawn.path).name
            log(f"[spawned] pid={spawn.pid} {name}")
            if name.lower() == "wechatappex.exe":
                cmd = " ".join(spawn.argv or [])
                role = "main"
                if "--type=" in cmd:
                    role = "ilink" if "ILinkServiceHost" in cmd else (
                        "network" if "NetworkService" in cmd else "-")
                owner = sbie.box_of(spawn.pid)
                log(f"  WEIXIN role={role} box={owner!r} argv={cmd[:100]}")
                seen.append((spawn.pid, role, owner))
        except Exception:
            log("on_spawned err:", traceback.format_exc()[-300:])
        finally:
            # 立刻放行，避免阻塞浏览器启动
            try:
                dev.resume(spawn.pid)
            except Exception as e:
                log("  resume err:", e)

    try:
        dev.on("spawn-added", on_spawned)
        dev.enable_spawn_gating()
        log("spawn gating 已开启")
    except Exception as e:
        log("enable_spawn_gating 失败:", type(e).__name__, e)
        return 2

    log(f"观察 {a.seconds} 秒，看能否捕获 wechatappex 的创建")
    time.sleep(a.seconds)

    try:
        pending = dev.enumerate_pending_spawn()
        log(f"仍挂起的 spawn: {len(pending)}")
        for s in pending:
            log(f"  pid={s.pid} {Path(s.path).name}")
            try:
                dev.resume(s.pid)
            except Exception:
                pass
    except Exception:
        pass
    try:
        dev.disable_spawn_gating()
    except Exception:
        pass

    log(f"\n捕获到 {len(seen)} 个微信进程：")
    for pid, role, owner in seen:
        log(f"  pid={pid} role={role} box={owner}")
    log("done")
    print("\n".join(LOG))
    return 0


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log("EXCEPTION:\n" + traceback.format_exc())
        print("\n".join(LOG))
