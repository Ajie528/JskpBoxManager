"""Watch one Sandboxie box and attach hook_ilink.js to its WeChat runtime as early as possible (observe only).

Must run INSIDE the box (Sandboxie refuses frida-agent injection from the host):
    Start.exe /box:qb1 /hide_window python.exe hook_watch.py --box qb1 --out C:\\Users\\me\\jskp-frida-qb1.jsonl

- Box membership is checked with SbieApi_QueryProcess, so host QQBrowser / PC WeChat are never touched.
- ILinkServiceHost sends ilinkapp_autoauth within milliseconds of starting, so polling for it is a race.
  Instead the WeChatAppEx main process is attached as soon as the 100 ms poll sees it, with child gating, and
  ILinkServiceHost is hooked at birth. The first injection in a session costs 0.6 s or more, so it is paid up
  front on a throwaway python child before the browser starts (gating at the QQBrowser level is avoided: a
  failed attach there leaves the suspended child broken and the runtime never starts).
- Already-running processes (--no-launch case) are attached directly.
- Output: --out (JSON lines, everything) and the same name with .txt (readable ilink log + file/net events).
"""
from __future__ import annotations

import sys
from pathlib import Path

# 在箱内被隐藏窗口启动时看不到报错：先把 stderr 接到 --out 旁边的 .err 文件，再导入第三方包
if "--out" in sys.argv:
    try:
        _err = Path(sys.argv[sys.argv.index("--out") + 1]).with_suffix(".err")
        _err.parent.mkdir(parents=True, exist_ok=True)
        sys.stderr = open(_err, "w", encoding="utf-8", buffering=1)
    except Exception:
        pass

import argparse  # noqa: E402
import ctypes  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

import frida  # noqa: E402
import psutil  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from xlog_locate import locate_cached  # noqa: E402

HOOK_ROLES = {"main", "ilink", "network"}


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def role_of(name: str, cmd: str) -> str:
    name = name.lower()
    if name != "wechatappex.exe":
        return ""
    if "--type=" not in cmd:
        return "main"
    if "ILinkServiceHost" in cmd:
        return "ilink"
    if "NetworkService" in cmd:
        return "network"
    return ""


class Sbie:
    def __init__(self, dll_dir: str):
        try:
            self.dll = ctypes.WinDLL("SbieDll.dll")
        except OSError:
            self.dll = ctypes.WinDLL(str(Path(dll_dir) / "SbieDll.dll"))
        self.fn = self.dll.SbieApi_QueryProcess
        self.fn.restype = ctypes.c_long

    def box_of(self, pid: int) -> str:
        box = ctypes.create_unicode_buffer(64)
        img = ctypes.create_unicode_buffer(128)
        if self.fn(ctypes.c_void_p(pid), box, img, None, None) != 0:
            return ""
        return box.value


class Watcher:
    def __init__(self, a):
        self.box = a.box
        self.out = Path(a.out)
        self.txt = self.out.with_suffix(".txt")
        self.seconds = a.seconds
        self.source = Path(a.script).read_text(encoding="utf-8")
        self.sbie = Sbie(a.sbie_dir)
        self.device = frida.get_local_device()
        self.done: set[int] = set()
        self.roles: dict[int, tuple[str, str]] = {}
        self.unknown: dict[int, float] = {}
        self.sessions = {}
        self.rva_cache: dict[str, int | None] = {}
        self.lock = threading.Lock()
        self.counts = {"xlog": 0, "file": 0, "net": 0}
        self.device.on("child-added", self.on_child)

    # ---------- output ----------

    def write(self, rec: dict, text: str | None = None):
        rec.setdefault("at", now())
        rec.setdefault("box", self.box)
        with self.lock:
            with self.out.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            if text:
                with self.txt.open("a", encoding="utf-8") as f:
                    f.write(text + "\n")

    def on_message(self, pid: int, role: str, message, data):
        if message.get("type") == "error":
            self.write({"ev": "script-error", "pid": pid, "role": role, "desc": message.get("description"),
                        "stack": message.get("stack")}, f"{now()} [脚本错误] pid={pid} {message.get('description')}")
            return
        p = message.get("payload") or {}
        p.setdefault("pid", pid)
        p.setdefault("role", role)
        ev = p.get("ev")
        if ev in self.counts:
            self.counts[ev] += 1
        text = None
        if ev == "xlog":
            if "lvl" in p:
                text = f"{p['t']} {p['lvl']} [{role}] {p['tag']} {p['file']}:{p['line']} {p['msg']}"
            else:
                text = f"{now()} ? [{role}] {p.get('msg', '')}"
        elif ev == "file":
            text = f"{now()} [文件] [{role}] {p.get('op')} ok={p.get('ok')} {p.get('path')}"
        elif ev == "net":
            text = f"{now()} [网络] [{role}] {p.get('op')} {p.get('to') or p.get('host')} ({p.get('from')})"
        elif ev == "xlog-hooked":
            text = f"{now()} [已挂上 ilink 日志] pid={pid} role={role} {p.get('rva')}"
        self.write({"ev": "frida", **p}, text)

    # ---------- attach ----------

    def rva_for(self, exe: str) -> int | None:
        rt = Path(exe).parent
        key = str(rt).lower()
        if key not in self.rva_cache:
            dll = rt / "ilink2.dll"
            rva = None
            try:
                if dll.exists():
                    rva = locate_cached(dll)
            except Exception as exc:
                self.write({"ev": "xlog-locate-error", "dll": str(dll), "err": str(exc)})
            self.rva_cache[key] = rva
            self.write({"ev": "xlog-locate", "dll": str(dll), "rva": rva},
                       None if rva is not None else f"{now()} [警告] {dll} 里没找到 ilink 日志函数，只记文件/网络")
        return self.rva_cache[key]

    def attach(self, pid: int, role: str, exe: str, resume: bool = False):
        t0 = time.time()
        try:
            s = self.device.attach(pid)
            if role == "main":
                s.enable_child_gating()
            sc = s.create_script(self.source)
            sc.on("message", lambda m, d, pid=pid, role=role: self.on_message(pid, role, m, d))
            sc.load()
            rva = self.rva_for(exe) if role in HOOK_ROLES else None
            sc.exports_sync.init({"xlogRva": rva, "role": role})
            self.sessions[pid] = (s, sc)
            ms = int((time.time() - t0) * 1000)
            self.write({"ev": "frida-attached", "pid": pid, "role": role, "ms": ms, "resumed": resume},
                       f"{now()} [attach] pid={pid} role={role} {ms}ms" + (" (出生即拦截)" if resume else ""))
        except Exception as exc:
            self.write({"ev": "frida-err", "pid": pid, "role": role, "line": str(exc)},
                       f"{now()} [attach 失败] pid={pid} role={role}: {exc}")
        finally:
            if resume:
                try:
                    self.device.resume(pid)
                except Exception:
                    pass

    def claim(self, pid: int) -> bool:
        with self.lock:
            if pid in self.done:
                return False
            self.done.add(pid)
            return True

    def on_child(self, child):
        # 回调跑在 frida 的事件线程上，在这里同步调用 resume/attach 会卡死，被拦下的子进程就永远不恢复
        threading.Thread(target=self.handle_child, args=(child,), daemon=True).start()

    def handle_child(self, child):
        path = child.path or ""
        role = role_of(Path(path).name, " ".join(child.argv or []))
        self.write({"ev": "child", "pid": child.pid, "parent": child.parent_pid, "role": role or "-", "path": path})
        if role and self.claim(child.pid):
            self.attach(child.pid, role, path, True)
            return
        try:
            self.device.resume(child.pid)
        except Exception as exc:
            self.write({"ev": "resume-err", "pid": child.pid, "err": str(exc)})

    def scan(self):
        found = []
        for p in psutil.process_iter(["pid", "name"]):
            name = p.info["name"] or ""
            if name.lower() != "wechatappex.exe":
                continue
            pid = p.info["pid"]
            if pid in self.done:
                continue
            if pid not in self.roles:
                box = self.sbie.box_of(pid).lower()
                if box != self.box.lower():
                    # 刚创建的进程 SbieApi 可能还查不到所属沙箱（返回空）；主机上的进程也返回空。
                    # 空的先多查几秒再放弃，否则沙箱里刚起来的微信主进程会被永久跳过
                    first = self.unknown.setdefault(pid, time.time())
                    if box or time.time() - first > 5:
                        with self.lock:
                            self.done.add(pid)
                        self.write({"ev": "skip-other-box", "pid": pid, "sbieBox": box})
                    continue
                try:
                    cmd = " ".join(p.cmdline())
                    exe = p.exe()
                except Exception:
                    continue
                self.roles[pid] = (role_of(name, cmd), exe)
            role, exe = self.roles[pid]
            if not role:
                with self.lock:
                    self.done.add(pid)
                continue
            found.append((0 if role == "main" else 1 if role == "ilink" else 2, pid, role, exe))
        for _, pid, role, exe in sorted(found):
            if self.claim(pid):
                self.attach(pid, role, exe)

    def prewarm(self):
        # 第一次注入要 0.6 秒以上，先在箱内一个空闲的 python 子进程上付掉，免得付在微信主进程上
        t0 = time.time()
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            time.sleep(0.3)
            s = self.device.attach(p.pid)
            s.create_script("1;").load()
            s.detach()
            self.write({"ev": "prewarm", "ms": int((time.time() - t0) * 1000)})
        except Exception as exc:
            self.write({"ev": "prewarm-err", "err": str(exc)}, f"{now()} [警告] 预热注入失败: {exc}")
        finally:
            p.kill()

    def run(self) -> int:
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.prewarm()
        self.write({"ev": "watch-start", "frida": frida.__version__, "seconds": self.seconds},
                   f"{now()} 开始观测 {self.box}，{self.seconds} 秒，frida {frida.__version__}")
        deadline = time.time() + self.seconds
        try:
            while time.time() < deadline:
                self.scan()
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        for pid, (s, sc) in list(self.sessions.items()):
            for fn in (sc.unload, s.detach):
                try:
                    fn()
                except Exception:
                    pass
        self.write({"ev": "watch-end", **self.counts, "attached": len(self.sessions)},
                   f"{now()} 结束：attach {len(self.sessions)} 个进程；ilink 日志 {self.counts['xlog']} 行，"
                   f"文件 {self.counts['file']}，网络 {self.counts['net']}")
        return 0 if self.sessions else 1


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--box", default="qb1")
    ap.add_argument("--out", required=True)
    ap.add_argument("--seconds", type=int, default=240)
    ap.add_argument("--sbie-dir", default=r"C:\Program Files\Sandboxie-Plus")
    ap.add_argument("--script", default=str(Path(__file__).with_name("hook_ilink.js")))
    return Watcher(ap.parse_args()).run()


if __name__ == "__main__":
    raise SystemExit(main())
