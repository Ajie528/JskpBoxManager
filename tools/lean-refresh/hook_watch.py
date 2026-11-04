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
        # 长连接观测脚本（可选）：独立注入 ilink 角色，hook 心跳 / 会话超时
        self.longlink_path = Path(a.longlink_script) if a.longlink_script else None
        self.block_timeout = bool(a.block_timeout)
        self.longlink_source = None
        if self.longlink_path and self.longlink_path.exists():
            self.longlink_source = self.longlink_path.read_text(encoding="utf-8")
        self.longlink_at = {}
        self.sbie = Sbie(a.sbie_dir)
        self.device = frida.get_local_device()
        self.done: set[int] = set()
        self.roles: dict[int, tuple[str, str]] = {}
        self.sessions = {}
        self.rva_cache: dict[str, int | None] = {}
        self.longlink_cache: dict[str, dict] = {}
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

    def write_text_only(self, text: str):
        """只写可读 txt（用于高频事件，如 noop 心跳）。"""
        with self.lock:
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
        elif ev == "noop":
            if p.get("kind") == "enter":
                text = f"{now()} [心跳] noop 发送 #{p.get('total')} 间隔={p.get('gapSec')}s"
            else:
                text = f"{now()} [心跳] noop 完成 #{p.get('total')} 耗时={p.get('tookMs')}ms"
            # 心跳每 3 分钟一次、一天近 500 次，只写 txt 不写 jsonl，避免把 jsonl 撑大
            self.write_text_only(text)
            return
        elif ev == "session-timeout":
            text = f"{now()} [会话超时] {p.get('action')} #{p.get('total')} 调用栈={p.get('stack')}"
        elif ev == "longlink-hooked":
            text = f"{now()} [长连接观测已装] rva={p.get('rva')} 拦截={p.get('blockSessionTimeout')}"
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
            # ilink 角色额外挂长连接观测脚本（心跳 / 会话超时）
            if role == "ilink" and self.longlink_source:
                self.attach_longlink(pid, exe, s)
        except Exception as exc:
            self.write({"ev": "frida-err", "pid": pid, "role": role, "line": str(exc)},
                       f"{now()} [attach 失败] pid={pid} role={role}: {exc}")
        finally:
            if resume:
                try:
                    self.device.resume(pid)
                except Exception:
                    pass

    def attach_longlink(self, pid: int, exe: str, session):
        try:
            lrv = self.longlink_rva(exe)
            sc = session.create_script(self.longlink_source)
            sc.on("message", lambda m, d, pid=pid: self.on_message(pid, "ilink", m, d))
            sc.load()
            sc.exports_sync.init({"rva": lrv, "role": "ilink", "blockSessionTimeout": self.block_timeout})
            self.longlink_at[pid] = sc
            self.write({"ev": "longlink-attached", "pid": pid, "rva": lrv, "block": self.block_timeout},
                       f"{now()} [长连接观测] pid={pid} {'(已拦截会话超时)' if self.block_timeout else '(只观测)'}")
        except Exception as exc:
            self.write({"ev": "longlink-err", "pid": pid, "err": str(exc)},
                       f"{now()} [长连接观测失败] pid={pid}: {exc}")

    def longlink_rva(self, exe: str):
        rt = Path(exe).parent
        key = str(rt).lower()
        if key in self.longlink_cache:
            return self.longlink_cache[key]
        res = {}
        try:
            from longlink_locate import locate_all
            res = locate_all(rt / "ilink2.dll")
        except Exception as exc:
            self.write({"ev": "longlink-locate-error", "err": str(exc)})
        self.longlink_cache[key] = res
        self.write({"ev": "longlink-locate", "rva": res})
        return res

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
            # 归属检查必须每轮都做，不能只做一次就缓存进 roles：
            # 箱内能看到所有沙箱的 WeChatAppEx（Windows 进程表全局可见），
            # 一旦把别箱的 pid 记进 roles 就再也不会校验，之后可能跨箱 attach 被拒。
            try:
                owner = self.sbie.box_of(pid).lower()
            except Exception:
                continue
            if owner != self.box.lower():
                with self.lock:
                    self.done.add(pid)
                continue
            if pid not in self.roles:
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
    ap.add_argument("--longlink-script", default=str(Path(__file__).with_name("hook_longlink.js")),
                    help="长连接观测脚本；传空字符串可关闭")
    ap.add_argument("--block-timeout", action="store_true",
                    help="拦截 ilink 的会话超时回调（实验用；默认只观测，进程仍会被运行时收掉）")
    a = ap.parse_args()

    # 同一个沙箱只允许一个观测器：两个同时跑会各自 attach、日志每行写两遍，
    # 而且后启动的会把前一个的输出文件删掉（实测踩过）。
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    ERR_ALREADY_EXISTS = 183
    name = "Local\\JskpFridaWatch_" + a.box
    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(None, True, name)
    err = ctypes.get_last_error()
    if not handle:
        print(f"创建互斥量失败 (err={err})，继续运行")
    elif err == ERR_ALREADY_EXISTS:
        print(f"{a.box} 已经有一个观测器在运行，本进程退出")
        return 0

    return Watcher(a).run()


if __name__ == "__main__":
    raise SystemExit(main())
