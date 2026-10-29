"""Attach hook_ilink.js to a PID using Frida Python API (no frida.exe required)."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import frida


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: hook_attach.py <pid> <hook.js> <out.jsonl> [seconds]", file=sys.stderr)
        return 2
    pid = int(sys.argv[1])
    script_path = Path(sys.argv[2])
    out_path = Path(sys.argv[3])
    seconds = int(sys.argv[4]) if len(sys.argv) > 4 else 120
    source = script_path.read_text(encoding="utf-8")

    def on_message(message, data):
        rec = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "ev": "frida", "message": message}
        if data is not None:
            rec["data_len"] = len(data)
        with out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        payload = message.get("payload") if isinstance(message, dict) else None
        print(payload if payload is not None else message, flush=True)

    print(f"attach pid={pid} frida={frida.__version__}", flush=True)
    try:
        session = frida.attach(pid)
    except Exception as exc:
        rec = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "ev": "frida-err", "line": str(exc), "pid": pid}
        with out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(exc, file=sys.stderr, flush=True)
        return 1
    with out_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ev": "frida-attached",
            "pid": pid,
            "frida": frida.__version__,
        }, ensure_ascii=False) + "\n")
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            time.sleep(1)
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
    print("detach", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
