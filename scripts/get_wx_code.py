#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从本机「向僵多开管家」协议服务取「向僵尸开炮」的 wx.login code。

环境变量（不要把 IP/令牌写死进脚本）：
  JSKP_SERVER            例如 http://127.0.0.1:18000
  或 YYB_SERVER          兼容参考仓库格式：http://127.0.0.1:18000@qb1
  JSKP_PROTOCOL_TOKEN    协议令牌（界面「复制令牌」）；也可写在 YYB_PROTOCOL_TOKEN
  JSKP_REF / 参数        沙箱 qb1 / 1 / uin

用法：
  set JSKP_SERVER=http://127.0.0.1:18000
  set JSKP_PROTOCOL_TOKEN=你的令牌
  python get_wx_code.py qb1              # 取 code 并换业务 Token，stdout 输出一行 JSON
  python get_wx_code.py qb1 --code-only  # 只输出 code

游戏登录接口（解包所得，可用环境变量覆盖）：
  JSKP_GAME_BASE            默认 https://h5api.scgame.com.cn
  JSKP_GAME_APPID           默认 1048（游戏内部 appid，不是 wx appid）
  JSKP_GAME_CLIENT_VERSION  默认空
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

GAME_APPID = "wx31a9c726536cdacc"

# 第 5 步：拿 code 换「向僵尸开炮」业务 Token。
# 以下默认值来自解包 game.js（JskpBoxManager.exe unpack qb1）：
#   wx.login -> GET {BASE}/login/login_wxmg.php?appid=1048&js_code=<code>&uuid=&game_client_version=
#   返回 JSON：ret==0 成功，含 open_id / uin / wx_appid / token
# 可用环境变量覆盖，避免写死。
GAME_LOGIN_BASE = os.environ.get("JSKP_GAME_BASE", "https://h5api.scgame.com.cn").rstrip("/")
GAME_LOGIN_APPID = os.environ.get("JSKP_GAME_APPID", "1048")
GAME_CLIENT_VERSION = os.environ.get("JSKP_GAME_CLIENT_VERSION", "")


def parse_server_env() -> tuple[str, str]:
    """返回 (base_url, default_ref)。"""
    yyb = (os.environ.get("YYB_SERVER") or "").strip()
    if yyb:
        # 多行时取第一行；http://host:port@qb1
        line = next((ln.strip() for ln in yyb.splitlines() if ln.strip()), "")
        if "@" in line:
            base, ref = line.rsplit("@", 1)
            return base.rstrip("/"), ref.strip()
        return line.rstrip("/"), ""
    base = (os.environ.get("JSKP_SERVER") or "http://127.0.0.1:18000").strip().rstrip("/")
    return base, (os.environ.get("JSKP_REF") or "").strip()


def token() -> str:
    return (os.environ.get("JSKP_PROTOCOL_TOKEN") or os.environ.get("YYB_PROTOCOL_TOKEN") or "").strip()


def get_code(base: str, ref: str, ensure_running: bool = True) -> dict:
    url = f"{base}/wxapp/getCode"
    body = json.dumps(
        {"ref": ref, "app_id": GAME_APPID, "ensure_running": ensure_running},
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    tok = token()
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def exchange_game_token(code: str, uuid: str = "") -> dict:
    """用 wx.login code 调游戏登录接口，换业务 Token。code 一次性，拿到立刻用。"""
    params = urllib.parse.urlencode(
        {
            "appid": GAME_LOGIN_APPID,
            "js_code": code,
            "uuid": uuid,
            "game_client_version": GAME_CLIENT_VERSION,
        }
    )
    url = f"{GAME_LOGIN_BASE}/login/login_wxmg.php?{params}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "Mozilla/5.0 MicroMessenger")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    base, env_ref = parse_server_env()
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    code_only = "--code-only" in sys.argv
    ref = (args[0] if args else env_ref).strip()
    if not ref:
        print("用法：python get_wx_code.py qb1 [--code-only]", file=sys.stderr)
        print("并设置 JSKP_SERVER / JSKP_PROTOCOL_TOKEN", file=sys.stderr)
        return 2
    try:
        data = get_code(base, ref)
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"HTTP {e.code}: {err_body}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"请求失败：{e}", file=sys.stderr)
        return 1

    if not data.get("ok"):
        print("取码失败：" + str(data.get("error") or data), file=sys.stderr)
        return 1

    code = data.get("code") or ""
    print(
        f"# box={data.get('box')} uin={data.get('uin')} via={data.get('via')}",
        file=sys.stderr,
    )
    if code_only:
        print(code)
        return 0

    try:
        login = exchange_game_token(code)
    except urllib.error.HTTPError as e:
        print(f"游戏登录 HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"游戏登录请求失败：{e}", file=sys.stderr)
        return 1

    if str(login.get("ret")) != "0":
        print(f"游戏登录失败：ret={login.get('ret')} info={login.get('info')}", file=sys.stderr)
        return 1

    # stdout 只输出一行 JSON，方便其它脚本解析
    print(
        json.dumps(
            {
                "token": login.get("token", ""),
                "uin": login.get("uin", ""),
                "open_id": login.get("open_id", ""),
                "wx_appid": login.get("wx_appid", ""),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
