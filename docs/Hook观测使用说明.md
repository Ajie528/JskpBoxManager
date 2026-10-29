# Hook 观测使用说明（qb1）

用 Frida **只读**观测微信运行时（`WeChatAppEx`）：枚举名称里带 ilink / mmtls / wmpf / wechat 的模块，并记录对 `tdi_account.txt`、`psk.key`、`ilink` 路径的 `CreateFileW` / `MoveFileExW`。同时用管家同一套窗口识别，记下「向僵尸开炮」游戏窗。

- **只观测，不改参数、不注入自定义网络包。**
- **硬锁沙箱 `qb1`**，其它沙箱会直接拒绝。
- 入口是 C# 命令 `JskpBoxManager.exe hook`，不再使用 `tools/lean-refresh/*.ps1`。
- 进程和游戏窗用 `BoxView`（Sandboxie 箱内 PID + 窗口标题），避免以前 PowerShell 用 CIM 过滤进程名时，窗口已经在却报「没有 WeChatAppEx」。

正式保活仍以官方运行时 + 金库为准。本工具只做研究与排障。

---

## 1. 能做什么 / 不能做什么

| 能做 | 不能做 |
|------|--------|
| 冷启动 qb1（Blank / NoUrl / RuntimeOnly / Full） | 替你完成免扫保活或绕过扫码 |
| 等到「向僵尸开炮」窗口后，把 `hook_ilink.js` attach 到该进程 | 修改 AutoAuth 请求/响应 |
| 枚举名称含 ilink / mmtls / wmpf / wechat 的模块 | 保证一定 hook 到业务符号（取决于二进制） |
| 监视打开/移动 `tdi_account.txt`、`psk.key`、`ilink` 路径 | 在 Sandboxie 隔离导致 attach 失败时强行注入 |
| attach 失败时仍用文件监视记写入时间线 | 自动把结论写进正式 `refresh` 逻辑 |

---

## 2. 相关文件

脚本仍在 `tools/lean-refresh/`（只有 Frida 脚本，没有 ps1）：

| 文件 | 作用 |
|------|------|
| `hook_ilink.js` | 模块列表 + `CreateFileW` / `MoveFileExW` 路径过滤 |
| `hook_attach.py` | 用 Python Frida API attach（不依赖 `frida.exe`） |

C# 入口在主程序：

| 命令 | 作用 |
|------|------|
| `JskpBoxManager.exe hook qb1` | 冷启动、等游戏窗、Frida attach、文件监视 |
| `JskpBoxManager.exe lean qb1` | 精简启动候选，看密钥是否换新（不挂 Frida） |

日志写到**数据目录**（含 `profiles\qb1` 的安装目录，可用 `--appdir` 指定）：

```text
<AppDir>\logs\frida-ilink-qb1.jsonl
<AppDir>\logs\lean-refresh-qb1.jsonl
```

例如：

```text
D:\a_game_scrpit\JskpBoxManager-1.1.5\logs\frida-ilink-qb1.jsonl
```

若 exe 在仓库的 `bin\Release` 下、旁边没有金库，`hook` / `lean` 会自动改用已存在的 `JskpBoxManager-1.1.x\profiles\qb1`。

---

## 3. 环境要求

1. Windows + 已能正常使用「向僵多开管家」的同一套环境  
   Sandboxie-Plus、QQ 浏览器、qb1 沙箱与金库（`profiles\qb1`）。
2. Python 3（`py -3` 可用）。
3. Frida Python 包。没有时 `hook` 会尝试 `py -3 -m pip install frida`。

```powershell
py -3 -m pip install frida
py -3 -c "import frida; print(frida.__version__)"
```

---

## 4. 参数

```text
JskpBoxManager.exe hook qb1 [--appdir 目录] [--mode Full] [--seconds 180] [--pid N] [--no-launch] [--no-stop]
```

| 参数 | 默认 | 说明 |
|------|------|------|
| `--appdir` | 自动 | 含 `profiles\qb1` 的程序目录 |
| `--mode` | `Full` | `Blank` / `NoUrl` / `RuntimeOnly` / `Full` |
| `--seconds` | `180` | attach 之后继续监视的秒数 |
| `--pid` | `0` | 已指定则跳过「等窗口」 |
| `--no-launch` | 关 | 不冷启动，只观测当前已开的 qb1 |
| `--no-stop` | 关 | 结束后不停箱 |

### `--mode`

| Mode | 行为 | 适用 |
|------|------|------|
| `Blank` | QQBrowser + `about:blank` | 看不进游戏中心会不会起微信 |
| `NoUrl` | QQBrowser，无 URL | 同上 |
| `RuntimeOnly` | 沙箱内直接启 `WeChatAppEx.exe` | 看只拉运行时能否写凭证 |
| `Full` | QQBrowser + 游戏中心 | 完整路径，最容易看到游戏窗和换钥 |

need-scan 未清时，Full 可能进扫码页；命令会警告，仍可观测拒钥 / 清空。

等窗口的规则：最多约 90 秒。优先 attach **拥有「向僵尸开炮」窗口的 PID**；超时仍无游戏窗才退回微信主进程；都没有则只做文件监视。

---

## 5. 推荐操作

在仓库构建后执行（数据目录自动落到已安装的 1.1.x，也可写死 `--appdir`）：

```powershell
cd D:\a_game_scrpit\JskpBoxManager
dotnet build src\JskpBoxManager\JskpBoxManager.csproj -c Release

& "src\JskpBoxManager\bin\Release\net8.0-windows\win-x64\JskpBoxManager.exe" hook qb1 `
  --appdir D:\a_game_scrpit\JskpBoxManager-1.1.5 `
  --mode Full `
  --seconds 180
```

步骤：

1. 检查 Frida Python 包  
2. 终止 qb1  
3. 把金库 ilink 推到 live，warmup，清浏览器崩溃恢复页  
4. 按 `--mode` 启动  
5. 用 `BoxView` 等「向僵尸开炮」（最多约 90 秒）  
6. `hook_attach.py` 加载 `hook_ilink.js`  
7. 每 2 秒看一次 `tdi_account.txt` / `psk.key`  
8. 到点后结束 Frida，默认停箱  

控制台类似：

```text
frida python 17.x.x
launched mode=Full; waiting 向僵尸开炮 / WeChatAppEx...
game-window pid=12345 title=向僵尸开炮
attach pid=12345 via game-window
file-watch acct valid=True key=...
done; log=...\logs\frida-ilink-qb1.jsonl
```

游戏已经开着、只想补记窗口并 attach：

```text
JskpBoxManager.exe hook qb1 --no-launch --no-stop --seconds 120
```

精简候选对照（不挂 Frida）：

```text
JskpBoxManager.exe lean qb1 --modes Blank,NoUrl,RuntimeOnly --seconds 180
JskpBoxManager.exe lean qb1 --modes Full --seconds 180
```

---

## 6. 日志字段

`frida-ilink-qb1.jsonl` 每行一个 JSON：

| ev | 含义 |
|----|------|
| `start` / `launched` | 开始、已发启动 |
| `game-window` | 识别到游戏窗（含 title、pid、hwnd） |
| `attach` | 即将 attach 的 pid 与原因（`game-window` / `main-no-game-window` / `given`） |
| `frida` | `hook_attach.py` 收到的脚本消息（CreateFileW、模块列表等） |
| `frida-out` / `frida-err` | Python 标准输出 / 错误 |
| `file-watch` | 凭证或 psk 文件写入 |
| `no-wechat-process` | 90 秒内没有微信进程 |

---

## 7. 排障

| 现象 | 处理 |
|------|------|
| 以前 ps1 报「没有 WeChatAppEx」但窗口在 | 已改为 C# `BoxView`。用 `hook qb1 --no-launch` 对当前窗口再记一次 |
| `frida!` 里 attach 失败 | 主机注入常被 Sandboxie 拒绝。命令会改在**沙箱内**再 attach 一次，成功时日志里有 `frida-attached` |
| 只有文件监视、没有 `game-window` | 启动模式可能没进游戏（Blank 常见）。改 `--mode Full` 或加长等待 |
| 金库被拒、live 变 invalid | Full 对照可能触发服务端拒钥。先看 `file-watch` 的 `valid` |

---

## 8. 和正式保活的关系

qb1 可在 `keepalive.json` 打开 `leanRefresh`。正式换钥走 `RefreshSession`，不是本观测命令。`hook` 默认不改保活策略。
