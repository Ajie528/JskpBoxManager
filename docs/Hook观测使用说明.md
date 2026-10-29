# Hook 观测使用说明（qb1）

用 Frida **只读**观测 qb1 里微信小游戏运行时（`WeChatAppEx`）的保活过程：
把 ilink 模块自己的**明文日志**实时截下来（磁盘上的 `ilink_*.xlog` 是加密的，读不了），
同时记下凭证文件的读写和对外连接。最重要的一条是 **AutoAuth（免扫自动授权）成功还是失败、服务端返回什么**。

- **只观测**：不改参数、不改包、不发请求。
- **只支持 qb1**，其它沙箱直接拒绝。
- 入口是主程序命令 `JskpBoxManager.exe hook qb1`，脚本在 `tools/lean-refresh/`。

---

## 1. 原理（为什么以前 hook 效果不好）

旧版做法是「等游戏窗出来再从主机 attach 游戏窗进程」，有四个问题：

| 旧做法 | 问题 |
|------|------|
| 游戏窗出来后才 attach | 授权在游戏窗出来前几秒就做完了，截不到 |
| attach 拥有游戏窗的进程 | 授权在另一个子进程 `ILinkServiceHost` 里做 |
| 从主机注入 | Sandboxie 拒绝主机往箱内进程加载 frida-agent |
| hook `XloggerAppender::Write` | 这个版本根本不走它，一行都截不到 |

新做法：

1. **观测程序跑在 qb1 箱内**：`Start.exe /box:qb1 /hide_window pythonw.exe hook_watch.py ...`，箱内注入不会被拒。
2. **先启观测、后启浏览器**：观测程序起来后先在一个空 python 子进程上注入一次「预热」（第一次注入要 0.6 秒以上），然后才启动 QQ 浏览器。
3. **微信主进程一出现就 attach 并开「子进程拦截」**：`ILinkServiceHost` 一出生就被暂停、挂好钩子再放行，所以授权请求一条都不会漏。
4. **按 RTTI 找日志函数**：`xlog_locate.py` 在 `ilink2.dll` 里按类名 `ilink::CustomAppender` 找虚表第 4 项（本机这版 RVA 是 `0x1254c0`），每行日志都会经过它。微信更新后自动重新定位，结果缓存在 `xlog_rva_cache.json`。

微信运行时的进程关系（都在 qb1 里）：

```text
QQBrowser.exe（主进程）
└─ QQBrowser.exe --type=dll-extension
   └─ WeChatAppEx.exe（主进程，没有 --type）        ← role=main，开子进程拦截
      ├─ WeChatAppEx --utility-sub-type=flue.mojom.ILinkServiceHost   ← role=ilink，做授权
      ├─ WeChatAppEx ... NetworkService              ← role=network
      └─ gpu / renderer 等                           ← 不挂
```

---

## 2. 环境准备

1. 能正常使用管家的同一套环境：Sandboxie-Plus、QQ 浏览器、qb1 沙箱、金库 `profiles\qb1`。
2. **Python 3**（官网安装版即可，`py -3` 能用；需要带 `pythonw.exe`）。
3. Python 包：

```powershell
py -3 -m pip install frida psutil pefile
py -3 -c "import frida, psutil, pefile; print(frida.__version__)"
```

`hook` 命令发现缺包会自动执行上面的 pip 安装。本机（AJIE）已装 frida 17.24.3。

4. **脚本目录**：`hook` 会从 exe 所在目录往上找 `tools\lean-refresh\hook_watch.py`（最多 8 层）。
   - 在仓库里构建运行：自动找到，不用管。
   - 在别的电脑（比如 R7000P）用发布包：把仓库的整个 `tools\lean-refresh` 文件夹复制到安装目录下，变成
     `<安装目录>\tools\lean-refresh\hook_watch.py`。
5. **数据目录**：要有含 `profiles\qb1` 的安装目录。exe 旁边没有时，会自动在上级目录里找最近用过的 `JskpBoxManager-*`；也可以用 `--appdir` 指定。

---

## 3. 用法

```text
JskpBoxManager.exe hook qb1 [--appdir 目录] [--mode Full] [--seconds 240] [--no-launch] [--no-stop]
```

| 参数 | 默认 | 说明 |
|------|------|------|
| `--appdir` | 自动 | 含 `profiles\qb1` 的程序目录 |
| `--mode` | `Full` | 启动方式：`Blank` / `NoUrl` / `RuntimeOnly` / `Full`（Full 就是正式保活的完整启动） |
| `--seconds` | `240` | 观测多少秒（30–7200） |
| `--no-launch` | 关 | 不重启 qb1，只挂到当前已经开着的 qb1 上（授权已经做完，看不到 AutoAuth，用来长时间盯掉线） |
| `--no-stop` | 关 | 结束后不停箱 |

### 3.1 看一次完整的免扫授权（最常用）

```powershell
cd E:\game_script\jskp-box-manager
dotnet build src\JskpBoxManager\JskpBoxManager.csproj -c Release
& "src\JskpBoxManager\bin\Release\net8.0-windows\win-x64\JskpBoxManager.exe" hook qb1 --seconds 60
```

它会依次：检查 Python 包 → 停 qb1 → 把金库凭证推到箱内、预热、清崩溃恢复页 → 箱内启动观测程序（失败会自动重试，最多 3 次）→ 按 `--mode` 启动浏览器 → 观测 → 停箱 → 打印授权结果。

> 会重启 qb1。正在挂机的话先停下来，或者用 `--no-launch`。

### 3.2 边玩边盯掉线

先正常打开 qb1 进游戏，然后：

```powershell
JskpBoxManager.exe hook qb1 --no-launch --no-stop --seconds 3600
```

这样不会重启 qb1，一小时内被踢下线、会话超时、要求重新扫码等都会记下来。

---

## 4. 输出在哪、怎么看

日志在数据目录的 `logs` 下（多次运行是**追加**的，每次以「开始观测 qb1」开头）：

| 文件 | 内容 |
|------|------|
| `logs\frida-ilink-qb1.txt` | 给人看的：ilink 明文日志 + `[文件]` + `[网络]` + `[attach]` |
| `logs\frida-ilink-qb1.jsonl` | 同样内容的 JSON 版，便于脚本分析 |
| `logs\qb1.log` | 管家日志，`hook` 开头的行是控制台摘要（关键行 + 授权结果） |

运行中箱内的原始文件是 `C:\Sandbox\Ajie\qb1\user\current\jskp-frida-qb1.jsonl/.txt/.err`，主机每 2 秒同步一次；观测程序起不来时看 `.err`。

### 4.1 控制台 / qb1.log 正常的样子

```text
python=C:\...\python.exe frida=17.24.3
[attach] pid=1601208 role=main 49ms
[attach] pid=1603724 role=network 70ms (出生即拦截)
[attach] pid=1600480 role=ilink 223ms (出生即拦截)
[凭证] tdi_account.txt 重写 valid=True key=f0d5f7b5b305faca
===== 授权结果 =====
成功 AutoAuthResponse error=0 ret=0 msg=
```

- `role=ilink ... (出生即拦截)`：授权进程是出生时就挂上的，后面的授权一定截得到。
- `[凭证] tdi_account.txt 重写 valid=True`：授权成功后运行时把新凭证写回了箱内。
- `成功 AutoAuthResponse error=0 ret=0`：免扫授权成功，这次保活有效。

### 4.2 txt 里一行 ilink 日志的格式

```text
10-29 11:23:28.087 I [ilink] ilink::main tdi_auth_manager.cpp:50 SendAutoAuthRequestAsync: --> ...
时间               级别 进程   模块标签     源文件:行号             内容
```

级别：`V/D` 调试，`I` 信息，`W` 警告，`E/F` 错误。按关键词搜：

| 关键词 | 意义 |
|------|------|
| `SendAutoAuthRequestAsync` / `cmdid:3198` / `ilinkapp_autoauth` | 发出免扫授权请求 |
| `TdiCheckCgiResponse: cgi = AutoAuthResponse` | 授权返回；看 `error =`、`ret =`、`error_msg =` |
| `ManualAuth` / `get_login_qrcode` / `require manual` | 免扫失败，要求扫码 |
| `SessionTimeout` / `session timeout` / `Logout` / `kick` | 会话过期、被登出、被踢 |
| `longcloud.weixin.com` / `shortcloud.weixin.com` | 长连接 / 短连接服务器 |
| `[文件] ... tdi_account.txt` / `psk.key` / `applet.db` / `mpkv.db` | 凭证和小程序数据的读写 |

### 4.3 一次成功授权的完整过程（实测）

1. ilink 读 `psk.key` 和 `tdi_account.txt`。
2. 建立到 `longcloud.weixin.com` 的 mmtls 长连接（实测 `36.155.189.92:8080`、`117.185.25.64:5000`）。
3. 发 `/ilink/ilinkapp/sys/ilinkapp_autoauth`（cmdid 3198），约 0.25 秒后收到返回。
4. `TdiCheckCgiResponse: cgi = AutoAuthResponse, error = 0, ... ret = 0, error_msg =`。
5. 重写 `tdi_account.txt`、netbridge ini、`Applet\<md5(uin)>\data\2\applet.db`、`WMPF\mpfastload\mpkv.db`。
6. 之后才是同步消息（`/ilink/base/ilinksyncmsg`，3288）、小游戏转发（`wxaruntime_transfer`，2881）等。

所以「免扫保活」本质就是：带着上次的凭证做一次 AutoAuth，服务端同意（ret=0）就发新凭证。服务端不同意时返回非 0 的 `ret` 和 `error_msg`，运行时就转去扫码。

---

## 5. 排障

| 现象 | 原因 / 处理 |
|------|------|
| `找不到 Python 3` | 装 Python 3，确认 `py -3` 能用 |
| `Python 包不可用` | 手动执行提示里的 pip 命令；公司网络可加 `-i https://pypi.tuna.tsinghua.edu.cn/simple` |
| 找不到 `hook_watch.py` | 把 `tools\lean-refresh` 复制到安装目录下（见 2.4） |
| `Start.exe 退出码 0x40010004`、观测程序没起来 | 刚停箱后第一次在箱内启动偶尔被杀，命令会自动重试；三次都失败就看打印出来的 `.err` 内容 |
| `[attach 失败]` | 看后面的错误文字；进程刚好退出时会这样，一般不影响授权那条 |
| `没有截到 AutoAuth/ManualAuth 的返回` | 用了 `--no-launch`（授权早做完了），或者运行时没起来（浏览器卡在扫码页 / 崩溃恢复页）。不加 `--no-launch` 再跑一次 |
| 授权结果是 `失败 ... ret=非0 msg=...` | 服务端拒了这份凭证：常见是同一个微信号在别的电脑/沙箱扫过码，旧凭证被顶掉。需要重新扫码 |
| 主机上的 PC 微信、QQ 浏览器会不会被挂上 | 不会。观测程序按 Sandboxie 的箱名过滤，只挂 qb1 里的进程 |

---

## 6. 和正式保活的关系

`hook` 只是观测工具，不改保活策略。正式换钥走 `refresh`（`RefreshSession`）；qb1 可在 `keepalive.json` 打开 `leanRefresh` 先试精简启动，失败回退 Full。

精简候选对照（不挂 Frida）：

```text
JskpBoxManager.exe lean qb1 --modes Blank,NoUrl,RuntimeOnly --seconds 180
```

**注意**：同一个微信号只能在一个地方保持免扫。两台电脑的 qb1 用同一个号时，后扫码的那台会把先前那台的凭证顶掉，先前那台的 AutoAuth 就会失败。
