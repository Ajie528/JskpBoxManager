# 向僵多开管家（JskpBoxManager）

在一台电脑上用 Sandboxie-Plus + QQ 浏览器同时开多个微信小游戏「向僵尸开炮」，每个沙箱一个微信号；
登录一次后自动免扫码，并且可以定时在后台「保活」，让登录长期有效。

更新内容见 [CHANGELOG.md](CHANGELOG.md)。程序里点右上角「版本与更新记录」可以看到当前版本。

## 需要先装的软件

**日常使用（启动游戏、保活、扫码）只需要前两个**，其余只在用高级工具时才需要。

| 软件 | 必需? | 说明 |
| --- | --- | --- |
| Sandboxie-Plus | **必需** | 装在哪个盘都行，程序会自动找 |
| QQ 浏览器 | **必需** | 正常安装即可；第一次在沙箱里打开小游戏时会自动装好微信小程序运行环境 |

本程序自带 .NET 运行时，不需要另外安装。

### 可选：用高级工具时才需要

| 软件 | 用到的功能 | 安装方式 |
| --- | --- | --- |
| **Python 3** | `hook`（Frida 观测）、`observe` | `winget install Python.Python.3.13`，或从 [python.org](https://www.python.org/downloads/windows/) 装（勾选 Add to PATH） |
| **frida / psutil / pefile** | 同上（Python 包） | 程序检测到缺失会自动 `pip install`；也可手动：`py -3 -m pip install frida psutil pefile` |
| **Wireshark**（含 tshark） | `token`（抓业务 Token）、`keylog` 配合解密 | `winget install WiresharkFoundation.Wireshark`，安装时勾选 TShark |

几点说明：

- **Python 装不了会自动装。** 程序只能检测 Python；没装 Python 时 `hook` 会提示
  「找不到 Python 3」并给出安装命令，**不会自己装 Python**。三个 Python 包则是程序自动装的。
- **`hook` 只允许 `qb1`。** 它会在沙箱内启动 Frida 只读观测脚本，截获 ilink 的明文授权返回；
  为了不影响正在用的号，限定在 qb1 上做实验。
- **`hook` 需要沙箱里的 Python 能被执行。** Sandboxie 默认允许执行主机程序，一般无需额外配置。
  如果你的策略禁了 python.exe，需要在对应沙箱的配置里放行。
- **Wireshark 必须带 TShark**（命令行版 tshark.exe），只有图形界面不够。
  `token` 命令会自己找 `C:\Program Files\Wireshark\tshark.exe`。

### 可选：开发/发版才需要

| 软件 | 用途 |
| --- | --- |
| .NET 8 SDK | 编译源码：`winget install Microsoft.DotNet.SDK.8` |
| GitHub CLI | 手动发版 / 看 CI：`winget install GitHub.cli`，然后 `gh auth login` |

## 安装 / 拷到别的电脑

1. 把 `JskpBoxManager-版本号.zip` 解压到一个**固定的目录**，比如 `C:\application\jskp-box-manager`。
   以后不要随意挪动这个目录（挪了也行，打开一次管理界面按提示「修复计划任务」即可）。
2. 双击 `JskpBoxManager.exe` 打开管理界面。
3. 顶部显示 `Sandboxie x.x · QQ浏览器 x.x` 表示识别成功；识别失败会出现黄色提示条，按提示选择对应程序即可，或点「路径设置」。

程序目录里会生成这些数据（都在 exe 旁边）：

| 位置 | 内容 |
| --- | --- |
| `profiles\qbN\` | 每个沙箱的登录金库（**含微信登录凭证，不要发给别人**） |
| `logs\` | 运行日志、凭证事件 `ilink-events.jsonl` |
| `box-notes.json` | 账号备注 |
| `keepalive.json` | 保活设置 |
| `protocol.json` | 协议服务端口和令牌（**令牌等同登录权，不要外发**） |
| `paths.json` | 手动指定的软件路径（没手动指定就没有） |
| `logs\sslkeys-qbN.log` | 取 Token 时导出的 TLS 密钥（**能解密你的加密流量，不要外发**） |

完整的目录清单见下面「程序目录结构」一节。

## 程序目录结构

安装目录里**程序和运行数据是混在一起的**（这样整个目录拷到别的电脑就能用）。
升级时请只替换 `JskpBoxManager.exe`，或者用仓库里的 `deploy.ps1`，**不要整目录覆盖**，否则会删掉登录凭证。

### 程序文件（可以放心替换 / 重装）

| 名称 | 说明 |
| --- | --- |
| `JskpBoxManager.exe` | 主程序，单文件自带运行时 |
| `CHANGELOG.md` / `README.md` | 更新记录和本说明 |
| `tools\lean-refresh\` | Frida 观测脚本，`hook` 命令用 |

### 配置（程序会读，可以手动改；删了会回到默认值）

| 名称 | 说明 |
| --- | --- |
| `keepalive.json` | 静默保活：开关、计划时刻、协议续期、轮换额度 |
| `notify.json` | 过期提醒：推送通道、预警阈值、主动探测间隔 |
| `box-notes.json` | 每个沙箱的账号备注（桌面快捷方式的名字取自这里） |
| `protocol.json` | 协议服务的端口和令牌（**令牌等同登录权，不要外发**） |
| `paths.json` | 手动指定的 Sandboxie / QQ 浏览器路径（没手动指定就没有这个文件） |
| `update.json` | 自动更新的检查时间和「跳过此版本」 |
| `migrated.json` | 已从旧版导入过的标记（删了下次启动会重新提示导入） |

### 运行数据（**不要删，删了就丢登录**）

| 名称 | 说明 |
| --- | --- |
| `profiles\qbN\wmpf\` | 登录金库 + 游戏包缓存。`wmpf\ilink\` 里是微信免扫凭证，`wmpf\Applet\` 里是游戏包（每号约 6～7 GB，删了下次要重新下载） |
| `profiles\qbN\credential\` | 历史凭证快照（最多 30 份）、作废登记、冷却名单。**免扫失效时靠它逐个试回来** |
| `profiles\qbN\credential\pending-rotated.json` | **换到新 key 但还没写进 live/金库的临时落点**。正常情况下一瞬间就消失；如果一直在，说明上次换钥后进程被杀，下次启动会自动补写（见下方「换 key 必须立刻落盘」） |
| `profiles\qbN\browser\` | QQ 浏览器的登录态（cookie 等） |
| `profiles\qbN\refresh-need-scan.txt` | 待扫码标记；存在时启动会直接摆二维码 |
| `logs\ilink-events.jsonl` | 凭证事件（换 key / 被作废 / 扫码 / 保活结果），排查免扫问题的核心依据 |
| `logs\qbN.log` | 每个沙箱的详细运行日志 |
| `logs\qbN.rotate-log` | 每次换 key 的记账，用于「每天最多换 N 次」的风控额度 |
| `logs\qbN.renew-attempt` | 续期「结果未知」标记；正常情况会自动清掉 |
| `logs\sslkeys-qbN.log` | 取 Token 时导出的 TLS 密钥（**能解密你的加密流量，不要外发**） |

### 可以随时删除（都会自动重建或重新生成）

| 名称 | 说明 |
| --- | --- |
| `logs\` 里的旧日志 | 排查完就能删；程序按需新建 |
| `logs\frida-ilink-*.jsonl/.txt` | `hook` 抓的观测日志，只是归档，程序不会回头读 |
| `samples\` | 「采集数据样板」生成的排查截面（只有哈希，不含明文密钥） |
| `update\` | 自动更新下载的临时文件，装完即可清空 |
| `profiles\qbN\backups\` | **旧版遗留**，现版本不会再写这个目录，可直接删 |

### 换 key 必须立刻落盘（改动代码时务必遵守）

AutoAuth 是**轮换**语义：服务端返回成功的那一刻，旧 key 就已经作废了。
所以「拿到新 key」到「写进本地」之间不能有空窗——中间崩了，旧 key 废了、新 key 也没了，这个号只能重新扫码。

**规矩**：任何调用 `Exchange()` 拿到成功响应的代码，**下一步必须是 `SavePending()`**，
然后才允许做停箱、写 live、推金库这些慢动作。

```csharp
var (ok, code, newKey, newEnc, newSrv, why) = Exchange(cred, uin, host, port, cap);
if (!ok) return ...;

// ★ 立刻落盘，不做任何等待
SavePending(box, cred.Uin, newKey, newEnc, newSrv, hash, oldKeyHash, "why");

// 之后才写 live + 金库（停箱、校验……）
```

`pending-rotated.json` 是「已换到、未写进 live」的标记。`CommitPending()` 写成功后删除它；
进程被杀导致残留时，`RecoverPending()` 会在下次启动/保活时自动补写。

补写点必须早于两处判断，否则永远补不上：

| 陷阱 | 后果 |
|------|------|
| `DecideWake`（密钥 <5h 就跳过） | 崩溃时 live 是已废的旧 key、新 key 在 pending 里；越新的 key 越被这条规则挡住 |
| `VaultSync.PrepareBeforeLaunch`（把金库推回 live） | 金库那时可能是旧 key，会反向覆盖待写的新 key |

所以两个入口都把 `HasPending → RecoverPending` 放在了最前面。

### 占用空间说明
主要占用是 `profiles\qbN\wmpf\Applet\`（游戏包缓存），每个号约 6～7 GB，16 个号合计 60 GB 以上。
它的作用是清空沙箱后**不必重新下载游戏**。如果实在要腾空间，这是唯一能大幅瘦身的地方，
但代价是下次启动每个号都要重新下载一遍。

## 从旧版（PowerShell 版 QQ 多开管理）迁移

1. 先关掉旧版的「QQ多开管理」窗口，并确认没有沙箱正在运行。
2. 打开新版，顶部会提示「发现旧版程序的数据」，点「导入旧版数据」。也可以随时点右上角「导入旧版数据」手动选择旧目录。
3. 导入会：复制登录金库、备注、保活设置；把保活计划任务改为由新版执行；重建桌面快捷方式。**旧目录不会被改动**，可以留作备份。
4. 导入后只用新版。新旧两个版本同时操作同一个沙箱会互相干扰。

## 日常使用

- **启动游戏**：双击列表里的沙箱，或选中后点「启动游戏」，也可以用桌面快捷方式 `jskp-备注`。
  有保存的登录会直接进游戏；需要扫码时会弹出二维码窗口，用对应的微信扫一下。
- **多开**：按住 Ctrl 多选后点「启动游戏」，会每隔 15 秒依次启动，避免一起冷启动卡住。
- **停止沙箱**：保存登录后关闭沙箱里的全部程序。直接关游戏窗口也可以，程序会自动保存并收尾。
- **释放浏览器内存**：游戏开久了 QQ 浏览器会占很多内存，点一下即可回收，不影响游戏。
- **深度压缩内存（含游戏）**：连游戏本体一起压工作集，数字大降；但正玩时会回升、提交不变，适合临时腾物理内存。**会拖断 ilink 长连接，仅手动用、别用在保活/常驻上**。顶栏「自动压内存 N 分」只压 QQ 浏览器、不动游戏本体（仅界面开着时生效）。
- **换号 / 登录出错**：「清除登录 / 换号重新扫码」，下次启动重新扫码。游戏包和备注保留。
- **新建沙箱**：点「＋ 新建沙箱」，第一次启动扫码登录即可。
- **角色和攻击力**：进游戏后自动从游戏里读出来，显示在列表的「角色」「攻击力」两列。
  攻击力按角色 ID 定位当前属性块，换装备或刚登录都能马上读到；没读到时点右侧「游戏角色」的「重新读取」。

### 更新程序

打开管理界面时会自动检查新版本，顶栏出现「● 有新版本」时点一下，看完更新内容点「立即更新」即可，
程序会自己下载、校验、替换并重启。金库、备注、保活设置都不会动，正在玩的游戏也不受影响。
也可以在「版本与更新记录」里点「检查更新」，或到 [Releases](https://github.com/Ajie528/JskpBoxManager/releases) 手动下载。

### 登录状态说明

| 显示 | 含义 |
| --- | --- |
| 免扫可用 | 有有效的登录凭证，启动直接进游戏 |
| 需要扫码 | 服务器不再认这个凭证，启动后扫一次码即可恢复 |
| 需要扫码（已被顶掉） | 同一个微信号在别的电脑或沙箱扫码登录过 |
| 未登录 | 新沙箱或清除过登录 |

**同一个微信号只能有一个地方保持免扫**：后扫码的会把先登录的顶掉（手机微信、PC 微信里直接玩不受影响；
只是两边同时在玩时，游戏会弹「该帐号在其他地方登录」把另一边挤下线，点确定后重新进游戏仍然免扫）。
列表里出现 ⚠ 表示有两个沙箱登录的是同一个微信号。

### 高级工具（取 Token / 抓包 / 解包 / 保活）

选中沙箱后点详情里的「🛠 高级工具」，在弹出窗口里点按钮即可，不用敲命令：取业务 Token、导 TLS 密钥、解包 wxapkg、抓 wx 请求、Frida 观测、凭证导入导出、状态、读角色等。右侧实时显示输出，取到 Token 可一键复制。

### 取业务 Token

「向僵尸开炮」的业务登录接口已通过抓包解密确认：免扫进游戏时游戏会请求
`h5api.scgame.com.cn//login/login_wxmg.php?appid=1048&js_code=<wx.login码>&...`，返回里带 `token`、`uin`、`open_id`。

本程序能自动把这个 token 抓出来（**需本机装 Wireshark**，安装时勾选 Npcap）：

- **界面**：选中沙箱 →「🛠 高级工具」→「取业务 Token」。它会冷启动免扫登录、自动抓包解密，取到后显示并可一键复制。约 2 分钟、会冷启动该箱。
- **HTTP**：勾选顶栏「协议服务」后，`GET http://127.0.0.1:18000/token?ref=qb1`（请求头带 `Authorization: Bearer <复制令牌得到的值>`）同样返回 token。

原理与边界见 [docs/抓登录接口与解包.md](docs/抓登录接口与解包.md)、[docs/协议服务说明.md](docs/协议服务说明.md)。

> 顶栏「协议服务」里的 `/wxapp/getCode`（CDP 取 wx.login code）对本游戏取不到码（微信运行时无调试端口），已改以 `/token` 为准，getCode 仅作兼容保留。

### Frida 观测（hook）—— 需要 Python

`hook` 用来**看清微信授权到底发生了什么**：在沙箱内挂一个只读的 Frida 脚本，截获
`ilinkapp_autoauth` 的请求和明文返回（含 `ret` / `error_msg`），不改包、不改参数、不写任何凭证。

#### 依赖

| 依赖 | 是否自动装 |
| --- | --- |
| Python 3 | **不自动装**。程序会检测并提示，需自己装 |
| `frida` / `psutil` / `pefile` | **自动装**（首次 `hook` 时程序会 `pip install`） |

装 Python：

```powershell
winget install Python.Python.3.13
# 或从 https://www.python.org/downloads/windows/ 下载，安装时勾选 "Add python.exe to PATH"
```

装好后自检（应能打印版本号）：

```powershell
py -3 --version
py -3 -m pip install frida psutil pefile
py -3 -c "import frida,psutil,pefile;print(frida.__version__)"
```

如果 `hook` 报「找不到 Python 3」或「Python 包不可用」，按提示把上面那段命令跑一遍即可。

> 观测脚本在 `tools\lean-refresh\hook_watch.py`，**必须和 exe 放在一起**（发布包里已带）。
> 程序会优先在**程序目录**里找 `tools\lean-refresh\hook_watch.py`，找不到才往上级目录找，
> 都找不到会报「找不到 tools\lean-refresh\hook_watch.py」。
> 如果同时存在仓库和安装目录两份，用的是**程序目录**那份；用了别处的会在 `logs\app.log` 里记一行。

#### 用法

```powershell
# 观测一次冷启动（默认启动浏览器、跑 240 秒、结束停箱）
.\JskpBoxManager.exe hook qb1

# 只观测、不启动（沙箱里已有运行时在跑时用）
.\JskpBoxManager.exe hook qb1 --no-launch --seconds 300

# 观测完不停箱
.\JskpBoxManager.exe hook qb1 --no-stop
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--seconds N` | 240 | 观测时长，30～7200 |
| `--no-launch` | 关 | 不冷启动，只挂到已运行的进程上 |
| `--no-stop` | 关 | 结束时不停箱 |
| `--mode` | Full | 启动模式（Full 等） |

#### 产物

| 文件 | 内容 |
| --- | --- |
| `logs\frida-ilink-qb1.jsonl` | 逐行 JSON 事件（结构化，便于脚本处理） |
| `logs\frida-ilink-qb1.txt` | 人读版，含 `AutoAuthResponse ... ret = 0` 这类关键行 |

**只允许 `qb1`**：这是实验功能，限定在一个号上，避免影响正在用的账号。
同一时间只能有一个 hook 在跑（重复启动会提示先关掉那个窗口）。

#### 拿它排查什么

- 免扫失败时，看 `AutoAuthResponse` 的 `ret`（`0` 成功 / `-13` 作废）和 `error_msg`；
- 区分「运行时压根没发 AutoAuth」（`--no-launch` 下看不到记录）和「发了但被拒」；
- 确认 `sessiontimeout` 是否真的出现（实测关游戏本身不会触发，见 `docs/ilink长连接与免扫掉线.md`）。

> 想要**纯协议**视角的原始响应（不依赖运行时、不发 Python），用 `autoauth-dump qb1` ——
> 它直接连服务器发一次 AutoAuth 并把完整响应结构 dump 出来。两者的区别：
> `hook` 看的是**官方运行时自己发的请求**，`autoauth-dump` 看的是**我们自己发的请求**。
> 结论见 [docs/AutoAuth响应字段实测.md](docs/AutoAuth响应字段实测.md)。

### 关于「永久在线 / 不开游戏也在线」

做不到纯 HTTP 的永久在线，两层都验证过：

- **微信免扫**（ilink）：续期有两条路——① 保活冷启动，让官方运行时自己发一次 AutoAuth（最可靠）；② **纯协议续期**，不开浏览器、直接连微信服务器发同一个 AutoAuth（约 0.5 秒，需沙箱已停）。见 `docs/mmtls直连可行性研究.md`、`docs/保活选项说明.md`。免扫链本身还有寿命、会被别处扫码顶掉。
- **游戏在线**：游戏的「在线」是一条到 `ws82-t5game2.scgame.com.cn` 的长连 WebSocket，由 Unity 运行时驱动；关游戏就断开。拿到的 `token` 只代表「已登录」，不等于「在线」。定时请求某个 URL **维持不了**在线。

想「关了游戏尽量别掉线」，用下面保活里的「**关游戏后常驻轻量运行时**」把运行时挂着，而不是指望 HTTP 续命。

### 静默保活

到点在后台冷启动一次沙箱，微信自动授权换新登录凭证后自动关闭，全程不弹窗。

- 顶部「静默保活总开关」控制全部沙箱；右侧可为选中的沙箱单独设置「每隔 N 小时」或「每天 HH:MM」。
- 每天模式下各沙箱依次错开 10 分钟（qb1 在设定时刻，qb2 晚 10 分钟……）。
- 游戏正开着时到点只保存凭证，不会重启游戏。
- 实测空闲 10 天以上登录仍然有效，每天保活一次足够。
- **计划任务每小时醒一次，但不是每小时都续**（1.5.37 起）：真正要不要动上游由程序判断——
  密钥超过 20 小时强制续、密钥不到 6 小时不动它、上次失败按退避等待、今天已续过就跳过。
  这样一次临时失败能在几小时后补上，而不是白等一整天。日志里会写明每次跳过的原因（`refresh skipped: ...`）。
- **轮换额度可以在界面上改**（1.5.37 起）：右侧「静默保活 → 轮换额度」里能填三个数——
  **每天最多换几次 key**（默认 8，填 0 用默认）、**密钥满几小时强制续期**（默认 20）、
  **密钥不到几小时就别动它**（默认 6）。列表新增「今日换 key」列显示 `已换/上限`，
  到 0 变红表示今天不再轮换。全局限额在「过期提醒设置」里，单箱设置优先。
- **关游戏后常驻轻量运行时**（可选）：关掉游戏窗时不整箱停，而是藏窗、压内存，保留微信运行时长连接，尽量不掉线。每箱仍占数百 MB 内存。点「停止」仍会整箱关掉。详见 [docs/保活选项说明.md](docs/保活选项说明.md)。
- 保活依赖 Windows 计划任务 `jskp-keepalive-qbN`，需要电脑开机且用户已登录。

## 出问题怎么办

1. 选中沙箱，看右侧「最近日志」，或点「打开完整日志」。
2. 点右上角「导出诊断包」，桌面会生成一个 zip，发给维护的人。诊断包里只有日志、配置和凭证摘要（哈希值），**不含**登录密钥本身。
3. 点「版本与更新记录」→「复制版本信息」，一起发过去。

## 命令行

日常操作都在界面里（包括「🛠 高级工具」）。桌面快捷方式和计划任务调用的是下面这些命令，一般不用手动执行：

```text
JskpBoxManager.exe                  打开管理界面
JskpBoxManager.exe launch qb1       启动并看门
JskpBoxManager.exe refresh qb1      静默保活一次
JskpBoxManager.exe stop qb1         保存登录并停止
JskpBoxManager.exe clear qb1        清除登录
JskpBoxManager.exe status qb1       输出状态（可重定向到文件）
JskpBoxManager.exe role qb1         读一次角色和攻击力（加 --dry 只显示不写入）
JskpBoxManager.exe observe qb1      观测微信/游戏窗与凭证变化（日志 logs\observe-qb1.jsonl）
JskpBoxManager.exe hook qb1         Frida 只读观测（仅 qb1；日志 logs\frida-ilink-qb1.jsonl；需 Python 3）
JskpBoxManager.exe protorenew qb1  不开浏览器，直接用协议换新密钥（需沙箱已停）
JskpBoxManager.exe notify           检查所有沙箱，超期未续期就推送微信
JskpBoxManager.exe notify --probe   主动连服务器验证凭证是否还有效
JskpBoxManager.exe notify --test    发一条测试通知
JskpBoxManager.exe cred-save qb1 --dir 目录   导出整套凭证（重放实验用，只读）
JskpBoxManager.exe cred-load qb1 --dir 目录   把导出的凭证写回沙箱 live（需先停箱）
JskpBoxManager.exe token qb1        一条龙抓包解密，输出业务 token（需装 Wireshark）
JskpBoxManager.exe keylog qb1       导出游戏 TLS 密钥（配合 Wireshark 解密）
JskpBoxManager.exe unpack qb1       定位并解包游戏 wxapkg（logs\wxapkg-qb1\）
JskpBoxManager.exe capture qb1      CDP 抓 wx.request / wx.login（本游戏抓不到，留作排查）
JskpBoxManager.exe getcode qb1      CDP 取 wx.login code（本游戏取不到，仅兼容）
JskpBoxManager.exe server           本机协议 HTTP 服务（提供 /token）
JskpBoxManager.exe samples          采集一份免扫状态截面到 samples\（排查用）
JskpBoxManager.exe autoauth-dump qb1   抓一次 AutoAuth 原始响应（会真实换 key，可加 --no-commit）
JskpBoxManager.exe shortcuts        按当前沙箱重建桌面快捷方式（qbN-角色名）
JskpBoxManager.exe version          输出版本号
JskpBoxManager.exe update           检查并更新到最新版本（不打开界面）
```

抓业务登录接口的步骤见 [docs/抓登录接口与解包.md](docs/抓登录接口与解包.md)。
免扫失效的排查工具与已归档样本见 [samples/README.md](samples/README.md)，
「服务端到底回不回传有效期」的实测结论见 [docs/AutoAuth响应字段实测.md](docs/AutoAuth响应字段实测.md)。

## 开发与发版

- 需要 .NET 8 SDK：`winget install Microsoft.DotNet.SDK.8`
- 调试：`dotnet build`；打包：`powershell -ExecutionPolicy Bypass -File build.ps1`，产物在 `dist\`。
- 发新版（自动）：
  1. 修改 `Directory.Build.props` 里的 `<Version>`；
  2. 在 `CHANGELOG.md` 最上面新增一节 `## [版本号] - 日期`，写清楚新增 / 变化 / 修复；
  3. 提交并推送到 `main`。GitHub Actions 会自动打包、打 `v版本号` 标签并创建 Release
     （说明取自 CHANGELOG 对应一节，上传 `JskpBoxManager.exe`、`JskpBoxManager.exe.sha256` 和 zip），各电脑上的程序就会提示更新。
     版本号没改的推送只做编译检查，不发版。
- 其他电脑上的开发环境、调试方法、发版失败排查见 [docs/开发者指南.md](docs/开发者指南.md)。
