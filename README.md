# 向僵多开管家（JskpBoxManager）

在一台电脑上用 Sandboxie-Plus + QQ 浏览器同时开多个微信小游戏「向僵尸开炮」，每个沙箱一个微信号；
登录一次后自动免扫码，并且可以定时在后台「保活」，让登录长期有效。

更新内容见 [CHANGELOG.md](CHANGELOG.md)。程序里点右上角「版本与更新记录」可以看到当前版本。

## 需要先装的软件

| 软件 | 说明 |
| --- | --- |
| Sandboxie-Plus | 装在哪个盘都行，程序会自动找 |
| QQ 浏览器 | 正常安装即可；第一次在沙箱里打开小游戏时会自动装好微信小程序运行环境 |

本程序自带 .NET 运行时，不需要另外安装。

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

### 关于「永久在线 / 不开游戏也在线」

做不到纯 HTTP 的永久在线，两层都验证过：

- **微信免扫**（ilink）：续期必须让官方运行时发一次 AutoAuth，只能靠保活冷启动，没有纯 HTTP 续期（见 `docs/mmtls直连可行性研究.md`）。免扫链本身还有寿命、会被别处扫码顶掉。
- **游戏在线**：游戏的「在线」是一条到 `ws82-t5game2.scgame.com.cn` 的长连 WebSocket，由 Unity 运行时驱动；关游戏就断开。拿到的 `token` 只代表「已登录」，不等于「在线」。定时请求某个 URL **维持不了**在线。

想「关了游戏尽量别掉线」，用下面保活里的「**关游戏后常驻轻量运行时**」把运行时挂着，而不是指望 HTTP 续命。

### 静默保活

到点在后台冷启动一次沙箱，微信自动授权换新登录凭证后自动关闭，全程不弹窗。

- 顶部「静默保活总开关」控制全部沙箱；右侧可为选中的沙箱单独设置「每隔 N 小时」或「每天 HH:MM」。
- 每天模式下各沙箱依次错开 10 分钟（qb1 在设定时刻，qb2 晚 10 分钟……）。
- 游戏正开着时到点只保存凭证，不会重启游戏。
- 实测空闲 10 天以上登录仍然有效，每天保活一次足够。
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
JskpBoxManager.exe hook qb1         Frida 只读 hook（仅 qb1，日志 logs\frida-ilink-qb1.jsonl）
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
JskpBoxManager.exe version          输出版本号
JskpBoxManager.exe update           检查并更新到最新版本（不打开界面）
```

抓业务登录接口的步骤见 [docs/抓登录接口与解包.md](docs/抓登录接口与解包.md)。

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
