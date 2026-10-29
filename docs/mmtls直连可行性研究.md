# mmtls / ilink 直连续期：可行性研究

结论：**技术上可能，工程上不划算，不建议作为主方案。** 现在采用的「官方运行时自己续期 + 本地凭证只进不退」已经能拿到直连想要的效果（无人值守续期、不弹扫码），而直连要多付出几周到几个月的逆向工作、每次微信升级都可能失效，并且有封号风险。

下面是依据、难点和一个低成本的折中路线。

---

## 1. 已经确认的事实（来自 qb1 沙箱实测）

扫码登录在 QQ 浏览器里走的是微信运行时（WeChatAppEx / WMPF）的 **ilink** 通道，不是网页 OAuth。


| 文件                                                              | 内容                                                                                                                                                                           | 作用判断                                                |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `ilink\default\tdi\ilinkapp_0600005ba4e935\0\6\tdi_account.txt` | `kTdiKeyAutoauthKey`（约 200 字节 base64，以 `BgAA` 开头）、`kTdiKeyAutoauthEncKey`（18 字节）、`Uin`、`Username`（`ow9TZ…@im.ilinkapp_…`）、`DeviceId`、`ServerId`、`LoginType=4`、`LoginScene=5` | **长效凭证**。和微信客户端的 AutoAuth 机制同构：凭 AutoAuthKey 免密换新会话 |
| `ilink\default\psk.key`（228 字节）                                 | 二进制                                                                                                                                                                          | mmtls 的 PSK 会话恢复票据（类 TLS 1.3 0-RTT），短期              |
| `ilink\default\host\mmtls_ctrl.ini`                             | `KEY_XXX_ENABLE=true`                                                                                                                                                        | mmtls 开关                                            |
| `ilink\default\host\ipportrecords2.xml`                         | `117.185.25.64`，端口 443 / 5000                                                                                                                                                | 长连接入口                                               |
| `device_uuid_0`（16 字节）                                          | 设备标识                                                                                                                                                                         | 与 `kTdiKeyDeviceId` 配套                              |


10/23 到 10/27 的观察：每次运行时成功握手，`tdi_account.txt` 和 `psk.key` 会**同一秒一起重写**。`Uin` / `Username` 由「微信号 + ilink 应用」决定：同一个微信号在两台电脑、不同时间扫码，`Uin` 都一样；10/27 `Uin` 变化是因为换了一个微信号扫码。同一个号每次免扫，AutoAuthKey 都会换新（实测结果见 `docs\服务端规则测试.md`）。

## 2. 直连要实现的东西

要绕开 QQ 浏览器和 WeChatAppEx、自己发包续期，至少需要：

1. **mmtls 握手与记录层**
  微信公开过设计思路（基于 TLS 1.3：ECDHE + 服务器静态公钥校验 + PSK 恢复 + AES-GCM 记录层），但没有公开规范。客户端内置的服务器公钥、扩展字段、版本号都要从二进制里抠出来。
2. **ilink 业务协议**
  AutoAuth 请求的 cgi / cmdid、protobuf 结构、字段顺序，以及 `AutoauthEncKey` 怎么参与加密或签名，这些完全没有公开资料，只能逆向 WeChatAppEx 里的 ilink 模块。
3. **设备与客户端指纹**
  `DeviceId`、`ServerId`、客户端版本、ilink AppId、风控上报（`kvcomm` 目录里那些 `reportnow_*.statistic` 就是上报数据）。指纹不一致时服务端可能直接作废会话，甚至标记账号。
4. **续期结果回写**
  直连拿到新 AutoAuthKey 和 PSK 以后，还要按运行时的格式写回 `tdi_account.txt` / `psk.key`，否则下次打开游戏的仍是旧凭证。也就是说，游戏照样要靠官方运行时来跑，直连只是替代「续期」这一步。



## 3. 工作量与风险


| 项目                                     | 估计           |
| -------------------------------------- | ------------ |
| 定位 ilink 模块、Hook 出明文请求（Frida / x64dbg） | 1–2 周        |
| 复原 mmtls 握手 + 记录层并能通过服务端校验             | 2–4 周，不确定性最大 |
| 复原 AutoAuth 请求与响应                      | 1–3 周        |
| 每次 QQ 浏览器 / WMPF 升级后的跟进                | 持续，不可预期      |


风险：

- **封号 / 风控**：非官方客户端发出的包，只要指纹或时序和官方不同就可能被识别。代价是丢号，而不只是重新扫码。
- **协议漂移**：WMPF 版本号已经在目录名里（`WXRuntime_V22346514299`），升级频繁，每次升级都可能改握手或字段。
- **条款**：逆向和仿冒客户端违反微信 / 腾讯的服务条款。
- **收益有限**：如果服务端对这种第三方设备会话设了「最长存活期」，直连和官方运行时一样续不过去；如果没设，官方运行时已经能续。两种情况下直连都不带来额外能力。



## 4. 对比：现在的方案能做到什么

`ilink-credential.ps1` 加上保活计划任务：

- 凭证一旦更新就存进金库（运行中每 30 秒检查一次，停箱前后各存一次），并保留最近 12 份历史；
- 启动、失败回滚、保活时只用新凭证覆盖旧凭证，旧备份不会再顶掉服务器已经轮换过的新密钥；
- 保活只需要拉起官方运行时，看到 `tdi_account.txt` 被重写并换新就算成功，然后关箱。

这和直连的效果一样：**定时让服务端看到一次合法的 AutoAuth**。区别只在于发包的是官方程序。

## 5. 折中路线（如果以后还想往下挖）

按成本从低到高：

1. **先测出服务端规则（强烈建议，零风险）**
  - 同一身份免扫重启 2–3 次，对比 `credential\history` 里的 `keySha`，确认 AutoAuthKey 是否每次轮换。
  - 停掉某个号的保活，记录它多少天后开始要求扫码，得到「不使用多久会失效」。
  - 一直保活某个号，记录它是否在某个固定天数后仍要求扫码，得到「最长存活期」。
   这三个数决定了保活间隔该设多少，也决定了任何方案（包括直连）的上限。
2. **精简运行时保活**（已开工，见下方「精简保活实验结果」）  
   命令：`JskpBoxManager.exe lean qb1`（硬锁 qb1，C#，用 BoxView 认进程）。正式保活见 `keepalive.json` 的 `leanRefresh`（默认关，仅建议 qb1 先开）。
3. **Hook 观测**（已开工）  
   命令：`JskpBoxManager.exe hook qb1`，脚本 `tools\lean-refresh\hook_ilink.js`。只观测 CreateFile/MoveFile 与模块列表，不改包。依赖本机 `pip install frida`。  
   **详细说明书**：[Hook观测使用说明.md](Hook观测使用说明.md)
4. **完整直连**：在 1–3 都做完、确认服务端没有最长存活期、而官方运行时又确实无法满足需求时才值得考虑。

### 精简保活 / Hook 用法（仅 qb1）

```text
# 精简启动候选（Blank → NoUrl → RuntimeOnly），看能否换新密钥
JskpBoxManager.exe lean qb1 --appdir D:\a_game_scrpit\JskpBoxManager-1.1.5

# 指定模式；Full 仅作对照（会走游戏中心）
JskpBoxManager.exe lean qb1 --modes RuntimeOnly --seconds 180

# Frida 观测（详见 Hook观测使用说明.md）
JskpBoxManager.exe hook qb1 --appdir D:\a_game_scrpit\JskpBoxManager-1.1.5 --mode Full --seconds 180
```

日志：`logs\lean-refresh-qb1.jsonl`、`logs\frida-ilink-qb1.jsonl`。  
Hook 逐步说明、参数、日志字段与排障见 [Hook观测使用说明.md](Hook观测使用说明.md)。

正式程序：保活设置勾选「精简保活」，或 JSON `"leanRefresh": true`。开启后 refresh 先试 Blank/NoUrl/RuntimeOnly，失败自动回退 Full。

### 精简保活实验结果（2026-10-29，R7000P qb1）

金库密钥 `a6516c7d…`（当天 08:57 扫码所得）。

| 候选 | 结果 | 说明 |
|------|------|------|
| Blank（QQBrowser + about:blank） | timeout / 无 WeChat | 不打开游戏中心时，**不会拉起 WeChatAppEx**，密钥不换新 |
| NoUrl（无 URL） | 同上 | 同上 |
| RuntimeOnly（直接启箱内 WeChatAppEx） | timeout，未见稳定换新 | 短时可能有进程，**未观察到 AutoAuth 换钥**；缺少小游戏/游戏中心触发 |
| Full（对照，GameUrl） | **15s 内 live 被清成 invalid** | 与既有「key-revoked」表现一致；本把金库密钥随后无法免扫 |

结论（阶段性）：

- **单纯去掉 GameUrl 或只启 WeChatAppEx，目前不能替代正式保活**；AutoAuth 仍依赖游戏中心 / 小游戏启动路径。
- 正式 `leanRefresh` 仍可开在 qb1 上：会快速试精简候选，无微信则早退并**回退 Full**，不改变其它号默认行为。
- 下一步：用 Hook/文件监视对比「Full 成功换钥」时的进程命令行与 `tdi_account.txt` 写入时机，再决定是否存在更轻的官方启动参数（例如只拉 WMPF 会话而不进游戏）。

## 6. 建议

- 主方案保持「官方运行时续期 + 凭证只进不退」（Full 路径）。
- 先跑第 5 节第 1 步，拿到轮换与过期规律，再定保活频率（目前默认每天一次）。
- 精简保活仅在 qb1 继续试验；未验证前不要默认打开其它号。
- 暂不投入 mmtls 直连。

