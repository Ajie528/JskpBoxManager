# mmtls / ilink 直连续期：可行性研究

## 结论（2026-11-05 11:56 更新）

**已完成：纯 Python 自实现 AutoAuth 续期打通，连续多次 `code=0`，无需 QQ 浏览器 / 微信运行时。**

原来的判断（「技术上可能，工程上不划算」）**已被推翻**——卡了两天的 `code=-2` 不是协议问题，
也不是 `AutoAuth.Device` 来源问题，而是 **wpkg 头字段 24 填错了值**：

| | 错误做法 | 正确做法 |
|---|---|---|
| 字段 24 | `kTdiKeyDeviceId`（32 字节二进制） | **`kTdiKeyIlinkAppId` 字符串**（`ilinkapp_0600005ba4e935`，22 字节） |

改这一处，一次就成功。详见 **6.3A**。

现状：

- ✅ 握手、加密、shortlink、AutoAuth、响应解密、凭证轮换全部跑通
- ✅ 链式验证：用上一轮的新凭证继续续期，连续 3 次全 `code=0`
- ✅ 新 `AutoauthKey` / `AutoauthEncKey` / `ServerId` 自动写回 `tdi_account.txt`
- ⬜ 尚未接进 C# 主程序（当前是 `tools/mmtls_autoauth.py`）
- ⬜ 尚未实现「发送前落盘 attempted」（防丢凭证，接入前必须补）

主方案仍然建议保留「官方运行时续期」作为兜底：直连每次微信升级都可能失效，
且服务端风控未知。但「能不能做到」这个问题，答案是**能**。

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
   命令：`JskpBoxManager.exe hook qb1`，观测程序在 qb1 箱内运行，ILinkServiceHost 出生即挂，截 ilink 明文日志（含 AutoAuth 的 ret / error_msg）、凭证文件读写和对外连接，不改包。依赖 `pip install frida psutil pefile`。  
   已确认：免扫保活就是 ilink 带旧凭证向 `longcloud.weixin.com` 发 `ilinkapp_autoauth`（cmdid 3198），ret=0 时写回新凭证。  
   **详细说明书**：[Hook观测使用说明.md](Hook观测使用说明.md)
4. **完整直连**：在 1–3 都做完、确认服务端没有最长存活期、而官方运行时又确实无法满足需求时才值得考虑。

### 精简保活 / Hook 用法（仅 qb1）

```text
# 精简启动候选（Blank → NoUrl → RuntimeOnly），看能否换新密钥
JskpBoxManager.exe lean qb1

# 指定模式；Full 仅作对照（会走游戏中心）
JskpBoxManager.exe lean qb1 --modes RuntimeOnly --seconds 180

# Frida 观测（详见 Hook观测使用说明.md）
JskpBoxManager.exe hook qb1 --seconds 60
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

#### 复测结论（2026-11-04，本机 qb1，v1.5.9）——此路确认不通

用 1.5.9 的完整观测工具（longlink + xlog hook）重跑 `RuntimeOnly`，把上次「阶段性」结论钉死：

```text
JskpBoxManager.exe lean qb1 --modes RuntimeOnly --seconds 120 --skip-stop
```

| 时刻 | 观察 |
|------|------|
| 17:08:02 | `QQBrowser start issued (lean, mode=RuntimeOnly)` |
| 17:08:05 | `live=082a34dcffd506fa  wxPid=29244  game=False  boxPids=9` ← **WeChatAppEx 进程确实起来了** |
| 17:08:17 → 17:09:47 | 每 15 秒采样，`live` 始终是 `082a34dcffd506fa` |
| 17:10:02 | `RESULT RuntimeOnly => timeout  liveKey=082a34dcffd506fa  120.9s  game=False` |
| 17:10:05 | `lean FAIL: 没有候选完成密钥换新` |

结论：

- **微信运行时能被拉起**（`wxPid=29244`、`boxPids` 稳定 5～9 个），但**120 秒内一次 `AutoAuth` 都不发**，密钥完全不变。
- 与 10-29 那次结果一致，跨版本复现（1.5.6 → 1.5.9），可以定论：**`AutoAuth` 必须由游戏中心页面触发**，光有 `WeChatAppEx` 进程不够。
- 推论：**「低成本探测凭证是否有效（不进游戏）」这条路走不通。** 检查凭证有效性唯一可行方式仍是真进一次游戏，也就是现在的每日静默保活本身。
- `leanRefresh` 仍保留为「先试轻量、失败回退 Full」的省钱路径，但不要指望它替代 Full。

### 能否从微信直接按 appid 拉起小游戏？（2026-11-04 评估）

「既然 `RuntimeOnly` 能把微信运行时拉起来，能不能直接让它打开某个小程序、省掉游戏中心那一步？」——技术上**可以拉起小程序，但救不了免扫续期**，原因如下。

先说结论：

| 问题 | 结论 |
|------|------|
| 能拉起小程序吗 | 能。WMPF 有 `launchApplet` 一类入口，`appid` + 启动参数即可，游戏本身也就是个 `.wxapkg` 小程序 |
| 能靠它触发 AutoAuth 吗 | **可能可以，但不值得做**（下面解释） |
| 能绕过游戏中心省资源吗 | 省不了多少，风险反而大 |

技术路径与障碍：

1. **拉起方式**：`WeChatAppEx` 是 Chromium 内核 + WMPF 承载，小程序入口在 `Applet\` 目录下的路由表与 `launch.config` 里。
   想直接 `Start.exe` 带参数拉起某个 appid，需要复刻 wmpf 的启动参数（`--appid=`、`--miniprogram-url` 之类），
   而真实参数是运行时动态生成的，不是固定字符串。
2. **AutoAuth 的触发点在游戏中心页**：实测证明 `AutoAuth` 不是进程启动就发，而是由**游戏中心页加载 → 请求授权 → ilink 发 `ilinkapp_autoauth`** 这条链路带出来的。
   即使能直接打开游戏小程序，它加载时会走「小程序登录」路径，仍需要 ilink 先完成授权——**绕不开，只是把触发点换了个地方**。
3. **风控与指纹**：绕过游戏中心意味着启动参数、`Referer`、`launch.config` 时序都和官方不同，
   属于协议层仿冒，有被识别/封号的风险（同 `mmtls 直连` 一节的评估）。
4. **收益有限**：省掉的是「游戏中心页加载那几秒」，而保活本身已经是后台静默执行，用户感知不到。
   为此承担指纹不一致的风险不划算。

**结论：不做。** 保持「Full 路径 + 每天一次冷启」为唯一续期方式；`RuntimeOnly` 只作为 lean 的省时前置尝试。

## 6. 自实现协议发包：已打通 mmtls，卡在 AutoAuth 业务层（2026-11-05）

> 这一节推翻了本文开头的「暂不投入」结论：**mmtls 协议本身已经用 Python 完整跑通**，
> 只剩 AutoAuth 的业务参数没对上。参考实现：[525815266/YYB-Go-Enhanced](https://github.com/525815266/YYB-Go-Enhanced)。

### 6.1 参考实现做了什么

它用 Go 重写了整套 mmtls + ilink 协议，**完全不依赖 QQ 浏览器 / WeChatAppEx**：

```
internal/protocol/
  mmtls_protocol.go   协议常量、记录层、shortlink 封包
  mmtls_crypto.go     HKDF / AES-GCM / ECDH
  mmtls_client.go     完整握手（ClientHello → ServerHello → CertVerify → NST → Finished）
  autoauth.go         AutoAuth 业务（cmdid 3198）+ 密钥轮换
  ilink.go            wpkg 头、Hybrid ECDH、session 解析
```

它的保活不是「冷启动进游戏」，而是**按 token 到期时间提前直接用 TCP 发 AutoAuth**：

```go
// keepalive.go
credentialsDueForRefresh(creds, now, ahead)   // 按 ExpiresAt - ahead 判断
keepAliveFailureBackoff(...)                   // 失败退避：5min / token 过期 15min
```

### 6.2 我们的实测结果：握手完全打通

用 `tools/mmtls_probe.py` 在本机实测（qb15）：

```
ClientHello (212B) → ServerHello cipher=0xc02b group=1 serverPubLen=65
  → CertVerify (0x0f)
  → NewSessionTicket (0x04)
  → Finished (0x14)   ← ServerFinished 校验通过
→ ClientFinished 已发

=== 握手成功 ===
NewSessionTicket 数量: 2
  type=1(PSK_ACCESS)  lifetime=604800s   (7 天)
  type=2(PSK_REFRESH) lifetime=2592000s  (30 天)
```

**这意味着协议层（最难的密钥派生、记录层、AAD、握手时序）已经全部正确。**

关键参数（都已验证）：

| 项 | 值 |
|---|---|
| 记录版本 | `0xf103` |
| 握手密码套件 | `0xc02b`（ECDHE P-256） |
| PSK 套件 | `0x00a8` |
| shortlink magic | `0x1110`，ver `0x076d` |
| 记录 AAD | `seq(8B) + ct(1B) + 0xf1 0x03 + cipherLen(2B)` |
| 握手密钥 | `expand_label(secret, "handshake key expansion", hsHash, 56)` → `[cKey|cIV|sKey|sIV]` |
| 应用密钥 | `expand_label(master, "application data key expansion", hFinal, 56)` |
| PSK 派生 | `expand_label(secret, "PSK_ACCESS"/"PSK_REFRESH", hCertV, 32)` |

### 6.3 AutoAuth 请求：能发出去、服务端能读懂，但业务层回 -2

> **2026-11-05 11:56 更新：此问题已解决，根因是 wpkg 头字段 24 填错。见 6.3A。**

### 6.3A 已解决：根因是 wpkg 头字段 24 填错（2026-11-05 11:56）

**结论：纯 Python 自实现续期已成功打通，不需要 QQ 浏览器、不需要微信运行时。**

#### 根因

参考仓库 `525815266/YYB-Go-Enhanced` 的 `internal/protocol/ilink.go` 里：

```go
ilinkDevice = []byte("ilinkapp_060000b7b93f6c")   // 硬编码的 ilink app id

func sessionWpkgHead(uin int64, f9, deviceID []byte) []byte {
    if len(deviceID) == 0 {
        deviceID = ilinkDevice        // ← 是 app id 字符串
    }
    return wpkgHead(ints, map[int][]byte{14: []byte{}, 24: deviceID, 27: f9})
}

func extractSession(mar []byte) (AppSession, error) {
    ...
    DeviceID: append([]byte(nil), ilinkDevice...),   // ← 同样写死成 app id
}
```

**wpkg 头字段 24 = `kTdiKeyIlinkAppId` 字符串**（`ilinkapp_0600005ba4e935`，22 字节），
**不是** `kTdiKeyDeviceId`（32 字节 base64 解码后的二进制）。

我们之前一直用 `device_id`（32 字节）填字段 24，服务端能解包（`ints[4]=0`、`ints[23]=0`）
但业务层判定会话不匹配 → `code=-2`。

#### 修复后的实测

```
  uin=25985012983767251 keyLen=162 encKeyLen=24 deviceLen=32 f9Len=35 ilinkAppId=ilinkapp_0600005ba4e935
=== AutoAuth 明文 204 字节 ===
=== 完整请求体 569 字节（含 wpkg 头）===
[握手] longcloud.weixin.com -> 101.226.142.222:5000
[握手] 完成
响应 cmd=3198 bodyLen=1326
响应头 ints={2: 25985012983767251, 4: 0, ..., 23: 0, 25: 17, ...}
base.code=0（有符号 0）        ← 之前一直是 -2
🧩 新 key: len=163 encKey: len=24 serverId: len=36
✅ 拿到轮换后的新凭证！
```

响应 `.2` 会话块完整下发：

| 响应字段 | 内容 |
|---|---|
| `..1` / `..2` | 新的 SendKey / RecvKey（24 字节各一） |
| `..3` | **新 AutoauthKey**（163 字节） |
| `..4` | **新 AutoauthEncKey**（24 字节） |
| `..9` | **新 ServerId**（36 字节，对应 wpkg 字段 27） |
| `..12` | Ticket（152 字节） |

#### 链式验证：连续三次续期全部成功

用上一轮拿到的新凭证再发一次，仍然 `code=0` 并再次下发新凭证——
说明**这是可持续的续期闭环，不是一次性**。

```
第 1 次  base.code=0  → 保存 newKey=BgAAxLbooK8g8kwS…
第 2 次  base.code=0  → 保存 newKey=…（用第 1 次的新 key）
第 3 次  base.code=0  → 保存 newKey=…（用第 2 次的新 key）
```

qb2 的 `tdi_account.txt` 已写回新凭证，`kTdiKeyAutoauthKey` / `kTdiKeyAutoauthEncKey` /
`kTdiKeyServerId` 三行同步更新。

#### `AutoAuth.Device` 的真实来源（不再是卡点）

明文结构：

```
request = pbLen(1, pbLen(1, AutoAuth.Device)) + pbVar(2, 1901) + pbLen(3, AutoAuth.Key)
```

参考实现的 `AutoAuth.Device` 是 ManualAuth 时本地生成的 **32 字节 `appDeviceID`**：

```go
func randomAppDeviceID() ([]byte, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    return b, err
}
```

即**客户端自己随机生成**、随后在 ManualAuth 的 `AppBaseRequest` 里上报给服务端，
AutoAuth 时原样带回。它不是 `login_buffer` 里的字段（那是 `ticket`/`device_id`，用途不同）。

实践上验证：用 `kTdiKeyDeviceId` 那 32 字节也能通过 `code=0`，
说明服务端在这一层**只要求与首次上报一致且长度 32**，不强制校验具体来源。
（仍建议后续抓一次真实请求确认官方填的是不是同一把。）

#### 仍未做的事

- 这个脚本只更新 `tdi_account.txt`，**没有写 `psk.key`**；PSK 每次握手都会重新派发，
  不影响续期，但如果要复用 0-RTT 就得自己存。
- 还没接进 C# 主程序（目前是 Python 工具）。
- `attempted` 语义：参考实现要求**发送前先落盘**，避免「请求已发出但结果丢失」后重放。
  当前脚本是成功后保存，若中途断网会出现「服务端已轮换、本地还是旧的」——这是真实风险，
  接入主程序时必须先写 `AttemptedAt` 再发送。

### 6.3B 修复前的失败记录（保留作为排查依据）

用 `tools/mmtls_autoauth.py --send` 实测：

```
=== 读取凭证 ===
  uin=25985013636912110 keyLen=162 encKeyLen=24 deviceLen=32 f9Len=35
=== AutoAuth 明文 204 字节 ===
=== Hybrid 加密后 435 字节 ===
=== 完整请求体 578 字节（含 wpkg 头）===
[握手] 完成
=== 发送 AutoAuth (cmdid 3198) ===
响应 cmd=3198 bodyLen=269
响应头 ints={2:0, 4:0, ..., 23:0, 25:17, 26:4, 28:1}   ← 传输层/应用层全部 0（通过）
[marker] 解密成功 21 字节
响应: {1: {1: -2, 2: ""}, 2: {4: 0, 5: ""}}
❌ 业务层拒绝 code = -2
```

**判读**：

- `ints[4]=0`（传输层 OK）、`ints[23]=0`（应用层 OK）→ **服务端完整解析了我们的请求**
- 响应密文 `0a0d08feffffffffffffffff011200120420002a00` 解密成功 → **加密链路完全正确**
- 但 `base.code = -2`（`0xFFFFFFFFFFFFFFFE` 的有符号解读）→ **业务层拒绝**

### 6.4 已排除的原因

| 尝试 | 结果 |
|---|---|
| `appVersion` ∈ {1901, 524545, 1504, 1900, 2100} | 全部 `-2` |
| `AutoAuth.Device` 用 `kTdiKeyDeviceId`(32B) vs `ServerId[:32]` | 全部 `-2` |
| wpkg 头 `ints[25]=17` vs `16` | 全部 `-2` |
| wpkg 头「直接构造」vs「解码后重组」 | **字节完全相同**（验证过 `identical: True`），排除该因素 |

### 6.5 当前判断：`AutoAuth.Device` 的来源可能不对

参考实现里 `AutoAuth.Device` 的来历很关键：

```go
// 来自 ManualAuth 的绑定，不是 tdi_account.txt 的字段
type autoAuthState struct {
    Device []byte   // ← 初次来自 login_buffer 的 field 2
    Key    []byte
    EncKey []byte
}

func parseLoginBuffer(loginBufferB64 string) (loginMeta, error) {
    fields := pbParse(raw)
    ticket, _ := fields[1].([]byte)
    device, _ := fields[2].([]byte)   // ← Device 在这里
    ...
    meta := loginMeta{Ticket: ticket, DeviceID: device, ...}
}
```

即：**`AutoAuth.Device` = `login_buffer` 的 field 2**，而 `login_buffer` 是**扫码时服务端下发、只存在于内存/响应里**的，不落盘。

我们从 `tdi_account.txt` 拿到的 `kTdiKeyDeviceId`（32 字节）**很可能不是同一个值**。

### 6.6 已排除的参数组合（2026-11-05，共 20+ 种）

用「新旧两套凭证」反复试，全部 `code=-2`：

| 维度 | 试过的值 | 结果 |
|------|----------|------|
| `appVersion` | 1901 / 524545 / 1504 / 1900 / 2100 | 全 `-2` |
| `AutoAuth.Device` 来源 | `kTdiKeyDeviceId`(32B) / `ServerId[:32]` | 全 `-2` |
| 明文嵌套层数 | 1 层 / 2 层 / 3 层 | 1 层 → `-20009`（传输层拒）；2/3 层 → `-2` |
| wpkg `ints[25]` | 17 / 16 | 17 → `-2`；16 → `-20007`（传输层拒） |
| wpkg `ints[2]`/`[22]` | 完整 64 位 uin / 32 位截断 | 全 `-2` |
| 凭证新旧 | 16:14 的旧 key / 11:00 的新 key | 全 `-2` |

**从数据库找 device 也失败**：`applet.db`（84KB）无 sqlite 头（加密）、`applet.db-wal`（1.6MB）、`mpkv.db`（全 0）
里都**搜不到 `DeviceId` 的原始字节**。

当时（错误地）结论：`AutoAuth.Device` 只存在于 `login_buffer`（扫码响应），本地没有任何副本。

> **此结论已被 6.3A 推翻**：`AutoAuth.Device` 是客户端在 ManualAuth 时**自己随机生成**的 32 字节，
> 与 `login_buffer` 无关。上面这 20+ 种组合全部失败的真实原因是
> **wpkg 头字段 24 填了 32 字节 DeviceId，而正确值是 ilinkAppId 字符串**——
> 跟 `AutoAuth.Device` 怎么填毫无关系。改对字段 24 后一次就 `code=0`。

### 6.7 扫码 hook 的硬障碍：Frida 在 ilink 上注入不可靠

> **这一节整体已不必要。** 既然 AutoAuth 不需要 `login_buffer`，
> 也就不需要 hook ManualAuth 去抓它。下面保留作为「Frida 在 ilink 上不可靠」的技术记录，
> 供以后需要抓别的内存数据时参考。

```
/ilink/ilinkapp/sys/ilinkapp_manualauth → 0xD77C0 (161B) 构造（写 cmdid 0xD7D + URL）
                                        → 0xD4710 (895B) 唯一调用者（完整流程）
```

但**实际 hook 全部失败**，原因是 `ProcessNotRespondingError`：

| 时间 | 场景 | ilink 注入结果 |
|------|------|----------------|
| 11:00 | 程序 launch，**未加 ManualAuth hook**，凭证有效（免扫） | ✅ `attached=5, err=0` |
| 11:13 | 手动 + child gating | ❌ 1 次失败，进程死 |
| 11:16 | 手动 + ilink 不 gating（放行后补挂） | ✅ 成功但慢 10 秒，错过 ManualAuth |
| 11:22 | 手动 + child gating | ❌ 失败 |
| 11:29 | 程序 launch + `hookManualAuth` 在 init 里挂 | ❌ **41 次失败** |
| 11:33 | 程序 launch + **延迟到 RPC 挂**（init 不挂） | ❌ 仍 41 次失败 |

关键推论：

- **只要走扫码（而非免扫），ilink 的注入就很容易超时**——它比免扫路径初始化更重。
- `enable_child_gating`（出生即拦截）在 ilink 上**必然失败**：进程被挂起后注入超时、随即被终止。
- 把 hook 从 `init()` 移到 RPC 延迟挂载**也没解决**（11:33 仍 41 次失败），
  说明瓶颈在 frida-agent 注入本身，不在我们的 hook 代码。
- qb15 反复启停 20+ 次后更差；qb1 一直 `err=0`，说明这是**沙箱实例状态**问题，不是全局故障。

### 6.8 下一步

**协议层已完成，剩下的都是工程接入。**

0. ~~在干净沙箱验证注入~~ / ~~抓真实 AutoAuth 请求~~ —— **已不需要**（见 6.3A）

1. **把续期接进主程序**（C#）：目前只有 Python 工具，需要移植或用 `Process` 调用。
   若移植，参考 `mmtls_autoauth.py` 的 `Mmtls` 类 + `hybrid_encrypt_with_key`，
   密码学部分用 .NET 的 `ECDiffieHellman` / `AesGcm` / `HKDF` 都能对应。
2. **发送前先落盘 `attempted`**：参考实现的关键约束——
   AutoAuth 会**轮换**服务端密钥，请求一旦发出，旧 key 就作废。
   必须先写「正在续期」标记再发送；成功后写新凭证，失败则保留旧凭证但**不能重放**。
   当前脚本是「成功后保存」，断网时有丢凭证风险，接入时必须改。
3. **补 `psk.key`**：续期不影响 PSK（每次握手重新派发），但若要 0-RTT 恢复需自行持久化。
4. **验证官方 `AutoAuth.Device`**（可选）：现在用 `kTdiKeyDeviceId` 能过，
   但确认官方到底填什么更稳妥。静态位置：`0xD7710`（构造）/ `0xD4390`（完整流程）。

### 6.9 工具清单

| 文件 | 用途 |
|------|------|
| `tools/mmtls_probe.py` | 只做 mmtls 握手，验证协议正确性（**已成功**） |
| `tools/mmtls_autoauth.py` | 完整 AutoAuth：读凭证 → 构造 → 发送 → 解密响应（`--send` 才发） |
| `tools/mmtls_autoauth_try.py` | 参数矩阵试错（appVersion × device × wpkg 变体） |
| `tools/lean-refresh/locate_manualauth_static.py` | 静态定位 ManualAuth 构造/流程函数 |
| `tools/lean-refresh/locate_autoauth_static.py` | 静态定位 AutoAuth 构造/流程函数 |

依赖：`py -3 -m pip install cryptography lz4`

## 6B. 保活计时模型：30 天扫码授权窗口（参考实现）

这是本轮从参考仓库学到的第二个关键点，直接决定了「免扫能活多久」。

### 参考仓库的做法

`internal/protocol/loginbuffer.go`：

```go
// ToMapForScan serializes credentials captured from a successful QR scan.
// The 30-day window is the scan/authorization window, not the time at which a
// legacy account happens to be refreshed by keepalive.
func (c LoginBufferCredentials) ToMapForScan() map[string]any {
    if c.RefreshToken != "" && c.RefreshTokenObservedAt <= 0 {
        c.RefreshTokenObservedAt = time.Now().Unix()   // ← 记「扫码那一刻」
    }
    return c.ToMap()
}
```

`internal/store/store.go` 的判定：

```go
if observedAt := int64Credential(a.Credentials, "refresh_token_observed_at"); observedAt > 0 {
    refreshTokenObservedAt = &observedAt
    // 满 25 天 → 建议重扫（提前 5 天，留出重扫余地）
    rescanRecommended = rescanRecommended ||
        time.Now().Unix()-observedAt >= int64((25*24*time.Hour)/time.Second)
}
```

`internal/httpapi/keepalive.go` 的保活触发是**另一套**，看 token 到期时间：

```go
func credentialsDueForRefresh(creds protocol.LoginBufferCredentials, now time.Time, ahead time.Duration) bool {
    return creds.ExpiresAt <= 0 || now.Add(ahead).Unix() >= creds.ExpiresAt
}
```

**三者的区别要分清**：

| 计时器 | 依据 | 含义 |
|---|---|---|
| 保活频率 | `ExpiresAt`（access token，默认 `expires_in=7200` 秒）+ 提前量 | 多久刷一次 token |
| 扫码授权窗口 | `refresh_token_observed_at`，**固定 30 天** | 从扫码起，多久后必须重扫 |
| 建议重扫 | 窗口满 **25 天** | 提前提醒，不是失效 |

关键注释说得很明确：**30 天是从「扫码」起算的窗口，不是「最后一次保活」起算**。
所以保活刷得再勤也延长不了它——这正是之前误判「约一天」的根源之一
（那些号其实是被保活跳过 / 常驻不滚 key 搞坏的，不是窗口到期）。

### 本机实测对上了

用新建的「扫码窗口」统计本机（2026-11-05 12:05）：

| 沙箱 | 已免扫 | 换新次数 | 状态 |
|---|---|---|---|
| qb8 | **20.0 天** | 8 | 免扫可用 |
| qb3 | **18.1 天** | 8 | 免扫可用 |
| qb2 | **14.9 天** | 7 | 免扫可用 |
| qb6 | 8.3 天 | 8 | 免扫可用 |

多个号已稳定跑到 15～20 天，与 30 天窗口模型吻合。

### GUI 上的落地

`Core/BoxSummary.cs` 新增：

```csharp
public const int AuthWindowDays = 30;    // 参考模型的窗口长度
public const int RescanWarnDays = 25;    // 满这么多天建议重扫

public DateTime ScanUtc;                 // 扫码时间（取免扫链起点）
public double? ScanDays;                 // 距今多少天
public double? AuthDaysLeft;             // 窗口还剩多少天
public bool RescanSuggested;             // 是否进入建议重扫区
public string ScanAgeShort;              // 表格短文本，如「14.9/30 天」
public string ScanAgeTip;                // 悬停完整说明
public string ScanWindowAlert;           // 满 25 / 超 30 时进 ⚠ 列
```

- 新增表格列 **「扫码已过」**：显示 `天数/30 天`，超过 25 天转橙、超过 30 天转红并显示「已超窗口」。
- 悬停显示扫码时间、剩余天数、**本机实测最长免扫链**、期间换新次数。
- 满 25 天 / 超 30 天时自动进 ⚠ 列（「已被服务端拒绝」优先级更高）。
- `status` 命令行输出同步增加 `扫码窗口 x/30 天` 一行。

注意：数据源是 `ilink-events.jsonl` 里的 `scan-login` / `new-identity` 事件。
如果那个号扫码太久、日志已滚掉，会显示「更早的记录已不存在」，此时天数只是**下限**。

## 6D. 纯协议续期已接入（2026-11-05 12:15）

`tools/mmtls_autoauth.py` 通过 C# 的 `Core/ProtocolRenew.cs` 接入：
按钮「⚡ 纯协议续期」/ 命令 `protorenew qbN`。

### 实测：9 个号全部成功

| 沙箱 | 结果 | 新 key |
|---|---|---|
| qb2 | ✅ | `9960b279`（链式第二次） |
| qb3 | ✅ | `54d6de1b`（链式第二次） |
| qb5 | ✅ | `1b1886bf` |
| qb6 | ✅ | `638a1d5e` |
| qb7 | ✅ | `7a11a394` |
| qb8 | ✅ | `e168cc12` |
| qb9 | ✅ | `219f2842` |
| qb11 | ✅ | `9c5dd85b` |
| qb13 | ✅ | `1fa51f07` |

### 排查中踩的坑（值得记住）

**部署目录的脚本是旧版**。`D:\...\JskpBoxManager-exe\tools\mmtls_autoauth.py` 停留在
10:28 的版本（还没有字段 24 修复），C# 调用它时全部 `-2`；而命令行直接跑仓库里的
新版脚本却成功。表现就是「同一个号，脚本能过、程序不能过」。

判别方法：看日志里有没有 `ilinkAppId=ilinkapp_...` 这一行——
旧版根本没有这行，而且请求体是 580 字节（旧）vs 569/571 字节（新）。

**第二个坑**：无符号 varint 解析。服务端返回 `-2` 是
`18446744073709551614`，C# 里按有符号读会变成 `long.MinValue`，
错误信息就成了 `-9223372036854775808`。

### 发送前落盘（Attempted 保护）

参考实现的关键约束，已在 `ProtocolRenew.Renew` 实现：

```
1. 写 logs\qbN.renew-attempt { at, uin, oldKeySha, stage:sent }
   └─ 写不进去 → 直接放弃，不发送
2. 发送 AutoAuth
3. 成功 → 写回新凭证（--save）+ 删除标记
4. 失败 → 标记保留
```

失败保留标记的意义：下次点续期会先警告「上次（MM-dd HH:mm）结果未知」，
让人自己判断能不能继续，而不是程序盲目重放一把可能已作废的 key。

## 6C. 建议

- **自实现续期已打通**（见 6.3A），不再有「协议层通了但业务层过不去」的卡点。
- 主方案仍建议保留「官方运行时续期」作为兜底：直连每次微信升级都可能失效，且服务端风控未知。
- 接入顺序：先做「发送前落盘 attempted」→ 再接进 C# → 最后才考虑替代官方续期。
- 不要再往「抓 `login_buffer`」方向投入，那条路是因为误判字段 24 才走上的岔路。


