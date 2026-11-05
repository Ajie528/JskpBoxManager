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

结论：`AutoAuth.Device` 只存在于 `login_buffer`（扫码响应），本地没有任何副本。

### 6.7 扫码 hook 的硬障碍：Frida 在 ilink 上注入不可靠

要抓 `login_buffer` 必须 hook 扫码流程（`ManualAuth`，cmdid 3453）。静态定位已完成：

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

1. **在干净沙箱上重试**（如 qb5，凭证 11-05 03:44、未反复启停过），先只挂最轻的 hook，验证 ilink 能否稳定注入。
2. **抓真实 AutoAuth 请求明文**：在 `0x0D7710`(构造) / `0x0D4390`(完整流程) 内部 dump `hybrid_encrypt` 的入参，
   能看到官方正确的 `Device` 与 `appVersion`（静态定位见 `docs/ilink长连接与免扫掉线.md` 9A.4）。
3. **扫码时记录 `login_buffer`**：需在 ilink 注入稳定的前提下进行；否则改成
   「先让扫码完成 → ilink 存活 → 立刻 attach」，牺牲 ManualAuth 但可扫内存。

### 6.9 工具清单

| 文件 | 用途 |
|------|------|
| `tools/mmtls_probe.py` | 只做 mmtls 握手，验证协议正确性（**已成功**） |
| `tools/mmtls_autoauth.py` | 完整 AutoAuth：读凭证 → 构造 → 发送 → 解密响应（`--send` 才发） |
| `tools/mmtls_autoauth_try.py` | 参数矩阵试错（appVersion × device × wpkg 变体） |
| `tools/lean-refresh/locate_manualauth_static.py` | 静态定位 ManualAuth 构造/流程函数 |
| `tools/lean-refresh/locate_autoauth_static.py` | 静态定位 AutoAuth 构造/流程函数 |

依赖：`py -3 -m pip install cryptography lz4`

## 6A. 建议

- 主方案保持「官方运行时续期 + 凭证只进不退」（Full 路径）——**当前零风险且已验证**。
- mmtls 自实现**协议层已通**（握手 / 加密 / 解密 / shortlink 全部验证），只差业务参数。
- 卡点两处：`AutoAuth.Device` 的来源、扫码时 Frida 注入 ilink 不稳定。
- 下一步优先在**干净沙箱**验证注入稳定性，再决定是否继续投入。


