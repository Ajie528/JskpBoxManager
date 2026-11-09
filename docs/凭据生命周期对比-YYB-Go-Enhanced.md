# 凭据生命周期与保活：YYB-Go-Enhanced vs 本仓库

> 调研日期：2026-11-09 ｜ 上游 `VERSION = 0.2.81`（commit `a778d63`）｜ 本仓库 `v1.5.36`（commit `5505bb5`）
> 方式：两侧源码逐段静态阅读 + 对照两份既有调研（上游 `仓库总览.md` / `保活链路深挖.md`）。
> **本文只记录与对比，未修改任何代码。**

---

## 0. 一页结论

| 问题 | YYB-Go-Enhanced | 本仓库（JskpBoxManager） |
| --- | --- | --- |
| 凭据是什么 | **四件、三层寿命**：OAuth token（约 2h）+ login_buffer + ILink PSK 会话（缓存 30m，实按服务端期限）+ native AutoAuth 材料（一次性） | **一层一体**：`tdi_account.txt`（AutoauthKey/EncKey/ServerId）+ `psk.key` + 配套文件，全是文件 |
| 凭据从哪来 | 纯 HTTP 扫码（`open.weixin.qq.com/connect/qrconnect`）→ 回调 → `pcyyb_get_wx_login_buffer_auth` | 真实 QQ 浏览器 + 微信运行时扫码，**运行时自己写盘**，我们只负责搬运与备份 |
| 存在哪 | SQLite `wechat_accounts.credentials` + `sessions` 表 | 文件系统：沙箱内 `WXRuntime_Log`（live）+ 金库 `profiles\qbN\wmpf` + 30 份历史快照 |
| 谁是"状态" | 数据库一个 `status` 字段（`alive/unknown/session_only/expired`），写入走 **CAS** | 没有单一字段：`live 有效？`+`金库？`+`作废登记`+`need-scan 标记`+`BoxPhase`，全部由文件派生 |
| 续期动作 | HTTP 刷新 OAuth token（**不轮换 AutoauthKey**） | 真实 AutoAuth（cmdid 3198）**每次都会轮换 key** |
| 续期频率 | 每 2 分钟扫全部账号，到期前 4 分钟刷（token 2h） | 默认**每天 1 次**（04:00 起各箱错开 10 分钟），密钥满 20h 强制 |
| 判死依据 | 类型化错误 + 错误码白名单（40030/42002/42007/40188/relogin…） | AutoAuth 返回 `-13/-14`，或运行时清空凭证文件 + 扫码页持续 N 秒 |
| 判死的副作用 | `expired` 会**抹掉凭据与缓存会话**（不可逆） | 只写 `need-scan` 标记 + 作废登记，**凭据文件不删** |
| 撤销后能否重建 | `session_only` → native AutoAuth（**一次性材料**，用完只能扫码） | 30 份历史快照逐把协议探测（**每把 0.1 秒**），全废才要求扫码 |
| 风控应对 | 五层：设备指纹固定 / 取码限速 / 熔断 / 登录预算 / AppID 黑名单 | 一层半：探测频率（≥30min、≤8 次/天、±35% 抖动、20–70s 间隔）+ 调度错峰 |
| 观测 | 结构化事件日志（7 天 1 万条）+ SQLite | `ilink-events.jsonl` + 每箱日志 + `AuthChain` 从日志回溯免扫链 |

**一句话**：上游是**在服务端重放微信客户端**，所以它必须造一套数据库状态机去管理"我看不见服务端真实状态"这件事，并用大量限流去压"重放本身产生的异常流量特征"；我们是**在本地编排真实客户端**，凭据是运行时自己写的文件，所以状态管理退化成"文件比新旧"，但换来一个新问题——**每次续期都是真轮换，轮换次数直接暴露给服务端**。

---

## 1. 上游：凭据生命周期的完整链路

### 1.1 三个层次的"活"（不是一件事）

这是理解上游全部代码的前提，来自 `docs/credential-session-layers.md` + 源码：

| 层次 | 对象 | 寿命 | 存哪 | 失效后 |
| --- | --- | --- | --- | --- |
| OAuth 授权 | `refresh_token` / `access_token`（`LoginBufferCredentials`） | 约 **2h**（`internal/protocol/loginbuffer.go:_requestCredentials` 把 `expires_in` 默认 7200） | `wechat_accounts.credentials` JSON | 用保存的 `login_buffer` 重登 |
| ILink 会话 | `WmpfSession`：UIN、F9、DeviceID、SendKey/RecvKey、**PSK** | 缓存 TTL **30m**（`internal/protocol/pool.go:54`），实际按服务端下发的 `PSK.ExpiredAt` | `sessions` 表 | 要 PSK 才能重建 → 走 native AutoAuth 或重新扫码 |
| AutoAuth 材料 | `Device`/`Key`/`EncKey`（来自 ManualAuth 响应） | **一次性**（`autoauth.go:30-32`：`AttemptedAt == 0` 才可用） | `sessions.session_blob.native_autoauth` | 用完即废 |

**关键推论**：OAuth 死了 ≠ ILink 会话死了 ≠ AutoAuth 材料还能用。后面所有"看起来矛盾"的代码，根源都在这里。

### 1.2 扫码 → login_buffer

```
GET  open.weixin.qq.com/connect/qrconnect  (appid=wxd44977328b36e647, snaapi_login,snaapi_runtime_pcsdk)
  ↓ 轮询 long.open.weixin.qq.com/connect/l/qrconnect         internal/qr/qr.go:PollQRCode
回调 yybadaccess.3g.qq.com/pc_yyb/pcyyb_oauth?code=...        ← 换 cookie 里的 openid/accesstoken/refreshtoken
  ↓                                                          qr.go:GetLoginBuffer → credentialsFromJar
POST yybadaccess.3g.qq.com/pc_yyb_auth/pcyyb_get_wx_login_buffer_auth
  ↓ MD5 签名头 Ual-Access-Signature = md5(body+ts+key+nonce)  loginbuffer.go:sign
login_buffer ← ext_info.list_s.login_buffer.value[0]
  ↓
POST /qr/{id}/confirm → storeFromScan → UpsertAccount(credentials.ToMapForScan())
```

三点值得注意：

1. **`GetLoginBuffer` 有 8 秒重试窗口**（`internal/httpapi/qr_confirm.go`）：微信"已授权"和 buffer 可读之间有延迟，重试只重发同一个 buffer 请求，不轮换任何东西，所以安全。
2. **`ToMapForScan()` 单独存在**：只有真正扫码写入 `refresh_token_observed_at`（扫码时间），续期不覆盖它。这是 30 天窗口的锚点，防止老记录被"刚刚扫过"污染。
3. **PCMgr / GameAssist / QQBrowser 三个渠道各走自己的换码端点**（`pcmgr.ExchangeCode`、`gameassist.ExchangeCode`、`qbbrowser.FetchBuffer`），但最后都汇进同一个 `WmpfSession`。

### 1.3 会话 → 取码（PSK 会话池）

`internal/protocol/pool.go` 的 `state()` 是整条链的枢纽，顺序不可颠倒：

```
读账号（CAS 快照 SameAuthorization 校验）
  → cachedSession(account, proxy)      命中且 PSK 未过期 → 直接用（CachedOnly = SessionOnly()）
  → session_only 且无 native 材料        → ErrCachedSessionUnavailable（硬失败，不重登）
  → 抢 (account,proxy) 锁 + 再读一次        （双检，防并发建会话）
  → session_only 且有 native 材料        → restoreNativeSession（轮换 AutoAuthKey）
  → 否则：loginSem 限流 → loginAndSession(loginBuffer)
        DNS 发现 → mmtls 握手 → cmdManualAuth(3453) → 提取 session + AutoAuthKey + PSK
  → PutSessionForAccount（CAS：账号在这一瞬间被重扫就整笔丢弃）
```

**注意 `cachedSession` 的一个历史兼容分支**（`pool.go:390-418`）：老版本把缓存硬砍在 30 分钟，即使服务端给的 PSK 还没到期。现在 `legacyDeadline` 分支只校验 PSK 真实期限就复用，不重写期限、不触发 ManualAuth。

### 1.4 状态机：四个状态 + 两条写入路径

| 状态 | 含义 | 落库时的副作用 |
| --- | --- | --- |
| `alive` | OAuth 有效 | 无 |
| `unknown` | 未验证 / 暂失败 / 凭据缺失 | 无（保留原凭据等重试） |
| `session_only` | **OAuth 被明确拒绝**，但 ILink 会话可能还能用 | 清 `credentials`（只留渠道标记 + `refresh_token_observed_at`）+ 清 `login_buffer` |
| `expired` | 终态，必须重扫 | 清空 `login_buffer` **和** `credentials`，并 `DELETE FROM sessions` |

来源：`internal/store/store.go:863-906`（`ApplyCredentialRefresh` 里 `if status == "expired"` / `if status == StatusSessionOnly` 两段改写，事务末尾 `count == 1 && status == "expired"` 再删 sessions）。

```
                    ┌────────── 扫码 / ManualAuth ──────────┐
                    ▼                                       │
   (新账号) ──► unknown ──刷新成功──► alive ──到期前 4m──►[后台续期]──► alive
                    │                   │                          │
                    │                   └──刷新失败(非终态)──► unknown ──┘
                    └──刷新失败(决定性拒绝)──┐
                                            ▼
                                         expired  ← 手动标记 / 凭据被抹（终态，三条路径都不再尝试）
                                            │
                    ┌── 判 expired 但该路由还有可复用 ILink 会话 ──┐
                    ▼                                          │
              session_only ◄───────────────────────────────────┘
                    │
                    ├── 取码 -14 且不在 2m 新鲜窗口 → native AutoAuth（一次性）
                    │        ├ 成功 → 仍是 session_only，PSK 换新
                    │        └ 失败 → 材料作废，只能重扫
                    └── 没有任何后台机制延长它
```

**两条写入路径的副作用不同**（这是容易看漏的地方）：

- `ApplyCredentialRefresh`（CAS，后台/按需刷新用）：只写库；`expired` 时由调用方补 `invalidateProxyLease` + `notifyOffline`。
- `setAccountStatus`（管理侧人工改状态）：`expired` 时额外 `InvalidateAccountSessions` + `invalidateProxyLease` + `clearKeepAliveRetry` + `circuit.forget`。

不是不一致，是分工：后台判死时要先尝试"降级保留会话"，所以不能无条件清。

### 1.5 续期：后台循环

`internal/httpapi/keepalive.go`：

- 每 `KeepAliveInterval`（默认 **2m**，`cmd/yyb-go/main.go:29`）扫一轮，启动即扫一次；每轮最多 **4 并发**（`:69`）。
- 过滤（`:77-82`）：`expired` 跳过、`session_only` 跳过、退避未到跳过。
- **`setting.Mode == "api"` 的账号无条件跳过**（`:124-130`）——动态代理租期短，用新 IP 续凭据保不住会话。这类账号在无人调接口时静默过期。
- 到期判定（`:491-498`）：pcmgr 用原生 `NextRenewAt()`（`RenewInterval/2`，未知时 1 天）；其余 `now + ahead >= ExpiresAt`，`ahead` 默认 **4m**（观察值，不是上游文档）。
- 单次刷新（`refreshAccountOnce`）顺序：抢每账号锁 → **重读数据库** → `expired` 直接返回 → `session_only` 返回错误 → 凭据缺失置 `unknown` → 未到期且非 force 直接返回 → 刷新 → 失败定状态 → **若定成 `expired` 先看该路由还有没有可复用 ILink 会话，有就降级 `session_only`**（`:275-284`）→ CAS 写库。
- **非 `force` 成功即结束，不取新 login_buffer**（`:310-315`）。buffer 恢复按需发生 → 意味着后台跑得再欢，buffer 也可能已经陈旧。

### 1.6 判死：全仓最严的一套白名单

`definitiveCredentialFailure`（`keepalive.go:375-428`）只认**类型化错误**：

- `ErrMissingRefreshToken`
- `*RefreshRejectedError` / `*LoginBufferRejectedError`，且满足其一：
  - code ∈ {**40030, 42002, 42007**}（正则 `rejectedRefreshCode` 也扫原始文本）
  - code/message 含 **40188** 且含 `invalid scope`
  - 含 `relogin` / `重新登录` / `重新授权`
  - **同时**含 `invalid|expired|过期|失效|无效` **和** `refresh token`（含中文"刷新令牌"）
- 递归 `Unwrap()`，且**多错误走 `Unwrap() []error`**——因为"刷新拒绝"和"check-login 兜底"是两个独立原因，`errors.As` 会停在第一个模糊拒绝上。
- **明确不算死**：传输错误 / 代理错误里出现的 `token expired`。

配套的 `-109` 处理（`loginbuffer.go:278-289`、`keepalive.go:466-473`）：`_auth` 路由把撤销包装成模糊的 `-109`，所以补一次官方 **check-login** 去拿决定性错误码，否则"被撤销的账号永远拿不到结论，只会无限重试"。

### 1.7 撤销后的"重建"：三条路径，责任是分开的

| 路径 | 触发 | 判死依据 | 能做什么 |
| --- | --- | --- | --- |
| `keepalive.go` 后台续期 | 到期前 4m | **唯一能写 `expired`** 的地方（白名单） | 尝试降级 `session_only` |
| `code_recovery.go` 取码修复 | 取码 `-14` | 只要求"应用层拒绝" | 保存票据重登（`recoverCodeWithTickets`）或 native 恢复（`session_only`） |
| `autoauth.go` native 恢复 | `session_only` 且材料可用 | 不判死，只成功/失败 | 轮换 AutoAuthKey + 取新 PSK |

取码修复的节制（`code_recovery.go`）：
- 新鲜窗口 **2m**：同一会话刚成功取过码，`-14` 更可能是 AppID 自己的拒绝 → 跳过修复（记 `protocol.recovery_skipped`）。
- 同一 `(账号, 路由, AppID)` **5 分钟**内不重复修。
- 走**登录预算** `AllowLogin`，用完保留原错误且**不记退避**（窗口滑过还能修）。
- 只在候选会话**取到非空 code** 后才原子替换共享缓存，失败保留旧会话和首次错误。

native AutoAuth 的硬约束（`autoauth.go`）：
- `cmdAutoAuth = 3198`，**只连一次、只发一次**，绝不在另一个节点重试。
- `AttemptedAt` 在**发送前**落库（`:239-245`）——旋转密钥一旦发出，服务端结果不可重放。
- 拒绝分三级：`transport`（`ints[4]`）/ `application`（`ints[23]`）/ `business`（内层 `[1]`）。
- 成功但 PSK 提取失败 → 把 PSK `ExpiredAt` 写成 `now-1s` 并**仍然保存 rotation**（密钥已经转了，不保存才真废）。

### 1.8 三条路径的判定一致性（复核结论）

| 维度 | 后台续期 | 取码修复 | native 恢复 |
| --- | --- | --- | --- |
| 把 `expired` 当终态 | 是 | 是 | 是 |
| 会**产出** `expired` | 会（唯一来源） | 不会 | 不会 |
| 判死严格度 | 严格（白名单） | 宽松（只要 `-14`） | 不判 |
| 传输错误算不算死 | 不算 | 不算 | 不算 |

**结论：`expired` 语义一致，严格度分层是有意为之**——责任集中在唯一有定价权的那条路径上。原调研担心的"三份实现互相打架"不成立。

---

## 2. 上游"风控应对"那一套：到底在防什么

先记住作者的自我定位（`docs/authorization-stability.md` 开头）：

> **这些措施是流量控制和诊断手段，不是修复**，不能恢复已被微信撤销的授权。默认值是保守的起点，不是测出来的安全值。

按"防哪种死亡路径"分类，比按版本号分类清楚得多：

### 2.1 防"成功的突发"（取码限速）

`internal/httpapi/pacing.go`。依据是一次正式环境事件：一个授权在 **7.5 秒内连续成功取到 12 个 code**，随后每一层都被拒。熔断只统计失败、登录预算只统计 OAuth 层调用，**全都拦不住一串全成功的请求**，所以补了限速：

- 每账号一个槽位队列，相邻请求至少隔 `YYB_CODE_MIN_GAP`（默认 **3s**），槽距超过 `MAX_WAIT`（默认 20s）**立即本地 429**，不打上游。
- `pacingMaxGap = 1m`、`pacingMaxWait = 2m` 是硬上限；`tuning.json` 可热改（1 秒生效，缺键沿用默认，解析失败保留上一次）。
- 拒绝走 `circuitOpenError{Scope:"pacing"}`，映射成统一的本地 429，语义上与上游 502、需重扫 409 区分开。

### 2.2 防"OAuth 层调用密集"（登录预算）

`internal/protocol/login_budget.go`。依据是回放实验：**约 150 秒内 38 次登录票据**就让一个健康授权被拒；而同期"没有任何任务触达"的授权连续续期成功。

- 滑动窗口，默认 **3 次 / 10 分钟**，只管**业务请求触发**的调用（新票据、ManualAuth、强制刷新）。
- 用完 → 请求保留原错误、**不向上游发起登录**、也不为这个 AppID 登记退避（窗口过后仍可修）。
- 后台续期与面板手动刷新**不受限**（定时或人工，次数少）。
- 作者明确记录：**这个上限在两轮对照回放里一次都没被触及**，也没有证据表明它带来额外保护。

### 2.3 防"反复撞同一个拒绝"（两级熔断）

`internal/httpapi/circuit.go`：

| 层 | 触发 | 冷却 |
| --- | --- | --- |
| target（账号 × AppID × 请求类型） | 连续 2 次 `-14`，或 3 次空 code | 10 分钟 |
| session（整个账号） | **5 分钟内 3 个不同 AppID 都被 `-14`** | 15 分钟 |

关键约束（都写在注释里，说明作者很清楚误判的代价）：
- 熔断是**纯本地决策**，不改账号状态、不清凭据、不碰数据库，返回本地 429。
- 只有 `-14` 与空 code 计入；网络、ManualAuth、OAuth、取消**都不算**（`circuitOther`）。
- 只有**取码**请求的 `-14` 计入 session 层（`countsTowardSession`）；取号/operateWxData 的拒绝只喂自己的 target。
- 任一成功 → 两层状态全清。
- 表满 4096 时优先丢"最近没活动"的，并限流打一条饱和日志，绝不让熔断卡住健康流量。

### 2.4 防"错的东西打上游"（AppID 策略，双层且会自学习）

`internal/httpapi/appid_policy.go`：

- **静态黑名单**：`wx5cd60c5d4817a188`（腾讯电脑管家网站应用）、`wx2f5d8f9715c59d10`（京东护照）。依据是"一次这样的取码就让两个健康账号丢授权"。命中直接本地 **403**，不发上游。
- **动态学习**：某 AppID 取码"到了上游但没返回 code"，在**2 个不同账号**出现、或**累计 4 次**就永久禁用（存 `app_settings`，重启不丢）；任一成功清空计数。阈值可运行时改。
- `YYB_CODE_ALLOW_APPIDS` 永远优先（连学习结果都删掉）。

### 2.5 防"看起来像另一台设备"（设备指纹）

`internal/protocol/device.go`：`HMAC(instanceSeed, "yyb-go/app-device/v1", openid)` → 每账号一套**确定性** AppDeviceId + 本地管理型 MAC。同一实例内重启、重建缓存、重扫同一个号，设备都不变；不同账号、不同实例永不共享。

### 2.6 会话保护窗口（防"误判过期"）

`code_recovery.go` 的 2 分钟新鲜窗口。作者自己在注释里承认代价：*"在一个会话只够取一次码的账号上，守卫恰好拒绝了那个本来会成功的修复"*。

### 2.7 这套东西的已知边界（照作者口径）

- 没有任何已验证的办法保证长期不掉线，也没验证过 30 天保活。
- 熔断只统计失败、预算只统计 OAuth 调用，**全成功的突发它们拦不住**，限速补这个缺口。
- 登录预算的上限在两轮对照里一次都没被触及，没有证据表明它带来额外保护。
- 观察到的相关性：新授权几乎都在**偶数整点**的批量取码后失效（因果未验证）。
- 网站应用 AppID 取一次码后授权被拒：**机制未知**，所以默认拒绝。
- 小程序 AppID 与 H5/公众号/原生 APP AppID **不能混用**。

**我的判断**：这一整套的价值不在"保证不掉线"，而在**把不可控的上游行为变成可控的本地行为**——所有拒绝都有确定的 HTTP 语义（429/403/409/502），脚本侧可以据此退避；所有事件都带 `app_id`/`rejection`，掉线后能复盘到"最后 3 分钟取过哪些 AppID"（`account.expired` 的 `recent` 字段）。这是诊断能力，不是治愈能力，而作者从头到尾没说反。

---

## 3. 本仓库：凭据生命周期

### 3.1 只有一层"活"，而且它是文件

我们不做 OAuth，也不需要 login_buffer。凭据就是微信运行时写盘的这一套：

```
<沙箱>\user\current\AppData\Local\Tencent\QQBrowser\User Data\WXRuntime_Log\
    ilink\default\tdi\ilinkapp_xxx\0\6\tdi_account.txt
        kTdiKeyAutoauthKey / kTdiKeyAutoauthEncKey / kTdiKeyServerId / kTdiKeyUin / kTdiKeyDeviceId / kTdiKeyIlinkAppId
    ilink\default\psk.key
    + 配套文件：device_uuid_0、Applet\...\applet.db(-wal/-shm)、WMPF\mpfastload\mpkv.db(.crc)
      （清单见 Ilink.CompanionRels）
```

`Ilink.Read()` 判"有效"只要：`AutoauthKey` 非空 + `EncKey` 非空 + `Uin` 非空且 ≠ 0。KeyHash = `SHA256(key|enc)[:16]`。

三段式存储（路径见 `BoxPaths`）：

| 位置 | 角色 |
| --- | --- |
| `BoxPaths.WmpfLive`（沙箱内 `WXRuntime_Log`） | 运行时正在用/要用的那份 |
| `BoxPaths.WmpfVault`（`profiles\qbN\wmpf`） | 金库，沙箱清空/换机可还原 |
| `profiles\qbN\credential\history\<yyyyMMdd-HHmmss>-<key8>-<原因>\` | **历史快照，保留 30 份**（`Ilink.HistoryKeep`） |

### 3.2 状态不是字段，是五个独立信号

| 信号 | 实现 | 含义 |
| --- | --- | --- |
| `live.Valid` / `vault.Valid` | `Ilink.Live/VaultState` | 文件层面是否可解析 |
| `vault.WriteUtc > live.WriteUtc + 2s` | `Ilink.Save/Restore` 的比较 | 谁更新（2 秒容差防误判） |
| 作废登记 `profiles\qbN\credential\revoked.txt` | `Ilink.RegisterRevoked/IsRevoked` | 这把 key 被服务端明确拒过 |
| `need-scan` 标记 `profiles\qbN\refresh-need-scan.txt` | `NeedScan.Set/Clear/Superseded` | 判定必须重新扫码 |
| `BoxPhase`（`logs\qbN.state.json`） | `BoxStatusFile` | 界面阶段：Stopped/Starting/WaitingScan/InGame/Resident/Refreshing/Failed |

界面上的"免扫可用 / 疑似失效 / 需要扫码 / 未登录"是 `BoxSummary.Build()` 从上面这些信号**推导**出来的，不是存下来的。

**与上游最大的结构性差别**：上游有一个 CAS 的 `status` 字段，一次事务决定"这次刷新结果算不算数"；我们没有 CAS，用的是
- 文件 mtime 比较（`Save` 遇 `vault-newer` 直接拒写、`Restore` 遇 `live-newer` 先 adopt 再返回）；
- 进程级互斥（每箱 `LaunchSession.TryLock` + 全局 `Local\JskpBoxManager.Keepalive` 12 分钟）；
- 一次性快照（`protocol-renewed.json`，30 分钟内有效）+ `DropSnapshot()` 在"有意换凭据"时主动失效。

这套机制覆盖了本场景（单机、单写者、沙箱是排他的），但它**没有**上游那种"刷新期间账号被重扫 → 整笔结果丢弃"的原子保证，靠的是"沙箱运行中不允许续期"这条更粗的纪律。

### 3.3 三条"判死"的路径

| 路径 | 判据 | 后果 |
| --- | --- | --- |
| 协议续期返回 `-13/-14` | `ProtocolRenew.Exchange` 的 `code` ∈ {-2,-13,-14} | 先逐把试历史，全废才 `NeedScan.Set("protocol-renew-revoked")` |
| 运行时清空凭证 + 扫码页持续 | `Ilink.RevokedSinceLaunch` + `HasStrictQr` 持续 15s（refresh）/ 60s（重试轮）/ 20s（recover 单把） | 标 `suspected-revoked`，**先不烧 key**，恢复金库重试一次 |
| 扫码连续失败 2 次 | `NeedScan.RegisterQrFailure` | `need-scan` |

### 3.4 续期：两条完全不同的路

**(A) 冷启动（最可靠）**：计划任务 → `refresh qbN` → 停箱 → 推金库 → 开浏览器 → 等运行时就绪 → **运行时自己发 AutoAuth** → `Ilink.WaitRenewed` 检测 `tdi_account.txt` 被重写 → 存金库 → 停箱。6 分钟超时、最多 2 次。

**(B) 纯协议续期（`ProtocolRenew`）**：C# 直连 `longcloud.weixin.com:5000`，mmtls 握手 + `cmdAutoAuth(3198)` + Hybrid ECDH，**0.5 秒**，不开浏览器。

(B) 的三条硬约束，和上游 native AutoAuth 几乎同构：

1. **发送前先落盘** `logs\qbN.renew-attempt`（`at/uin/oldKeySha/stage`）；写不进去就**放弃发送**。理由与上游 `AttemptedAt` 一致：旋转一旦被接受，旧 key 立即作废，先发后写会因断网/被杀变成"服务端已换新、本地还是旧的"。
2. **必须沙箱已停**（`CheckRenewable`）。qb15 实测：运行中续期成功后 **2 秒**被运行时写回旧 key，4 秒后游戏窗消失。
3. **写回后存一份快照** `protocol-renewed.json`，运行时若把旧 key 写回就自动纠正；快照 **30 分钟后失效**（qb16 曾因快照长期存在来回打架）。

### 3.5 撤销/失效后的重建：历史快照 + 协议逐把探测

这是本仓库最独特的一块，也是 v1.5.36 刚加固的地方：

```
当前 key 被拒 / live 无效 / 冷启动失败
  → CredentialHistory(box)：金库 + 30 份历史快照，按 IsVault → SavedAt 降序，跳过已作废
  → 逐把 ProbeFile()：只发 AutoAuth，不停箱、不开浏览器、不写文件（每把 ≈0.1 秒）
        ├ 服务端返回 -13/-14 → 这把废了，下一把（零成本）
        ├ 网络错误          → 下一把
        └ 返回 0            → **这时才停箱** → RestoreCredentialSet → CommitToFile 落新 key
  → 全废 → need-scan（reason=history-all-failed）
```

支撑它的是一条实测知识：**服务端不是"只认最新一把"**——10 月 16 / 18 日的旧 key 放了 20 多天仍然有效，qb10/qb12 就是这样救回来的。这跟上游"PSK 会话按路由缓存"是完全不同的思路：上游缓存的是**当前会话**，我们缓存的是**历史 key 序列**。

**作废登记的必要性**：被服务端明确拒绝（-13/-14）的那一把必须登记，否则历史探测每轮都会把它再试一遍，白白多打一次上游请求。反过来，`ClearRevokedKey` / `ClearRevoked` 支持人工翻案（赌这次是本地损坏而非真被顶）。

> v1.5.37 修了两处：① `RegisterRevoked` 的调用点在 1.5.18 移除 Frida 记录时被一起删掉了，`revoked.txt` 此后**再没被写过**；现在协议续期与探测被拒时都会调新增的 `RegisterRevokedKey`。② 原实现会**连带**把金库里同号更旧的 key 一并作废，这与"旧 key 常仍可用"的实测冲突，已改为只登记真正被拒的那一把。

### 3.6 我们这一侧的风控意识

只有频率，没有请求级限流——因为**我们本来就没有"请求级入口"**：`/wxapp/getCode` 对本游戏取不到码，`/token` 是一次冷启动 2 分钟的一条龙。所以"突发取码打死授权"这条路径在我们这儿不存在。

实际存在的频率控制（`CredentialProbe`）：

| 措施 | 值 | 依据 |
| --- | --- | --- |
| 探测最短间隔 | **30 分钟** | qb4 在 2026-11-07 被每 2 分钟探测连滚 4 次 key，当天下午整条链被作废 |
| 每号每天轮换上限 | **8 次** | 同上 |
| 到期时间抖动 | **±35%** | 不踩点 |
| 首次错开 | 每箱 ≈1.6 分钟（97s×箱号 + 随机） | 多箱同时启动不挤在同一分钟 |
| 同轮间隔 | 随机 **20–70 秒**，**串行不并发** | 同一公网 IP 几秒内连发十几个 AutoAuth 是明显异常特征 |
| 保活调度 | 默认每天 04:00，各箱错开 10 分钟 | qb15 闲置 3 天 0 次续期仍免扫；qb4 每 2 小时冷启反而约一天失效 |

注意最后一条的结论与上游**方向相反**：上游要"勤续期"（token 2 小时），我们要"少续期"（key 约 1 天）。原因不是谁对谁错，而是**续期的语义不同**——上游刷新 token 不动 AutoAuthKey，我们每次续期都在真轮换 key，**轮换本身才是风险**。

---

## 4. 逐项对比

### 4.1 生命周期对象

| 对象 | 上游 | 本仓库 |
| --- | --- | --- |
| OAuth token | 有，约 2h，后台每 2m 盯 | **无**（不走 YYB OAuth） |
| login_buffer | 有，按需取；非 force 续期不刷新 | **无** |
| ILink 会话（PSK） | 有，`sessions` 表，TTL 30m / 服务端 PSK 期限 | **无独立会话概念**，运行时自己的 psk.key 随凭证一起备份 |
| AutoAuthKey | 有，ManualAuth 响应里自带，随会话重建而轮换 | **有，是唯一的凭据主体**，由我们主动轮换 |
| 历史 key 序列 | **无** | **有，30 份快照** |
| 作废登记 | 无（靠 `expired` 终态 + 删 sessions） | **有**，`credential\revoked.txt` 逐 key 粒度 |
| 扫码时间锚点 | `refresh_token_observed_at`（在 credentials JSON 里） | `logs\qbN.scan.json`（独立文件，避免日志滚动丢失） |
| 30 天窗口 | **只实现了 25 天"建议重扫"**（`store.go:1155` 的 `>= 25*24h` → `rescan_recommended`），**没有 30 天硬闸门** | 两档都算：`AuthWindowDays = 30` 转红、`RescanWarnDays = 25` 转橙（`BoxSummary`），且明确标注"参考模型"，与本地实测寿命并列显示 |

> 关于 30 天：两边都不是硬编码拦截，只是一个**观察模型**。上游把它做成 `rescan_recommended` 提示位（`internal/store/store.go:1155`）；我们做成界面列 + 告警（`BoxSummary.AuthWindowDays`）。真正决定能不能用的永远是服务端——我们 `docs\服务端规则测试.md` 里实测到的最长免扫链是 **5 天 1 小时**（qb1，10-30 08:35 扫码 → 11-04 09:40 全程 `AutoAuth ret=0`）；而 `ilink长连接与免扫掉线.md` 记录的另一次失效（qb1，密钥空闲约 10.2h 后被拒）作者已明确判定**不是空闲时效**。两个数都比 30 天窗口短得多，所以这个窗口在我们这边基本只起"提醒"作用，不是真实约束。

### 4.2 状态与并发

| 维度 | 上游 | 本仓库 |
| --- | --- | --- |
| 状态载体 | 数据库 `status` 字段（4 值） | 5 个文件/派生信号，无单一字段 |
| 并发写保护 | **CAS**（`ApplyCredentialRefresh` 的 `WHERE ... credentials IS ? AND status IS ?`） | 文件 mtime 比较 + 进程互斥 + 30 分钟快照 |
| 过期快照作废 | `SameAuthorization`（ID+OpenID+credentialJSON 一致） | `DropSnapshot` / `snapshot expired` / `vault-newer` 拒写 |
| 重扫竞态 | 整笔刷新结果丢弃（`applied == false` → `unknown`） | 靠"沙箱运行中禁止续期 + LauncherPid 锁"回避，非原子 |

### 4.3 判死严格度

| 维度 | 上游 | 本仓库 |
| --- | --- | --- |
| 依据 | 类型化错误 + 错误码白名单 | 协议返回码 `-13/-14/-2` + 运行时清空文件 + 扫码页持续时间 |
| 传输错误 | 明确不算死 | 不算死（`ProbeFile` 网络错误只换下一把） |
| 会不会误杀 | 宁可 `unknown` 也不误判 `expired` | 有 `Suspected` 中间态：凭证被清 + 扫码页持续 N 秒才算"疑似"，且**先不烧 key** |
| 判死是否破坏性 | **是**，抹凭据 + 删会话 | **否**，只写标记；凭据文件保留（历史仍可回溯） |

### 4.4 撤销后的可恢复性

| 场景 | 上游 | 本仓库 |
| --- | --- | --- |
| OAuth 被撤销 | `session_only`，PSK 会话可续用 | 不适用（无 OAuth） |
| 被别的设备扫码顶掉 | 只能重扫（refresh token 不可恢复） | 只能重扫（`-13` 后逐把历史全废，写 `need-scan`；作废登记防止反复试） |
| 本地文件损坏 / 被写回旧值 | 有 `session_only` + native AutoAuth（一次性） | **30 份历史 + 0.1s/把协议探测**，命中即换新，不停箱 |
| 一次网络抖动 | native 材料被 `AttemptedAt` 烧掉，无第二次机会 | `renew-attempt` 保留标记，下次先告警而非盲目重放；历史路径可绕过 |

**这一项是我们明显强于上游的地方**，但强的原因不是工程更好，而是**观察到了"旧 key 不一定废"这个事实**——上游没有这条观察，所以它只能做"一次性材料 + 会话缓存"。

### 4.5 上游风控措施在我们这边的"对应物"

| 上游措施 | 我们有没有 | 说明 |
| --- | --- | --- |
| 固定设备标识 | 等价 | 沙箱里的 `device_uuid_0` + `kTdiKeyDeviceId` 是运行时自己的持久设备，天然固定 |
| 取码限速（3s） | **不需要** | 无请求级取码入口（CDP 取码对本游戏不通） |
| 熔断（target/session） | **不需要** | 同上；我们的"重复撞拒绝"由作废登记 + 每日上限解决 |
| 登录预算（3 次/10m） | **部分有** | `MaxRotationsPerDay = 8`，但统计口径不同（见 4.6） |
| AppID 黑名单 | 等价 | 只允许本游戏 `wx31a9c726536cdacc`（`WxLoginCode.Get` 里硬拒其它 appid） |
| 会话保护窗口（2m） | **无直接对应** | 上游用它避免"刚验证成功又被 -14 就重登"；我们没有请求级登录，最接近的是 `NeedScan.Superseded`（新凭证写入即清标记，避免拿旧标记降级）和 `Suspected` 的持续观察窗口 |
| tuning.json 热调参 | **部分等价** | `keepalive.json` / `notify.json` 每次 `Load()` 现读，改完下一次判断即生效；缺的是"文件写坏时保留上一次有效值"的兜底 |
| 掉线通知 | 有 | `Notifier`，按 key 哈希限流（同一把 key 6 小时内只推一次） |
| 掉线前请求快照 | **无** | 我们不是请求驱动，没有"最近 3 分钟取过哪些 AppID"这个概念 |

### 4.6 三个值得记录的差异细节

**(1) 轮换次数的统计口径不完整。**

我们的 `MaxRotationsPerDay = 8` 只在 4 处记账：`RefreshSession` 的协议续期、`LaunchSession` 的预检、`RecoverSession` 的两种探测。**冷启动成功**（运行时自己发 AutoAuth）和**手动开游戏**滚出来的新 key 只记 `key-rotated` 事件，不进 `rotate-log`。也就是说：一天里手动开关游戏 20 次，key 滚了 20 次，但"今天已换 8 次"的判据仍然是 0。上游的登录预算则覆盖了业务请求触发的所有 OAuth 调用（后台与手动除外），口径统一。

**(2) 我们的退避是"等下一次调度"，上游是"per-account 定时器"。**

上游有 `keepAliveRetryAt` 内存表（5m / 15m / remaining÷2），进程重启即清（已知弱点 R7）。我们失败后没有 per-account 退避，直接等计划任务的下一次（每天一次或每 N 小时）——更慢但更"少打扰上游"，也算符合"越勤越容易滚断"的实测。副作用是：一次临时故障会浪费一整天的窗口。

**(3) 我们的"终态"比上游软，但需要人工。**

上游 `expired` 是数据库终态，后台循环永远不再碰它；我们 `need-scan` 也只是个文件标记，`RefreshSession.Core` 开头就 `return`（`:190-194`），但 `NeedScan.ClearIfRenewed` 会在"任何来源产生了更新的有效凭证"时自动清除——包括用户手动开沙箱扫码、导入凭证、历史探测成功。这比上游的单向终态更宽容，代价是状态判断分散在 6 个文件里，读代码的人必须同时看几处才能说清"这个号现在到底什么状态"。

---

## 5. 结构性差异的根因（为什么不能直接互相抄）

| 根因 | 上游 | 本仓库 |
| --- | --- | --- |
| **谁是客户端** | 服务端**重放**客户端（mmtls/ilink/ManualAuth 自己实现） | **编排**真实客户端（Sandboxie + QQ 浏览器 + WeChatAppEx） |
| 后果 1 | 看得见协议每一层 → 可以做细粒度判定、缓存会话、native 恢复 | 只看得到文件 → 状态必须从 mtime/内容/hash 派生 |
| 后果 2 | 任何流量特征都是"假的" → 必须限流伪装 | 流量就是真实客户端 → 不需要伪装，但**轮换次数是真的** |
| 后果 3 | 一个实例服务多账号、多 AppID、多租户 | 一机一号一沙箱，单 AppID，无多租户 |
| 后果 4 | 凭据进数据库 → 状态可 CAS、可审计、可多进程 | 凭据在沙箱里 → 只能靠文件搬运 + 停箱纪律 |
| **失败面** | OAuth 被撤（主要）+ 被顶 | **被顶（主要）+ 30 天窗口 + 本地文件损坏/写回** |
| **优化目标** | 别被上游判定为异常流量 | 别把 key 滚断、别把本地状态搞乱 |

**所以"上游 2 分钟一次、我们一天一次"不是水平差距，是对象差距**：它续的是 2 小时的 token，我们滚的是寿命约一天、且**每滚一次就消耗一次风险额度**的 AutoAuthKey。

---

## 6. 两边的真实缺口对照

### 6.1 上游的已知缺口，在我们这边的对应物

| 上游缺口 | 我们这边 |
| --- | --- |
| **R1：`session_only` 没有后台续命机制**，唯一活路是一次性 native 材料，材料用完或 PSK 到期就只能扫码 | **不存在**：我们靠 30 份历史快照 + 0.1s/把探测，是"多把可试"，不是"一次机会" |
| **R2：AutoAuth 材料一次性且不可重试**，弱网一次抖动就烧掉一张票 | **缓解但未根治**：`renew-attempt` 保留标记避免盲目重放，历史路径可换下一把；但**单把凭证**的抖动仍然只能靠下一把 |
| **R3：`api` 模式代理账号被后台续期完全跳过**，无人调接口时静默过期 | **不存在**（无代理维度），但有同类问题：只有计划任务在跑，**界面没开、任务没注册就等于无保活** |
| **R4：非 force 续期不刷新 `login_buffer`**，buffer 可能陈旧 | **不存在**（无 buffer），但**同类问题存在**：金库与 live 之间靠 mtime 比较，如果运行时"合法地"写了第三把 key 而我们正好在用旧快照纠错，会来回打架（qb16 案例，已用 30 分钟快照有效期缓解） |
| **R5：2m 新鲜窗口与"一会话一码"账号冲突** | 同类风险较小（我们不做请求级修复），但 `Suspected` 的 15s/60s 阈值同样是经验值 |
| **R6：并发刷新不按代理维度错峰**，同 IP 多账号同 tick 一起刷 | **我们做得更好**：串行 + 20–70s 随机间隔 + ±35% 抖动 + 每箱错开 |
| **R7：退避表只在内存**，重启即清 | 我们相反：状态全在文件，重启不丢，但**没有 per-account 退避** |
| **R8：读配置失败时"照常刷"** | 同类：`RefreshSession` 多处 `catch {}` 后继续（`NeedScan.ClearIfRenewed`、`Ilink.Save` 失败等），偏向"继续做"而非"停下来" |

### 6.2 我们的缺口，上游没有

| 缺口 | 位置 | 严重度 |
| --- | --- | --- |
| ~~轮换计数不覆盖冷启动~~ | `Ilink.Save` 的 `key-rotated` 分支 vs `CredentialProbe.RecordRotation` | **已修（v1.5.37）** |
| **状态分散在 6 个文件**，没有人能一眼回答"这个号现在什么状态" | `Ilink` / `NeedScan` / `BoxStatusFile` / `ScanBaseline` / `AuthChain` / `BoxSummary.Build` | 中（可维护性，不是正确性） |
| **无原子快照语义**：金库/live/历史/作废/need-scan 各自独立更新，没有上游那种"一笔事务决定结果算不算数" | `VaultSync` / `Ilink` | 中（已用锁 + 停箱回避，但依赖"纪律"而非"机制"） |
| ~~失败后无退避，只能等下一次调度~~ | `RefreshSession.Core` 末尾 | **已修（v1.5.37）**：落盘退避 + 每小时唤醒 |
| **参数不热更新** | `keepalive.json` / `notify.json` 由 `Load()` 每次调用现读，实际上已是热更新；缺的只是"写坏了保留上次有效值"的兜底（`tuning.json` 那种语义） | 低 |

---

## 7. 如果要互相借，借什么（仅建议，本文未改代码）

按"收益 ÷ 风险"排序：

| 优先级 | 建议 | 借自 | 状态 |
| --- | --- | --- | --- |
| 1 | **让 `key-rotated` 统一进 `rotate-log`** | 上游"登录预算口径统一"的思路 | **已实施（v1.5.37）**：`Ilink.Save` 产生 `key-rotated` 时记账，按 key 哈希去重 |
| 2 | **给 `need-scan` 加"上次尝试时间 + 下次可试时间"** | 上游 `keepAliveRetryAt`（但落文件） | **已实施（v1.5.37）**：`NeedScan.RegisterFailure/ClearRetry`，30min 起、翻倍、封顶 6h |
| 3 | 计划任务改为高频唤醒 + 沙箱侧判断 | 上游"每 2m 扫全部账号、按账号决定是否到期" | **已实施（v1.5.37）**：`Keepalive.DecideWake` + `PT1H` 重复触发 |
| 4 | 密钥还新时不为了"确认"去轮换 | 上游"非 force 续期不取新 buffer"（等价思路：不做无谓动作） | **已实施（v1.5.37）**：`Keepalive.DefaultMinKeyAgeHours = 6`（可按沙箱调） |
| 5 | 修复作废登记丢失，且不连带作废旧 key | 我们自己的实测（旧 key 常仍可用） | **已实施（v1.5.37）**：新增 `RegisterRevokedKey`；`RegisterRevoked` 不再连带 |
| 6 | **给上游提一个 PR：历史 key 快照** | 我们 | 待办（未做） |
| 7 | 学上游的 `tuning.json` 兜底 | 上游 | 待办（未做） |
| 8 | 学上游的事件词表纪律 | 上游 | 待办（未做） |

**不建议借的**：请求级限流 / 熔断 / 登录预算。我们没有请求级入口，引入只会增加无人受益的复杂度。

### 实施时的两个关键修正（读代码才发现的坑）

1. **退避不能盖过"密钥已过硬上限"**：原本密钥超 20h 就该强制续，若同时处于 6 小时退避期，
   等于让它自然过期——用"救上游"换了"丢账号"。现在 `DecideWake` 里密钥超龄时无视退避，
   且失败登记用 `urgent` 把退避压到 30 分钟。
2. **每小时唤醒会放大轮换次数**：interval 模式或"今日已到点"在整天都成立，会让补跑变成
   整天反复滚 key，远超 `MaxRotationsPerDay`。现在两个分支都加了额度兜底。

---

## 附录：本次核对过的位置

**上游（YYB-Go-Enhanced `0.2.81`）**

- `internal/protocol/loginbuffer.go` 全文（凭据结构、刷新、check-login、buffer 取用、脱敏）
- `internal/protocol/pool.go` 全文（会话池、CAS、legacy 缓存兼容、blob 序列化）
- `internal/protocol/code_recovery.go` 全文（取码修复、新鲜窗口、5 分钟退避、登录预算接入）
- `internal/protocol/autoauth.go` 全文（cmd 3198、一次性材料、三级拒绝、发送前落盘）
- `internal/protocol/login_budget.go`、`device.go`、`internal/pcmgr/client.go`（`NextRenewAt`）
- `internal/httpapi/keepalive.go` 全文（循环、过滤、退避、白名单、降级 session_only）
- `internal/httpapi/pacing.go`、`circuit.go`、`appid_policy.go`、`qr_confirm.go`、`offline_notify.go`、`app.go`（扫码确认、`invokeWXApp` 的拒绝分流）
- `internal/store/store.go:846-910`（`ApplyCredentialRefresh` / `SetAccountStatus`）、`internal/store/account_rebind.go`
- `internal/qr/qr.go`、`internal/qr/channels.go`
- `docs/credential-session-layers.md`、`authorization-stability.md`、`code-pacing-20261102.md`

**本仓库（JskpBoxManager `v1.5.36`）**

- `Core/Ilink.cs`、`Core/ProtocolRenew.cs`、`Core/RecoverSession.cs`、`Core/RefreshSession.cs`
- `Core/NeedScan.cs`、`Core/CredentialProbe.cs`、`Core/Keepalive.cs`、`Core/VaultSync.cs`
- `Core/AuthChain.cs`、`Core/ScanBaseline.cs`、`Core/BoxSummary.cs`、`Core/BoxStatusFile.cs`
- `Core/LaunchSession.cs`（预检、历史恢复、常驻续期）、`Core/WxLoginCode.cs`、`Core/ProtocolServer.cs`
- `docs/保活选项说明.md`、`docs/ilink长连接与免扫掉线.md`、`docs/mmtls直连可行性研究.md`、`docs/服务端规则测试.md`

**未验证 / 仅从代码推断**

- 上游 `login_buffer` 自身是否有有效期（代码里没有显式 TTL）
- 本仓库"一天里手动开关游戏多次"对服务端风控的实际影响（无对照实验）
- 上游动态 AppID 学习阈值（2 账号 / 4 次）在单账号部署下的实际触发频率
