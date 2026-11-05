# ilink 长连接与「免扫掉线」研究

记录 ilink 长连接（noop 心跳）到底能维持多久、关游戏后为什么必须重新扫码，以及
「用 Hook 保住心跳」这条路走到哪一步、为什么走不通。

对应代码：`tools/lean-refresh/hook_longlink.js`、`tools/lean-refresh/longlink_locate.py`、
`tools/lean-refresh/hook_watch.py`（`--longlink-script`）。

---

## 1. 结论先说

| 问题 | 结论 |
|------|------|
| ilink 长连接本身稳不稳 | **很稳**。实测 qb4 连续 17.8 小时、qb15 关游戏后仍持续，零中断 |
| 心跳间隔是多少 | **210 秒**（`next:210000`），由 mars 的 `LongLinkWithMMTLS::__RunReadWrite` 布闹钟 |
| **这个心跳是谁的心跳** | **是微信服务器（腾讯 `longcloud.weixin.com`）的 noop 心跳**，不是游戏服务器的。详见第 1.1 节 |
| 关游戏后为什么必须重扫 | **不是关游戏本身导致的**（见第 3 节 2026-11-04 常驻实测：关游戏后 35 分钟长连接与心跳均正常，`sessiontimeout` 零次）。真正原因是**整箱被停掉时进程被杀**，以及保活被跳过 |
| 「Hook 保住 noop 心跳」能解决吗 | **前提不成立**：心跳从来没断过，所以「保心跳」不是问题所在 |
| 常驻保活能不能保住长连接 | **旧版本不能**（主进程活着但 ilink 早死了，见第 4 节）；1.5.9 起会检测并重连。**1.5.9 实测：常驻确实能保住长连接** |

### 1.1 这个心跳是微信服务器的心跳吗？

**是。** 证据链：

| 证据 | 内容 |
|------|------|
| 连接目标 | `_configMarsNetcore: m_longlink_host_ = longcloud.weixin.com`<br>`SetLongLink: host:longcloud.weixin.com port:80 port:443 port:5000 port:8080` |
| 实际握手服务器 | `task end callback long cmdid:10724, err(0,0,0), svr(101.226.142.220:80, NewDNSIP, longcloud.weixin.com)` |
| 心跳报文 | `start noop taskid:4294967295, cmdid:6, next:210000` → `__NoopResp: noop succ, interval:210000` |
| 协议栈 | `mars::stn::`（腾讯开源的 mars 网络库）+ `LongLinkWithMMTLS`（微信私有 mmtls 传输层） |
| 进程 | `WeChatAppEx.exe --type=utility --... ILinkServiceHost`（微信运行时 WMPF 的 ilink 服务宿主） |

所以要分清两层：

1. **微信层（ilink / mars / mmtls）** —— 连 `longcloud.weixin.com`，管登录态、AutoAuthKey 续期、心跳（`cmdid:6` noop）。**这才是决定「要不要重新扫码」的那一层。**
2. **游戏层** —— 连 `tunnel-dga.scgame.com.cn`、`ws82-t5game2.scgame.com.cn` 等，管游戏内在线状态。

**长连接存活 ≠ 游戏在线。** 关掉游戏窗后游戏层的连接会断（所以游戏里会掉线），但微信层的 ilink 连接可以继续活着——这正是 2026-11-04 实测到的现象。

> 补充：`cmdid:6` 在 mars 里是标准的 **noop（空操作）心跳**，由 `LongLink::__NoopResp` 处理响应。
> 它的作用是让 NAT/防火墙不回收连接、让服务端知道客户端还活着；它**不是**在验证「这个账号的登录凭据是否仍然有效」——
> 后者由业务请求（如 `/ilink/ilinkapp/sys/ilinkapp_autoauth`）的返回决定。

---

## 2. 长连接长什么样（2026-11-04，qb15，游戏全程开启 93 分钟）

```
11-04 12:08:16.042  LongLinkConnectMonitor::LongLinkConnectMonitor: handler:(58376,36)
11-04 12:08:16.044  NetCore::CreateLongLink: create long link default-longlink
11-04 12:08:16.353  LongLink::__ConnectStatus: connect status from:0 to:1   ← 建连
11-04 12:08:16.697  LongLink::__ConnectStatus: connect status from:1 to:2   ← 已连接
11-04 12:08:16.702  __RunReadWrite: start noop taskid:4294967295, cmdid:6, next:210000
11-04 12:08:16.731  LongLink::__NoopResp: end noop
11-04 12:08:16.732  LongLink::__NoopResp: noop succ, interval:210000
11-04 12:08:16.765  __OnLongLinkStatuChanged: cancel auto connect
```

要点：

- 通道是 **mars + mmtls**（`longcloud.weixin.com`，443 / 5000 / 80），不是标准 WebSocket；
- 心跳是 `cmdid:6` 的 noop，`next:210000` 毫秒 = **210 秒**；实测常驻期间有时会降到 **180 秒**（服务端在响应里回 `interval`，客户端照此调整）；
- 连上之后 93 分钟内**没有任何重连或断开**记录。

## 3. 心跳是健康的：qb4 连续 17.8 小时的证据

进程 37656（`ILinkServiceHost` 角色）从 `11-02 17:36` 活到 `11-03 11:23`，按小时统计 noop：

| 小时 | 11-02 18 | 19 | 20 | 21 | 22 | 23 | 11-03 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| noop 次数 | 21 | 21 | 20 | 21 | 24 | 21 | 21 | 21 | 20 | 24 | 20 | 21 | 20 | 21 | 36 | 22 | 20 | 17 |

每小时约 20 次 = 每 3 分钟一次，**没有任何一小时掉链子**。

## 4. 那次「会话失效」的完整时序（qb4，11-03）

死亡前 4 秒的完整时序（`frida-ilink-qb4.jsonl`，pid 37656）：

```
11:23:56.893  StartTaskEx                                    ← 上报 kvcomm 数据
11:23:57.057  LongLinkWithMMTLS::__RunReadWrite: task socket send sock:1708, cmdid:10724
              cgi:/cgi-bin/mmae-bin/aereportkvcomm
11:23:57.097  __RunReadWrite: task socket recv sock:1708, recv len:88     ← 收到响应，链路正常
11:23:57.206  __SingleRespHandle: task end callback err(0, 0, 0)         ← TCP 层完全成功
11:23:57.207  UnPackResponse: resp ilink app head encrypt_algo:0, compress_algo:0, datalen:0
11:23:57.207  UnPackResponse: App layer sessiontimeout!                  ← 业务层拒绝
11:23:57.207  AutoUnPackInternalCgi: UnPackResponse failed!
11:23:57.208  __OnAppSessionTimeout  (this = 0xa8401f0)
11:23:57.210  __OnAppSessionTimeout  (this = 0xa8aef40)
11:23:57.211  __Cancel / CancelAllTask
11:23:57.212  TdiClearLoginStatus                                        ← 清登录态
11:23:57.409  Uninit → Stop → 进程退出
```

关键判读：

1. **不是心跳超时**。`err(0, 0, 0)` 说明这条请求的链路层完全成功，心跳在此前刚成功发过（11:23:57.057）。
2. **是业务层拒绝**。`datalen:0` + `App layer sessiontimeout!`，即服务端回了「这个 app 会话已失效」。
3. **触发点在数据上报**（`aereportkvcomm`），不是纯心跳。
4. **死亡是运行时主动自杀**。`TdiClearLoginStatus` 之后 `Uninit`、`Stop`，130ms 内退出，不是崩溃。

> 顺带纠正一个早前的误判：11-03 10:59 那次「深度压缩内存（含游戏）」**没有**压断长连接——
> 压完之后 ilink 又正常跑了 24 分钟（10:5x 段 254 行、11:0x 段 253 行日志）。当时的 CHANGELOG 归因不准，1.5.8 已改正。

### 4.1 关键更正（2026-11-04 常驻实测）：`sessiontimeout` 不是「关游戏」触发的

上面 11-03 那次看起来像「关游戏 11 秒后被踢」，于是当时判定为「关游戏 → 服务端下发 sessiontimeout」。
**这个因果链是错的**，2026-11-04 的对照实验推翻了它。

实验设置：qb15 开启「常驻 + 实验拦截」，正常进游戏后**手动关掉游戏窗口**，让箱子保持运行。

| 时刻 | 事件 |
|------|------|
| 16:14:10 | 观测器启动（`block session timeout is ON`），三个 hook 全挂上 |
| 16:14:28 | 进游戏，新 key `b1605ba5` |
| **16:16:08** | **关游戏 → `game closed -> enter resident (hide+trim, keep ilink runtime)`**（箱没停） |
| 16:16:17 | `[心跳] noop 发送 #1`（关游戏后 9 秒，心跳照常） |
| 16:17:24 | `noop #2  间隔=67.1s` |
| 16:20:24 | `noop #3  间隔=180.3s` |
| 16:23:24 | `noop #4  间隔=180.3s` |
| 16:24:25 | `noop #5  间隔=60.2s` |
| **16:48:14** | **ilink 进程 24572 仍存活**（关游戏后 32 分钟），CPU 11.28s→12.81s 仍在增长 |
| 16:50:27 | 重启观测器后再次捕获 `noop #1`（ilink 35 分钟仍活跃） |
| 全程 | **`session-timeout` 事件 0 次** |

结论：

- **关游戏本身不会让服务端下发 `sessiontimeout`。** 常驻模式下 ilink 活了 35 分钟以上，心跳（`cmdid:6` noop）稳定 180 秒一次、服务端正常回应，一次 `sessiontimeout` 都没出现。
- 11-03 那次的真相更可能是：**程序在 `game closed -> stop box` 后 7 秒就整箱停掉**，ilink 被 `Sandboxie.Terminate` 强杀；那次 `aereportkvcomm` 上报在进程被杀前后收到了异常响应，才触发 `sessiontimeout` 分支。
- 也就是说：**qb4 反复掉线的真因是「程序自己停箱 + 每日保活被跳过」，而不是服务端踢人。**

> 这也意味着「实验拦截（`--block-timeout`）」在实际场景里可能根本用不上——没有 `sessiontimeout` 需要拦。
> 开关保留，用于将来验证其他路径是否有该回调。

## 5. 为什么「Hook 保存 noop 心跳」救不了（前提本身不成立）

想用 Hook 维持长连接，逻辑前提是「心跳断了导致被踢」。事实不是这样：

- 心跳全程健康（qb4 连续 17.8 小时、qb15 关游戏后 35 分钟，都是 180～210 秒一次、零中断）；
- 真正的失效来自**业务请求**的响应（`App layer sessiontimeout`），与心跳无关；
- 因此「给心跳续命」并不能延长免扫寿命，它守的是连接不断，而不是登录态有效。

这条路的实际价值是**观测**（看清连接与心跳的真实状态），不是**修复**。

## 6. 现在能做什么（按有效性排序）

### 6.1 已验证有效：少冷启、日常真的在玩、保活每天一次

qb1（中华丨阿杰）从 10-30 08:35 扫码起连续免扫到 11-04 09:40，**5 天 1 小时**，全程 `AutoAuth ret=0`。
详见 [`服务端规则测试.md`](服务端规则测试.md) 的「G 组结论更新」。

对照 qb4 之所以约一天就掉：常驻导致保活被跳过 + 常驻期不滚 key + 主进程活着但 ilink 已死。

### 6.2 1.5.9 起：常驻会检测 ilink 是否真的活着

以前的常驻只看 `WeChatRuntimeUp`（微信主进程），**检测不到 ilink 进程已经退出**：

```
qb4 常驻期间 Frida 只挂到 main / network 两个角色，ilink 角色再没出现
```

现在新增 `BoxView.IlinkConnected`（按 `ILinkServiceHost` 命令行判断），常驻循环每轮检查；
发现 ilink 没了就重开 GameUrl 让它重新拉起来并顺带滚一次 key。

### 6.3 常驻到底有没有用（2026-11-04 实测结论）

**有用，而且比之前判断的更可靠。** 常驻模式下：

- 关游戏后 ilink 进程持续存活（实测 35 分钟以上，CPU 仍在增长）；
- 心跳（`cmdid:6` noop）稳定维持，服务端正常回应；
- `sessiontimeout` **零次**。

前提是 1.5.9 修的「ilink 存活检测」要生效——旧版常驻会掉进「主进程活着但 ilink 早死了」的假象里。

### 6.4 最省心的方案

两种都可以，按内存预算选：

| 方案 | 适用 | 说明 |
|------|------|------|
| **每日一次冷启**（推荐） | 内存紧、号多 | qb1 用这套连续免扫 5 天 1 小时。常驻关掉即可 |
| **常驻轻量运行时** | 想让连接一直不断 | 1.5.9 起会检测 ilink 存活并自动重连；关游戏后勤滚 key（6 小时节流 / 20 小时强制） |

---

## 7. 怎么复现观测

### 7.1 只观测（默认，安全）

```text
cd <程序目录>\tools\lean-refresh
py -3 hook_watch.py --box qb1 --out C:\Users\<你>\jskp-frida-qb1.jsonl --seconds 600 ^
    --sbie-dir "C:\Program Files\Sandboxie-Plus"
```

必须在**箱内**运行（Sandboxie 不允许主机向箱内注入）：

```text
"C:\Program Files\Sandboxie-Plus\Start.exe" /box:qb1 /hide_window ^
    D:\Programs\Python\Python313\pythonw.exe hook_watch.py --box qb1 ^
    --out C:\Users\<你>\jskp-frida-qb1.jsonl --seconds 600 ^
    --sbie-dir "C:\Program Files\Sandboxie-Plus"
```

或者用程序自带命令（会自动处理箱内启动）：

```text
JskpBoxManager.exe launch qb1     # 勾了「启动与游戏中也记录授权」即可
```

### 7.2 拦截会话超时（已移除）

这个开关**已在 1.5.17 移除**。它当初只是为了验证一个假设：
「服务端判定 session timeout 后，如果拦住进程不让它退出，长连接还在的话业务是否还能继续用」。

假设已经被否证——2026-11-04 qb15 常驻实测：关游戏后 **35 分钟** ilink 仍然存活、
CPU 持续增长、心跳稳定在 180 秒、`session-timeout` **0 次**。
也就是说掉线根本不是 session timeout 引起的，而是程序自己停箱把进程杀了
（再加上每日保活被跳过）。拦不拦这个回调，对结果没有影响。

现在观测器**只观测不干预**：`__OnAppSessionTimeout` 原样执行，进程该退出就退出，
日志照常记录 `session-timeout` 事件和调用栈。预期结果与解读：

| 观察 | 含义 |
|------|------|
| 日志出现 `[会话超时] blocked` 且进程没死 | 拦截生效 |
| 之后 noop 心跳继续、`ret=0` 恢复 | 意外的好结果：会话可自愈 |
| noop 继续但所有业务请求被拒 | 僵尸连接，无实用价值（**最可能**） |
| 进程仍然退出 | 拦截点选错或还有其他退出路径 |

> 注意：这是**实验开关**，默认关闭。它会跳运行时的 `TdiClearLoginStatus` / `Uninit`，
> 行为未被验证过，可能留下不干净的状态。别在重要的号上开。

### 7.3 关键日志怎么看

| 关键词 | 含义 |
|--------|------|
| `noop succ, interval:210000` | 心跳成功，间隔 210 秒 |
| `App layer sessiontimeout!` | **服务端判会话失效**，这是致命的 |
| `err(0, 0, 0)` | 链路层成功（与业务层结果无关） |
| `TdiClearLoginStatus` | 开始清登录态，紧接着进程就会退出 |
| `__ConnectStatus: connect status from:X to:Y` | 长连接状态机（0=未连 1=连接中 2=已连 3=断开中） |

---

## 8. 工具与实现细节

### 8.1 `longlink_locate.py`

按**日志宏字面量**定位函数（ilink2.dll 没有这些函数的导出）：

```
"mars::stn::LongLink::__NoopResp: "  →  唯一引用它的函数 = __NoopResp
```

做法：找到 `.rdata` 里的字符串 → 扫 x64 的 `lea reg,[rip+disp32]` / `mov reg,imm64` 引用 →
用 `.pdata` 异常目录把引用点归属到函数。结果按 `文件大小+mtime` 缓存到 `longlink_rva_cache.json`。

当前定位结果（`WXRuntime_V22346514299`）：

| 目标 | RVA |
|------|-----|
| `noop_resp` | `0x33d330` |
| `run_read_write` | `0x330d10` |
| `on_session_timeout` | `0x169930` |
| `unpack_response` | `0x1a6360` |

**注意**：`TdiClearLoginStatus` / `OnAppSessionTimeout` 在 DLL 里只以「字符串表」形式出现
（紧挨 `TdiClearSession` / `TdiLogoutAsync`），不是日志宏字面量，按引用定位会落到数据表而不是函数，
所以没有列为可拦截目标——清登录态的时机改为从日志流观测。

### 8.2 `hook_longlink.js`

只注入 ilink 角色进程，`rpc.exports.init({rva, role})`：

- `noop` 事件：记录心跳次数与相邻间隔（验证心跳健康度）
- `session-timeout` 事件：记录触发次数与调用栈（只观测，不拦截）
- `readwrite` 事件：只记耗时 >50ms 的读写循环（正常是空转）

### 8.3 已知限制

- RVA 依赖具体 `ilink2.dll` 版本，升级后自动重新定位（缓存按 size+mtime 失效）。
- 调用栈是简化回溯（读 RSP 连续指针），只作线索，不做精确符号化。
- 拦截模式用 `Interceptor.replace` + `NativeCallback` 返回 void，不保证覆盖所有退出路径。

### 8.4 隔离是怎么生效的（实测澄清）

一开始怀疑「观测器读到了别的沙箱的数据」，2026-11-04 在 qb15 箱内实测后确认：
**隔离判断是准确的，没有跨箱泄漏**。

```
== 自身 ==
self pid=26060  box_of(self)='qb15'

== 枚举所有 WeChatAppEx ==
pid=1256    box=qb1    **别箱**  role=network
pid=53712   box=qb1    **别箱**  role=main
pid=59348   box=qb1    **别箱**  role=ilink
pid=65916   box=qb15   本箱      role=main
pid=54044   box=qb15   本箱      role=ilink
pid=19552   box=qb15   本箱      role=network

== filter 结果 ==
保留(本箱): qb15 的 6 个
跳过(别箱): qb1 的 6 个
```

要点：

- **Windows 进程表是全局的**，箱内能「看见」别箱进程（`psutil.process_iter` 会列出来）。
  这是操作系统行为，不是 Sandboxie 配置问题。
- **真正的隔离靠 `SbieApi_QueryProcess` 归属判断**：它准确返回每个 pid 属于哪个箱。
- 跨箱 **attach 会被拒绝**（`VirtualAllocEx` 返回 `ERROR_ACCESS_DENIED`），这本身就是一道硬隔离。

所以数据不会串，但「看得见」这件事要正确处理。原来 `scan()` 只在 `pid not in self.roles` 时才校验归属，
一旦某个 pid 被记进 `roles` 就不再校验——多开时这是隐患。已改为**每轮都校验归属**。

### 8.5 实测踩到的真 bug（已修）

**bug 1：RVA 缓存被旧结果污染**

改了 `WANTED` 里的 tag 之后，缓存键没变，于是继续返回上一版算出的 `null`：

```
longlink-hooked ... "on_session_timeout": null, "results": {"noop_resp": true, "on_session_timeout": false, ...}
```

现在缓存键带上了 `WANTED` 的指纹，并且**部分失败不写缓存**（下次重算而不是沿用空值）。

**bug 2：同一沙箱可以起多个观测器**

两个观测器同时挂同一批进程，日志每行写两遍、后启动的还会删掉前一个的输出文件。
现在用命名互斥量 `Local\JskpFridaWatch_<box>` 保证一个沙箱只有一个观测器：

```
$ python hook_watch.py --box qbX --out ...   # 第二个进程会打印并退出
qbX 已经有一个观测器在运行，本进程退出
```

**bug 3：`scan()` 读到空 role 就永久放弃该进程（ilink 永远挂不上的元凶）**

进程刚被 fork 出来时 `cmdline` 常常还读不全，`role_of()` 返回空串。旧代码：

```python
if not role:
    self.done.add(pid)     # 永久放弃
    continue
```

于是该 pid 进了 `done`。稍后 frida 的 `child-added` 事件到来，`claim()` 发现已在 `done` 里，返回 `False`，
结果**只 resume、不 attach**，而且一条错误日志都不写。表现就是：`child` 事件有 ilink，但永远没有 `frida-attached`。

现在改为：连续 10 轮（约 1 秒）读不出角色才放弃；并且 `scan()` 会重试「已 claim 但无活跃 session」的 pid。

**bug 4：`handle_child` 的异常被静默吞掉**

它跑在 daemon 线程里，`pythonw` 下 stderr 不可见，异常等于消失。现在加了 `child-handler-err` 兜底记录（含 traceback）。

**bug 5：`scan()` 抛异常会中断整个观测循环**

外层只有 `except KeyboardInterrupt`。现在包了 try + `scan-err` 记录，并每 60 秒写一行心跳
（`[心跳] 观测中：已挂 N 个进程…`），用来区分「在扫但没目标」和「卡死在某个调用里」。

**bug 6：DNS 主机名乱码（`hook_ilink.js`）**

`u16()` / `u8()` 直接调 `readUtf16String(max)`，内存里没有 NUL 结尾时会一路读越界，把堆上的垃圾一起返回。
日志里 `wpad����…`、`cdn-t5game1.scgame.com.cn�ۺ��ۺ…` 就是这么来的。

现在先按上限读一块固定长度、在块内找 NUL 截断；再用 `normHost()` 按白名单
（字母 / 数字 / `-` / `.` / `_` / `:`）截到第一个非法字符。实测：

```
'wpad\x00x'                        -> 'wpad'
'cdn-t5game1.scgame.com.cn\x01\x02' -> 'cdn-t5game1.scgame.com.cn'
'cdn-t5game1.scgame.com.cn纵纵'      -> 'cdn-t5game1.scgame.com.cn'
'\x01\x02'                          -> ''
```

### 8.6 观测器必须在微信运行之后再启动（否则白跑）

`hook_watch.py` 靠 `scan()` 轮询发现 `WeChatAppEx`。如果观测器比浏览器先启动，
在它启动后的短窗口内箱里没有目标进程，就只能一直空转到 deadline。

实测 qb15 15:23:02 启动的观测器，虽然随后浏览器起来了，但那个实例全程 0 attach；
在同一时刻重起一个观测器立刻挂上 main/ilink/network 三个进程。

**结论**：想观测一次启动过程，用 `JskpBoxManager.exe launch qbN`（它在浏览器前起观测器，靠出生即拦截）；
想补挂已经在跑的沙箱，直接单独起 `hook_watch.py`。

---

## 9. 下一步值得测的

1. **常驻扛不扛得过 24 小时**（最关键的待验证项）。2026-11-04 已确认常驻 35 分钟内心跳与连接全正常，
   但还没跑满一天。如果常驻能扛过，就可以替代每日冷启。
2. **`aereportkvcomm` 上报频率**与 `SmcCore hit freqlimit` 积压的关系：
   qb4 那次 `sessiontimeout` 前 1 分钟有大量上报积压，是否与「长时间不活跃 → 集中补报」有关。
3. ~~**`--block-timeout` 是否还有必要**~~：本次实测 `sessiontimeout` 零次，说明正常场景用不上。
   已在 1.5.17 移除该选项，观测器改为只观测不干预。

## 9A. 主动触发 AutoAuth 的三条路（2026-11-04 试过两条不通，第三条待收尾）

目标：不冷启动也能让运行时发一次 `AutoAuth` 来续期。逐条验证如下。

### 9A.1 CDP 调 `wx.login` —— 握手被拒

```
getcode qb15 --no-ensure  →  取码失败：The operation was canceled.
qb15.log                  →  wx.login getCode failed: The server returned status code '500'
                              when status code '101' was expected.
```

`status 500 when 101 expected` = **WebSocket 升级被拒**，不是页面没 `wx`。
停掉 Frida 观测器后重试仍失败，排除注入干扰；两个游戏中心标签页都试过。

> 附带发现：`getcode` 的 `ensure` 逻辑会把 resident 状态的箱重新拉进游戏
> （`17:50:35 wx.login: game not up -> ensure running` → `17:50:43 resident: game window back`），
> 但那次并没有触发 AutoAuth。

### 9A.2 重开 GameUrl / RuntimeOnly —— 不触发

| 做法 | 结果 |
|------|------|
| `RuntimeOnly`（只启 WeChatAppEx） | 微信进程起来（`wxPid` 正常、`boxPids` 稳定），120 秒内 **AutoAuth 0 次** |
| resident 态 `StartBrowser(GameUrl)` | 游戏窗回来了、ilink CPU 涨了，**AutoAuth 0 次**，key 不变 |
| CDP `Page.reload` 游戏中心 | 命令发出但页面未重载（ws id 未变），**AutoAuth 0 次** |

原因一致：**运行时自认为 app session 仍然有效**（ilink 进程活着、心跳正常），不需要重新授权。
它只在 session 失效或进程冷启动时才发。

### 9A.3 Frida 主动调 —— 机制可行，但最初的定位方法错误（附教训）

**定位方法（可复用）**：给 `hook_ilink.js` 加 `stackOnAuth`，命中 AutoAuth 相关日志时用
`Thread.backtrace` 采栈，再用 `.pdata` 异常目录把返回地址归属到函数。

冷启动一次拿到的 `SendAutoAuthRequestAsync` 调用栈（ilink2.dll 内 RVA）：

```
0x2269FA -> func 0x2269CB  (52B)    ← 日志包装
0x22CAF2 -> func 0x22C9D0  (347B)
0x229BAD -> func 0x229B70  (70B)
0x22267A -> func 0x2224D0  (498B)
0x2224AA -> func 0x2223C0  (268B)
0xD6097  -> func 0xD5FE0   (559B)   ← 顶层调度
```

`0x229B70` 的反汇编（当时据此判定它是 `SendAutoAuthRequestAsync` 本体）：

```asm
48 89 54 24 10   mov [rsp+10h], rdx
4c 89 44 24 18   mov [rsp+18h], r8
4c 89 4c 24 20   mov [rsp+20h], r9
53               push rbx
48 83 ec 20      sub rsp, 20h
48 8b d9         mov rbx, rcx            ; rcx = this
48 c7 41 48 00…  mov qword [rcx+48h], 0
48 83 c1 38      add rcx, 38h
…                ; 清空 [rcx+38h] 的 std::string
e8 83 b5 ff ff   call 0x225130           ; 疑似 SendRequestEx
48 8b c3         mov rax, rbx
```

#### 实测验证：这个判断是错的

第一次尝试「抓 this 后主动调用」时，直接 hook `0x229B70` 观察，结果：

```
autoauth-call 事件 638 次，来自 37 个不同的 this 指针：
  0x13548140, 0x13548270, 0x135483a0, 0x135484d0, ...（每次 +0x130，疑似数组）
  0x1359e4a0, 0x1359e5d0, ...（另一段）
```

再用 `NativeFunction` 主动调用一次：

```json
{"ev": "autoauth-invoke", "thisPtr": "0x49674f0", "ok": true, "ret": "0x49674f0", "callsBefore": 234}
```

**调用本身成功、进程没崩、返回值正常**（符合 `mov rax, rbx`），但：

| 观察 | 结果 |
|------|------|
| 新增 `AutoAuthResponse` | ❌ **0 次**（唯一那条是运行时自己在 18:18:34 发的） |
| key 变化 | ❌ 仍是 `23853ed2`（18:15:31） |
| 游戏窗口 | ✅ 仍在，进程正常 |

**三条证据推翻原判断**：

1. 被 **37 个不同 `this`** 调用 —— AutoAuth 应该只有一个 `TdiAuthManager` 实例；
2. 调用 **638 次** —— AutoAuth 不可能这么频繁；
3. 主动调用后**没有产生任何 AutoAuth 请求**。

结论：`0x229B70` 是个**通用的请求发送/日志包装函数**（清一个 string + 调通用发送），
**不是 `SendAutoAuthRequestAsync`**。

#### 教训：从调用栈反推函数是错的

「栈上出现了这个地址」只能说明它在调用链上，**不能说明它就是那个函数**。
我当初直接从栈帧推出「`0x229B70` = `SendAutoAuthRequestAsync`」，这个推断不成立。

正确的定位思路应该是：**只挑「调用次数少（1–2 次）、`this` 唯一、且紧邻 `cmdid 3198` 发送点」的函数**，
再用「调用它之后是否出现新的 `AutoAuthResponse`」来验证。

#### 但这轮验证了一个有价值的事实

**Frida 能在运行中的 ilink 进程里安全调用内部函数而不崩溃**（`ok: true`、进程存活、游戏在跑）。
也就是说机制可行，只是**没调对函数**。这条路技术上没被堵死，但需要更精确的定位，
且即使找到，常驻态下调用是否被服务端接受仍未验证。

### 9A.4 静态定位的正确方法：找 URL 字符串的代码引用（2026-11-04 突破）

前面 9A.3 的失败暴露了一个方法论错误：**用「日志采栈」反推函数**。
采到的是「日志输出时」的栈，而我们要找的是「构造请求时」的函数——两者完全不同的调用路径。

**正确做法：找业务标识串（URL / cmdid）在代码里的引用。**

`/ilink/ilinkapp/sys/ilinkapp_autoauth` 这个 URL 在构造请求时**一定被引用**，
比日志字面量（死符号、无引用）可靠得多。工具：`tools/lean-refresh/locate_autoauth_static.py`。

定位结果（`WXRuntime_V22346514299`）：

```
"/ilink/ilinkapp/sys/ilinkapp_autoauth"  fileoff=0x770258
    ↓ 代码引用（lea rip+disp32）仅 1 处
0xD7710  (161B)   构造 AutoAuth 请求
    ├─ 引用该 URL
    └─ mov dword [rbx+10h], 0xC7E    ← 0xC7E = 3198 = AutoAuth 的 cmdid
    ↓ 唯一调用者（仅 1 处）
0xD4390  (895B)   完整的 AutoAuth 流程
    ├─ call 0xD7710   ← 构造请求
    ├─ call 0xB41C0   ← 设置凭证
    ├─ call 0x224F60  ← 发送
    └─ call 0x222D50
```

**`0xD7710` 的关键反汇编片段**：

```asm
+025  c7 43 10 7e 0c 00 00   mov dword [rbx+10h], 0xC7E   ; cmdid = 3198
+034  48 8d 0d 75 4b 83 00   lea rcx, [全局]
+066  41 b8 25 00 00 00      mov r8d, 25h                ; 长度 37 = URL 字节数
+06D  48 8d 15 d6 9a 69 00   lea rdx, [AutoAuth URL]     ; ← URL
+078  e8 86 96 fd ff         call 0xB0E10                ; 赋值
```

**与误判函数的对比（说明静态定位更准）**：

| 函数 | 被调用 | 不同 this | 含 cmdid 3198 | 结论 |
|------|--------|-----------|----------------|------|
| `0x229B70`（旧误判，来自采栈） | 638 次 | **37 个** | ❌ | 通用发送包装 |
| **`0xD4390`（静态定位）** | **1 次** | 1 个 | ✅ | **真正的 AutoAuth** |

#### 尚未完成的验证

**`0xD4390` / `0xD7710` 还没有被「主动调用」成功过。** 但静态定位本身已经用**行为**验证过了：

在游戏正常运行期间（ilink 进程已稳定、无登录动作），对这两个函数挂 hook 观察 40 秒：

```
[hook 结果] [{"name":"auto_auth","ok":true,"addr":"0x7ffa513e4390"},
             {"name":"auto_auth_build","ok":true,"addr":"0x7ffa513e7710"}]
观察 40 秒（游戏正常运行）→ 最终 state: {}      ← 零触发
```

| 函数 | 游戏运行 40 秒内的触发次数 |
|------|---------------------------|
| `0xD4390`（静态定位） | **0** |
| `0xD7710`（静态定位） | **0** |
| `0x229B70`（旧的误判） | **638** |

**0 次 vs 638 次**——这从行为上证明了静态定位是对的：AutoAuth 只在登录时发生一次，
而通用函数会在各种请求里疯狂触发。

#### AutoAuth 的精确时序（2026-11-05 00:39 实测，qb15 冷启动）

这一条对「主动 hook」很关键：

```
00:39:53.725   SendAutoAuthRequestAsync: -->       ← 进程起来后约 1 秒
00:39:53.769   TdiSendRequest cgi=AutoAuthRequest, body 206B
00:39:54.435   socket send (mmtls)
00:39:54.799   TdiCheckCgiResponse cgi=AutoAuthResponse, error=0 ret=0
00:39:59       （我们那次把 hook 延后 1.5 秒，结果 00:39:59 才 ready，完全错过）
```

**从 ilink 进程创建到 AutoAuth 完成只有约 4 秒。** 所以 `hookAutoAuth` 必须**立即挂**，
不能靠 `setTimeout` 延迟——1.5 秒的延迟就已经错过了整个请求。

（早前那次「延后 1.5 秒」是因为怀疑注入竞态导致 `ProcessNotRespondingError`。
后来验证：那个崩溃是**手动 `Start.exe` 启动、跳过 warmup** 造成的，
走程序 `launch`（内含 `warmup sandbox`）时注入稳定，多次 `attached=3/4, err=0`。
延迟已移除。）

#### 下一步如果要继续

1. 用程序 `launch`（**不要**手动 `Start.exe`，否则大概率注入失败）。
2. 打开实验开关（`keepalive.json` 的 `"invokeAutoAuth": true`，v1.5.10 起支持）。
3. hook 现在会立即挂上，应在 `00:39:53.7` 这个时间点抓到 `0xD4390` 的调用与参数。
4. 抓到后自动等 2 秒再主动调一次，判据是「是否出现新的 `AutoAuthResponse` + key 是否换新」。

> 注意：`0xD4390` 是完整流程（895B），参数不止 `this`。
> hook 里已把 `args[0..3]` 全部记录，需要看实测数据才知道哪个才是对象指针。

### 9A.5 结论

**目前没有任何可行手段让常驻态「主动续期」。** 冷启动仍是最可靠的方式，实测 24 秒完成：

```
18:06:26  冷启动（key = 16:14 的 b1605ba5）
18:06:49  SendAutoAuthRequestAsync
18:06:52  AutoAuthResponse error=0 ret=0
18:06:50  key → 23853ed2   ← 换新
```

#### 为什么「hook 抓 this 再主动调」这条路失败了（时序窗口只有 4 秒）

2026-11-05 00:39 在 qb15 上做了一次完整的冷启动观测，拿到了精确时序：

```
00:39:53.725   SendAutoAuthRequestAsync: -->
00:39:53.769   TdiSendRequest cgi=AutoAuthRequest, body 206B
00:39:54.799   TdiCheckCgiResponse cgi=AutoAuthResponse, error=0 ret=0   ← 完成
```

**从 ilink 进程创建到 AutoAuth 完成只有约 4 秒。**

而 Frida 的注入链路本身就吃掉大部分窗口：

```
ilink 进程创建
  → hook_watch.py 的 100ms 轮询发现它
  → device.attach() + create_script() + load()  ≈ 200–300ms
  → exports_sync.init() 到 JS 里的 hookAutoAuth 执行
  → 才轮到 Interceptor.attach(0xD4390)
```

即便把 `hookAutoAuth` 的延迟从 1.5 秒改成 0（已改），实测仍然没赶上（`autoauth-call` 计数 0）。

**正确方向（若以后还想做）**：不要「attach 已启动的进程」，而应 `frida.spawn()` 挂起启动 →
装好 hook → `resume()`。这样 hook 在第一条指令前就位，不存在抢不到窗口的问题。

#### 2026-11-05 实测：这两条替代路径也都不通

在 qb15 箱内验证后确认，`spawn` 方案在 Sandboxie 环境里同样不可行：

| 方案 | 结果 |
|------|------|
| **`device.enable_spawn_gating()`** | ❌ **`NotSupportedError: not yet supported on this OS`** —— frida 17.24.3 在 Windows 上根本没实现 spawn gating |
| **`device.spawn(沙箱内 exe 路径)`** | ❌ Sandboxie 会重定向进程路径，host 侧拿不到可 spawn 的沙箱内路径 |
| attach 已启动的 ilink | ❌ 4 秒窗口抢不到（见上） |

**结论：在「程序自己 launch → 浏览器 → WeChatAppEx → ilink」这条链上，
没有任何办法在 AutoAuth 之前把 hook 装好。**

#### 所以这个方向到此为止

即使能做成，收益也很小：冷启动一次只需 **24 秒**，而现有机制已经覆盖了
「每日自动保活」和「弹码时自动试历史凭证」（v1.5.11）。主动续期省下的只是那 24 秒。

保留的工具（`tools/lean-refresh/`）：

| 文件 | 用途 |
|------|------|
| `hook_ilink.js` 的 `stackOnAuth` | 命中 AutoAuth 日志时采栈，用于动态定位未知函数 |
| `hook_ilink.js` 的 `invokeAutoAuth()` / `autoAuthState()` | RPC：查看是否抓到 this、主动调用（仅在有 this 时安全） |
| `autoauth_probe.py` / `autoauth_verify.py` | 箱内独立实验脚本，验证上述流程 |
| `locate_autoauth_static.py` | **静态定位 AutoAuth 函数（按 URL 字符串的代码引用找），这是本轮最有价值的工具** |
| `longlink_locate.py` 的 `DYN_RVA` | 记录定位出的 RVA（**换 WXRuntime 版本必须重新做静态定位**） |

> 实验过程中的一个环境教训：**短时间内反复 stop/launch 同一个沙箱**会让 Sandboxie
> 报 `SBIE2203 与 Sandboxie 服务的通信失败: RPCSS_SXS`（沙箱内 DCOM/RPC 组件来不及初始化）。
> 服务本身没问题（`SbieSvc` 仍 Running、新建沙箱正常），停箱后重试即可。
> 做这类实验时节奏要放缓，每次之间留足时间。

## 10. 观测已跑通（2026-11-04）

### 10.1 qb1：三个 hook 全挂上（15:30）

```json
{"ev": "longlink-hooked", "pid": 59348, "role": "ilink",
 "rva": {"noop_resp": 3396400, "run_read_write": 3345680, "on_session_timeout": 1481104, "unpack_response": 1729376},
 "results": {"noop_resp": true, "on_session_timeout": true, "run_read_write": true}}
```

心跳事件（`[心跳] noop 发送 #N 间隔=Ns`，写在 `.txt` 里、不写 jsonl 以免撑大）：

```
2026-11-04 15:31:34 [心跳] noop 发送 #1 间隔=-s
2026-11-04 15:32:21 [心跳] noop 发送 #2 间隔=47.0s
```

（47 秒是首个基准，之后稳定在 180～210 秒。）

### 10.2 qb15：常驻 + 拦截，关游戏后 35 分钟实测（16:14–16:51）

```json
{"ev": "frida-attached", "pid": 24572, "role": "ilink", "ms": 51}
{"ev": "longlink-hooked", "pid": 24572, "on_session_timeout": 1481104, ...,
 "results": {"noop_resp": true, "on_session_timeout": true, "run_read_write": true}}
{"ev": "longlink-attached", "pid": 24572}
```

完整时间线：

| 时刻 | 事件 |
|------|------|
| 16:14:10 | 观测器启动，`block session timeout is ON` |
| 16:14:28 | 进游戏，新 key `b1605ba5` |
| **16:16:08** | 手动关游戏 → `enter resident`（箱没停） |
| 16:16:17 | `noop #1`（关游戏后 9 秒） |
| 16:17:24 | `noop #2` 间隔 67.1s |
| 16:20:24 | `noop #3` 间隔 180.3s |
| 16:23:24 | `noop #4` 间隔 180.3s |
| 16:24:25 | `noop #5` 间隔 60.2s |
| **16:48:14** | **ilink 24572 仍存活**（32 分钟），CPU 11.28s→12.81s |
| 16:50:27 | 重启观测器，再次捕获 `noop #1` |
| **16:51:49** | **ilink 存活 35 分钟**，CPU 13.11s，`session-timeout` 计数 **0** |

**结论：关游戏不会导致 `sessiontimeout`；常驻能维持 ilink 长连接与心跳。** 详见第 4.1 节的更正说明。
