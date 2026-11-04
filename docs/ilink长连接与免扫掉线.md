# ilink 长连接与「免扫掉线」研究

记录 ilink 长连接（noop 心跳）到底能维持多久、关游戏后为什么必须重新扫码，以及
「用 Hook 保住心跳」这条路走到哪一步、为什么走不通。

对应代码：`tools/lean-refresh/hook_longlink.js`、`tools/lean-refresh/longlink_locate.py`、
`tools/lean-refresh/hook_watch.py`（`--longlink-script` / `--block-timeout`）。

---

## 1. 结论先说

| 问题 | 结论 |
|------|------|
| ilink 长连接本身稳不稳 | **很稳**。实测 qb4 连续 17.8 小时、每小时约 20 次 noop 心跳，零中断 |
| 心跳间隔是多少 | **210 秒（3.5 分钟）**，由 mars 的 `LongLinkWithMMTLS::__RunReadWrite` 布闹钟 |
| 关游戏后为什么必须重扫 | 服务端在业务层回 **`App layer sessiontimeout!`**，运行时随即 `TdiClearLoginStatus` → `Uninit` → **进程自杀** |
| 「Hook 保住 noop 心跳」能解决吗 | **不能**。心跳本来就没断过，踢人的不是心跳超时，而是服务端在业务响应里判会话失效 |
| 常驻保活能不能保住长连接 | **旧版本不能**（见第 4 节：主进程活着但 ilink 早死了，整段常驻是「假长连接」）；1.5.9 起会检测并重连 |

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
- 心跳是 `cmdid:6` 的 noop，`next:210000` 毫秒 = **210 秒**；
- 连上之后 93 分钟内**没有任何重连或断开**记录。

## 3. 心跳是健康的：qb4 连续 17.8 小时的证据

进程 37656（`ILinkServiceHost` 角色）从 `11-02 17:36` 活到 `11-03 11:23`，按小时统计 noop：

| 小时 | 11-02 18 | 19 | 20 | 21 | 22 | 23 | 11-03 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| noop 次数 | 21 | 21 | 20 | 21 | 24 | 21 | 21 | 21 | 20 | 24 | 20 | 21 | 20 | 21 | 36 | 22 | 20 | 17 |

每小时约 20 次 = 每 3 分钟一次，**没有任何一小时掉链子**。

## 4. 真正的原因：服务端在业务层判会话失效

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
3. **触发点在数据上报**（`aereportkvcomm`），不是纯心跳。也就是说服务端在「你还有没有在真正使用」这件事上有独立判定。
4. **死亡是运行时主动自杀**。`TdiClearLoginStatus` 之后 `Uninit`、`Stop`，130ms 内退出，不是崩溃。

对照：关游戏发生在 `11:23:46`，`sessiontimeout` 在 `11:23:57`，相隔 11 秒。时间上确实紧跟关游戏，
但**直接扳机是那次上报的响应**，这也解释了为什么有时关游戏后还能撑一阵。

> 顺带纠正一个早前的误判：11-03 10:59 那次「深度压缩内存（含游戏）」**没有**压断长连接——
> 压完之后 ilink 又正常跑了 24 分钟（10:5x 段 254 行、11:0x 段 253 行日志）。当时的 CHANGELOG 归因不准，1.5.8 已改正。

## 5. 为什么「Hook 保存 noop 心跳」救不了

想用 Hook 维持长连接，前提是「心跳断了导致被踢」。事实不是这样：

- 心跳全程健康，服务端仍然踢；
- 踢的信号来自**业务响应**，与心跳无关；
- 就算拦掉 `__OnAppSessionTimeout` 让进程不自杀（`--block-timeout`），服务端已经判定会话失效，
  后续业务请求大概率仍被拒——只是把「进程退出」变成「僵尸连接」。

所以这条路的价值是**观测**，不是**修复**。

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

### 6.3 最省心的方案

**不用常驻。** qb1 已经用 5 天证明「常驻关 + 每天一次冷启 + 日常正常玩」是最稳的组合。
常驻只在必须省内存时才开，且要知道它的长连接随时可能已经断了。

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

### 7.2 拦截会话超时（实验，谨慎）

**两种方式**，效果相同：

**方式一：GUI 勾选（推荐）**

主界面选中沙箱 → 「静默保活」区 → 勾上橙色的
**「实验：拦截会话超时不让运行时退出（只用于验证；默认只观测）」** → 「保存保活设置」。

勾选后该号下次启动/保活时，`hook_watch.py` 会自动带 `--block-timeout`，日志会写：

```
live auth probe: block session timeout is ON (experimental) — ilink will NOT self-exit on App layer sessiontimeout
```

配置存在 `keepalive.json` 的 `"blockSessionTimeout": true`。

**方式二：命令行**

```text
py -3 hook_watch.py --box qb1 --out ... --seconds 600 --block-timeout
```

预期结果与解读：

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

只注入 ilink 角色进程，`rpc.exports.init({rva, blockSessionTimeout})`：

- `noop` 事件：记录心跳次数与相邻间隔（验证心跳健康度）
- `session-timeout` 事件：记录触发次数与调用栈（`observed` / `blocked`）
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

### 8.5 两个实测踩到的真 bug（已修）

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

### 8.6 观测器必须在微信运行之后再启动（否则白跑）

`hook_watch.py` 靠 `scan()` 轮询发现 `WeChatAppEx`。如果观测器比浏览器先启动，
在它启动后的短窗口内箱里没有目标进程，就只能一直空转到 deadline。

实测 qb15 15:23:02 启动的观测器，虽然随后浏览器起来了，但那个实例全程 0 attach；
在同一时刻重起一个观测器立刻挂上 main/ilink/network 三个进程。

**结论**：想观测一次启动过程，用 `JskpBoxManager.exe launch qbN`（它在浏览器前起观测器，靠出生即拦截）；
想补挂已经在跑的沙箱，直接单独起 `hook_watch.py`。

---

## 9. 下一步值得测的

1. **`--block-timeout` 实跑一次**，确认是「僵尸连接」还是「能自愈」——这决定这条路彻底否掉还是留一线。
2. **对比「关游戏」与「上报触发」的先后**：在不动游戏、只让它挂着的情况下，是否也会被 sessiontimeout？
   如果只有关游戏才触发，那常驻的目标应该是「别让游戏窗真的关掉」（最小化而非关闭）。
3. **测 `aereportkvcomm` 上报频率**与 `SmcCore hit freqlimit` 积压的关系：
   qb4 死亡前 1 分钟有大量上报积压，是否是「长时间不活跃 → 集中补报 → 撞上会话失效判定」。

## 10. 观测已跑通（2026-11-04 15:30，qb1）

三个 hook 全部挂上并抓到心跳：

```json
{"ev": "longlink-hooked", "pid": 59348, "role": "ilink",
 "rva": {"noop_resp": 3396400, "run_read_write": 3345680, "on_session_timeout": 1481104, "unpack_response": 1729376},
 "blockSessionTimeout": false,
 "results": {"noop_resp": true, "on_session_timeout": true, "run_read_write": true}}
```

心跳事件（`[心跳] noop 发送 #N 间隔=Ns`，写在 `.txt` 里、不写 jsonl 以免撑大）：

```
2026-11-04 15:31:34 [心跳] noop 发送 #1 间隔=-s
2026-11-04 15:32:21 [心跳] noop 发送 #2 间隔=47.0s
```

间隔 47 秒是因为观测器 attach 时心跳闹钟已经在跑，第一个事件不算基准。
之后应稳定在 **210 秒**（见第 2 节）。
