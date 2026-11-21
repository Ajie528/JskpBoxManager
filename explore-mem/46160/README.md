# 46160 内存读取勘查记录

> 目标窗口：`向僵尸开炮`（PID 46160）
> 勘查时间：2026-11-18
> 勘查方式：`ReadProcessMemory` 只读，不写目标进程、不注入、不挂线程

---

## 1. 46160 到底是什么

| 项 | 值 |
| --- | --- |
| 进程名 | `WeChatAppEx.exe` |
| 角色 | 微信小程序运行时 **browser（主）进程** |
| 工作集 | 约 36.6 MB |
| 窗口句柄 | `0x33E0E2C`（54399820） |
| 窗口标题 | 向僵尸开炮 |
| 命令行 | `--log-level=0 --helper-handle-value=529927087 --product-id=3000 ...`（**无** `--type=`） |
| 所属沙箱 | **qb1** |

### 为什么它读不到游戏数据

46160 是 browser 主进程，**只负责窗口与进程编排**，里面没有角色数据。
游戏本体跑在它的子进程里：

```
QQBrowser.exe 38796  (qb1 主浏览器, --remote-debugging-port=9301)
 └─ QQBrowser.exe 23064  (--type=dll-extension)
     └─ WeChatAppEx.exe 46160   ← 目标窗口（browser 主进程，36.6 MB）
         ├─ WeChatAppEx.exe 38200  --type=renderer --wmpf-render-type=2 --wmpf-appid=wx31a9c726536cdacc  (227 MB) ★ 游戏本体
         ├─ WeChatAppEx.exe  976   --type=renderer --wmpf-render-type=4 --wmpf-appid=preload-6   (1.5 MB)
         ├─ WeChatAppEx.exe 8544   --type=utility  (50 MB)
         ├─ WeChatAppEx.exe 20088  --type=gpu-process  (80 MB)
         └─ WeChatAppEx.exe 24612  --type=utility  (47 MB)
```

**结论：真正要读的是 38200**（`--wmpf-render-type=2` + 游戏 appid 的 renderer），
46160 只是它的父进程和窗口宿主。程序里 `RoleReader.GameRenderers()` 就是按这个规则找的。

---

## 2. 已确认能读到的数据（pid 38200）

### 2.1 角色档案 JSON

地址 `0x3BD04DC94D6`，UTF-16LE，675 字节，以 `{"user_id":...}` 开头。
整段是游戏上报 `/api/report/login` 的登录数据：

```json
{
  "user_id": "191975176",
  "channel_openid": "ozHdy67rKadMLraxBLUcE_fmCjCM",
  "channel_unionid": "",
  "server_id": "9788",
  "server_name": "9788",
  "role_id": "4170728974166104000",
  "role_name": "中华丨阿杰、欧",
  "role_level": "202",
  "game_id": "3022",
  "package_id": 9999,
  "sdk_version": "2.1.8",
  "wx_sdk_version": "3.10.3",
  "wx_version": "3.7.6",
  "device_type": 3,
  "device_os": "microsoft",
  "device_factory": "microsoft",
  "device_system": "11 x64",
  "uuid": "d6d7ab91-81ac-2f50-2c5e-5f4632286c0f",
  "system": "Windows 11 x64",
  "platform": "windows",
  "wx_language": "zh_CN",
  "is_dnsdk_debug": 0,
  "play_page": 0,
  "scene": 1168,
  "query_info": "wxgamepro%3DCpsCBgAAoXkpQY8_cGOg-Vui",
  "game_version": "2.212",
  "battery_level": 100,
  "is_charging": 1
}
```

字段来源：`find 'role_name' --utf16` 命中 `0x3BD04DC94D8`（区域内 +0x2CC8D8）。
同区域 `+0x9A5E2` 处还有一份**埋点日志文本**（`[Track]: do doTrack ... uin: ...`），
那是日志缓冲，不是真实档案，别拿它读。

### 2.2 角色属性块（攻击力）

角色 ID `4170728974166104000` 在进程里出现 **342~353 处**（`tools\probe-anchor.ps1` 可复现）。
只有一个块同时满足「+0x1C 与 +0x20 都等于等级」——这就是「当前角色」块：

```
锚点基址 0x3C485C291D8
+0x1C = 202      等级
+0x20 = 202      等级（冗余副本）
+0xB4 = 1        标志（实测可为 1 或 2，不能写死）
+0xB8 = 82544    ★ 攻击力
```

C 型副本（旧值，用 +0x4C 时间戳挑最新）：
`0x3C49299A8D0`（+0x4C=1794995002）、`0x3C485C018D0`（+0x4C=1794987802），
两处 +0x28 都是 82544，与 D 型一致，可信。

### 2.3 属性块周围其它数值（同块，偏移相对 +0x1C 起点）

| 偏移 | 值 | 推测含义 |
| --- | --- | --- |
| +0x1C / +0x20 | 202 / 202 | 等级 |
| +0x24 / +0x28 | 9431 / 9431 | 经验 / 上限 或 战力相关 |
| +0x2C | 5527 | 待定 |
| +0x30 | 20 | 待定 |
| +0x34 | 8064564 | 待定（大数，可能是总经验） |
| +0x38 | 753 | 待定 |
| +0x40 | 2 | 待定 |
| +0x44 | 1794995002 | 时间戳（2026-11-18 附近） |
| +0x4C | 3 | 待定 |
| +0x54 | 23650 | 待定 |
| +0x58 | 25790 | 待定 |
| +0x5C | 253 | 待定 |
| +0x60 | 26165 | 待定 |
| +0x6C | 4030 | 待定 |
| +0x88 | 1450 | 待定 |
| +0xB8 | **82544** | **攻击力** |

> 这些偏移的含义未验证，只记录现场。要定论需换装备/升级前后对比。

---

## 2.4 引擎类型（决定读法）

| 证据 | 结论 |
| --- | --- |
| `wasm-function#95614`、`emscripten_wxglxBindTexture` | 游戏跑在 **WebAssembly** 里 |
| `il2cpp`、`GameAssembly`、`UnityPlayer` 符号 | Unity + **IL2CPP 编译成 wasm** |
| `flue.dll`（187 MB）+ `xweb_elf.dll` | 承载 wasm 的是腾讯 **xweb** 内核 |
| 线性内存 `0x3C480000000` 768 MB | 就是 **wasm 线性内存**，所有游戏对象都在里面 |

这是**最关键的一条**：IL2CPP 的 C# 对象在 wasm 里不是 Windows 原生布局，
而是 wasm 线性内存里的偏移量。所以：
- **不能用** Cheat Engine 式的「找指针链」；
- 偏移量每次加载都可能变（wasm 堆会重新分配）；
- 唯一稳的锚点是**数据本身**（角色 ID、钻石数值等）。

## 2.6 【已解决】迷宫「箭头左右是什么」——完整可读结构

### 结论：能读到，而且已经实测验证

用「点一下箭头 + 内存差分」把整条链打通了。现在可以**只读**地拿到：

1. 当前层、迷宫币、积分、最高分
2. 完整 24 个格子（row / 类型 / 事件 id / 列）
3. **箭头指向左右哪两格**

### 关键地址（本次实测，重启会变）

| 用途 | 地址（PID 38200） | 说明 |
| --- | --- | --- |
| `MazeDataMgr` 实例 | `0x3C483D008FC` | 迷宫对象起点 |
| 格子列表 List | `0x3C485A0EEC0` | 从对象 `+0x58` 得到 |
| 格子数组 | `0x3C494332BE0` | List `+0x08`（wasm32 偏移） |

### MazeDataMgr 字段布局（与 IL2CPP 元数据声明顺序完全一致）

基址 `0x3C483D008FC`，每个 int32：

| 偏移 | 字段 | 实测值 | 含义 |
| --- | --- | --- | --- |
| +0x00 | `<CurSelectRow>` | 2 | **箭头选中项 → row** |
| +0x04 | `<CurSelectCol>` | 1~2 | 选中项 → col |
| +0x08 | `m_preLevel` | 1 | 上一层 |
| +0x0C | `<SweepCondtion>` | 3 | 扫荡条件 |
| +0x10 | `m_curLevel` | **2** | **当前层（画面 2/3）** |
| +0x14 | `m_curType` | 1 | 当前格类型 |
| +0x18 | `m_curRow` | 1 | 当前格 row |
| +0x1C | `m_curCol` | 1 | 当前格 col |
| +0x20 | `m_mazeCoin` | **205** | **迷宫币（画面门票）** |
| +0x24 | `m_mazeScore` | **700** | **本期积分** |
| +0x28 | `<NeedJumpUI>` | 0 | |
| +0x2C | `m_nextRow` | 1 | 下一格 row |
| +0x30 | `m_nextCol` | 1 | 下一格 col |
| +0x34 | `m_preRow` | 1 | 上一格 row |
| +0x38 | `m_preCol` | 1 | 上一格 col |
| +0x3C | `m_highestMazeScore` | **700** | **本期最高分** |
| +0x40 | `<ResetCount>` | 31 | 重置次数 |
| +0x44 | `<FinCnt>` | 1012 | 完成计数 |
| +0x48 | `<CurSelectChoseId>` | 0 | 选项 id |
| +0x4C | `m_mazeBagData` | 指针 | 背包 |
| +0x50 | `m_mazeShopData` | 指针 | 商店 |
| +0x54 | `m_mazeScoreAwardData` | 指针 | 积分奖励 |
| +0x58 | `m_listCSMessMapData` | `0x05A0EEC0` | **格子列表** |

### 差分实测（最硬的证据）

点**左箭头**（购物车）前后：

```
0x3C483D008FC   11 → 2    ← CurSelectRow 变了
```

点**右箭头**（扳手/安全区）后：

```
0x3C483D008FC    2 → 2    ← 落在 row=2
0x3C483D00900    1 → 2    ← CurSelectCol 跟着变
```

画面变化与之一致：

| 点击 | 弹窗 | 对应格子 |
| --- | --- | --- |
| 左箭头 | 「商店 / 消耗迷宫币进行大买特买」 | row11 col32 类型1 |
| 右箭头 | 「安全区 / 应该能略作修整」 | row2 类型1 事件0 |

### 格子列表结构（List<CSMessMapData>，wasm32）

```
List  @ 0x3C485A0EEC0
  +0x00  klass        0x0F071958
  +0x08  _items       0x14332BE0  → 绝对 0x3C494332BE0
  +0x0C  _size        24          （24 个格子）

Array @ 0x3C494332BE0
  +0x0C  max_length   32
  +0x10  元素起点     （每项 4 字节指针）
```

单个格子 `CSMessMapData`（40+ 字节）：

| 偏移 | 字段 | 说明 |
| --- | --- | --- |
| +0x00 | klass | |
| +0x08 | 事件类型 | 1/2/3 |
| +0x0C | 事件 id | 1000/1030/1050/1070/1080/1090/1100/1150 |
| +0x10 | **row** | 层/行号，1~11 |
| +0x14 | col / 子 id | 12/22/32/102/201/301/411 |
| +0x18 | 标志 | 0 或 3 |

### 本次读到的全部 24 个格子

```
row=1   1 格  → #0(类型1,事件0,col2)
row=2   2 格  → #1(类型1,事件0,col201)  #2(类型2,事件1000,col301)
row=3   3 格  → #3(类型1,事件1000,col301) #4(类型2,事件0,col12) #5(类型3,事件1090,col102)
row=4   2 格  → #6(类型1,事件0,col12)    #7(类型2,事件0,col12)
row=5   3 格  → #8(类型1,事件1000,col301) #9(类型2,事件1080,col102) #10(类型3,事件1150,col411)
row=6   2 格  → #11(类型1,事件0,col22)   #12(类型2,事件0,col22)
row=7   3 格  → #13(类型1,事件0,col12)   #14(类型2,事件1000,col301) #15(类型3,事件1070,col102)
row=8   2 格  → #16(类型1,事件0,col12)   #17(类型2,事件0,col12)
row=9   3 格  → #18(类型1,事件1100,col102) #19(类型2,事件1050,col102) #20(类型3,事件1030,col102)
row=10  2 格  → #21(类型1,事件1000,col301) #22(类型2,事件0,col201)
row=11  1 格  → #23(类型1,事件0,col32)   ← 曾指向这里（商店）
```

### 怎么用它判断「左箭头是什么、右箭头是什么」

```
1. 找 MazeDataMgr 实例（mazehunt，锚点：层数 + 迷宫币 + 最高分）
2. 读 +0x10 = 当前层，+0x18 = 当前 row
3. 从 +0x58 拿格子列表，读全部格子
4. 筛选 row == 当前层 + 1 的格子 → 就是两个箭头指向的候选
5. 按 col 从小到大 = 左、右
6. 看每格的「事件 id」判断内容（需配合配置表映射到图标）
```

> **注意**：`CurSelectRow`（+0x00）在点箭头时会变，它记录的是"将要进入的 row"。
> 点完会弹确认框（商店/安全区），确认后才真正推进 `m_curLevel`。

### 复现命令

```powershell
MemProbe mazehunt 2 700 --pid 38200              # 定位迷宫实例
MemProbe mazecells 0x3C485A0EEC0 --pid 38200     # 解析全部格子
MemProbe diff 0x3C483D008FC 0x60 --pid 38200     # 读迷宫对象字段
MemProbe snap before.bin --pid 38200             # 差分：先存快照
MemProbe snap after.bin  --pid 38200             #       点一下
MemProbe snapdiff before.bin after.bin --pid 38200
```

## 2.7 【最终方案】零硬编码的全自动定位

`MazeLocator.cs` 实现了不依赖任何地址、任何魔法数值的定位。**每次都能自动找到。**

### 定位算法（四步，全靠结构特征）

```
① 找大块可读内存
   枚举所有 ≥32MB 的可读区域（大的在前），逐个尝试。
   不能只认「最大那块」——有的沙箱里 wasm 内存会被拆段。

② 扫格子列表 List<CSMessMapData>
   在候选内存里按 4 字节步进，找同时满足：
     +0x0C  _size      ∈ [8, 80]
     +0x08  _items     是合法 wasm 偏移（0x1000 ~ size-0x100）
     且每个元素都满足：
       类型 ∈ 1..5、事件 id ∈ 0..99999、row ∈ 0..200、col ∈ 0..100000
       且 row 单调不减
   这套组合的误命中率极低（实测 768MB 里只有 21 个候选，
   且后续步骤会自动筛掉无关的）。

③ 反查引用 → 得到 MazeDataMgr 基址
   在内存里找「值等于该 List 偏移」的 4 字节位置（wasm32 指针），
   命中位置减去 +0x58（格子列表字段偏移）= MazeDataMgr 基址。

④ 读字段并二次校验
   列表指针必须指回同一个 List；当前层 0..20、迷宫币/积分在合理范围。
   全部通过才认可，否则换下一个候选。
```

### 左右判定（★ 已纠正确认，以本节为准）

早期我以为是「第几个选项」，**那是错的**。三次实测后确认真实规则：

`CurSelectCol`（对象 +0x04）存的是**格子 `类型` 字段的值**（= 行内第几列），
不是选项序号，也不是坐标。

```
当前列 = m_curCol（对象 +0x1C）
上层   = row == m_curRow + 1 的格子

可选项 = 上层里 类型 == 当前列  或  类型 == 当前列 + 1
         （其它列走不到，所以 3 格的行只有 2 个箭头）

左箭头 = 类型 == 当前列
右箭头 = 类型 == 当前列 + 1
```

验证证据（全部截图留档）：

| 操作 | CurSelectCol | 对应格子 | 弹窗 |
| --- | --- | --- | --- |
| row1列1 点左箭头 | **1** | `#1(类型1,事件0)` | 商店 |
| row1列1 点右箭头 | **2** | `#2(类型2,事件1000)` | 安全区 |
| row2列2 点左箭头 | **2** | `#4(类型2,事件0)` | 本层怪物 |
| row2列2 点右箭头 | **3** | `#5(类型3,事件1090)` | 随机事件 |

### 用法

```powershell
# 一键：自动找进程 + 自动定位
cd d:\a_game_scrpit\JskpBoxManager\explore-mem
powershell -ExecutionPolicy Bypass -File .\Maze.ps1

# 指定沙箱 / 指定进程
.\Maze.ps1 -Box qb1
.\Maze.ps1 -RendererPid 38200

# 直接用工具
MemProbe maze --pid 38200
```

### 输出示例（实测）

```
沙箱 qb1   渲染进程 PID 38200   930.2 MB
wasm 线性内存  0x3C480000000  768 MB
MazeDataMgr     0x3C483D008FC   （wasm 内偏移 0x3D008FC）
格子列表        0x3C485A0EEC0   24 格

当前层 2   迷宫币 205   积分 700   最高分 700   完成 31
当前位置 行=1 列=1   下一步 行=1 列=1
选中状态 CurSelectRow=2 CurSelectCol=2

── 下一步可选格子（画面两个黄色箭头，1=左 2=右）共 2 个 ──
   [1] 左   类型=1  事件=0  row=2 col=201  标志=0   (#1)
   [2] 右   类型=2  事件=1000  row=2 col=301  标志=0   (#2)  ★当前选中
```

### 实测性能

| 场景 | 耗时 |
| --- | --- |
| 扫 768 MB 找格子列表 | ~2 秒 |
| 完整定位（含反查引用） | ~2 秒 |
| 同一进程重复运行 | 结果稳定，地址不变 |

### 已知边界

| 情况 | 表现 |
| --- | --- |
| 游戏没启动 / 没进迷宫界面 | 返回「没定位到迷宫数据」，不会报错 |
| 沙箱进程读不到内存（Sandboxie 权限） | 返回「没有可读的大块内存」 |
| 已到顶层（没有下一行） | `Options` 为空，输出「没有可选项」 |
| 事件 id → 图标名 | **仍未解决**，见下方 |

### 还差一环：事件 id 的语义

> **已部分解决** —— 见同目录 `事件id对照表.md`。
>
> 已实测确认：
>
> | 事件 id | 类型 | 弹窗标题 |
> | --- | --- | --- |
> | **0** | 1 | **商店**（消耗迷宫币购买） |
> | **1000** | 2 | **安全区**（可以休整） |
>
> 其余（1030/1050/1070/1080/1090/1100/1150）还没逐个点过，
> 跑 `Experiment.ps1` 可以自动采集。

### 格子字段语义（实测）

`CSMessMapData` 每格 40 字节：

| 偏移 | 字段 | 含义 |
| --- | --- | --- |
| +0x08 | 类型 | 1/2/3 ≈ 分支路线的第几条 |
| +0x0C | **事件 id** | 决定弹什么界面（0=商店，1000=安全区…） |
| +0x10 | **row** | 行号 |
| +0x14 | 美术 id | 外观样式，**不是位置**（同行可重复） |
| +0x18 | 标志 | 0 或 3 |

**左右顺序的判定**：不走 `col`/美术 id，而是走**列表原始顺序**。
`Options` = `row == 当前行+1` 的格子，按 Index 升序，第 1 个是左、第 2 个是右。
这与 `CurSelectCol`（1=左、2=右）严格对应，已用两次点击实测验证。

## 2.5 迷宫（雾境迷宫）勘查过程（历史，已由 2.6 / 2.7 解决）

画面：2/3 层，当前角色在中间，两个黄色箭头指向下一排，
左边是购物车、右边是扳手/加号，再往右是问号。

内存里**确认存在**的迷宫符号（都在 wasm 元数据段 `0x3C481F79xxx`，是类型名不是实例）：

```
MazeDataMgr        MazeMapData        cSMessMapShopRes
CurRow / CurCol    NextRow / NextCol  PreRow
CurSelectRow / CurSelectCol          CurSelectChoseId
MazeCoin           MazeScore          HighestMazeScore
FinCnt             ResetCount         SweepCondtion
CanMoveCell        GetMazeMapDatas    GetMazeRowCellDatasByRow
IsMaxRow           GetCurMazeMaxRow   GetBossPos
MazeBagData/MazeShopData/MazeBlessDatas/...
```

**这说明游戏逻辑层确实有完整的格子坐标与事件类型结构**，方向是对的。

但**目前没有直接定位到实例数据**，障碍是：

| 障碍 | 实测结果 |
| --- | --- |
| 迷宫状态不是 JSON | `"curRow":` / `"curCol":` / `"cellDatas"` 全部 0 命中（只有符号名） |
| 迷宫不在配置表里 | `allConfig_3/4.json`（含 4000+ 配置表）中 `maze`/`Maze` 出现 **0 次**，说明是服务端动态下发 |
| 结算时间戳搜不到 | 按 +6h10m~13m 逐分钟搜 int32，0 命中（可能存的是格式化字符串或毫秒） |
| CDP 进不去游戏页 | 9301 端口只有 QQ 浏览器自己的标签，游戏在 WeChatAppEx 的 WebView 里**没有调试端口** |
| 小整数命中太多 | 700（最高积分）在 wasm 里命中 30+ 处，无法唯一定位 |

### 可行的三条路（按成功率排序）

**A. 用 IL2CPP 元数据还原结构（最可靠）**
`MazeDataMgr` 的字段顺序在 wasm 元数据里是连续的：
`CurSelectRow → CurSelectCol → SweepCondtion → CurRow → CurCol → MazeCoin → MazeScore → NextRow → NextCol → PreRow → HighestMazeScore → ResetCount → FinCnt → ...`
拿到这些字段的**类型和顺序**后，就能按固定偏移读出「当前格」和「下一格」，
再配合 `GetMazeRowCellDatasByRow(row)` 的语义，推出左右各是什么。
> 需要先导出 `global-metadata.dat`（当前沙箱里没找到，可能内嵌在 `.ab` 包的 `.bin` 里）。

**B. 数值锚点 + 结构验证（中等）**
迷宫里有「本期最高积分 700」，若这一期没变过，它就是稳定的锚点。
找到 700 后，按 `MazeScore`/`HighestMazeScore` 相邻关系验证哪些命中是真身。
> 难点：700 命中 30 多处，需要逐个看上下文排除。

**C. 换装备/推进一步做差分（最慢但最确定）**
在迷宫点一下左或右，然后对比前后内存差异 —— 变化的那几个 int 就是
`CurRow`/`CurCol`/`CurSelectChoseId`。
> 这是唯一不依赖元数据的方法，缺点是需要人工点一次。

---

## 3. 结论与建议

1. **不要对 46160 本体读游戏数据**，它会命中窗口标题、埋点日志等噪声；
   正确目标是它的 `--wmpf-render-type=2` 子进程（当前 38200）。
2. 现有 `JskpBoxManager.exe role qb1` 已经能读到：角色名、等级、区服、攻击力、角色 ID，
   走的就是 46160 → 38200 这条路，**基座可用**。
3. 可增量读取的新东西：
   - 完整登录 JSON（`user_id` / `channel_openid` / `uuid` / `game_version` / `scene` 等）
   - 属性块里的其它数值（需前后对比才能定含义）
4. 进程 PID 每次启动都会变，**必须动态解析**（`RoleReader.GameRenderers(box)` 已实现）。

---

## 4. 勘查工具

`MemProbe\`（本目录，独立小工程，不参与主程序编译）：

```
MemProbe map                          内存区域 + 模块概况
MemProbe procs                        列游戏渲染进程候选
MemProbe json                         抠出所有含 role_name 的完整 JSON
MemProbe atk 角色ID 等级               复现 D/C 型攻击力定位
MemProbe find 文本 [--utf16] [--ctx N] 字符串搜索 + 上下文
MemProbe dump 0x地址 长度              十六进制 + 可读文本
MemProbe ptr 0x地址                    反向找指针
MemProbe int 数值                      找 int32
MemProbe near 0x地址 半径              看某地址周围
--pid N  指定进程（默认 46160）  --modules 连模块内存一起扫  --max N 结果上限
```

原始输出都在本目录 `01-…09-*.txt`。
