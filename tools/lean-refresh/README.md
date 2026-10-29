# 精简保活实验 + Frida 观测（仅 qb1）

入口是主程序的 C# 命令，不再使用 PowerShell。

| 命令 | 作用 |
|------|------|
| `JskpBoxManager.exe hook qb1` | 等「向僵尸开炮」窗口，attach `hook_ilink.js`，并监视凭证文件 |
| `JskpBoxManager.exe lean qb1` | 冷启动候选 Blank / NoUrl / RuntimeOnly（可加 Full），看密钥是否换新 |

本目录只保留 Frida 脚本：

| 文件 | 作用 |
|------|------|
| `hook_ilink.js` | 模块列表 + `CreateFileW` / `MoveFileExW` |
| `hook_attach.py` | Python Frida API attach |

硬锁 **qb1**。依赖：Sandboxie-Plus、QQ 浏览器、`py -3 -m pip install frida`。

详细步骤见 [`docs/Hook观测使用说明.md`](../../docs/Hook观测使用说明.md)。

```text
JskpBoxManager.exe hook qb1 --appdir D:\a_game_scrpit\JskpBoxManager-1.1.5 --mode Full --seconds 180
JskpBoxManager.exe lean qb1 --modes Blank,NoUrl,RuntimeOnly --seconds 180
```

`keepalive.json` 每箱可设 `"leanRefresh": true`（默认关；当前仅建议 qb1）。开启后正式 `refresh` 先试精简候选，失败回退 Full。
