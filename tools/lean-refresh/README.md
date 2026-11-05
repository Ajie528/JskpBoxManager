# Frida 观测脚本（仅 qb1）

入口是主程序的 C# 命令，不再使用 PowerShell。

| 命令 | 作用 |
|------|------|
| `JskpBoxManager.exe hook qb1` | 等「向僵尸开炮」窗口，attach `hook_ilink.js`，并监视凭证文件 |
| `JskpBoxManager.exe protorenew qb1` | 不开浏览器，直接用协议换新密钥（需沙箱已停） |

本目录只保留 Frida 脚本：

| 文件 | 作用 |
|------|------|
| `hook_ilink.js` | 模块列表 + `CreateFileW` / `MoveFileExW` |
| `hook_attach.py` | Python Frida API attach |

硬锁 **qb1**。依赖：Sandboxie-Plus、QQ 浏览器、`py -3 -m pip install frida`。

详细步骤见 [`docs/Hook观测使用说明.md`](../../docs/Hook观测使用说明.md)。

```text
JskpBoxManager.exe hook qb1 --appdir D:\a_game_scrpit\JskpBoxManager-exe --mode Full --seconds 180
JskpBoxManager.exe protorenew qb1 --appdir D:\a_game_scrpit\JskpBoxManager-exe
```

> 「精简保活」（Blank / NoUrl / RuntimeOnly 候选）已在 1.5.20 移除：三次实测证明
> `AutoAuth` 必须由游戏中心页面触发，只启运行时不会换钥。省资源的需求由纯协议续期承担。
