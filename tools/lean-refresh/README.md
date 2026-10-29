# 精简保活实验 + Frida 观测（仅 qb1）

入口是主程序的 C# 命令：

| 命令 | 作用 |
|------|------|
| `JskpBoxManager.exe hook qb1` | 箱内启动观测程序，截 ilink 明文日志（含 AutoAuth 授权结果）、凭证文件读写、对外连接 |
| `JskpBoxManager.exe lean qb1` | 冷启动候选 Blank / NoUrl / RuntimeOnly（可加 Full），看密钥是否换新 |

本目录文件：

| 文件 | 作用 |
|------|------|
| `hook_watch.py` | 在 qb1 箱内运行：预热注入，WeChatAppEx 主进程一出现就 attach 并拦截子进程，ILinkServiceHost 出生即挂 |
| `hook_ilink.js` | 注入脚本：ilink 日志（`CustomAppender::append`）、凭证文件、connect / DNS |
| `xlog_locate.py` | 按 RTTI 在 `ilink2.dll` 里找日志函数的 RVA，结果缓存到 `xlog_rva_cache.json` |

依赖：Python 3、`py -3 -m pip install frida psutil pefile`。`build.ps1` 会把本目录打进发布包的 `tools\lean-refresh\`。

正式保活勾选「记录授权结果」（`keepalive.json` 的 `"probeAuth": true`）时，也用 `hook_watch.py` 截每次 AutoAuth 的 ret / error_msg。

```text
JskpBoxManager.exe hook qb1 --seconds 60
JskpBoxManager.exe hook qb1 --no-launch --no-stop --seconds 3600
```

详细步骤、输出解读和排障见 [`docs/Hook观测使用说明.md`](../../docs/Hook观测使用说明.md)。

`keepalive.json` 每箱可设 `"leanRefresh": true`（默认关；当前仅建议 qb1）。开启后正式 `refresh` 先试精简候选，失败回退 Full。
