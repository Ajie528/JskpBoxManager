/**
 * ilink 长连接 / 会话超时观测（只读 + 可选拦截）。注入沙箱里的 WeChatAppEx。
 *
 * 背景（实测 qb4，2026-11-03）：
 *   - ilink 的 noop 心跳是健康的：每 3.5 分钟一次，连续 17.8 小时没有中断（20 次/小时）。
 *   - 杀死的不是心跳超时，而是服务端在一次业务上报（/cgi-bin/mmae-bin/aereportkvcomm）
 *     的响应里回了 "App layer sessiontimeout!"（TCP 层 err(0,0,0) 完全成功）。
 *   - 收到后运行时立刻 TdiClearLoginStatus -> Uninit -> 进程退出。
 *   所以「保住心跳」不能阻止被踢；能观测的是「踢之前服务端看到了什么」，能试探的是
 *   「不让它自杀，连接还能不能用」。
 *
 * 观测（默认开）：
 *   - noop 心跳收发：__NoopResp 调用、间隔变化
 *   - 长连接读写循环：__RunReadWrite 中的连接状态变化
 *   - 会话超时：__OnAppSessionTimeout 被调用（谁触发、调用栈）
 *   - 所有 ilink 明文日志（由 hook_ilink.js 的 xlog hook 提供）
 *
 * 只观测，不干预：`__OnAppSessionTimeout` 原样执行，进程该退出就退出。
 */
'use strict';

let cfg = { rva: {} };
let hooked = false;
const stats = { noop: 0, lastNoopAt: 0, sessionTimeout: 0, statusChanges: 0 };

function emit(obj) {
  send(Object.assign({ ts: Date.now(), pid: Process.id, role: cfg.role || 'ilink' }, obj));
}

function mono() {
  return Date.now();
}

function callerChain(ctx, depth) {
  const out = [];
  try {
    let addr = ctx.returnAddress;
    const mod = Process.findModuleByName('ilink2.dll');
    for (let i = 0; i < (depth || 6); i++) {
      const sym = DebugSymbol.fromAddress(addr);
      let label = '';
      if (sym && sym.name) label = sym.name;
      else if (mod && addr.compare(mod.base) >= 0 && addr.compare(mod.base.add(mod.size)) < 0)
        label = 'ilink2+0x' + addr.sub(mod.base).toString(16);
      else label = addr.toString();
      out.push(label);
      // 读上一层返回地址（栈回溯的简化版：只能拿 RSP 上连续的值，作为线索够用）
      const sp = ctx.rsp;
      if (!sp) break;
      try {
        const next = sp.add(8 * (i + 1)).readPointer();
        if (next.isNull()) break;
        addr = next;
      } catch (_) { break; }
    }
  } catch (_) { }
  return out;
}

function hookNoop(mod) {
  const rva = cfg.rva.noop_resp;
  if (rva == null) return false;
  try {
    Interceptor.attach(mod.base.add(rva), {
      onEnter() {
        this.t = mono();
        stats.noop++;
        const gap = stats.lastNoopAt ? ((this.t - stats.lastNoopAt) / 1000).toFixed(1) : '-';
        stats.lastNoopAt = this.t;
        emit({ ev: 'noop', kind: 'enter', gapSec: gap, total: stats.noop });
      },
      onLeave() {
        emit({ ev: 'noop', kind: 'leave', tookMs: mono() - this.t, total: stats.noop });
      }
    });
    return true;
  } catch (e) {
    emit({ ev: 'hook-error', target: 'noop_resp', err: String(e) });
    return false;
  }
}

function hookSessionTimeout(mod) {
  const rva = cfg.rva.on_session_timeout;
  if (rva == null) return false;
  try {
    const addr = mod.base.add(rva);
    Interceptor.attach(addr, {
      onEnter() {
        stats.sessionTimeout++;
        emit({
          ev: 'session-timeout', action: 'observed', total: stats.sessionTimeout,
          stack: callerChain(this, 6)
        });
      }
    });
    emit({ ev: 'hook', target: 'on_session_timeout', mode: 'attach(observe)' });
    return true;
  } catch (e) {
    emit({ ev: 'hook-error', target: 'on_session_timeout', err: String(e) });
    return false;
  }
}

function hookRunReadWrite(mod) {
  const rva = cfg.rva.run_read_write;
  if (rva == null) return false;
  try {
    Interceptor.attach(mod.base.add(rva), {
      onEnter() { this.t = mono(); },
      onLeave() {
        const d = mono() - this.t;
        if (d < 50) return;  // 绝大多数调用是空转，只记耗时长的
        emit({ ev: 'readwrite', tookMs: d });
      }
    });
    return true;
  } catch (e) {
    emit({ ev: 'hook-error', target: 'run_read_write', err: String(e) });
    return false;
  }
}

function start() {
  if (hooked) return true;
  const mod = Process.findModuleByName('ilink2.dll');
  if (!mod) return false;
  hooked = true;
  const ok = {
    noop_resp: hookNoop(mod),
    on_session_timeout: hookSessionTimeout(mod),
    run_read_write: hookRunReadWrite(mod),
  };
  emit({
    ev: 'longlink-hooked', module: mod.name, base: mod.base.toString(),
    rva: cfg.rva, results: ok
  });
  return true;
}

rpc.exports = {
  init(c) {
    cfg = Object.assign(cfg, c || {});
    if (!start() && typeof Process.attachModuleObserver === 'function') {
      Process.attachModuleObserver({
        onAdded(m) { if (m.name.toLowerCase() === 'ilink2.dll') start(); }
      });
    }
    return { hooked, cfg };
  },
  stats() { return Object.assign({}, stats); }
};
