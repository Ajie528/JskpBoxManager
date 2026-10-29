/**
 * Frida 只读观测脚本（注入沙箱里的 WeChatAppEx）。不改参数、不发包。
 *
 * 1. ilink 明文日志：ilink2.dll 内 ilink::CustomAppender::append（宿主把它加密写进 ilink_*.xlog 之前）。
 *    函数 RVA 由 xlog_locate.py 按 RTTI 离线算出，通过 rpc.exports.init 传进来。
 * 2. 凭证文件：kernelbase CreateFileW / MoveFileExW / DeleteFileW / ReplaceFileW 命中 tdi_account.txt、psk.key、ilink 目录。
 * 3. 网络：ws2_32 connect / WSAConnect 目标地址，GetAddrInfoW / getaddrinfo 域名（每个只记一次）。
 */
'use strict';

let cfg = { xlogRva: null, role: '' };
let xlogHooked = false;
const seenNet = new Set();

function emit(obj) {
  send(Object.assign({ ts: Date.now(), pid: Process.id, role: cfg.role }, obj));
}

function u16(p, max) {
  try { return p.isNull() ? '' : (p.readUtf16String(max || 1024) || ''); } catch (_) { return ''; }
}

function u8(p, max) {
  try { return p.isNull() ? '' : (p.readUtf8String(max || 4096) || ''); } catch (_) {
    try { return p.readCString(max || 4096) || ''; } catch (__) { return ''; }
  }
}

function interestingPath(s) {
  if (!s) return false;
  const l = s.toLowerCase();
  return l.indexOf('tdi_account') >= 0 || l.indexOf('psk.key') >= 0 ||
    l.indexOf('\\ilink\\') >= 0 || l.indexOf('/ilink/') >= 0 ||
    l.indexOf('applet.db') >= 0 || l.indexOf('mpkv.db') >= 0 || l.indexOf('device_uuid') >= 0;
}

function exp(mod, name) {
  try { return Process.getModuleByName(mod).getExportByName(name); } catch (_) { return null; }
}

// ---------- 1. ilink 明文日志 ----------

/** MSVC x64 std::string：size 在 +16，capacity 在 +24；capacity >= 16 时数据在堆上（+0 是指针）。 */
function stdString(p, max) {
  try {
    const size = p.add(16).readU64().toNumber();
    const cap = p.add(24).readU64().toNumber();
    if (size <= 0 || size > 1 << 20 || cap < size) return '';
    const data = cap >= 16 ? p.readPointer() : p;
    return data.readUtf8String(Math.min(size, max || 16384)) || '';
  } catch (_) { return ''; }
}

// "10-29 11:04:37.713 1597988/1598700/0 I mars::mmext longlink_with_mmtls.cc:839 Func: message"
const LINE = /^(\S+ \S+) (\d+)\/(\d+)\/\d+ ([VDIWEF]) (\S+) (\S+?):(\d+) (.*)$/s;

function hookXlog(mod) {
  if (xlogHooked || cfg.xlogRva == null) return;
  xlogHooked = true;
  const fn = mod.base.add(cfg.xlogRva);
  Interceptor.attach(fn, {
    onEnter(args) {
      const text = stdString(args[2]).replace(/\s+$/, '');
      if (!text) return;
      const m = LINE.exec(text);
      if (m) emit({ ev: 'xlog', t: m[1], tid: +m[3], lvl: m[4], tag: m[5], file: m[6], line: +m[7], msg: m[8] });
      else emit({ ev: 'xlog', msg: text });
    }
  });
  emit({ ev: 'xlog-hooked', module: mod.name, at: fn.toString(), rva: '0x' + cfg.xlogRva.toString(16) });
}

function watchIlinkModule() {
  const m = Process.findModuleByName('ilink2.dll');
  if (m) { hookXlog(m); return; }
  if (typeof Process.attachModuleObserver === 'function') {
    Process.attachModuleObserver({
      onAdded(mod) { if (mod.name.toLowerCase() === 'ilink2.dll') hookXlog(mod); }
    });
  } else {
    const t = setInterval(function () {
      const mm = Process.findModuleByName('ilink2.dll');
      if (mm) { clearInterval(t); hookXlog(mm); }
    }, 20);
  }
}

// ---------- 2. 凭证文件 ----------

function hookFiles() {
  const lib = Process.findModuleByName('kernelbase.dll') ? 'kernelbase.dll' : 'kernel32.dll';
  const create = exp(lib, 'CreateFileW');
  if (create) Interceptor.attach(create, {
    onEnter(a) { this.p = u16(a[0]); this.acc = a[1].toUInt32(); this.disp = a[4].toUInt32(); },
    onLeave(r) {
      if (!interestingPath(this.p)) return;
      const write = (this.acc & 0x40000000) !== 0 || (this.acc & 0x10000000) !== 0;
      emit({ ev: 'file', op: write ? 'open-write' : 'open-read', path: this.p, disp: this.disp, ok: !r.equals(ptr('-1')) });
    }
  });
  const move = exp(lib, 'MoveFileExW');
  if (move) Interceptor.attach(move, {
    onEnter(a) { this.s = u16(a[0]); this.d = u16(a[1]); },
    onLeave(r) {
      if (interestingPath(this.s) || interestingPath(this.d))
        emit({ ev: 'file', op: 'move', path: this.d, src: this.s, ok: r.toInt32() !== 0 });
    }
  });
  const del = exp(lib, 'DeleteFileW');
  if (del) Interceptor.attach(del, {
    onEnter(a) { this.p = u16(a[0]); },
    onLeave(r) { if (interestingPath(this.p)) emit({ ev: 'file', op: 'delete', path: this.p, ok: r.toInt32() !== 0 }); }
  });
  const rep = exp(lib, 'ReplaceFileW');
  if (rep) Interceptor.attach(rep, {
    onEnter(a) { this.d = u16(a[0]); this.s = u16(a[1]); },
    onLeave(r) {
      if (interestingPath(this.s) || interestingPath(this.d))
        emit({ ev: 'file', op: 'replace', path: this.d, src: this.s, ok: r.toInt32() !== 0 });
    }
  });
  return lib;
}

// ---------- 3. 网络 ----------

function sockaddr(p) {
  try {
    const fam = p.readU16();
    if (fam === 2) {
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      const b = p.add(4).readByteArray(4);
      return new Uint8Array(b).join('.') + ':' + port;
    }
    if (fam === 23) {
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      const b = new Uint8Array(p.add(8).readByteArray(16));
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(((b[i] << 8) | b[i + 1]).toString(16));
      return '[' + parts.join(':') + ']:' + port;
    }
  } catch (_) {}
  return '';
}

function once(kind, v) {
  const k = kind + '|' + v;
  if (seenNet.has(k)) return false;
  seenNet.add(k);
  return true;
}

function caller(ctx) {
  try {
    const m = Process.findModuleByAddress(ctx.returnAddress);
    return m ? m.name : '';
  } catch (_) { return ''; }
}

function hookNet() {
  if (!Process.findModuleByName('ws2_32.dll')) {
    try { Module.load('ws2_32.dll'); } catch (_) { return false; }
  }
  for (const name of ['connect', 'WSAConnect']) {
    const f = exp('ws2_32.dll', name);
    if (!f) continue;
    Interceptor.attach(f, {
      onEnter(a) {
        const to = sockaddr(a[1]);
        if (to && once('connect', to)) emit({ ev: 'net', op: name, to, from: caller(this) });
      }
    });
  }
  const gaiW = exp('ws2_32.dll', 'GetAddrInfoW');
  if (gaiW) Interceptor.attach(gaiW, {
    onEnter(a) { const h = u16(a[0], 256); if (h && once('dns', h)) emit({ ev: 'net', op: 'dns', host: h, from: caller(this) }); }
  });
  const gai = exp('ws2_32.dll', 'getaddrinfo');
  if (gai) Interceptor.attach(gai, {
    onEnter(a) { const h = u8(a[0], 256); if (h && once('dns', h)) emit({ ev: 'net', op: 'dns', host: h, from: caller(this) }); }
  });
  return true;
}

function interestingModules() {
  return Process.enumerateModules()
    .filter(m => /ilink|mmtls|flue|wmpf|wechat|xweb/i.test(m.name))
    .map(m => ({ name: m.name, base: m.base.toString(), size: m.size }));
}

rpc.exports = {
  init(c) {
    cfg = Object.assign(cfg, c || {});
    const fileLib = hookFiles();
    const net = hookNet();
    watchIlinkModule();
    emit({ ev: 'script-load', arch: Process.arch, fileLib, net, modules: interestingModules() });
    return true;
  },
  ping() { return 'pong'; }
};
