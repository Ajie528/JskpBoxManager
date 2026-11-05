/**
 * Frida 只读观测脚本（注入沙箱里的 WeChatAppEx）。不改参数、不发包。
 *
 * 1. ilink 明文日志：ilink2.dll 内 ilink::CustomAppender::append（宿主把它加密写进 ilink_*.xlog 之前）。
 *    函数 RVA 由 xlog_locate.py 按 RTTI 离线算出，通过 rpc.exports.init 传进来。
 * 2. 凭证文件：kernelbase CreateFileW / MoveFileExW / DeleteFileW / ReplaceFileW 命中 tdi_account.txt、psk.key、ilink 目录。
 * 3. 网络：ws2_32 connect / WSAConnect 目标地址，GetAddrInfoW / getaddrinfo 域名（每个只记一次）。
 * 4. 业务 HTTPS 明文：BoringSSL SSL_write / SSL_read，截「向僵尸开炮」登录请求（js_code）和返回（token）。
 */
'use strict';

let cfg = { xlogRva: null, role: '', stackOnAuth: true, autoAuthRva: null, manualAuthRva: null };
const authState = { thisPtr: null, calls: 0 };
const manualState = { calls: 0 };
let xlogHooked = false;
let sslHooked = false;
const seenNet = new Set();

// 只上报命中这些关键词的明文，避免把所有 HTTPS 流量都倒出来
const HTTP_KEYWORDS = ['login_wxmg', 'scgame.com.cn', 'js_code=', '"token"', 'wx_mds_charge', 'dodjoy.com', 'h5api'];

function emit(obj) {
  send(Object.assign({ ts: Date.now(), pid: Process.id, role: cfg.role }, obj));
}

/**
 * 读一个以 NUL 结尾的 UTF-16 字符串，最多 maxChars 个字符。
 *
 * 直接用 `readUtf16String(max)` 在内存里没有 NUL 时会一路读下去、把堆上的垃圾
 * 一起返回（实测 GetAddrInfoW 的参数常出现这种情况，日志里就是一大串乱码）。
 * 这里先按 maxChars*2 字节读一块，在块内找 NUL 截断；找不到就返回这段并标记。
 */
function u16(p, maxChars) {
  const limit = Math.max(1, maxChars || 260);
  try {
    if (p.isNull()) return '';
    let buf;
    try { buf = p.readByteArray(limit * 2); } catch (_) { buf = p.readByteArray(64); }
    if (!buf) return '';
    const view = new Uint16Array(buf);
    let end = view.length;
    for (let i = 0; i < view.length; i++) {
      if (view[i] === 0) { end = i; break; }
    }
    if (end === 0) return '';
    return String.fromCharCode.apply(null, view.subarray(0, end));
  } catch (_) { return ''; }
}

/**
 * 读一个以 NUL 结尾的 UTF-8 / ANSI 字符串。
 *
 * 同样的问题：`readUtf8String(max)` 在没有 NUL 时会读越界。而且 GetAddrInfoW 之外的
 * 路径偶尔给的是 ANSI（本地代码页），UTF-8 解出来会变问号——两种都试一下，取更"干净"的那个。
 */
function u8(p, maxBytes) {
  const limit = Math.max(1, maxBytes || 512);
  try {
    if (p.isNull()) return '';
    let buf;
    try { buf = p.readByteArray(limit); } catch (_) { buf = p.readByteArray(64); }
    if (!buf) return '';
    const bytes = new Uint8Array(buf);
    let end = bytes.length;
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) { end = i; break; }
    }
    if (end === 0) return '';
    const slice = bytes.subarray(0, end);
    let sUtf8;
    try { sUtf8 = new TextDecoder('utf-8', { fatal: false }).decode(slice); } catch (_) { sUtf8 = ''; }
    let sAnsi;
    try { sAnsi = new TextDecoder('gbk', { fatal: false }).decode(slice); } catch (_) { sAnsi = ''; }
    // 选替换字符更少的那个；一样多就用 UTF-8
    const bad = (s) => (s.match(/\uFFFD/g) || []).length;
    if (sAnsi && bad(sAnsi) < bad(sUtf8)) return sAnsi;
    return sUtf8;
  } catch (_) { return ''; }
}

/** 只保留可打印字符，域名/路径这类值用得上（避免把二进制垃圾写进日志）。 */
function cleanText(s, maxLen) {
  if (!s) return '';
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (c < 0x20 || c === 0x7F) continue;          // 控制字符
    if (c >= 0x80 && c < 0xA0) continue;           // C1 控制字符
    out += ch;
  }
  const lim = maxLen || 200;
  return out.length > lim ? out.slice(0, lim) + '…' : out;
}

/**
 * 校验并规整一个主机名。
 *
 * 实测 GetAddrInfoW 的 pNodeName 有时指向不带 NUL 的缓冲区，越界读出来的尾巴会变成
 * 一长串乱码（日志里 `wpad����…`、`cdn-t5game1.scgame.com.cn�ۺ��ۺ…` 都是这样）。
 * 合法主机名只允许字母/数字/`-`/`.`/`_` 和 IPv6 的 `:`，所以按白名单截断到第一个非法字符。
 */
function normHost(raw) {
  if (!raw) return '';
  let s = String(raw).trim();
  const bad = /[^A-Za-z0-9._:\-\[\]]/;
  const m = bad.exec(s);
  if (m) s = s.slice(0, m.index);
  if (!s) return '';
  if (s.length > 253) s = s.slice(0, 253);
  // 至少要像个主机名：含字母，或以数字点分（IP）
  if (!/[A-Za-z]/.test(s) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return '';
  return s;
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

      // 动态定位：命中 AutoAuth 时把 ilink2.dll 内的调用栈打出来。
      // AutoAuth 那几个函数没有可用于静态定位的日志宏字面量（字符串是死的符号名、无代码引用），
      // 只能趁它真的被调用时，从栈上的返回地址反推函数入口。
      if (cfg.stackOnAuth && AUTH_TRACE.test(text)) {
        try {
          const frames = [];
          let depth = 0;
          for (const f of Thread.backtrace(this.context, Backtracer.FUZZY)) {
            if (depth++ > 24) break;
            const mod2 = Process.findModuleByAddress(f);
            if (!mod2 || mod2.name.toLowerCase() !== 'ilink2.dll') continue;
            frames.push('0x' + f.sub(mod2.base).toString(16));
          }
          emit({ ev: 'auth-stack', msg: text.slice(0, 160), frames });
        } catch (e) { }
      }
    }
  });
  emit({ ev: 'xlog-hooked', module: mod.name, at: fn.toString(), rva: '0x' + cfg.xlogRva.toString(16) });
}

// 命中这些日志行就采栈（AutoAuth 的发送 / 返回 / ManualAuth）
const AUTH_TRACE = /SendAutoAuthRequest|AutoAuthResponse|SendManualAuthRequest|ilinkapp_autoauth|TdiCheckCgiResponse|ManualAuth|manualauth/i;

/**
 * ManualAuth 流程 hook（扫码登录时走这条）。
 *
 * 静态定位（2026-11-05，WXRuntime_V22346514299，见 locate_manualauth_static.py）：
 *   0xD77C0 (161B)  构造 ManualAuth 请求（引用 /ilink/ilinkapp/sys/ilinkapp_manualauth
 *                   + mov dword [rbx+10h], 0xD7D 即 cmdid 3453），只被调用 1 次
 *   0xD4710         它的唯一调用者（完整 ManualAuth 流程）
 *
 * 目的：扫码时把 ManualAuth 的请求/响应完整 dump 下来，
 * 特别是 login_buffer 里的 Device 字段（AutoAuth 需要它，但不在 tdi_account.txt 里）。
 */
function hookManualAuth(mod) {
  const rva = cfg.manualAuthRva;
  if (rva == null) return false;
  try {
    Interceptor.attach(mod.base.add(rva), {
      onEnter(args) {
        manualState.calls++;
        manualState.a0 = args[0];
        manualState.a1 = args[1];
        emit({
          ev: 'manualauth-call', n: manualState.calls, tid: this.threadId,
          a0: args[0].toString(), a1: args[1].toString(),
          a2: args[2].toString(), a3: args[3].toString(),
        });
        // 从 this 对象往外扫：login_buffer 可能作为 std::string 挂在某个偏移上。
        // 每个指针位置都试着 dump，找形如 protobuf 的内容（0x0a 开头）。
        try { scanObjectForProto('manualauth', args[0]); } catch (_) {}
      },
      onLeave(ret) {
        emit({ ev: 'manualauth-return', n: manualState.calls, ret: ret.toString() });
        // 返回后对象里应该有解析好的 login_buffer
        try { scanObjectForProto('manualauth-after', manualState.a0); } catch (_) {}
      }
    });
    emit({ ev: 'manualauth-hooked', rva: '0x' + rva.toString(16), ready: true });
    return true;
  } catch (e) {
    emit({ ev: 'manualauth-hook-error', err: String(e) });
    return false;
  }
}

/**
 * 扫描一个对象的前 N 个指针大小槽位，凡是看起来像「指向 protobuf 的指针」就 dump。
 * protobuf 特征：首字节 0x0a / 0x08 / 0x12 等，且长度合理（16..4096）。
 */
function scanObjectForProto(tag, objPtr) {
  if (!objPtr || objPtr.isNull()) return;
  for (let off = 0; off < 0x200; off += 8) {
    let p;
    try { p = objPtr.add(off).readPointer(); } catch (_) { continue; }
    if (!p || p.isNull() || p.compare(ptr('0x10000')) < 0) continue;
    // 候选 1：直接是 protobuf 起始
    try { probeProto(tag + '+0x' + off.toString(16), p); } catch (_) {}
    // 候选 2：std::string（size 在 +16，数据在 +0 或内联）
    try {
      const size = p.add(16).readU64().toNumber();
      const cap = p.add(24).readU64().toNumber();
      if (size > 16 && size < 8192 && cap >= size) {
        const data = cap >= 16 ? p.readPointer() : p;
        if (data && !data.isNull()) probeProto(tag + '+0x' + off.toString(16) + '-str', data, Math.min(size, 2048));
      }
    } catch (_) {}
  }
}

/** 首字节像 protobuf 就 dump 一段。 */
function probeProto(tag, p, len) {
  try {
    const first = p.readU8();
    // 合法 protobuf 首字节：field1 varint(0x08) / field1 len(0x0a) / field2(0x10/0x12)
    if (first !== 0x0a && first !== 0x08 && first !== 0x12 && first !== 0x10) return;
    const n = len || 512;
    dumpMem('proto-' + tag, p, n);
  } catch (_) {}
}

/** 把一段内存的 hex + 可读 ASCII 发出来（用于逆向未知结构）。 */
function dumpMem(tag, ptr_, len) {
  if (!ptr_ || ptr_.isNull()) return;
  try {
    const buf = ptr_.readByteArray(len);
    if (!buf) return;
    const bytes = new Uint8Array(buf);
    let hex = '';
    let ascii = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
      const c = bytes[i];
      ascii += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
    }
    emit({ ev: 'mem-dump', tag, addr: ptr_.toString(), len: bytes.length, hex, ascii });
  } catch (_) {}
}

/**
 * AutoAuth 主动续期实验（默认关闭）。
 *
 * 背景：AutoAuth 只在「冷启动 / session 失效」时由运行时自己发，常驻态下不会发。
 * 想让它提前发生，就得自己调 SendAutoAuthRequestAsync。
 *
 * 该函数的地址是通过调用栈动态定位出来的（没有可静态定位的日志字面量）：
 *   0x229B70  只做「打日志 -> 调 SendRequestEx(0x225130)」，
 *             签名 = void SendAutoAuthRequestAsync(TdiAuthManager* this)
 *             rcx 必须是有效的 TdiAuthManager 实例（会写 [rcx+48h]、清空 [rcx+38h] 的 std::string）
 *
 * 所以这里做两件事：
 *   1. observe：在 0x229B70 上挂 Interceptor，记下被调用时的 rcx（= this），供后续复用
 *   2. call：   用记下的 this 主动调一次，观察是否真的会发 AutoAuth 并换新 key
 */
function hookAutoAuth(mod) {
  const rva = cfg.autoAuthRva;
  if (rva == null) return false;
  try {
    Interceptor.attach(mod.base.add(rva), {
      onEnter(args) {
        // 0xD4390 是完整 AutoAuth 流程（895 字节），参数不止 this。
        // 先把前 4 个参数都记下来，避免误判哪个才是对象指针。
        const a0 = args[0], a1 = args[1], a2 = args[2], a3 = args[3];
        authState.thisPtr = a0;
        authState.calls++;
        emit({
          ev: 'autoauth-call', who: 'runtime',
          a0: a0.toString(), a1: a1.toString(), a2: a2.toString(), a3: a3.toString(),
          thisPtr: a0.toString(), n: authState.calls, tid: this.threadId,
        });
      },
      onLeave(ret) {
        emit({ ev: 'autoauth-return', n: authState.calls, ret: ret.toString() });
      }
    });
    emit({ ev: 'autoauth-hooked', rva: '0x' + rva.toString(16), ready: true });
    return true;
  } catch (e) {
    emit({ ev: 'autoauth-hook-error', err: String(e) });
    return false;
  }
}

/** 用已知的 this 指针主动调一次 SendAutoAuthRequestAsync。返回是否成功调用。 */
function invokeAutoAuth() {
  if (cfg.autoAuthRva == null) return { ok: false, why: 'rva 未知' };
  if (!authState.thisPtr) return { ok: false, why: '还没有抓到 this 指针（需要先有一次真实 AutoAuth）' };
  const mod = Process.findModuleByName('ilink2.dll');
  if (!mod) return { ok: false, why: 'ilink2.dll 未加载' };
  const before = authState.calls;
  try {
    const fn = new NativeFunction(mod.base.add(cfg.autoAuthRva), 'pointer', ['pointer']);
    const r = fn(authState.thisPtr);
    return { ok: true, thisPtr: authState.thisPtr.toString(), ret: r.toString(), callsBefore: before };
  } catch (e) {
    return { ok: false, why: String(e) };
  }
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
    onEnter(a) {
      const h = normHost(u16(a[0], 256));
      if (h && once('dns', h)) emit({ ev: 'net', op: 'dns', host: h, from: caller(this) });
    }
  });
  const gai = exp('ws2_32.dll', 'getaddrinfo');
  if (gai) Interceptor.attach(gai, {
    onEnter(a) {
      const h = normHost(u8(a[0], 256));
      if (h && once('dns', h)) emit({ ev: 'net', op: 'dns', host: h, from: caller(this) });
    }
  });
  return true;
}

function interestingModules() {
  return Process.enumerateModules()
    .filter(m => /ilink|mmtls|flue|wmpf|wechat|xweb/i.test(m.name))
    .map(m => ({ name: m.name, base: m.base.toString(), size: m.size }));
}

// ---------- 4. 业务 HTTPS 明文（BoringSSL SSL_write / SSL_read） ----------

/** 读指针处的字节为字符串（可能含二进制，按 latin1 原样取，便于关键词匹配）。 */
function rawStr(p, len) {
  try {
    if (p.isNull() || len <= 0) return '';
    const n = Math.min(len, 1 << 16);
    const bytes = new Uint8Array(p.readByteArray(n));
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  } catch (_) { return ''; }
}

function wanted(text) {
  if (!text) return false;
  for (const k of HTTP_KEYWORDS) if (text.indexOf(k) >= 0) return true;
  return false;
}

function emitHttp(dir, text) {
  if (!wanted(text)) return;
  // 截断，别把整个响应体灌进日志
  const out = text.length > 8000 ? text.slice(0, 8000) + '...<truncated>' : text;
  emit({ ev: 'http', dir, len: text.length, text: out });
}

/** 在所有已加载模块里找 SSL_write / SSL_read 导出（Chromium 常静态链接 BoringSSL，可能找不到）。 */
function findSslExports() {
  const want = ['SSL_write', 'SSL_read', 'SSL_write_ex', 'SSL_read_ex'];
  const found = {};
  for (const m of Process.enumerateModules()) {
    for (const n of want) {
      if (found[n]) continue;
      try {
        const e = m.getExportByName(n);
        if (e && !e.isNull()) found[n] = { addr: e, module: m.name };
      } catch (_) {}
    }
  }
  return found;
}

function hookSsl() {
  if (sslHooked) return;
  const f = findSslExports();
  const names = Object.keys(f);
  if (names.length === 0) {
    emit({ ev: 'ssl-missing', note: '未找到 SSL_write/SSL_read 导出（BoringSSL 可能被静态链接/裁剪）' });
    return;
  }
  sslHooked = true;

  // int SSL_write(SSL*, const void* buf, int num) —— 出站明文（请求）
  if (f.SSL_write) {
    Interceptor.attach(f.SSL_write.addr, {
      onEnter(a) { try { emitHttp('write', rawStr(a[1], a[2].toInt32())); } catch (_) {} }
    });
  }
  // int SSL_write_ex(SSL*, const void* buf, size_t num, size_t* written)
  if (f.SSL_write_ex) {
    Interceptor.attach(f.SSL_write_ex.addr, {
      onEnter(a) { try { emitHttp('write', rawStr(a[1], a[2].toInt32())); } catch (_) {} }
    });
  }
  // int SSL_read(SSL*, void* buf, int num) —— 入站明文（响应），返回值是实际字节数
  if (f.SSL_read) {
    Interceptor.attach(f.SSL_read.addr, {
      onEnter(a) { this.buf = a[1]; },
      onLeave(r) { try { const n = r.toInt32(); if (n > 0) emitHttp('read', rawStr(this.buf, n)); } catch (_) {} }
    });
  }
  if (f.SSL_read_ex) {
    Interceptor.attach(f.SSL_read_ex.addr, {
      onEnter(a) { this.buf = a[1]; this.pn = a[3]; },
      onLeave() { try { const n = this.pn.isNull() ? 0 : this.pn.readU32(); if (n > 0) emitHttp('read', rawStr(this.buf, n)); } catch (_) {} }
    });
  }
  emit({ ev: 'ssl-hooked', funcs: names.map(n => n + '@' + f[n].module) });
}

rpc.exports = {
  init(c) {
    cfg = Object.assign(cfg, c || {});
    const fileLib = hookFiles();
    const net = hookNet();
    watchIlinkModule();
    hookSsl();
    // ilink2.dll 可能比本脚本晚加载：watchIlinkModule 里会回调 hookXlog，
    // AutoAuth 的 hook 要单独等模块出现。
    //
    // AutoAuth 在 ilink 进程创建后约 1 秒内就发出去了（实测 00:39:53.725 开始，
    // 00:39:54.799 已收到 ret=0），所以这个 hook **必须立刻挂**，不能延迟——
    // 之前延后 1.5 秒导致 hook 在 00:39:59 才 ready，完全错过了。
    // （早前那次注入崩溃是「手动 Start.exe 启动、跳过 warmup」造成的，与 hook 时机无关；
    //   走程序 launch 时注入稳定：attached=3 err=0。）
    const tryAutoAuth = () => {
      const m = Process.findModuleByName('ilink2.dll');
      if (m && hookAutoAuth(m)) return true;
      return false;
    };
    if (cfg.autoAuthRva != null) {
      if (!tryAutoAuth() && typeof Process.attachModuleObserver === 'function') {
        Process.attachModuleObserver({
          onAdded(m) { if (m.name.toLowerCase() === 'ilink2.dll') tryAutoAuth(); }
        });
      }
    }
    // ManualAuth（扫码）hook：**不在 init 里挂**。
    // 实测：init 阶段多做一次 Interceptor.attach 会拖慢注入，导致 ilink 进程
    // ProcessNotRespondingError（连续 41 次失败），扫码直接失败。
    // 改成由主进程在 ilink attach 成功后通过 RPC 调 hookManualAuthNow() 挂载。
    if (cfg.manualAuthRva != null) {
      emit({ ev: 'manualauth-deferred', rva: '0x' + cfg.manualAuthRva.toString(16) });
    }
    emit({ ev: 'script-load', arch: Process.arch, fileLib, net, modules: interestingModules() });
    return true;
  },
  ping() { return 'pong'; },
  /** 查当前状态：是否已抓到 this 指针、AutoAuth 被调用过几次。 */
  autoAuthState() {
    return {
      rva: cfg.autoAuthRva == null ? null : '0x' + cfg.autoAuthRva.toString(16),
      thisPtr: authState.thisPtr ? authState.thisPtr.toString() : null,
      calls: authState.calls,
    };
  },
  /** 主动调一次 SendAutoAuthRequestAsync（实验：可能破坏运行时状态，谨慎使用）。 */
  invokeAutoAuth() { return invokeAutoAuth(); },
  /**
   * 由主进程在 ilink 稳定后调用，挂上 ManualAuth hook。
   * 不在 init 里挂的原因见 init() 的注释（会让 ilink 注入超时）。
   */
  hookManualAuthNow() {
    const m = Process.findModuleByName('ilink2.dll');
    if (!m) return { ok: false, why: 'ilink2.dll 未加载' };
    return { ok: hookManualAuth(m), rva: cfg.manualAuthRva == null ? null : '0x' + cfg.manualAuthRva.toString(16) };
  },
  /** 同上，用于 AutoAuth（避免 init 阶段拖慢注入）。 */
  hookAutoAuthNow() {
    const m = Process.findModuleByName('ilink2.dll');
    if (!m) return { ok: false, why: 'ilink2.dll 未加载' };
    return { ok: hookAutoAuth(m), rva: cfg.autoAuthRva == null ? null : '0x' + cfg.autoAuthRva.toString(16) };
  },
};
