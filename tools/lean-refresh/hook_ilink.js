/**
 * Frida observe-only script for WeChatAppEx in qb1.
 * - Enumerate modules whose name hints ilink/mmtls/wmpf
 * - Watch WriteFile / MoveFileExW hitting tdi_account.txt or psk.key
 * Does NOT modify arguments or inject network traffic.
 */
'use strict';

function emit(obj) {
  send(Object.assign({ ts: Date.now() }, obj));
}

function u16(p, max) {
  try {
    if (p.isNull()) return '';
    return p.readUtf16String(max || 512) || '';
  } catch (_) {
    return '';
  }
}

function interestingPath(s) {
  if (!s) return false;
  const lower = s.toLowerCase();
  return lower.indexOf('tdi_account.txt') >= 0 ||
    lower.indexOf('psk.key') >= 0 ||
    lower.indexOf('\\ilink\\') >= 0 ||
    lower.indexOf('/ilink/') >= 0;
}

function listInterestingModules() {
  const hits = [];
  Process.enumerateModules().forEach(function (m) {
    const n = (m.name || '').toLowerCase();
    if (n.indexOf('ilink') >= 0 || n.indexOf('mmtls') >= 0 || n.indexOf('wmpf') >= 0 ||
        n.indexOf('wechat') >= 0 || n.indexOf('mm') === 0) {
      hits.push({ name: m.name, base: m.base.toString(), size: m.size });
    }
  });
  return hits;
}

function exportByName(mod, name) {
  try {
    const m = Process.getModuleByName(mod);
    if (typeof m.getExportByName === 'function') return m.getExportByName(name);
    if (typeof m.findExportByName === 'function') return m.findExportByName(name);
  } catch (_) {}
  try {
    if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(name);
  } catch (_) {}
  return null;
}

function hookKernel32Writes() {
  const k32 = exportByName('kernel32.dll', 'WriteFile');
  if (k32) {
    Interceptor.attach(k32, {
      onEnter: function (args) {
        this.h = args[0];
        this.n = args[2].toInt32();
      },
      onLeave: function (retval) {
        // Path not available from WriteFile alone; rely on CreateFileW trail below.
      }
    });
  }

  const create = exportByName('kernel32.dll', 'CreateFileW');
  if (create) {
    Interceptor.attach(create, {
      onEnter: function (args) {
        this.path = u16(args[0], 1024);
      },
      onLeave: function (retval) {
        if (!interestingPath(this.path)) return;
        emit({
          ev: 'CreateFileW',
          path: this.path,
          handle: retval.toString(),
          ok: !retval.equals(ptr('-1'))
        });
      }
    });
  }

  const move = exportByName('kernel32.dll', 'MoveFileExW');
  if (move) {
    Interceptor.attach(move, {
      onEnter: function (args) {
        this.src = u16(args[0], 1024);
        this.dst = u16(args[1], 1024);
      },
      onLeave: function (retval) {
        if (!interestingPath(this.src) && !interestingPath(this.dst)) return;
        emit({
          ev: 'MoveFileExW',
          src: this.src,
          dst: this.dst,
          ok: retval.toInt32() !== 0
        });
      }
    });
  }

  const write = k32;
  // Pair with last CreateFile is hard; also hook NtWriteFile via path map if needed later.
  emit({ ev: 'hooks', createFileW: !!create, moveFileExW: !!move, writeFile: !!write });
}

function scanModuleStrings(mod, needles) {
  const found = [];
  try {
    const ranges = Process.enumerateRangesSync({ protection: 'r--', coalesce: true })
      .filter(function (r) {
        return r.base.compare(mod.base) >= 0 &&
          r.base.compare(mod.base.add(mod.size)) < 0;
      });
    // Keep light: only check module name list; deep string scan is expensive.
  } catch (_) { }
  return found;
}

rpc.exports = {
  ping: function () { return 'pong'; },
  modules: function () { return listInterestingModules(); }
};

emit({ ev: 'script-load', pid: Process.id, arch: Process.arch });
emit({ ev: 'modules', list: listInterestingModules() });
hookKernel32Writes();
