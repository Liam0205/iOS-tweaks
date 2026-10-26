'use strict';

function resolve(name) {
  try { return Module.getGlobalExportByName(name); } catch (e) { }
  try { return Module.getExportByName(null, name); } catch (e) { }
  return null;
}

let LOG = null;
let LOGBUF = [];
function log(s) {
  const line = '[' + new Date().toISOString().substr(11, 12) + '] ' + s + '\n';
  LOGBUF.push(line);
  if (LOG) { try { LOG.write(line); LOG.flush(); } catch (e) { } }
}

(function openLog() {
  let home = null;
  try {
    const ge = resolve('getenv');
    const name = Memory.allocUtf8String('HOME');
    const p = new NativeFunction(ge, 'pointer', ['pointer'])(name);
    if (p && !p.isNull()) home = p.readUtf8String();
  } catch (e) { }
  const cands = [];
  if (home) { cands.push(home + '/Documents/aia_probe.log'); cands.push(home + '/tmp/aia_probe.log'); }
  cands.push('/var/mobile/Containers/Data/Application/A7D7B11F-8AAF-47E1-8DC7-F86B81B50CFA/Documents/aia_probe.log');
  for (const p of cands) {
    try {
      LOG = new File(p, 'a');
      LOG.write('\n===== probe start ' + new Date().toISOString() + ' home=' + home + ' =====\n');
      LOG.flush();
      return;
    } catch (e) { LOG = null; }
  }
})();

function cstr(p, n) {
  if (!p || p.isNull()) return 'NULL';
  try { return p.readUtf8String(n || 200); } catch (e) { return '<unreadable>'; }
}
function modinfo(p) {
  try { const m = Process.findModuleByAddress(p); return m ? (m.name + '+0x' + p.sub(m.base).toString(16)) : 'no-module'; }
  catch (e) { return 'err'; }
}
function bt(ctx, depth) {
  try {
    return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, depth || 10)
      .map(a => '      ' + modinfo(a) + ' (' + a + ')').join('\n');
  } catch (e) { return '      bt fail ' + e; }
}

log('agent pid=' + Process.id + ' logfile ready');

function hook(name, spec) {
  const p = resolve(name);
  if (!p) { log('notfound ' + name); return false; }
  try { Interceptor.attach(p, spec); log('hooked ' + name); return true; }
  catch (e) { log('hookfail ' + name + ': ' + e); return false; }
}

// getenv 全量记录（带调用栈）
hook('getenv', {
  onEnter(args) { this.n = cstr(args[0]); this.caller = this.returnAddress; },
  onLeave(ret) {
    log('getenv("' + this.n + '") -> ' + cstr(ret) + '   caller=' + modinfo(this.caller) + '\n' + bt(this.context, 6));
  }
});

// 文件与 dyld
['open', 'stat', 'lstat', 'access', 'readlink', 'fopen', 'dlopen', 'dlsym',
 'sysctl', 'ptrace', '_dyld_register_func_for_add_image', 'pthread_create',
 'class_copyMethodList', 'method_exchangeImplementations', 'objc_copyImageNames',
 'NSClassFromString', 'objc_getClass'].forEach(function (n) {
  hook(n, {
    onEnter(args) {
      let a = '';
      try {
        const idx = (n === 'dlsym' || n === 'openat' || n === 'pthread_create' ||
                     n === '_dyld_register_func_for_add_image' ||
                     n === 'class_copyMethodList' || n === 'method_exchangeImplementations' ||
                     n === 'objc_copyImageNames') ? (n === 'dlsym' ? 1 : (n === 'pthread_create' ? 2 : 0)) : 0;
        a = cstr(args[idx]);
      } catch (e) { }
      this.n = n; this.a = a; this.caller = this.returnAddress;
    },
    onLeave(ret) {
      log(this.n + '("' + this.a + '") -> ' + ret + '   caller=' + modinfo(this.caller));
    }
  });
});

Process.setExceptionHandler(function (d) {
  log('EXCEPTION ' + d.type + ' addr=' + d.address + ' pc=' + d.context.pc + ' (' + modinfo(d.context.pc) + ')' +
      ' lr=' + d.context.lr + ' (' + modinfo(d.context.lr) + ')' +
      ' fp=' + d.context.fp + ' sp=' + d.context.sp);
  for (let i = 0; i < 29; i++) { try { log('  x' + i + '=' + d.context['x' + i]); } catch (e) { } }
  try { log('  pc=' + d.context.pc + ' lr=' + d.context.lr + ' fp=' + d.context.fp + ' sp=' + d.context.sp); } catch (e) { }
  log('BT:\n' + bt(d.context, 16));
  return false;
});

log('hooks installed');
