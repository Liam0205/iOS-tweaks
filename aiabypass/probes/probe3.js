'use strict';

function log(s) { send({ m: s }); }

function cstr(p, n) {
  if (!p || p.isNull()) return 'NULL';
  try { return p.readUtf8String(n || 200); } catch (e) { return '<unreadable>'; }
}

function modinfo(p) {
  try {
    const m = Process.findModuleByAddress(p);
    if (!m) return 'no-module';
    return m.name + '+0x' + p.sub(m.base).toString(16);
  } catch (e) { return 'err'; }
}

log('=== modules at agent load ===');
try {
  Process.enumerateModules().forEach(function (m) {
    log('MOD ' + m.name + ' base=' + m.base + ' size=0x' + m.size.toString(16));
  });
} catch (e) { log('enumerateModules fail ' + e); }

function resolve(name) {
  try { return Module.getGlobalExportByName(name); } catch (e) { }
  try { return Module.getExportByName(null, name); } catch (e) { }
  return null;
}

function bt(ctx, depth) {
  try {
    return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, depth || 8)
      .map(a => modinfo(a) + ' (' + a + ')').join('\n     ');
  } catch (e) { return 'bt fail ' + e; }
}

// getenv 带调用栈
const gp = resolve('getenv');
if (gp) {
  Interceptor.attach(gp, {
    onEnter(args) { this.n = cstr(args[0]); },
    onLeave(ret) {
      log('getenv("' + this.n + '") -> ' + cstr(ret) +
          '  ret=' + ret + '\n     bt: ' + bt(this.context, 6));
    }
  });
}

// 关键 libc 入口带调用栈（只记录前几次）
let budget = 200;
function hookBt(name, argIndex) {
  const p = resolve(name);
  if (!p) { log('notfound ' + name); return; }
  try {
    Interceptor.attach(p, {
      onEnter(args) {
        if (budget-- <= 0) return;
        let a = '';
        try { a = cstr(args[argIndex || 0]); } catch (e) { }
        log(name + '("' + a + '") from ' + modinfo(this.returnAddress) + '\n     bt: ' + bt(this.context, 5));
      }
    });
    log('hooked ' + name);
  } catch (e) { log('hookfail ' + name + ': ' + e); }
}
['open', 'stat', 'lstat', 'fopen', 'access', 'readlink', 'dlopen', 'dlsym'].forEach(n => hookBt(n, 0));
hookBt('_dyld_register_func_for_add_image', 0);
hookBt('pthread_create', 2);

Process.setExceptionHandler(function (d) {
  log('EXCEPTION ' + d.type + ' addr=' + d.address + ' pc=' + d.context.pc + ' (' + modinfo(d.context.pc) + ')' +
      ' lr=' + d.context.lr + ' (' + modinfo(d.context.lr) + ')' +
      ' fp=' + d.context.fp + ' sp=' + d.context.sp);
  for (let i = 0; i < 29; i++) { try { log('  x' + i + '=' + d.context['x' + i]); } catch (e) { } }
  log('BT:\n     ' + bt(d.context, 14));
  return false;
});

log('=== hooks installed ===');
