'use strict';

function resolve(n) {
  try { return Module.getGlobalExportByName(n); } catch (e) { }
  try { return Module.getExportByName(null, n); } catch (e) { }
  return null;
}

let LOG = null;
function log(s) {
  const line = '[' + new Date().toISOString().substr(11, 12) + '] ' + s + '\n';
  if (LOG) { try { LOG.write(line); LOG.flush(); } catch (e) { } }
  try { send({ m: s }); } catch (e) { }
}
(function () {
  const cands = ['/var/mobile/Containers/Data/Application/A7D7B11F-8AAF-47E1-8DC7-F86B81B50CFA/Documents/aia_probe.log'];
  for (const p of cands) { try { LOG = new File(p, 'a'); LOG.write('\n===== start ' + new Date().toISOString() + ' =====\n'); LOG.flush(); return; } catch (e) { LOG = null; } }
})();

function s(p) { if (!p || p.isNull()) return 'NULL'; try { return p.readCString(); } catch (e) { return '<unreadable>'; } }
function mod(p) {
  try { const m = Process.findModuleByAddress(p); return m ? (m.name + '+0x' + p.sub(m.base).toString(16)) : 'no-module'; } catch (e) { return '?'; }
}

function hook(n, argi, extra) {
  const p = resolve(n);
  if (!p) { log('notfound ' + n); return; }
  try {
    Interceptor.attach(p, {
      onEnter(a) {
        this.c = this.returnAddress;
        try { this.a0 = s(a[argi || 0]); } catch (e) { this.a0 = '?'; }
        if (extra) { try { this.x = extra(a); } catch (e) { this.x = '?'; } }
      },
      onLeave(r) {
        log(n + '("' + this.a0 + '"' + (this.x ? ' ' + this.x : '') + ') = ' + r + '   <- ' + mod(this.c));
      }
    });
  } catch (e) { log('hookfail ' + n + ' ' + e); }
}

['open', 'stat', 'lstat', 'access', 'readlink', 'fopen', 'dlopen', 'dlsym', 'sysctl', 'ptrace'].forEach(n => {
  hook(n, n === 'dlsym' ? 1 : 0, n === 'sysctl' ? (a => { try { return 'mib=[' + a[1].readU32() + ',' + a[1].add(4).readU32() + ']'; } catch (e) { return '?'; } }) : null);
});
hook('_dyld_register_func_for_add_image', 0, a => 'fn=' + a[0]);
hook('pthread_create', 2, a => 'start=' + a[2]);
hook('NSClassFromString', 0);
hook('objc_getClass', 0);
hook('class_copyMethodList', 0);
hook('method_exchangeImplementations', 0, a => 'b=' + a[1]);
hook('objc_copyImageNames', 0);

Process.setExceptionHandler(function (d) {
  log('EXCEPTION ' + d.type + ' addr=' + d.address + ' pc=' + d.context.pc + ' (' + mod(d.context.pc) + ')' +
      ' lr=' + d.context.lr + ' (' + mod(d.context.lr) + ') sp=' + d.context.sp);
  for (let i = 0; i < 29; i++) { try { log('  x' + i + '=' + d.context['x' + i]); } catch (e) { } }
  try {
    log('BT:\n' + Thread.backtrace(d.context, Backtracer.FUZZY).slice(0, 16)
      .map(a => '    ' + mod(a) + ' (' + a + ')').join('\n'));
  } catch (e) { }
  return false;
});

log('hooks ready');
