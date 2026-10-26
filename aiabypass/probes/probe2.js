'use strict';

let LOG = null;
function openLog() {
  let dir = null;
  try {
    const NSHomeDirectory = new NativeFunction(
      Module.getGlobalExportByName('NSHomeDirectory'), 'pointer', []);
    dir = new ObjC.Object(NSHomeDirectory()).toString();
  } catch (e) { }
  if (!dir) dir = '/var/mobile';
  const path = dir + '/Documents/aia_probe.log';
  try {
    LOG = new File(path, 'a');
    LOG.write('\n===== probe start ' + new Date().toISOString() + ' =====\n');
    LOG.flush();
    return path;
  } catch (e) {
    return 'logopenfail ' + e;
  }
}

function log(s) {
  const line = '[' + new Date().toISOString().substr(11, 12) + '] ' + s + '\n';
  if (LOG) { try { LOG.write(line); LOG.flush(); } catch (e) { } }
  send({ m: s });
}

function cstr(p, n) {
  if (!p || p.isNull()) return null;
  try { return p.readUtf8String(n || 200); } catch (e) { return '<unreadable>'; }
}

function resolve(name) {
  try { return Module.getGlobalExportByName(name); } catch (e) { }
  try { return Module.getExportByName(null, name); } catch (e) { }
  return null;
}

function hook(name, spec) {
  const p = resolve(name);
  if (!p) { log('notfound ' + name); return false; }
  try { Interceptor.attach(p, spec); return true; }
  catch (e) { log('hookfail ' + name + ': ' + e); return false; }
}

const where = openLog();
log('log file: ' + where);
log('agent loaded in pid ' + Process.id);

// ---------- 终止原语 ----------
['exit', 'abort', 'kill', 'raise', '_exit', 'pthread_exit', 'task_terminate'].forEach(function (n) {
  hook(n, {
    onEnter(args) {
      log('TERMINATE ' + n + ' arg0=' + args[0] + ' bt=' +
        Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 6)
          .map(a => DebugSymbol.fromAddress(a).toString()).join(' | '));
    }
  });
});

// ---------- 文件 / 环境 ----------
hook('open', {
  onEnter(args) { this.p = cstr(args[0]); },
  onLeave(ret) { log('open("' + this.p + '") -> ' + ret); }
});
hook('openat', {
  onEnter(args) { this.p = cstr(args[1]); },
  onLeave(ret) { log('openat("' + this.p + '") -> ' + ret); }
});
['stat', 'lstat', 'access', 'readlink', 'fopen'].forEach(function (n) {
  hook(n, {
    onEnter(args) { this.p = cstr(args[0]); },
    onLeave(ret) { log(n + '("' + this.p + '") -> ' + ret); }
  });
});
hook('getenv', {
  onEnter(args) { this.n = cstr(args[0]); },
  onLeave(ret) { log('getenv("' + this.n + '") -> ' + cstr(ret)); }
});
hook('sysctl', {
  onEnter(args) { this.mib = ''; try { this.mib = args[1].readU32().toString(16); } catch (e) { } },
  onLeave(ret) { log('sysctl(mib=' + this.mib + ') -> ' + ret); }
});
hook('ptrace', {
  onEnter(args) { log('ptrace(req=' + args[0] + ')'); }
});

// ---------- dyld / 镜像 ----------
hook('_dyld_image_count', { onLeave(ret) { log('_dyld_image_count -> ' + ret); } });
hook('_dyld_get_image_name', {
  onLeave(ret) { log('_dyld_get_image_name -> ' + cstr(ret)); }
});
hook('_dyld_register_func_for_add_image', {
  onEnter(args) { log('_dyld_register_func_for_add_image(fn=' + args[0] + ')'); }
});
hook('dlsym', {
  onEnter(args) { this.n = cstr(args[1]); },
  onLeave(ret) { log('dlsym("' + this.n + '") -> ' + ret); }
});
hook('dladdr', { onEnter(args) { log('dladdr(' + args[0] + ')'); } });

// ---------- objc / hook 检测 ----------
hook('objc_copyImageNames', {
  onEnter(args) { this.out = args[0]; },
  onLeave(ret) { log('objc_copyImageNames -> ' + ret); }
});
hook('class_copyMethodList', {
  onEnter(args) { this.c = cstr(Module.getGlobalExportByName('class_getName') ? args[0] : args[0]); },
  onLeave(ret) { log('class_copyMethodList("' + this.c + '") -> ' + ret); }
});
hook('method_exchangeImplementations', {
  onEnter(args) { log('method_exchangeImplementations(' + args[0] + ',' + args[1] + ')'); }
});
hook('NSClassFromString', {
  onEnter(args) { this.n = cstr(args[0]); },
  onLeave(ret) { log('NSClassFromString("' + this.n + '") -> ' + ret); }
});

// ---------- 线程 ----------
hook('pthread_create', {
  onEnter(args) { this.fn = args[2]; log('pthread_create start_routine=' + args[2]); },
  onLeave(ret) { log('pthread_create -> ' + ret); }
});

// ---------- 异常 ----------
Process.setExceptionHandler(function (d) {
  log('EXCEPTION ' + d.type + ' addr=' + d.address + ' pc=' + d.context.pc +
      ' lr=' + d.context.lr + ' fp=' + d.context.fp + ' sp=' + d.context.sp);
  for (let i = 0; i < 29; i++) {
    try { log('  x' + i + '=' + d.context['x' + i]); } catch (e) { }
  }
  try {
    log('BT:\n' + Thread.backtrace(d.context, Backtracer.FUZZY)
      .map(a => '   ' + DebugSymbol.fromAddress(a).toString()).join('\n'));
  } catch (e) { log('bt fail ' + e); }
  return false;
});

log('hooks installed');
