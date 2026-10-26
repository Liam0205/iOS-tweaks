'use strict';

function ts() {
  const d = new Date();
  return d.toISOString().substr(11, 12);
}

function log(s) {
  send({ t: ts(), m: s });
}

const hooked = {};

function tryHook(name, handler) {
  try {
    let p = null;
    try { p = Module.getGlobalExportByName(name); } catch (e) {
      try { p = Module.getExportByName(null, name); } catch (e2) { log('resolve fail ' + name); return; }
    }
    if (!p) { log('notfound ' + name); return; }
    Interceptor.attach(p, handler);
    hooked[name] = true;
  } catch (e) {
    log('hookfail ' + name + ' ' + e);
  }
}

function cstr(p) {
  if (!p || p.isNull()) return null;
  try { return p.readUtf8String(256); } catch (e) { return '?'; }
}

// ---- file / env observation ----
['open', 'openat', 'stat', 'lstat', 'access', 'readlink', 'getenv',
 'fopen', 'dladdr', 'dlsym', 'sysctl', 'ptrace'].forEach(function (n) {
  tryHook(n, {
    onEnter(args) {
      this.n = n;
      this.a0 = cstr(args[0]);
      this.a1 = args[1].toUInt32 ? args[1].toUInt32() : 0;
      if (n === 'getenv' || n === 'dlsym') this.s = cstr(args[1]);
      else if (n === 'dladdr') this.s = 'ptr=' + args[0];
      else if (n === 'sysctl') this.s = 'mib=' + args[1].toUInt32();
      else this.s = '';
    },
    onLeave(ret) {
      log(this.n + '("' + this.a0 + '"' + (this.s ? ' , ' + this.s : '') + ') -> ' + ret);
    }
  });
});

try {
  const dyldName = Module.getGlobalExportByName('_dyld_get_image_name');
  Interceptor.attach(dyldName, {
    onLeave(ret) { log('_dyld_get_image_name -> ' + cstr(ret)); }
  });
  const dyldCount = Module.getGlobalExportByName('_dyld_image_count');
  Interceptor.attach(dyldCount, { onLeave(ret) { log('_dyld_image_count -> ' + ret); } });
} catch (e) { log('dyld hook fail ' + e); }

try {
  const reg = Module.getGlobalExportByName('_dyld_register_func_for_add_image');
  Interceptor.attach(reg, {
    onEnter(args) { log('_dyld_register_func_for_add_image(fn=' + args[0] + ')'); }
  });
} catch (e) { log('add_image hook fail ' + e); }

// ---- objc / hook detection ----
['objc_copyImageNames', 'class_copyMethodList', 'method_getImplementation',
 'method_exchangeImplementations', 'getsectiondata', 'NSClassFromString',
 'objc_getClass'].forEach(function (n) {
  tryHook(n, {
    onEnter(args) { this.a = cstr(args[0]); },
    onLeave(ret) { log(n + '("' + this.a + '") -> ' + ret); }
  });
});

// ---- thread creation ----
tryHook('pthread_create', {
  onEnter(args) { log('pthread_create start_routine=' + args[2] + ' arg=' + args[3]); },
  onLeave(ret) { log('pthread_create -> ' + ret); }
});

// ---- exception capture ----
Process.setExceptionHandler(function (details) {
  log('EXCEPTION type=' + details.type + ' addr=' + details.address + ' pc=' + details.context.pc +
      ' sp=' + details.context.sp + ' lr=' + details.context.lr + ' fp=' + details.context.fp);
  try {
    log('BACKTRACE:\n' + Thread.backtrace(details.context, Backtracer.ACCURATE)
      .map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join('\n'));
  } catch (e) { log('bt fail ' + e); }
  return false; // let it crash so we can compare with the report
});

log('script loaded, hooked=' + Object.keys(hooked).join(','));
