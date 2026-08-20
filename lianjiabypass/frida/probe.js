'use strict';
// 第 2 轮 Frida 探测：抓退出路径 + 检测判定链
// 目标：链家 com.exmart.HomeLink / JGBSDK

// frida 17 起 ObjC/Swift bridge 不再全局注入，需显式 require
var ObjC = (typeof globalThis !== 'undefined') ? globalThis.ObjC : undefined;
if (!ObjC || !ObjC.available) {
  try {
    ObjC = require('frida-objc-bridge');
    if (typeof globalThis !== 'undefined') { globalThis.ObjC = ObjC; }
  } catch (e) {}
}

function ts() { return (Date.now() % 100000) / 1000.0; }
function log(m) { console.log('[' + ts().toFixed(3) + '] ' + m); }

// frida 17 移除了 Module.findExportByName —— 兼容 shim
function findExport(modName, name) {
  try {
    if (Module.findExportByName) { return Module.findExportByName(modName, name); }
  } catch (e) {}
  try {
    if (modName) {
      var m = Process.findModuleByName(modName);
      return m ? m.findExportByName(name) : null;
    }
    if (Module.findGlobalExportByName) { return Module.findGlobalExportByName(name); }
    // 回退：遍历模块
    var found = null;
    Process.enumerateModules().some(function (mod) {
      var p = mod.findExportByName(name);
      if (p) { found = p; return true; }
      return false;
    });
    return found;
  } catch (e) { return null; }
}

function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(function (a) { return DebugSymbol.fromAddress(a).toString(); })
      .join('\n    ');
  } catch (e) { return '<bt failed: ' + e + '>'; }
}

// ========== 1) 退出路径：libc + syscall 层 ==========
['exit', '_exit', 'abort', '__exit', 'exit_group'].forEach(function (name) {
  var p = findExport(null, name);
  if (!p) { return; }
  Interceptor.attach(p, {
    onEnter: function (args) {
      log('EXIT >>> ' + name + '(' + args[0].toInt32() + ') tid=' + this.threadId);
      log('  backtrace:\n    ' + bt(this.context));
    }
  });
  log('hooked exit path: ' + name + ' @ ' + p);
});

// raw syscall SYS_exit(1) / SYS_exit_group 通过 svc —— hook libsystem_kernel 的 syscall wrapper
var syscallP = findExport("libsystem_kernel.dylib", "syscall");
if (syscallP) {
  Interceptor.attach(syscallP, {
    onEnter: function (args) {
      var n = args[0].toInt32();
      if (n === 1 || n === 169) { // SYS_exit=1
        log('SYSCALL exit >>> num=' + n + ' tid=' + this.threadId);
        log('  backtrace:\n    ' + bt(this.context));
      }
    }
  });
  log('hooked libsystem_kernel!syscall');
}

// ========== 2) JGBSDK 检测函数 ==========
function hookJGB() {
  var jgb = Process.findModuleByName('JGBSDK');
  if (!jgb) { log('JGBSDK not loaded yet'); return false; }
  log('JGBSDK base=' + jgb.base + ' size=' + jgb.size);
  // 已知内部唯一 _exit 调用点静态偏移 0xbc4c
  var exitCall = jgb.base.add(0xbc4c);
  try {
    Interceptor.attach(exitCall, {
      onEnter: function () {
        log('JGB internal _exit call @0xbc4c HIT tid=' + this.threadId);
        log('  backtrace:\n    ' + bt(this.context));
      }
    });
    log('hooked JGB internal exit-site @0xbc4c');
  } catch (e) { log('hook 0xbc4c failed: ' + e); }
  return true;
}

// ========== 3) LJBRProtectManager 方法遍历 ==========
function dumpProtectManager() {
  if (!ObjC || !ObjC.available) { log('ObjC not available'); return; }
  var cls = ObjC.classes.LJBRProtectManager;
  if (!cls) { log('LJBRProtectManager absent'); return; }
  log('=== LJBRProtectManager methods ===');
  cls.$ownMethods.forEach(function (m) { log('  ' + m); });

  // hook 所有实例/类方法打点
  cls.$ownMethods.forEach(function (mname) {
    try {
      var impl = cls[mname].implementation;
      Interceptor.attach(impl, {
        onEnter: function () { this._m = mname; log('LJBR call ' + mname); }
      });
    } catch (e) {}
  });
}

// 检测类可能延迟加载，用定时器轮询（只执行一次）
var tries = 0;
var jgbDone = false;
var timer = setInterval(function () {
  tries++;
  if (jgbDone) { return; }
  if (hookJGB() || tries > 40) {
    jgbDone = true;
    try { dumpProtectManager(); } catch (e) { log('dumpProtectManager err: ' + e); }
    clearInterval(timer);
  }
}, 100);

log('probe.js loaded, waiting for modules...');
