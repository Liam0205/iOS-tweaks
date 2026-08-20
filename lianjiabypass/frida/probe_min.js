'use strict';
// 最小验证：spawn 模式下 Interceptor 是否真的生效
// hook open/openat（App 启动必然大量调用），计数命中

function log(m) { console.log(m); }

function findExport(modName, name) {
  try { if (Module.findExportByName) return Module.findExportByName(modName, name); } catch (e) {}
  try {
    if (modName) { var m = Process.findModuleByName(modName); return m ? m.findExportByName(name) : null; }
    var found = null;
    Process.enumerateModules().some(function (mod) {
      var p = mod.findExportByName(name); if (p) { found = p; return true; } return false;
    });
    return found;
  } catch (e) { return null; }
}

var counters = {};
['open', 'openat', 'stat', 'access', 'objc_msgSend'].forEach(function (name) {
  var p = findExport(null, name);
  if (!p) { log('MISS export: ' + name); return; }
  counters[name] = 0;
  Interceptor.attach(p, {
    onEnter: function () {
      counters[name]++;
      if (counters[name] <= 3) {
        var arg = '';
        try { arg = (name === 'objc_msgSend') ? '' : Memory.readUtf8String(this.context.x0); } catch (e) {}
        log('HIT ' + name + ' #' + counters[name] + ' ' + arg);
      }
    }
  });
  log('hooked ' + name + ' @ ' + p);
});

// 每秒汇报计数
var ticks = 0;
setInterval(function () {
  ticks++;
  log('TICK ' + ticks + ' counts=' + JSON.stringify(counters));
}, 1000);

log('probe_min loaded');
