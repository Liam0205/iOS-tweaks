// Round 60: Frida 定位 Promon 越狱判定点
// 策略: 在 hsbcchinax 基址上 hook exit(1) 封装 0x1f05dc, 命中时 dump 调用栈 + 寄存器,
// 直接看是哪条路径决定 exit。再 hook 检测子函数看返回值。
'use strict';

function log(m){ send({t:'log', m:m}); }

function waitForModule(name, cb){
  let m = Process.findModuleByName(name);
  if (m){ cb(m); return; }
  const iv = setInterval(()=>{
    m = Process.findModuleByName(name);
    if (m){ clearInterval(iv); cb(m); }
  }, 5);
}

waitForModule('hsbcchinax', function(mod){
  const base = mod.base;
  log('hsbcchinax base=' + base + ' size=' + mod.size);

  // exit(1) 封装 0x1f05dc: 命中即 dump
  const EXIT_WRAP = base.add(0x1f05dc);
  try {
    Interceptor.attach(EXIT_WRAP, {
      onEnter: function(args){
        log('★EXIT(0x1f05dc) HIT');
        log('  backtrace:');
        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        bt.forEach((a,i)=>{
          const off = a.sub(base);
          log('    #'+i+' +0x'+off.toString(16)+'  ('+a+')');
        });
      }
    });
    log('hooked exit wrapper 0x1f05dc');
  } catch(e){ log('exit hook fail: '+e); }

  // 状态机 0x75bf7c 入口 + 4 个 exit 调用点前的状态
  const EXIT_SITES = [0x760570, 0x760988, 0x769484, 0x76b078];
  EXIT_SITES.forEach(site=>{
    try {
      Interceptor.attach(base.add(site), {
        onEnter: function(){
          log('exit-site +0x'+site.toString(16)+' reached (state machine about to exit)');
        }
      });
    } catch(e){ log('site '+site.toString(16)+' hook fail: '+e); }
  });
});
