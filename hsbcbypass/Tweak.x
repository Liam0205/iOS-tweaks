// Round 65 探针: PRMShieldEventManager 是 Promon 的 ObjC 入口类, 有 performSecurityChecks 方法。
// 策略(abcbypass 式纯 ObjC swizzle, 不碰 __TEXT, 不触发自旋):
//   1) 记录 performSecurityChecks 是否被调、何时;
//   2) 试 no-op 它, 看能否跳过检测(OBSERVE_ONLY 控制)。
// 注意 init[42] 的 C 初始化检测独立于此 ObjC 方法(3s 退出来自那), 此法可能只覆盖后续检测层, 但 ObjC hook 干净, 值得试。
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>

#ifndef NEUTRALIZE
#define NEUTRALIZE 0   // 0=只观测(调 orig); 1=no-op(跳过检测)
#endif

static int g_fd = -1;
static double g_t0 = 0;
static void emit(const char *s){ if(g_fd>=0)(void)write(g_fd,s,strlen(s)); }
static void emitv(const char*label,unsigned long v){
  char b[128];int p=0;const char*l=label;while(*l)b[p++]=*l++;b[p++]='0';b[p++]='x';
  char t[18];int n=0;if(!v){t[n++]='0';}while(v){int d=v&0xf;t[n++]=d<10?'0'+d:'a'+d-10;v>>=4;}
  while(n)b[p++]=t[--n];b[p++]='\n';if(g_fd>=0)(void)write(g_fd,b,p);
}
static double now_ms(void){ return (g_t0>0)?(CFAbsoluteTimeGetCurrent()-g_t0)*1000:0; }

// 保存原 IMP
static void (*orig_perform)(id,SEL);

static void my_perform(id self, SEL _cmd){
  emitv("[performSecurityChecks] 被调 t_ms=", (unsigned long)now_ms());
#if NEUTRALIZE
  emit("  → NEUTRALIZE: 跳过(不调 orig)\n");
  return;
#else
  emit("  → observe: 调 orig\n");
  if(orig_perform) orig_perform(self,_cmd);
  emit("  ← orig 返回\n");
#endif
}

%ctor {
  g_t0 = CFAbsoluteTimeGetCurrent();
  char path[256];
  snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",
           NSTemporaryDirectory().fileSystemRepresentation, getpid());
  FILE*f=fopen(path,"w"); if(f)fclose(f);
  g_fd=open(path,O_WRONLY|O_APPEND);
  emitv("ctor: NEUTRALIZE=", NEUTRALIZE);

  // 等 PRMShieldEventManager 类注册(它有 +load, 应在早期已注册)
  Class cls = objc_getClass("PRMShieldEventManager");
  if(!cls){ emit("ctor: PRMShieldEventManager 未注册(可能还没load)\n"); }
  else {
    SEL sel = sel_registerName("performSecurityChecks");
    Method m = class_getInstanceMethod(cls, sel);
    if(m){
      orig_perform = (void(*)(id,SEL))method_getImplementation(m);
      method_setImplementation(m, (IMP)my_perform);
      emit("ctor: 已 swizzle -[PRMShieldEventManager performSecurityChecks]\n");
    } else {
      // 也可能是类方法
      Method cm = class_getClassMethod(cls, sel);
      if(cm){
        orig_perform=(void(*)(id,SEL))method_getImplementation(cm);
        method_setImplementation(cm,(IMP)my_perform);
        emit("ctor: 已 swizzle +[PRMShieldEventManager performSecurityChecks]\n");
      } else emit("ctor: 找不到 performSecurityChecks 方法\n");
    }
  }
}
