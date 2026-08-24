// Round 60 探针: 用 ElleKit MSHookFunction 在退出封装 0x1f05dc 上挂钩,
// 命中(= Promon 决定 exit(1))时 dump fp-chain 调用栈, 定位 0x75bf7c 里哪条 exit-case 触发。
// 这跑在**未破坏的真实检测序列**里(不 nop-store, exit 必经 0x1f05dc), 避开之前的自旋/竞争问题。
// 关键前提(Round50 已证): 无 __TEXT 完整性校验, inline hook 0x1f05dc 不会被 Promon 发现。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>
#import <pthread.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

// ElleKit / Substrate C API
extern void MSHookFunction(void *symbol, void *replace, void **result);

#define EXIT_WRAP_OFF 0x1f05dc   // exit(1) 封装(mov x16,#1 → svc 网关)

static int g_fd = -1;
static intptr_t g_slide = 0;
static double g_t0 = 0;

static void emit(const char *s){ if(g_fd>=0) (void)write(g_fd, s, strlen(s)); }
static void emit_hex(const char *label, unsigned long v){
  char b[64]; int p=0; const char *l=label; while(*l) b[p++]=*l++;
  b[p++]='0'; b[p++]='x';
  char t[18]; int n=0; if(!v){t[n++]='0';} while(v){int d=v&0xf; t[n++]=d<10?'0'+d:'a'+d-10; v>>=4;}
  while(n) b[p++]=t[--n]; b[p++]='\n';
  if(g_fd>=0)(void)write(g_fd,b,p);
}

// fp-chain 回溯: x29 链, 每帧 [fp]=上一个fp, [fp+8]=返回地址(LR)
static void dump_backtrace(void){
  emit("=== EXIT(0x1f05dc) 命中, fp-chain 回溯 ===\n");
  void *fp = __builtin_frame_address(0);
  for (int i=0; i<24 && fp; i++){
    void **frame = (void**)fp;
    void *next = frame[0];
    void *lr   = frame[1];
    if (!lr) break;
    unsigned long off = (unsigned long)lr - (unsigned long)g_slide;
    // 只关心落在 hsbcchinax __text(0x8000..0x76c5fc)内的返回地址
    char line[80]; int p=0;
    line[p++]=' '; line[p++]='#';
    if(i>=10){ line[p++]='0'+i/10; } line[p++]='0'+i%10;
    line[p++]=' '; line[p++]='+'; line[p++]='0'; line[p++]='x';
    char t[18]; int n=0; unsigned long v=off; if(!v){t[n++]='0';} while(v){int d=v&0xf;t[n++]=d<10?'0'+d:'a'+d-10;v>>=4;}
    while(n) line[p++]=t[--n];
    line[p++]='\n';
    if(g_fd>=0)(void)write(g_fd,line,p);
    if (next <= fp) break;   // fp 必须递增, 否则栈坏了
    fp = next;
  }
  emit("=== 回溯结束 ===\n");
}

static void (*orig_exit_wrap)(void);
static void my_exit_wrap(void){
  // 命中即回溯; 然后仍调用原封装(让 App 正常退出, 只观测不改行为)
  double d = (CFAbsoluteTimeGetCurrent()-g_t0)*1000;
  emit_hex("[EXIT-0x1f05dc] t_ms=", (unsigned long)d);
  dump_backtrace();
  // 注意: 原封装是"发起 exit syscall"的, 调它进程就结束; 不返回。
  if (orig_exit_wrap) orig_exit_wrap();
}

// 0x75bf7c 状态机入口 hook: 确认它是否运行 + 何时
static void (*orig_75bf7c)(void);
static void my_75bf7c(void){
  double d=(CFAbsoluteTimeGetCurrent()-g_t0)*1000;
  emit_hex("[ENTER-0x75bf7c] t_ms=", (unsigned long)d);
  if (orig_75bf7c) orig_75bf7c();
  d=(CFAbsoluteTimeGetCurrent()-g_t0)*1000;
  emit_hex("[RETURN-0x75bf7c] t_ms=", (unsigned long)d);  // 若能返回, 说明检测没在里面 exit
}

// 通用 libc exit/_exit/abort hook, 抓非 0x1f05dc 的退出路径
static void (*orig_libc_exit)(int);
static void my_libc_exit(int code){
  double d=(CFAbsoluteTimeGetCurrent()-g_t0)*1000;
  emit_hex("[libc exit] code=", (unsigned long)code);
  emit_hex("  t_ms=", (unsigned long)d);
  dump_backtrace();
  if (orig_libc_exit) orig_libc_exit(code);
}
static void (*orig_libc__exit)(int);
static void my_libc__exit(int code){
  emit_hex("[libc _exit] code=", (unsigned long)code);
  dump_backtrace();
  if (orig_libc__exit) orig_libc__exit(code);
}

static void (*orig_abort)(void);
static void my_abort(void){ emit("[abort]\n"); dump_backtrace(); if(orig_abort) orig_abort(); }

static int (*orig_pthread_kill)(void*, int);
static int my_pthread_kill(void *t, int sig){ emit_hex("[pthread_kill] sig=",(unsigned long)sig); dump_backtrace(); return orig_pthread_kill?orig_pthread_kill(t,sig):0; }

static int (*orig_kill)(int,int);
static int my_kill(int pid,int sig){ emit_hex("[kill] sig=",(unsigned long)sig); dump_backtrace(); return orig_kill?orig_kill(pid,sig):0; }

static void (*orig_pthread_exit)(void*);
static void my_pthread_exit(void *v){ emit("[pthread_exit]\n"); dump_backtrace(); if(orig_pthread_exit) orig_pthread_exit(v); }

// Mach 终止路径
static int (*orig_task_terminate)(unsigned int);
static int my_task_terminate(unsigned int t){ emit("[task_terminate]\n"); dump_backtrace(); return orig_task_terminate?orig_task_terminate(t):0; }
static int (*orig_thread_terminate)(unsigned int);
static int my_thread_terminate(unsigned int t){ emit("[thread_terminate]\n"); dump_backtrace(); return orig_thread_terminate?orig_thread_terminate(t):0; }
static int (*orig___pthread_kill)(void*,int);
static int my___pthread_kill(void*t,int s){ emit_hex("[__pthread_kill] sig=",(unsigned long)s); dump_backtrace(); return orig___pthread_kill?orig___pthread_kill(t,s):0; }
static void (*orig_exit_group)(int);
static void my_exit_group(int c){ emit_hex("[exit_group] code=",(unsigned long)c); dump_backtrace(); if(orig_exit_group)orig_exit_group(c); }

// 通用 hook 助手
static void hookf(const char *name, void *repl, void **orig){
  void *p = dlsym((void*)-2, name);
  if (p){ MSHookFunction(p, repl, orig); char b[64]; snprintf(b,sizeof(b),"ctor: hooked %s\n",name); emit(b); }
}

static intptr_t hsbc_slide(void){
  uint32_t n=_dyld_image_count();
  for(uint32_t i=0;i<n;i++){ const char*nm=_dyld_get_image_name(i);
    if(nm&&strstr(nm,"hsbcchinax")) return _dyld_get_image_vmaddr_slide(i); }
  return 0;
}

%hook UIApplication
- (void)_terminateWithStatus:(int)status {
  emit_hex("[_terminateWithStatus] status=", (unsigned long)status);
  dump_backtrace();
  %orig;
}
- (void)terminateWithSuccess {
  emit("[terminateWithSuccess]\n");
  dump_backtrace();
  %orig;
}
%end

%ctor {
  g_t0 = CFAbsoluteTimeGetCurrent();
  char path[256];
  snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",
           NSTemporaryDirectory().fileSystemRepresentation, getpid());
  FILE *f=fopen(path,"w"); if(f) fclose(f);
  g_fd = open(path, O_WRONLY|O_APPEND);

  g_slide = hsbc_slide();
  emit_hex("ctor: slide=", (unsigned long)g_slide);
  if(!g_slide){ emit("ctor: 未找到 hsbcchinax\n"); return; }

  void *target = (void*)(0x1f05dc + g_slide);   // EXIT_WRAP_OFF
  MSHookFunction(target, (void*)my_exit_wrap, (void**)&orig_exit_wrap);
  emit_hex("ctor: hooked exit wrapper @", (unsigned long)target);

  void *sm = (void*)(0x75bf7c + g_slide);
  MSHookFunction(sm, (void*)my_75bf7c, (void**)&orig_75bf7c);
  emit_hex("ctor: hooked 0x75bf7c @", (unsigned long)sm);

  // libc 各种退出/终止路径
  hookf("exit", (void*)my_libc_exit, (void**)&orig_libc_exit);
  hookf("_exit", (void*)my_libc__exit, (void**)&orig_libc__exit);
  hookf("abort", (void*)my_abort, (void**)&orig_abort);
  hookf("pthread_kill", (void*)my_pthread_kill, (void**)&orig_pthread_kill);
  hookf("pthread_exit", (void*)my_pthread_exit, (void**)&orig_pthread_exit);
  hookf("kill", (void*)my_kill, (void**)&orig_kill);
  hookf("task_terminate", (void*)my_task_terminate, (void**)&orig_task_terminate);
  hookf("thread_terminate", (void*)my_thread_terminate, (void**)&orig_thread_terminate);
  hookf("__pthread_kill", (void*)my___pthread_kill, (void**)&orig___pthread_kill);
  hookf("exit_group", (void*)my_exit_group, (void**)&orig_exit_group);
  hookf("__exit", (void*)my_libc__exit, (void**)&orig_libc__exit);

  // ObjC 退出路径(abcbypass 里 Promon 用 -[UIApplication _terminateWithStatus:])
  Class ua = objc_getClass("UIApplication");
  if (ua){
    emit("ctor: UIApplication 存在, 将监视 _terminateWithStatus:(见 %hook)\n");
  }
}
