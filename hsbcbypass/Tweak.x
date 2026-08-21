// Round 37 探针: 观测 Promon SHIELD 的越狱检测输入(文件探测)
// 只观测不改行为(除非 OBSERVE_ONLY=0): hook fileExistsAtPath: + libc 文件探测, 记录路径 + 发起模块.
#import <Foundation/Foundation.h>
#import <pthread.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <objc/runtime.h>
#import "fishhook.h"

// 设为 1 = 只观测; 设为 0 = 同时对越狱路径返回"不存在"(实际绕过实验)
#ifndef OBSERVE_ONLY
#define OBSERVE_ONLY 1
#endif

static double g_t0=0;
static void lg(NSString*l){
  static NSString*p=nil;
  if(!p)p=[NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"hsbc_probe_%d.log",getpid()]];
  NSString*e=[l stringByAppendingString:@"\n"];
  FILE*f=fopen([p fileSystemRepresentation],"a");
  if(f){fwrite(e.UTF8String,1,strlen(e.UTF8String),f);fclose(f);}
}
#define L(fmt,...) do{if(g_t0==0)g_t0=CFAbsoluteTimeGetCurrent();double d=(CFAbsoluteTimeGetCurrent()-g_t0)*1000;lg([NSString stringWithFormat:(@"[+%.0fms] " fmt),d,##__VA_ARGS__]);}while(0)

// 判定一个路径是否是"越狱特征路径"
static int is_jb_path(const char*p){
  if(!p)return 0;
  static const char*keys[]={"Cydia","Sileo","MobileSubstrate","substrate","/var/jb","TweakInject",
    "/bin/bash","/bin/sh","/usr/sbin/sshd","/etc/apt","/private/var/lib/apt","frida","cynject",
    "/Applications/Cydia","libhooker","ElleKit","/var/binpack","Zebra","dopamine","/private/preboot",
    "jailbreak","/usr/lib/TweakInject",".dylib",NULL};
  for(int i=0;keys[i];i++) if(strstr(p,keys[i])) return 1;
  return 0;
}
// 发起调用的模块名(是否 hsbcchinax 自己在探). ret0 = 直接调用者(我们的 hook 的调用方).
static const char* module_of(void*ret){
  Dl_info info; if(ret&&dladdr(ret,&info)&&info.dli_fname){
    const char*b=strrchr(info.dli_fname,'/'); return b?b+1:info.dli_fname;
  }
  return "?";
}
#define CALLER module_of(__builtin_return_address(0))

// ---- libc 文件探测 hook (fishhook GOT, 不改函数头, 不触发反 inline-hook 自检) ----
static int (*o_stat)(const char*,struct stat*);
static int (*o_lstat)(const char*,struct stat*);
static int (*o_access)(const char*,int);
static int (*o_open)(const char*,int,...);
static FILE*(*o_fopen)(const char*,const char*);

static void note(const char*fn,const char*path,int jb,const char*m){
  // 只记 hsbcchinax / Promon 发起的, 或所有越狱路径查询
  if(jb || (m && strstr(m,"hsbcchinax")))
    L(@"%s(\"%s\") jb=%d ← %s",fn,path?path:"(null)",jb,m);
}
static int my_stat(const char*p,struct stat*s){int jb=is_jb_path(p);note("stat",p,jb,CALLER);
#if !OBSERVE_ONLY
  if(jb){errno=ENOENT;return -1;}
#endif
  return o_stat(p,s);}
static int my_lstat(const char*p,struct stat*s){int jb=is_jb_path(p);note("lstat",p,jb,CALLER);
#if !OBSERVE_ONLY
  if(jb){errno=ENOENT;return -1;}
#endif
  return o_lstat(p,s);}
static int my_access(const char*p,int m){int jb=is_jb_path(p);note("access",p,jb,CALLER);
#if !OBSERVE_ONLY
  if(jb){errno=ENOENT;return -1;}
#endif
  return o_access(p,m);}
static int my_open(const char*p,int fl,...){int jb=is_jb_path(p);note("open",p,jb,CALLER);
#if !OBSERVE_ONLY
  if(jb){errno=ENOENT;return -1;}
#endif
  mode_t md=0; if(fl&O_CREAT){va_list a;va_start(a,fl);md=(mode_t)va_arg(a,int);va_end(a);}
  return o_open(p,fl,md);}
static FILE* my_fopen(const char*p,const char*md){int jb=is_jb_path(p);note("fopen",p,jb,CALLER);
#if !OBSERVE_ONLY
  if(jb){errno=ENOENT;return NULL;}
#endif
  return o_fopen(p,md);}

// ---- ObjC: -[NSFileManager fileExistsAtPath:] 与 :isDirectory: ----
static BOOL (*o_fe)(id,SEL,NSString*);
static BOOL (*o_fed)(id,SEL,NSString*,BOOL*);
static BOOL my_fe(id self,SEL _cmd,NSString*path){
  int jb=path?is_jb_path(path.UTF8String):0;
  const char*m=CALLER;
  if(jb||(m&&strstr(m,"hsbcchinax"))) L(@"fileExistsAtPath:(\"%@\") jb=%d ← %s",path,jb,m);
#if !OBSERVE_ONLY
  if(jb) return NO;
#endif
  return o_fe(self,_cmd,path);
}
static BOOL my_fed(id self,SEL _cmd,NSString*path,BOOL*isDir){
  int jb=path?is_jb_path(path.UTF8String):0;
  const char*m=CALLER;
  if(jb||(m&&strstr(m,"hsbcchinax"))) L(@"fileExistsAtPath:isDirectory:(\"%@\") jb=%d ← %s",path,jb,m);
#if !OBSERVE_ONLY
  if(jb){if(isDir)*isDir=NO;return NO;}
#endif
  return o_fed(self,_cmd,path,isDir);
}

static void* hb(void*a){for(int i=0;;i++){if(i%20==0)L(@"♥ #%d",i);usleep(10000);}return NULL;}

// ---- 加密 stub 槽轮询: 抓 Promon 运行时解密出的真实指针 ----
// 静态槽 VA(hsbcchinax __TEXT vmaddr=0, 运行时 = slot + slide)
#define SLOT_7748d8 0x84c000UL
#define SLOT_775034 0x84c020UL
static uintptr_t g_slide2=0; static const struct mach_header* g_base=NULL;
static uintptr_t hsbc_slide(void){
  if(g_slide2)return g_slide2;
  uint32_t n=_dyld_image_count();
  for(uint32_t i=0;i<n;i++){const char*nm=_dyld_get_image_name(i);
    if(nm&&strstr(nm,"hsbcchinax")){g_base=_dyld_get_image_header(i);g_slide2=_dyld_get_image_vmaddr_slide(i);return g_slide2;}}
  return 0;
}
static void resolve_slot(const char*tag,uintptr_t slotVA){
  uintptr_t sl=hsbc_slide(); if(!sl)return;
  uintptr_t*slot=(uintptr_t*)(slotVA+sl);
  uintptr_t v=*slot;
  // 合法进程内指针? dladdr 能解析即为已解密
  Dl_info info;
  if(v>0x100000000UL && v<0x300000000000UL && dladdr((void*)v,&info)){
    const char*sym=info.dli_sname?info.dli_sname:"(no-sym)";
    const char*fn=info.dli_fname?info.dli_fname:"?";
    const char*b=strrchr(fn,'/'); b=b?b+1:fn;
    L(@"★解密 %s slot=0x%lx → 0x%lx = %s (%s off+0x%lx)",tag,slotVA,v-sl,sym,b,
      (unsigned long)((uintptr_t)v-(uintptr_t)info.dli_fbase));
  }
}
static void* slotpoll(void*a){
  usleep(50000);
  int done7=0,done5=0;
  for(int i=0;i<4000 && !(done7&&done5);i++){ // 最多 poll ~8s
    uintptr_t sl=hsbc_slide();
    if(sl){
      uintptr_t*s7=(uintptr_t*)(SLOT_7748d8+sl),*s5=(uintptr_t*)(SLOT_775034+sl);
      Dl_info di;
      if(!done7 && *s7>0x100000000UL && dladdr((void*)*s7,&di)){resolve_slot("7748d8",SLOT_7748d8);done7=1;}
      if(!done5 && *s5>0x100000000UL && dladdr((void*)*s5,&di)){resolve_slot("775034",SLOT_775034);done5=1;}
    }
    usleep(2000);
  }
  if(!done7)L(@"slot 0x84c000 未解密(8s 内)");
  if(!done5)L(@"slot 0x84c020 未解密(8s 内)");
  return NULL;
}

static void install_objc_hook(void){
  Class c=objc_getClass("NSFileManager");
  Method me=class_getInstanceMethod(c,@selector(fileExistsAtPath:));
  if(me){o_fe=(void*)method_getImplementation(me);method_setImplementation(me,(IMP)my_fe);L(@"hooked fileExistsAtPath:");}
  Method me2=class_getInstanceMethod(c,@selector(fileExistsAtPath:isDirectory:));
  if(me2){o_fed=(void*)method_getImplementation(me2);method_setImplementation(me2,(IMP)my_fed);L(@"hooked fileExistsAtPath:isDirectory:");}
}

%ctor{
  @autoreleasepool{
    L(@"注入 pid=%d (Round37 输入探针 OBSERVE_ONLY=%d)",getpid(),OBSERVE_ONLY);
    struct rebinding r[]={
      {"stat",my_stat,(void*)&o_stat},
      {"lstat",my_lstat,(void*)&o_lstat},
      {"access",my_access,(void*)&o_access},
      {"open",my_open,(void*)&o_open},
      {"fopen",my_fopen,(void*)&o_fopen},
    };
    rebind_symbols(r,5);
    L(@"fishhook 已装 (stat/lstat/access/open/fopen)");
    install_objc_hook();
    pthread_t t; pthread_create(&t,NULL,hb,NULL); pthread_detach(t);
    pthread_t t3; pthread_create(&t3,NULL,slotpoll,NULL); pthread_detach(t3);
  }
}
