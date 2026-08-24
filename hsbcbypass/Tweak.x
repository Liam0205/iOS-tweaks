// Round 68(内核PoC前置诊断): 从 China 进程内部, 报告 Promon 可能哈希到的"异常":
//   1) 所有加载的 image(找注入物: ellekit/substrate/tweak, 及 /var/jb 路径);
//   2) dyld 共享缓存的若干关键 libSystem 函数, 其内存首字节 vs. 该函数应有的 pristine 序言,
//      判断是否被 inline hook 改过(= Promon 内存比对会抓到的差异)。
// 目的: 确定"零注入自研tweak"时, 到底什么内存被改了 → 决定内核 VM 过滤要伪装哪块。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <dlfcn.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>

static int g_fd=-1;
static void emit(const char*s){if(g_fd>=0)(void)write(g_fd,s,strlen(s));}
static void emitf(const char*fmt,...){
  char b[512];va_list ap;va_start(ap,fmt);vsnprintf(b,sizeof(b),fmt,ap);va_end(ap);
  if(g_fd>=0)(void)write(g_fd,b,strlen(b));
}

// 判断一个函数入口 16 字节里是否有典型 inline-hook 蹦床(adrp+br / ldr+br / b imm)
static int looks_hooked(const void*fn){
  const uint32_t*p=(const uint32_t*)fn;
  uint32_t i0=p[0], i1=p[1];
  // b/bl imm26: 高6位 000101(b)/100101(bl)
  if((i0&0xfc000000)==0x14000000) return 1;          // b
  // adrp x16 (i0) + br x16 常见蹦床
  if((i0&0x9f00001f)==0x90000010 && (p[2]&0xfffffc1f)==0xd61f0000) return 2;
  // ldr x16,[pc..]; br x16
  if((i0&0xff00001f)==0x58000010 && (i1&0xfffffc1f)==0xd61f0000) return 3;
  return 0;
}

%ctor {
  char path[256];
  snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",NSTemporaryDirectory().fileSystemRepresentation,getpid());
  FILE*f=fopen(path,"w");if(f)fclose(f); g_fd=open(path,O_WRONLY|O_APPEND);

  // 1) 枚举加载的 image, 标注非 /System 非 cache 的注入物
  uint32_t n=_dyld_image_count();
  emitf("=== 加载的 image 共 %u; 非系统注入物: ===\n", n);
  int injected=0;
  for(uint32_t i=0;i<n;i++){
    const char*nm=_dyld_get_image_name(i);
    if(!nm) continue;
    // 系统库/cache 跳过, 只报注入物
    if(strncmp(nm,"/System/",8)==0 || strncmp(nm,"/usr/lib/",9)==0) continue;
    if(strstr(nm,"/China.app/") ) continue;  // app 自身
    emitf("  [inj] %s\n", nm);
    injected++;
  }
  emitf("=== 注入物计数(非系统/非app): %d ===\n", injected);

  // 2) 抽查若干 libSystem 常用函数, 看入口是否被 inline hook(shared cache 被改)
  const char*fns[]={"open","stat","access","read","close","sysctl","exit","mmap",
                    "objc_msgSend","malloc","strcmp","fopen","dlopen","task_self_trap",NULL};
  emit("=== libSystem/常用函数入口 hook 检查(shared cache 完整性) ===\n");
  int hooked=0;
  for(int i=0;fns[i];i++){
    void*p=dlsym(RTLD_DEFAULT, fns[i]);
    if(!p){ emitf("  %s: 未解析\n", fns[i]); continue; }
    int h=looks_hooked(p);
    if(h){ emitf("  %s @%p: ★HOOKED(type%d) 首字=%08x\n", fns[i], p, h, *(uint32_t*)p); hooked++; }
    else  emitf("  %s @%p: clean 首字=%08x\n", fns[i], p, *(uint32_t*)p);
  }
  emitf("=== 被 hook 的函数数: %d ===\n", hooked);
  emit("=== 诊断结束 ===\n");
}
