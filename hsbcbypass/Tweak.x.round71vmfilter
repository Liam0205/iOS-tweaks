// Round 71 / PoC 阶段A3: 用户态 vm_region_recurse_64 过滤, 隐藏注入 dylib 区域。
// Promon 用 vm_region_recurse_64 遍历全地址空间找注入 dylib(Round70 确认)。
// 本 hook: 当原函数返回的区域属于"注入 dylib"(dladdr 判路径含 procursus/var jb/TweakInject/ellekit),
// 就用该区域末尾作为新起点再查, 循环跳过, 直到拿到非注入区域返回 → 遍历者看不到注入物。
// 保留自身: HSBCBypass 也会被跳过(它路径也在 procursus)。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>
#import <mach/mach.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);
typedef uint64_t mach_vm_address_t;

#ifndef PROBE_LOG
#define PROBE_LOG 1
#endif
static int g_fd=-1; static double g_t0=0;
static void emit(const char*s){if(PROBE_LOG&&g_fd>=0)(void)write(g_fd,s,strlen(s));}

// 某地址是否属于注入物(据 dladdr 的 image 路径)
static int addr_is_injected(unsigned long a){
  Dl_info di;
  if(dladdr((void*)a,&di) && di.dli_fname){
    if(strstr(di.dli_fname,"procursus")||strstr(di.dli_fname,"/var/jb")||
       strstr(di.dli_fname,"TweakInject")||strstr(di.dli_fname,"ellekit")||
       strstr(di.dli_fname,"MobileSubstrate")) return 1;
  }
  return 0;
}

// vm_region_recurse_64 过滤
static kern_return_t (*o_vrr64)(vm_map_t,vm_address_t*,vm_size_t*,natural_t*,vm_region_recurse_info_t,mach_msg_type_number_t*);
static int c_skip=0;
static kern_return_t my_vrr64(vm_map_t task,vm_address_t*addr,vm_size_t*sz,natural_t*depth,vm_region_recurse_info_t info,mach_msg_type_number_t*cnt){
  kern_return_t r = o_vrr64(task,addr,sz,depth,info,cnt);
  // 循环跳过注入区域
  int guard=0;
  while(r==KERN_SUCCESS && addr && sz && *sz>0 && addr_is_injected((unsigned long)*addr) && guard<2000){
    c_skip++;
    if(c_skip<=30){char b[128];snprintf(b,sizeof(b),"[skip#%d] 0x%lx sz=0x%lx\n",c_skip,(unsigned long)*addr,(unsigned long)*sz);emit(b);}
    vm_address_t next = *addr + *sz;   // 跳到本区域末尾
    *addr = next;
    r = o_vrr64(task,addr,sz,depth,info,cnt);
    guard++;
  }
  return r;
}

%ctor {
  g_t0=CFAbsoluteTimeGetCurrent();
  char path[256];snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",NSTemporaryDirectory().fileSystemRepresentation,getpid());
  FILE*f=fopen(path,"w");if(f)fclose(f); g_fd=open(path,O_WRONLY|O_APPEND);
  emit("A3: 安装 vm_region_recurse_64 过滤(隐藏注入区域)\n");
  void*p=dlsym(RTLD_DEFAULT,"vm_region_recurse_64");
  if(p){ MSHookFunction(p,(void*)my_vrr64,(void**)&o_vrr64); emit("A3: hooked vm_region_recurse_64\n"); }
  else emit("A3: 找不到 vm_region_recurse_64\n");
}
