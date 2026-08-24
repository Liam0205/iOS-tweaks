// Round 70 / PoC 阶段A2: 测"检测=vm_region 遍历"假设。
// hook mach_vm_region_recurse / vm_region_recurse_64 / mach_vm_region, 记录 Promon 是否调、扫哪些区域。
// 若 Promon 用它枚举内存找注入的可执行区(非cache/非app的 rwx 或 file-backed),
// 则可在此 hook 里过滤掉注入区域(用户态中等方案), 或据此定内核过滤点。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>
#import <mach/mach.h>
#import <dlfcn.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);
// mach_vm 类型(theos SDK 禁 mach_vm.h, 手工声明)
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;

static int g_fd=-1; static double g_t0=0;
static void emit(const char*s){if(g_fd>=0)(void)write(g_fd,s,strlen(s));}
static void emitf(const char*fmt,...){char b[400];va_list ap;va_start(ap,fmt);vsnprintf(b,sizeof(b),fmt,ap);va_end(ap);if(g_fd>=0)(void)write(g_fd,b,strlen(b));}
static double now_ms(void){return (g_t0>0)?(CFAbsoluteTimeGetCurrent()-g_t0)*1000:0;}

// hook mach_vm_region_recurse
static kern_return_t (*o_mvrr)(vm_map_t,mach_vm_address_t*,mach_vm_size_t*,natural_t*,vm_region_recurse_info_t,mach_msg_type_number_t*);
static int c_mvrr=0;
static kern_return_t my_mvrr(vm_map_t t,mach_vm_address_t*addr,mach_vm_size_t*sz,natural_t*depth,vm_region_recurse_info_t info,mach_msg_type_number_t*cnt){
  mach_vm_address_t in_addr = addr?*addr:0;
  kern_return_t r = o_mvrr(t,addr,sz,depth,info,cnt);
  c_mvrr++;
  if(c_mvrr<=40){
    struct vm_region_submap_info_64 *si=(struct vm_region_submap_info_64*)info;
    emitf("[mvrr#%d] in=0x%llx → addr=0x%llx sz=0x%llx prot=%c%c%c t=%.0fms\n",
      c_mvrr,(unsigned long long)in_addr,(unsigned long long)(addr?*addr:0),(unsigned long long)(sz?*sz:0),
      (r==0&&si)?((si->protection&1)?'r':'-'):'?',
      (r==0&&si)?((si->protection&2)?'w':'-'):'?',
      (r==0&&si)?((si->protection&4)?'x':'-'):'?', now_ms());
  }
  return r;
}
// hook vm_region_recurse_64
static kern_return_t (*o_vrr64)(vm_map_t,vm_address_t*,vm_size_t*,natural_t*,vm_region_recurse_info_t,mach_msg_type_number_t*);
static int c_vrr64=0;
static kern_return_t my_vrr64(vm_map_t t,vm_address_t*addr,vm_size_t*sz,natural_t*depth,vm_region_recurse_info_t info,mach_msg_type_number_t*cnt){
  kern_return_t r=o_vrr64(t,addr,sz,depth,info,cnt); c_vrr64++;
  // 标注该区域是否属于注入 dylib(用 dladdr 判断返回地址所属 image)
  if(c_vrr64<=400 && r==0 && addr){
    unsigned long a=(unsigned long)*addr;
    Dl_info di; const char*owner="?"; int inj=0;
    if(dladdr((void*)a,&di) && di.dli_fname){
      const char*b=strrchr(di.dli_fname,'/'); owner=b?b+1:di.dli_fname;
      if(strstr(di.dli_fname,"procursus")||strstr(di.dli_fname,"/var/jb")||strstr(di.dli_fname,"TweakInject")||strstr(di.dli_fname,"ellekit")) inj=1;
    }
    struct vm_region_submap_info_64 *si=(struct vm_region_submap_info_64*)info;
    char pr[4]={'-','-','-',0};
    if(si){ if(si->protection&1)pr[0]='r'; if(si->protection&2)pr[1]='w'; if(si->protection&4)pr[2]='x'; }
    emitf("[vrr64#%d] 0x%lx sz=0x%lx %s %s%s\n",c_vrr64,a,(unsigned long)(sz?*sz:0),pr, inj?"★INJ ":"", owner);
  }
  return r;
}
// hook proc_regionfilename(有些检测用它拿区域对应文件名)
static int (*o_prf)(int,uint64_t,void*,uint32_t);
static int c_prf=0;
static int my_prf(int pid,uint64_t addr,void*buf,uint32_t sz){
  int r=o_prf?o_prf(pid,addr,buf,sz):0; c_prf++;
  // 全部记录, 特别标注注入路径
  if(r>0&&buf){
    const char*fn=(const char*)buf;
    int inj = strstr(fn,"/procursus")||strstr(fn,"/var/jb")||strstr(fn,"TweakInject")||strstr(fn,"ellekit");
    emitf("[prf#%d] addr=0x%llx → %s%s\n",c_prf,(unsigned long long)addr, inj?"★INJ ":"", fn);
  }
  return r;
}

%ctor {
  g_t0=CFAbsoluteTimeGetCurrent();
  char path[256];snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",NSTemporaryDirectory().fileSystemRepresentation,getpid());
  FILE*f=fopen(path,"w");if(f)fclose(f); g_fd=open(path,O_WRONLY|O_APPEND);
  emit("A2: hook vm 枚举原语\n");

  void*p;
  if((p=dlsym(RTLD_DEFAULT,"mach_vm_region_recurse"))){ MSHookFunction(p,(void*)my_mvrr,(void**)&o_mvrr); emit("  hooked mach_vm_region_recurse\n"); }
  if((p=dlsym(RTLD_DEFAULT,"vm_region_recurse_64"))){ MSHookFunction(p,(void*)my_vrr64,(void**)&o_vrr64); emit("  hooked vm_region_recurse_64\n"); }
  if((p=dlsym(RTLD_DEFAULT,"proc_regionfilename"))){ MSHookFunction(p,(void*)my_prf,(void**)&o_prf); emit("  hooked proc_regionfilename\n"); }
}
