// Round 73 / PoC 方案U: hook mach 封装 0x40c698, 拦 mach_vm_read(id 4808) 结果,
// 把注入 dylib 区域头部的返回数据改成非注入(骗过 Promon 的 Mach-O 身份识别)。
// 先观测版: 确认能看到 in(请求地址) + out(reply 结构), 判断 reply 里数据在哪(inline/out-of-line)。
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

#define WRAP_OFF 0x40c698   // mach_msg 封装(mov x16,#-0x1f; blr gate)
#ifndef OBSERVE_ONLY
#define OBSERVE_ONLY 0      // 0=拦截(抹注入库头magic); 1=只观测
#endif

static int g_fd=-1; static intptr_t g_slide=0; static double g_t0=0;
static void emit(const char*s){if(g_fd>=0)(void)write(g_fd,s,strlen(s));}
static void emitf(const char*fmt,...){char b[400];va_list ap;va_start(ap,fmt);vsnprintf(b,sizeof(b),fmt,ap);va_end(ap);if(g_fd>=0)(void)write(g_fd,b,strlen(b));}
static double now_ms(void){return (g_t0>0)?(CFAbsoluteTimeGetCurrent()-g_t0)*1000:0;}

static int addr_is_injected(unsigned long a){
  Dl_info di;
  if(a && dladdr((void*)a,&di) && di.dli_fname){
    const char*f=di.dli_fname;
    if(strstr(f,"procursus")||strstr(f,"/var/jb")||strstr(f,"TweakInject")||
       strstr(f,"ellekit")||strstr(f,"MobileSubstrate")||strstr(f,"basebin")||
       strstr(f,"fakelib")||strstr(f,"systemhook")||strstr(f,"Substrate")||
       strstr(f,"/Cephei")||strstr(f,"Choicy")||strstr(f,"Crane")||strstr(f,"FLEX")||
       strstr(f,"BioProtect")||strstr(f,"AppSync")||strstr(f,"HSBCBypass"))
      return 1;
    // 短名 /usr/lib/systemhook.dylib 之类
    const char*b=strrchr(f,'/'); b=b?b+1:f;
    if(strcmp(b,"systemhook.dylib")==0) return 1;
  }
  return 0;
}

// 封装签名: mach_msg 风格, x0 = 消息缓冲(收发同一 buffer)。返回 kern_return_t。
typedef long (*wrap_t)(void* msg, long a1, long a2, long a3, long a4, long a5, long a6, long a7);
static wrap_t o_wrap=0;
static int c_call=0, c_4808=0;

static long my_wrap(void* msg, long a1,long a2,long a3,long a4,long a5,long a6,long a7){
  c_call++;
  uint32_t *hdr = (uint32_t*)msg;
  uint32_t msgid_in = (msg)? hdr[5] : 0;
  // 请求里的目标地址(mach_vm_read: body[3]=port desc, body[4]=address, body[5]=size 附近)
  uint64_t *body = (uint64_t*)msg;
  uint64_t req_addr = (msg)? body[4] : 0;   // 经验偏移(Round72c: body[4]=address)
  uint64_t req_size = (msg)? body[5] : 0;

  int inj = (msgid_in==4808) ? addr_is_injected((unsigned long)req_addr) : 0;
#if !defined(OBSERVE_ONLY) || OBSERVE_ONLY==0
  // ★ 拦截(调用前改源地址): 注入库的读 → 把源地址重定向到一个合法已加载库(hsbcchinax 基址),
  // 使 Promon 读到真实、合法、签名正常的 dylib 头, 而非注入库。避免清零致解析失败自旋。
  if(inj && msg){
    uint64_t legit = (uint64_t)(0x8000 + g_slide) & ~0x3fffULL;  // hsbcchinax mach header 页(vmaddr 0)
    // 用 hsbcchinax 的镜像基址(合法系统外但已签名的 App 库)。更稳妥用主程序基址。
    extern const struct mach_header* _dyld_get_image_header(uint32_t);
    const struct mach_header* mh0 = _dyld_get_image_header(0); // 主程序 China
    if(mh0) legit = (uint64_t)mh0;
    body[4] = legit + (req_addr & 0x0);   // 读合法库头(偏移0)
  }
#endif

  long r = o_wrap(msg,a1,a2,a3,a4,a5,a6,a7);

  if(msgid_in==4808){
    c_4808++;
    Dl_info di; const char*owner="?";
    if(req_addr && dladdr((void*)req_addr,&di) && di.dli_fname){const char*b=strrchr(di.dli_fname,'/');owner=b?b+1:di.dli_fname;}
    if(c_4808<=40)
      emitf("[4808#%d] addr=0x%llx sz=0x%llx inj=%d owner=%s%s t=%.0fms\n",
        c_4808,(unsigned long long)req_addr,(unsigned long long)req_size, inj, owner,
        inj?" →重定向到合法库":"", now_ms());
  }
  return r;
}

%ctor {
  g_t0=CFAbsoluteTimeGetCurrent();
  char path[256];snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",NSTemporaryDirectory().fileSystemRepresentation,getpid());
  FILE*f=fopen(path,"w");if(f)fclose(f); g_fd=open(path,O_WRONLY|O_APPEND);
  uint32_t n=_dyld_image_count();
  for(uint32_t i=0;i<n;i++){const char*nm=_dyld_get_image_name(i);if(nm&&strstr(nm,"hsbcchinax")){g_slide=_dyld_get_image_vmaddr_slide(i);break;}}
  if(!g_slide){emit("no slide\n");return;}
  MSHookFunction((void*)(WRAP_OFF+g_slide),(void*)my_wrap,(void**)&o_wrap);
  emitf("U: hooked mach封装 0x40c698 @0x%lx\n",(unsigned long)(WRAP_OFF+g_slide));
}
