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
static uint64_t g_legit_dylib=0;   // 一个合法系统 dylib 的运行时基址(伪装用)
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
  uint64_t snap_out = (msgid_in==4808 && msg) ? body[6] : 0;   // 输出缓冲(读后数据落这)

  long r = o_wrap(msg,a1,a2,a3,a4,a5,a6,a7);

#if !defined(OBSERVE_ONLY) || OBSERVE_ONLY==0
  // ★ 拦截(调用后改输出缓冲): 保留完整 Mach-O 结构, 只把 out_buf 里 systemhook 的
  // install-name 路径字符串(procursus/basebin/systemhook)改成系统库路径, 使 Promon 路径黑名单不命中。
  // 不动 magic/filetype/ncmds → 不破坏解析(避免 Round74 清零致自旋)。
  if(inj && r==0 && snap_out && req_size>0){
    char *buf=(char*)snap_out;
    size_t blen=(req_size>0x8000)?0x8000:(size_t)req_size;
    // 在读到的字节里找 systemhook 特征路径, 逐字节替换成合法路径(等长覆盖)。
    static const char sig[]="systemhook";
    for(size_t i=0;i+sizeof(sig)-1<blen;i++){
      if(memcmp(buf+i,sig,sizeof(sig)-1)==0){
        memcpy(buf+i,"CoreFounda",sizeof(sig)-1);  // 等长(10字节)伪装
      }
    }
    // 也改 procursus/basebin 前缀特征
    static const char sig2[]="procursus";
    for(size_t i=0;i+sizeof(sig2)-1<blen;i++){
      if(memcmp(buf+i,sig2,sizeof(sig2)-1)==0) memcpy(buf+i,"SystemLib",sizeof(sig2)-1);
    }
    if(c_4808<=20) emitf("  ↳拦截: 改 out_buf 0x%llx 内路径特征(保结构)\n",(unsigned long long)snap_out);
  }
#endif

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
  // 选一个合法系统 dylib 的基址(filetype=MH_DYLIB, 签名正常, 非注入)做伪装源。
  for(uint32_t i=0;i<n;i++){
    const char*nm=_dyld_get_image_name(i);
    if(nm && strcmp(nm,"/usr/lib/libobjc.A.dylib")==0){ g_legit_dylib=(uint64_t)_dyld_get_image_header(i); break; }
  }
  if(!g_legit_dylib){ // 回退: 找任意 /usr/lib 的 dylib
    for(uint32_t i=0;i<n;i++){const char*nm=_dyld_get_image_name(i);
      if(nm && strncmp(nm,"/usr/lib/",9)==0 && strstr(nm,".dylib")){g_legit_dylib=(uint64_t)_dyld_get_image_header(i);break;}}
  }
  emitf("ctor: g_legit_dylib=0x%llx\n",(unsigned long long)g_legit_dylib);
  MSHookFunction((void*)(WRAP_OFF+g_slide),(void*)my_wrap,(void**)&o_wrap);
  emitf("U: hooked mach封装 0x40c698 @0x%lx\n",(unsigned long)(WRAP_OFF+g_slide));
}
