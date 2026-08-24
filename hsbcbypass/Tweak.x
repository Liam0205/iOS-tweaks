// Round 66: 运行时中和 init[42] 的检测输入(方向1)
// init[42] 有 5 个 "bl <加密stub>; cmp w0,#0; cset 布尔" 检测点。stub(0x7753e8/0x77540c/0x7753c4/
// 0x7753f4/0x775418)是 __TEXT 里的跳板(ldr x16,[加密表槽]; br x16 → Promon 内部检测函数)。
// 策略: MSHookFunction 这 5 个 stub, 让它们直接返回 0(= 未越狱), 使所有 cset 布尔=clean,
// 状态机在 verdict 处自然 w9 != 0x144ab99a → 不 exit(改输入, 非改分支, 不自旋)。
// 先 OBSERVE 记录每个 stub 被调次数+原返回值; NEUTRALIZE=1 时强制返回 0。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);

#ifndef NEUTRALIZE
#define NEUTRALIZE 0   // 0=观测(记原返回值,调orig); 1=强制返回0
#endif

static int g_fd = -1;
static intptr_t g_slide = 0;
static double g_t0 = 0;
static void emit(const char*s){ if(g_fd>=0)(void)write(g_fd,s,strlen(s)); }
static void emitkv(const char*k,long v){
  char b[96];int p=0;const char*l=k;while(*l)b[p++]=*l++;
  int neg=v<0; unsigned long u=neg?-v:v; char t[24];int n=0; if(!u){t[n++]='0';} while(u){t[n++]='0'+u%10;u/=10;}
  if(neg)b[p++]='-'; while(n)b[p++]=t[--n]; b[p++]='\n'; if(g_fd>=0)(void)write(g_fd,b,p);
}
static double now_ms(void){return (g_t0>0)?(CFAbsoluteTimeGetCurrent()-g_t0)*1000:0;}

static intptr_t hsbc_slide(void){
  uint32_t n=_dyld_image_count();
  for(uint32_t i=0;i<n;i++){const char*nm=_dyld_get_image_name(i);
    if(nm&&strstr(nm,"hsbcchinax"))return _dyld_get_image_vmaddr_slide(i);}
  return 0;
}

// init[42] 里除 exit(0x774770) 外全部 9 个 stub + orig + 命中计数
typedef long (*fn_t)(long,long,long,long);
static struct det { unsigned long off; const char*name; fn_t orig; int calls; } g_det[] = {
  {0x774c20, "det_774c20", 0, 0},
  {0x774efc, "det_774efc", 0, 0},
  {0x774fec, "det_774fec", 0, 0},
  {0x775154, "det_775154", 0, 0},
  {0x7753c4, "det_7753c4", 0, 0},
  {0x7753e8, "det_7753e8", 0, 0},
  {0x7753f4, "det_7753f4", 0, 0},
  {0x77540c, "det_77540c", 0, 0},
  {0x775418, "det_775418", 0, 0},
};
#define NDET 9

// 为每个 stub 造一个 replacement(需要区分是哪个 → 用独立函数)
static long handle(int idx, long a0,long a1,long a2,long a3){
  g_det[idx].calls++;
#if NEUTRALIZE
  // 强制 clean: 返回 0
  if(g_det[idx].calls<=3){ char b[64];snprintf(b,sizeof(b),"[%s] call#%d → 强制0 t=%.0fms\n",g_det[idx].name,g_det[idx].calls,now_ms());emit(b);}
  return 0;
#else
  long r = g_det[idx].orig? g_det[idx].orig(a0,a1,a2,a3):0;
  if(g_det[idx].calls<=8){ char b[96];snprintf(b,sizeof(b),"[%s] #%d ret=%ld(0x%lx) t=%.0fms\n",g_det[idx].name,g_det[idx].calls,r,(unsigned long)r,now_ms());emit(b);}
  return r;
#endif
}
static long r0(long a,long b,long c,long d){return handle(0,a,b,c,d);}
static long r1(long a,long b,long c,long d){return handle(1,a,b,c,d);}
static long r2(long a,long b,long c,long d){return handle(2,a,b,c,d);}
static long r3(long a,long b,long c,long d){return handle(3,a,b,c,d);}
static long r4(long a,long b,long c,long d){return handle(4,a,b,c,d);}
static long r5(long a,long b,long c,long d){return handle(5,a,b,c,d);}
static long r6(long a,long b,long c,long d){return handle(6,a,b,c,d);}
static long r7(long a,long b,long c,long d){return handle(7,a,b,c,d);}
static long r8(long a,long b,long c,long d){return handle(8,a,b,c,d);}
static fn_t g_repl[NDET] = { (fn_t)r0,(fn_t)r1,(fn_t)r2,(fn_t)r3,(fn_t)r4,(fn_t)r5,(fn_t)r6,(fn_t)r7,(fn_t)r8 };

%ctor {
  g_t0=CFAbsoluteTimeGetCurrent();
  char path[256];
  snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",NSTemporaryDirectory().fileSystemRepresentation,getpid());
  FILE*f=fopen(path,"w");if(f)fclose(f);
  g_fd=open(path,O_WRONLY|O_APPEND);
  g_slide=hsbc_slide();
  emitkv("ctor NEUTRALIZE=", NEUTRALIZE);
  if(!g_slide){emit("no slide\n");return;}
  for(int i=0;i<NDET;i++){
    void*t=(void*)(g_det[i].off+g_slide);
    MSHookFunction(t,(void*)g_repl[i],(void**)&g_det[i].orig);
  }
  emit("ctor: 已 hook 5 个检测 stub\n");
}
