// Round 55 探针: svc 跳板观测器
// Promon 的所有 syscall 走数据段网关(槽 0x8510c8 -> 0x78befc = svc#0x80;ret)。
// 本探针把槽改指向自己的汇编跳板, 记录每次 (syscall号, 路径参数, 调用者PC), 再原样陷入内核。
// 配套二进制 patch: nop 掉安装点 0x346c74 的 str, 使 App 不再覆盖该槽(否则会盖掉我们的跳板)。
// 目的: 首次拿到 Promon 到底查了哪些越狱文件/用了哪些反调试 syscall 的地面真值(libc hook 全 0 命中)。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>

#ifndef OBSERVE_ONLY
#define OBSERVE_ONLY 1   // 1=只观测转发; 0=对越狱路径 syscall 返回 ENOENT/-1(拦截实验)
#endif

// slot / gate 的静态 vmaddr(见 analysis.md Round 52)
#define SLOT_VMADDR   0x8510c8UL
#define GATE_VMADDR   0x78befcUL

static double g_t0 = 0;
static char   g_logpath[256];
static intptr_t g_slide = 0;

static void lg(const char *s) {
  FILE *f = fopen(g_logpath, "a");
  if (f) { fwrite(s, 1, strlen(s), f); fputc('\n', f); fclose(f); }
}
#define L(fmt, ...) do{ \
  if (g_t0==0) g_t0=CFAbsoluteTimeGetCurrent(); \
  double d=(CFAbsoluteTimeGetCurrent()-g_t0)*1000; \
  char _b[600]; snprintf(_b,sizeof(_b),"[+%.0fms] " fmt, d, ##__VA_ARGS__); lg(_b); \
}while(0)

// 越狱特征路径
static int is_jb_path(const char *p) {
  if (!p) return 0;
  static const char *k[] = {"Cydia","Sileo","MobileSubstrate","substrate","/var/jb","TweakInject",
    "/bin/bash","/bin/sh","/usr/sbin/sshd","/etc/apt","/var/lib/apt","frida","cynject",
    "libhooker","ElleKit","ellekit","/var/binpack","Zebra","dopamine","/private/preboot",
    "jailbreak","/usr/lib/Tweak",".dylib","/Library/dpkg","/var/lib/dpkg","/usr/libexec/cydia",NULL};
  for (int i=0;k[i];i++) if (strstr(p,k[i])) return 1;
  return 0;
}

// arg0 是 char* 路径的 BSD syscall 号(iOS arm64)
static int arg0_is_path(long nr) {
  switch (nr) {
    case 5:   // open
    case 33:  // access
    case 58:  // readlink
    case 188: // stat
    case 190: // lstat
    case 220: // getattrlist
    case 338: // stat64
    case 340: // lstat64
    case 398: // open_nocancel
    case 12:  // chdir
    case 15:  // chmod
    case 82:  // pathconf
    case 157: // statfs (old)
      return 1;
    default: return 0;
  }
}
static const char* nr_name(long nr) {
  switch (nr) {
    case 5:return"open"; case 33:return"access"; case 58:return"readlink";
    case 188:return"stat"; case 190:return"lstat"; case 189:return"fstat";
    case 220:return"getattrlist"; case 338:return"stat64"; case 340:return"lstat64";
    case 339:return"fstat64"; case 398:return"open_nc"; case 202:return"sysctl";
    case 274:return"sysctlbyname"; case 169:return"csops"; case 170:return"csops_at";
    case 26:return"ptrace"; case 336:return"proc_info"; case 372:return"thread_selfid";
    case 6:return"close"; case 3:return"read"; case 4:return"write";
    default:return NULL;
  }
}

// ---- 低开销记录: 热路径只做原子计数 + 越狱路径进环形缓冲, 不 fopen(避免拖慢触发看门狗) ----
#define NR_MAX 600
static volatile uint64_t g_cnt[NR_MAX];   // 每个 syscall 号的调用次数
static volatile uint64_t g_total = 0;

// 全量 syscall 轨迹环形缓冲(热路径只填结构, 由 poller 线程落盘)。
// 记录前 N 个所有 syscall(不只越狱路径), 以便定位"自旋前最后一个 syscall"= 检测分流点。
typedef struct { long nr; long a0; long caller; double t; char path[200]; } trace_t;
#define TRACE_RING 2048
static trace_t g_ring[TRACE_RING];
static volatile uint32_t g_ring_w = 0;   // 写指针(只增)

// 由汇编跳板调用: nr=x16, a0/a1=参数, caller=封装的调用者PC
void hsbc_svc_record(long nr, long a0, long a1, long caller);
void hsbc_svc_record(long nr, long a0, long a1, long caller) {
  (void)a1;
  __sync_fetch_and_add(&g_total, 1);
  if (nr >= 0 && nr < NR_MAX) __sync_fetch_and_add(&g_cnt[nr], 1);
  // 跳过高频 IO 噪声(read/write/close/pread/mmap/lseek), 其余全记进轨迹环
  switch (nr) {
    case 3: case 4: case 6: case 153: case 197: case 199: return;
    default: break;
  }
  uint32_t idx = __sync_fetch_and_add(&g_ring_w, 1);
  if (idx == 0) {   // 第一次被调用就同步落一行(不依赖 poller), 证明跳板确被使用
    FILE *f = fopen(g_logpath, "a");
    if (f) { fprintf(f, "[FIRST-CALL] trampoline 首次命中 nr=%ld caller=+0x%lx\n",
                     nr, (unsigned long)(caller-(long)g_slide)); fclose(f); }
  }
  if (idx >= TRACE_RING) return;   // 只记前 TRACE_RING 个, 满了不覆盖(保留最早的分流现场)
  trace_t *h = &g_ring[idx];
  h->nr = nr; h->a0 = a0; h->caller = caller;
  h->t = (g_t0>0) ? (CFAbsoluteTimeGetCurrent()-g_t0)*1000 : 0;
  h->path[0] = 0;
  if (arg0_is_path(nr) && a0) {
    const char *path = (const char*)a0;
    strncpy(h->path, path, sizeof(h->path)-1);
    h->path[sizeof(h->path)-1] = 0;
  }
}

// 真网关运行时地址(ctor 里设 = 0x78befc + slide)。跳板尾调它, 使真正的 svc 在 __TEXT 内执行,
// 防 Promon 对"发起 svc 的 PC 是否在自身 __TEXT"做检查(我们的跳板在堆上, 自带 svc 会露馅)。
uintptr_t hsbc_g_realgate = 0;

// 汇编跳板: 保存/恢复所有传参寄存器, 调 record, 再 `br 真网关`(真网关=svc #0x80; ret)。
// 进入时 sp 指向封装 `stp x17,x30,[sp,#-0x10]!` 压入的 [x17,x30], 故 caller=[sp+0xa8]。
// x17 由封装 save/restore, 可自由 clobber; 尾调后真网关的 ret 用我们恢复的 x30(=封装续点)。
__asm__(
  ".text\n"
  ".align 4\n"
  ".globl _hsbc_svc_tramp\n"
  "_hsbc_svc_tramp:\n"
  "  sub  sp, sp, #0xa0\n"
  "  stp  x0, x1,  [sp, #0x00]\n"
  "  stp  x2, x3,  [sp, #0x10]\n"
  "  stp  x4, x5,  [sp, #0x20]\n"
  "  stp  x6, x7,  [sp, #0x30]\n"
  "  stp  x8, x16, [sp, #0x40]\n"
  "  str  x30,     [sp, #0x50]\n"
  "  ldr  x3, [sp, #0xa8]\n"    // caller (封装保存的 x30)
  "  mov  x0, x16\n"            // nr
  "  ldr  x1, [sp, #0x00]\n"    // a0
  "  ldr  x2, [sp, #0x08]\n"    // a1
  "  bl   _hsbc_svc_record\n"
  "  ldp  x0, x1,  [sp, #0x00]\n"
  "  ldp  x2, x3,  [sp, #0x10]\n"
  "  ldp  x4, x5,  [sp, #0x20]\n"
  "  ldp  x6, x7,  [sp, #0x30]\n"
  "  ldp  x8, x16, [sp, #0x40]\n"
  "  ldr  x30,     [sp, #0x50]\n"
  "  add  sp, sp, #0xa0\n"
  "  svc  #0x80\n"              // 自带 svc(55b 已证明转发正确, 48 syscall 无误)
  "  ret\n"
);
extern void hsbc_svc_tramp(void);

// 找 hsbcchinax 的 slide
static intptr_t hsbc_slide(void) {
  uint32_t n = _dyld_image_count();
  for (uint32_t i=0;i<n;i++) {
    const char *nm = _dyld_get_image_name(i);
    if (nm && strstr(nm, "hsbcchinax"))
      return _dyld_get_image_vmaddr_slide(i);
  }
  return 0;
}

// poller: 每 1s 落盘一次计数快照(每类 syscall 增量)+ 新的越狱路径命中。
// 这样即使检测阶段是 syscall 风暴, 热路径也只做原子加, 由本线程慢速落盘。
#include <pthread.h>
#include <unistd.h>
static uint64_t g_prev[NR_MAX];
static uint32_t g_ring_r = 0;
static void *poller(void *arg) {
  (void)arg;
  for (int tick=0; tick<40; tick++) {
    usleep(1000*1000);
    // 落盘本秒新增的 syscall 轨迹(全量, 越狱路径加 ★)
    uint32_t w = g_ring_w; if (w > TRACE_RING) w = TRACE_RING;
    while (g_ring_r < w) {
      trace_t *h = &g_ring[g_ring_r];
      int jb = h->path[0] && is_jb_path(h->path);
      if (h->path[0])
        L("%s%s(\"%.180s\") caller=+0x%lx @%.0fms", jb?"★JB ":"", nr_name(h->nr)?:"?", h->path,
          (unsigned long)(h->caller - (long)g_slide), h->t);
      else
        L("%s(#%ld) a0=0x%lx caller=+0x%lx @%.0fms", nr_name(h->nr)?:"?", h->nr,
          (unsigned long)h->a0, (unsigned long)(h->caller - (long)g_slide), h->t);
      g_ring_r++;
    }
    // 每秒的 syscall 增量表(只打非零变化)
    char line[512]; int p=0;
    p += snprintf(line+p, sizeof(line)-p, "t=%ds total=%llu Δ{", tick+1, (unsigned long long)g_total);
    int any=0;
    for (int nr=0; nr<NR_MAX; nr++) {
      uint64_t c=g_cnt[nr]; if (c==g_prev[nr]) continue;
      const char *nm=nr_name(nr);
      if (nm) p += snprintf(line+p, sizeof(line)-p, "%s=%llu ", nm, (unsigned long long)(c-g_prev[nr]));
      else    p += snprintf(line+p, sizeof(line)-p, "#%d=%llu ", nr, (unsigned long long)(c-g_prev[nr]));
      g_prev[nr]=c; any=1;
      if (p>440) break;
    }
    snprintf(line+p, sizeof(line)-p, "}");
    if (any) L("%s", line);
  }
  return NULL;
}

%ctor {
  g_t0 = CFAbsoluteTimeGetCurrent();
  snprintf(g_logpath, sizeof(g_logpath), "%s/hsbc_probe_%d.log",
           NSTemporaryDirectory().fileSystemRepresentation, getpid());
  FILE *f = fopen(g_logpath, "w"); if (f) fclose(f);

  g_slide = hsbc_slide();
  L("ctor: hsbcchinax slide=0x%lx OBSERVE_ONLY=%d", (unsigned long)g_slide, OBSERVE_ONLY);

  if (!g_slide) { L("ctor: 未找到 hsbcchinax, 放弃"); return; }

  volatile uintptr_t *slot = (volatile uintptr_t *)(SLOT_VMADDR + g_slide);
  uintptr_t prior = *slot;
  uintptr_t realgate = GATE_VMADDR + g_slide;
  // 记录先后顺序: prior==0 说明我们早于 App 安装点(好); ==realgate 说明 App 已装(晚, 检测可能已跑)
  L("ctor: slot@0x%lx prior=0x%lx realgate=0x%lx tramp=0x%lx (%s)",
    (unsigned long)slot, (unsigned long)prior, (unsigned long)realgate,
    (unsigned long)&hsbc_svc_tramp,
    prior==0 ? "早于App安装(理想)" : (prior==realgate ? "App已安装(晚)" : "未知值"));

  hsbc_g_realgate = realgate;   // 跳板尾调真网关(0x78befc+slide), 使 svc 在 __TEXT 内执行
  *slot = (uintptr_t)&hsbc_svc_tramp;
  uintptr_t readback = *slot;   // 立即读回, 确认我们的写入生效
  L("ctor: 已把 svc 网关重定向到本探针跳板; readback=0x%lx (%s)",
    (unsigned long)readback,
    readback==(uintptr_t)&hsbc_svc_tramp ? "确认=跳板" : "异常!非跳板");

  pthread_t th;
  pthread_create(&th, NULL, poller, NULL);
  pthread_detach(th);
}
