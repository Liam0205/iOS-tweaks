// HSBCHKBypass 0.0.37：持续扫描"非镜像的可执行内存"，把退出桩改成 ret。
//
// 依据：
//   - 0.0.36 在启动 386ms 时由自己调用 exit(99)，钩子命中、procwatch 读到 99，
//     证明退出时刻 libc 的 exit 钩子仍然有效；App 的 exit(1) 确实没经过它；
//   - 0.0.33 在构造函数里一次性扫描非镜像可执行内存，找到并把两个 "movz x16,#1; svc"
//     改成了 ret，App 依然退出；
//   - 说明那块带桩的内存很可能是启动中期才分配出来的（哈希虚拟机创建自己的跳板页）。
//
// 这一版把扫描放进循环里，每 20ms 一次，专门盯新出现的区域。

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <pthread.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>

#import <substrate.h>

static int g_fd = -1;
static uint64_t g_start;

static uint64_t now_ms(void) {
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000ULL;
}

static void wf(const char *fmt, ...) {
    if (g_fd < 0) return;
    char buf[512];
    int off = snprintf(buf, sizeof(buf), "[%llums] ", now_ms() - g_start);
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    write(g_fd, buf, (size_t)(off + n));
}

static uintptr_t g_txt_lo[1500], g_txt_hi[1500];
static int g_txt_n;

static void snapshot_text_ranges(void) {
    uint32_t n = _dyld_image_count();
    g_txt_n = 0;
    for (uint32_t i = 0; i < n && g_txt_n < 1500; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        const uint8_t *cmds = (const uint8_t *)h + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < h->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)cmds;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    g_txt_lo[g_txt_n] = (uintptr_t)h;
                    g_txt_hi[g_txt_n] = (uintptr_t)h + (uintptr_t)seg->vmsize;
                    g_txt_n++;
                    break;
                }
            }
            cmds += lc->cmdsize;
        }
    }
}

static int in_image_text(uintptr_t a) {
    for (int i = 0; i < g_txt_n; i++) if (a >= g_txt_lo[i] && a < g_txt_hi[i]) return 1;
    return 0;
}

static int g_patched;

static void patch_exit_stubs(int tick) {
    vm_address_t addr = 0;
    int scanned = 0;
    while (1) {
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t bi;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&bi, &cnt, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
        if (kr != KERN_SUCCESS) break;
        if ((bi.protection & VM_PROT_EXECUTE) && size >= 8 && !in_image_text(addr)) {
            scanned++;
            const unsigned char *p = (const unsigned char *)addr;
            const unsigned char *end = p + size;
            while (p + 8 <= end) {
                const unsigned char *q = memchr(p, 0x01, (size_t)(end - p - 7));
                if (!q || q + 4 > end) break;
                if (!(q[1] == 0x10 && q[2] == 0x00 && q[3] == 0xd4)) { p = q + 1; continue; }
                uint32_t prev; memcpy(&prev, q - 4, 4);
                if (tick == 0) {
                    uint32_t c1, c2, c3;
                    memcpy(&c1, q - 4, 4); memcpy(&c2, q - 8, 4); memcpy(&c3, q - 12, 4);
                    wf("  svc @ %p 前：%08x %08x %08x\n", q, c3, c2, c1);
                }
                // movz x16, #imm  (0xD2800000 | imm<<5 | 16)
                if ((prev & 0xFF800000u) == 0xD2800000u && (prev & 0x1F) == 16) {
                    uint32_t imm = (prev >> 5) & 0xFFFF;
                    if (imm == 1) {
                        long ps = sysconf(_SC_PAGESIZE);
                        uintptr_t page = (uintptr_t)q & ~(uintptr_t)(ps - 1);
                        if (vm_protect(mach_task_self(), page, (vm_size_t)ps, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS) {
                            uint32_t ret_insn = 0xD65F03C0u;
                            memcpy((void *)q, &ret_insn, 4);
                            vm_protect(mach_task_self(), page, (vm_size_t)ps, 0,
                                       VM_PROT_READ | VM_PROT_EXECUTE);
                            g_patched++;
                            wf("!! 第 %d 拍发现并改写了退出桩 @ %p（累计 %d）\n", tick, q, g_patched);
                        }
                    }
                }
                p = q + 4;
            }
        }
        addr += size;
    }
    if (tick == 0) wf("第 0 拍：扫 %d 个非镜像可执行区域，已改写 %d 个桩\n", tick, scanned, g_patched);
}

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 400; i++) {
        patch_exit_stubs(i);
        usleep(15 * 1000);
    }
    return NULL;
}

__attribute__((constructor)) static void ctor(void) {
    g_start = now_ms();
    NSString *caches = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (!caches) return;
    NSString *lp = [caches stringByAppendingPathComponent:@"hsbchkbypass.log"];
    g_fd = open([lp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0) return;
    wf("===== 0.0.38 启动 pid=%d =====\n", getpid());
    snapshot_text_ranges();
    wf("镜像 __TEXT 范围 %d 个\n", g_txt_n);
    pthread_t th;
    pthread_create(&th, NULL, worker, NULL);
    wf("构造函数结束\n");
}
