// HSBCBypass —— 主线程 PC 采样(定位退出前活动模块)
//
// 检测/退出用内联 svc,hook 抓不到;但代码在哪个模块执行是可观测的。
// 后台线程高频 thread_get_state 读主线程 PC,记录所属模块。
// 退出前最后采样到的模块 = 触发退出的代码所在。不 hook 任何函数 → 不被反制。

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <pthread.h>
#import <mach/mach.h>

static double g_t0 = 0;
static void hsbc_log(NSString *line) {
    static NSString *path = nil;
    if (!path) path = [NSTemporaryDirectory() stringByAppendingPathComponent:
                       [NSString stringWithFormat:@"hsbc_probe_%d.log", getpid()]];
    NSString *e = [line stringByAppendingString:@"\n"];
    FILE *f = fopen([path fileSystemRepresentation], "a");
    if (f) { fwrite(e.UTF8String, 1, strlen(e.UTF8String), f); fclose(f); }
}
#define HSBCLOG(fmt, ...) do { \
    if (g_t0==0) g_t0=CFAbsoluteTimeGetCurrent(); \
    double dt=(CFAbsoluteTimeGetCurrent()-g_t0)*1000.0; \
    hsbc_log([NSString stringWithFormat:(@"[+%.0fms] " fmt), dt, ##__VA_ARGS__]); \
} while(0)

static const char *mod_of(uint64_t a, uintptr_t *off) {
    Dl_info di;
    if (a && dladdr((void*)a,&di) && di.dli_fname) {
        const char *b=strrchr(di.dli_fname,'/'); b=b?b+1:di.dli_fname;
        if(off)*off=(uintptr_t)a-(uintptr_t)di.dli_fbase;
        return b;
    }
    return NULL;
}

static thread_t g_self_sampler = MACH_PORT_NULL;

// 采样线程:枚举所有线程,读每个线程 PC,记录 App 自带模块的活动
static void *sampler(void *a) {
    char last[256]="";
    g_self_sampler = pthread_mach_thread_np(pthread_self());
    for (;;){
        thread_act_array_t threads; mach_msg_type_number_t tc=0;
        if (task_threads(mach_task_self(),&threads,&tc)!=KERN_SUCCESS){ usleep(1000); continue; }
        for (mach_msg_type_number_t i=0;i<tc;i++){
            if (threads[i]==g_self_sampler) continue;  // 跳过自己
            arm_thread_state64_t ts; mach_msg_type_number_t cnt=ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(threads[i],ARM_THREAD_STATE64,(thread_state_t)&ts,&cnt)!=KERN_SUCCESS) continue;
            uint64_t pc=__darwin_arm_thread_state64_get_pc(ts);
            uint64_t lr=(uint64_t)__darwin_arm_thread_state64_get_lr(ts);
            uintptr_t off=0, loff=0;
            const char *m=mod_of(pc,&off);
            const char *lm=mod_of(lr,&loff);
            if (m && (strstr(m,"TMX")||strstr(m,"Transmit")||strstr(m,"Turing")||
                      strstr(m,"BioCatch")||strstr(m,"RemoteSale")||strstr(m,"China")||
                      strstr(m,"RASP")||strstr(m,"VASCO")||strstr(m,"MobileSecurity")||
                      strstr(m,"ChinaFacial")||strstr(m,"HKEApi")||strstr(m,"Sensors")||
                      strstr(m,"ZAiSee")||strstr(m,"Tealium")||strstr(m,"UserSecurity"))){
                char cur[256]; snprintf(cur,256,"%s+0x%lx",m,off);
                if(strcmp(cur,last)!=0){
                    HSBCLOG(@"PC@ %s+0x%lx (LR %s+0x%lx)", m, off, lm?lm:"?", loff);
                    strncpy(last,cur,255);
                }
            }
        }
        for (mach_msg_type_number_t i=0;i<tc;i++) mach_port_deallocate(mach_task_self(),threads[i]);
        vm_deallocate(mach_task_self(),(vm_address_t)threads,tc*sizeof(thread_act_t));
        usleep(300);
    }
    return NULL;
}

static void *heartbeat(void *a){for(int i=0;;i++){if(i%20==0)HSBCLOG(@"♥ #%d",i);usleep(10000);}return NULL;}

%ctor {
    @autoreleasepool {
        HSBCLOG(@"探针注入 pid=%d", getpid());
        pthread_t st; pthread_create(&st,NULL,sampler,NULL); pthread_detach(st);
        pthread_t hb; pthread_create(&hb,NULL,heartbeat,NULL); pthread_detach(hb);
    }
}
