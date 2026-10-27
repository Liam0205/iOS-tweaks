// procwatch：从进程外看目标进程的结束方式。
//
// 用 kqueue 的 EVFILT_PROC 等目标退出，kevent 返回的 data 就是 wait 状态，
// 可以区分"正常退出（带退出码）"和"被信号终止（带信号号）"。
// 这是进程内探针看不到的部分：进程被外部 SIGKILL 时，进程内什么都来不及写。
//
// 注册时必须带 NOTE_EXITSTATUS，否则 data 恒为 0，会被误读成"退出码 0"。
// data 为 0x100 才是"正常退出、退出码 1"。

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <time.h>

static unsigned long long up_ms(void){ return clock_gettime_nsec_np(CLOCK_UPTIME_RAW)/1000000ULL; }

static void report_status(int st) {
    if (WIFEXITED(st)) printf("结束方式：正常退出，退出码 %d\n", WEXITSTATUS(st));
    else if (WIFSIGNALED(st)) printf("结束方式：被信号终止，信号 %d (%s)\n", WTERMSIG(st),
                                     WTERMSIG(st) == SIGKILL ? "SIGKILL" :
                                     WTERMSIG(st) == SIGSEGV ? "SIGSEGV" :
                                     WTERMSIG(st) == SIGILL ? "SIGILL" :
                                     WTERMSIG(st) == SIGABRT ? "SIGABRT" :
                                     WTERMSIG(st) == SIGBUS ? "SIGBUS" : "?");
    else printf("结束方式：未知状态 0x%x\n", st);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "用法: procwatch <pid> [超时秒]\n"); return 2; }
    pid_t pid = atoi(argv[1]);
    int timeout = argc > 2 ? atoi(argv[2]) : 30;

    // 顺手试一下 task_for_pid，后面是否能用外部采样取决于它。
    task_t t = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &t);
    printf("task_for_pid(%d) → kr=%d (%s)\n", pid, kr, kr == KERN_SUCCESS ? "可用" : "不可用");
    if (kr == KERN_SUCCESS) {
        task_basic_info_data_t bi;
        mach_msg_type_number_t cnt = TASK_BASIC_INFO_COUNT;
        if (task_info(t, TASK_BASIC_INFO, (task_info_t)&bi, &cnt) == KERN_SUCCESS)
            printf("  当前 CPU 时间 %u.%06u 秒\n", bi.user_time.seconds, bi.user_time.microseconds);
        mach_port_deallocate(mach_task_self(), t);
    }

    printf("注册时刻 uptime=%llums\n", up_ms());

    int kq = kqueue();
    if (kq < 0) { perror("kqueue"); return 1; }
    struct kevent ke;
    EV_SET(&ke, pid, EVFILT_PROC, EV_ADD | EV_ENABLE, NOTE_EXIT | NOTE_EXITSTATUS, 0, NULL);
    if (kevent(kq, &ke, 1, NULL, 0, NULL) < 0) { perror("kevent 注册"); return 1; }

    struct timespec ts = { timeout, 0 };
    struct kevent out;
    int n = kevent(kq, NULL, 0, &out, 1, &ts);
    if (n < 0) { perror("kevent 等待"); return 1; }
    if (n == 0) { printf("超时：%d 秒内没有退出\n", timeout); return 0; }
    printf("退出时刻 uptime=%llums  ", up_ms());
    printf("fflags=0x%x 退出状态 0x%x  ", out.fflags, (unsigned)out.data);
    report_status((int)out.data);
    return 0;
}
