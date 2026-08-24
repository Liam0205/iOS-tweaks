// Round 69 / PoC 阶段A1: 验证"检测=dyld image 枚举"假设。
// 在 %ctor 早期改 _dyld_all_image_infos.infoArray, 把 /var/jb(/private/preboot) 注入的 dylib 条目
// 从数组里"摘掉"(用列表末尾的合法条目覆盖, 缩短 count), 使 Promon 枚举 image 时看不到注入物。
// 若这样能绕过 3s 退出 → 检测就是 image 枚举, 问题大幅简化(可能纯用户态解, 不必内核)。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>
#import <mach/mach.h>
#import <mach/task.h>
#import <sys/mman.h>

static int g_fd=-1;
static void emit(const char*s){if(g_fd>=0)(void)write(g_fd,s,strlen(s));}
static void emitf(const char*fmt,...){char b[512];va_list ap;va_start(ap,fmt);vsnprintf(b,sizeof(b),fmt,ap);va_end(ap);if(g_fd>=0)(void)write(g_fd,b,strlen(b));}

// 判断路径是否是"越狱注入物"(要隐藏的)
static int is_injected(const char*p){
  if(!p) return 0;
  if(strstr(p,"/private/preboot/") && strstr(p,"/procursus/")) return 1; // rootless jb 前缀
  if(strstr(p,"/var/jb/")) return 1;
  if(strstr(p,"TweakInject")||strstr(p,"ellekit")||strstr(p,"MobileSubstrate")) return 1;
  return 0;
}

// 取 dyld_all_image_infos(通过 task_info TASK_DYLD_INFO)
static struct dyld_all_image_infos* get_all_image_infos(void){
  task_dyld_info_data_t info;
  mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
  if(task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &cnt)!=KERN_SUCCESS) return NULL;
  return (struct dyld_all_image_infos*)(uintptr_t)info.all_image_info_addr;
}

%ctor {
  char path[256];
  snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",NSTemporaryDirectory().fileSystemRepresentation,getpid());
  FILE*f=fopen(path,"w");if(f)fclose(f); g_fd=open(path,O_WRONLY|O_APPEND);

  struct dyld_all_image_infos *aii = get_all_image_infos();
  if(!aii){ emit("A1: 拿不到 all_image_infos\n"); return; }
  emitf("A1: all_image_infos @%p, infoArrayCount=%u infoArray=%p\n",
        aii, aii->infoArrayCount, aii->infoArray);

  // infoArray 是 const, 需临时改可写. 先统计要隐藏的
  const struct dyld_image_info *arr = aii->infoArray;
  uint32_t n = aii->infoArrayCount;
  if(!arr||!n){ emit("A1: infoArray 空\n"); return; }

  // 原地压缩数组: 把非注入的条目前移, 注入的丢弃, 缩短 count。
  // infoArray 内存通常在 dyld 的可写数据区; 尝试直接写, 失败则 mprotect。
  size_t page = getpagesize();
  uintptr_t start = (uintptr_t)arr & ~(page-1);
  uintptr_t end = ((uintptr_t)(arr+n) + page-1) & ~(page-1);
  mprotect((void*)start, end-start, PROT_READ|PROT_WRITE);

  struct dyld_image_info *warr = (struct dyld_image_info*)arr;
  uint32_t w=0, hidden=0;
  for(uint32_t i=0;i<n;i++){
    const char*fp = warr[i].imageFilePath;
    if(is_injected(fp)){ emitf("  hide[%u] %s\n", i, fp?fp:"?"); hidden++; continue; }
    if(w!=i) warr[w]=warr[i];
    w++;
  }
  // 缩短 count(改 all_image_infos.infoArrayCount)
  mprotect((void*)((uintptr_t)aii & ~(page-1)), page*2, PROT_READ|PROT_WRITE);
  aii->infoArrayCount = w;
  emitf("A1: 原 %u 条 → 保留 %u 条, 隐藏 %u 条注入 image\n", n, w, hidden);
  emit("A1: 完成(若 Promon 走 image 枚举, 应看不到注入物)\n");
}
