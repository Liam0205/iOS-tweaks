// Round 64 探针: 解析 init[42] 的加密 stub 表(0x84c000), 拿 6 个检测函数的真实目标,
// 判断哪个是真越狱检测。策略: hook init[42] 主体 0x43e188 入口, 里面 stub 表此时可能还没解密;
// 故改为 hook 各检测点 bl 的目标封装, 或用后台轮询读表槽直到非零/解密。
// 更稳: hook 0x775418/0x7753c4 等 stub 本身(它们 br x16, x16=[表槽]); 命中时 dladdr(x16) 看真身。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>
#import <pthread.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);

static int g_fd = -1;
static intptr_t g_slide = 0;

static void emit(const char *s){ if(g_fd>=0)(void)write(g_fd,s,strlen(s)); }
static void emitv(const char *label, unsigned long v){
  char b[128]; int p=0; const char*l=label; while(*l)b[p++]=*l++;
  b[p++]='0';b[p++]='x'; char t[18];int n=0; if(!v){t[n++]='0';} while(v){int d=v&0xf;t[n++]=d<10?'0'+d:'a'+d-10;v>>=4;}
  while(n)b[p++]=t[--n]; b[p++]='\n'; if(g_fd>=0)(void)write(g_fd,b,p);
}
// 解析一个运行时地址属于哪个 image + 符号
static void resolve(const char *tag, void *addr){
  char b[300]; int p=0; const char*t=tag; while(*t)b[p++]=*t++;
  b[p++]='=';
  unsigned long v=(unsigned long)addr;
  b[p++]='0';b[p++]='x'; char tb[18];int n=0; unsigned long vv=v; if(!vv){tb[n++]='0';} while(vv){int d=vv&0xf;tb[n++]=d<10?'0'+d:'a'+d-10;vv>>=4;} while(n)b[p++]=tb[--n];
  Dl_info info;
  if(addr && dladdr(addr,&info)){
    b[p++]=' '; b[p++]='(';
    const char*fn=info.dli_fname? (strrchr(info.dli_fname,'/')?strrchr(info.dli_fname,'/')+1:info.dli_fname):"?";
    while(*fn && p<250)b[p++]=*fn++;
    if(info.dli_sname){ b[p++]=':'; const char*sn=info.dli_sname; while(*sn && p<290)b[p++]=*sn++; }
    b[p++]=')';
  }
  b[p++]='\n'; if(g_fd>=0)(void)write(g_fd,b,p);
}

static intptr_t hsbc_slide(void){
  uint32_t n=_dyld_image_count();
  for(uint32_t i=0;i<n;i++){const char*nm=_dyld_get_image_name(i);
    if(nm&&strstr(nm,"hsbcchinax"))return _dyld_get_image_vmaddr_slide(i);}
  return 0;
}

// 后台轮询: 反复读加密表槽, 一旦非零(已解密)就 resolve 出真身, 记录后退出
static const struct { const char *name; unsigned long off; } g_slots[] = {
  {"stub_7753e8_off0xb0",  0xb0},
  {"stub_77540c_off0xf70", 0xf70},
  {"stub_7753c4_off0x100", 0x100},
  {"stub_7753f4_off0x48",  0x48},
  {"stub_775418_off0xf8",  0xf8},
  {NULL,0}
};
static void *poller(void *arg){
  (void)arg;
  unsigned long tablebase = 0x84c000 + g_slide;
  int done[8]={0};
  for(int tick=0; tick<3000; tick++){   // ~3s, 每 1ms
    for(int i=0; g_slots[i].name; i++){
      if(done[i]) continue;
      volatile uintptr_t *slot=(volatile uintptr_t*)(tablebase+g_slots[i].off);
      uintptr_t v=*slot;
      if(v && v!=0 && (v>>40)==0){   // 非零且像合法地址(高位为0)
        resolve(g_slots[i].name, (void*)v);
        done[i]=1;
      }
    }
    usleep(1000);
  }
  emit("poller: 结束\n");
  return NULL;
}

%ctor {
  char path[256];
  snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",
           NSTemporaryDirectory().fileSystemRepresentation, getpid());
  FILE*f=fopen(path,"w"); if(f)fclose(f);
  g_fd=open(path,O_WRONLY|O_APPEND);
  g_slide=hsbc_slide();
  emitv("ctor: slide=", (unsigned long)g_slide);
  if(!g_slide){ emit("no hsbcchinax\n"); return; }
  emitv("ctor: 加密表基址 0x84c000+slide=", (unsigned long)(0x84c000+g_slide));

  pthread_t th; pthread_create(&th,NULL,poller,NULL); pthread_detach(th);
}
