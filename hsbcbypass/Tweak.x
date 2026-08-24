// Round 67(方向2): 逆 Promon 内存比对。决策函数 0x7753c4(w0, bufA=x1, bufB=x2) 返回 0 却仍退出,
// 说明 verdict 在别处比对收集到的数据。本探针 hook 0x7753c4, dump 它的 3 个参数(w0 值 + 两个缓冲区内存),
// 看 Promon 收集/比对的到底是什么(dyld cache? 内存页? 校验和?)。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <fcntl.h>
#import <unistd.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);

static int g_fd=-1; static intptr_t g_slide=0; static double g_t0=0;
static void emit(const char*s){if(g_fd>=0)(void)write(g_fd,s,strlen(s));}
static double now_ms(void){return (g_t0>0)?(CFAbsoluteTimeGetCurrent()-g_t0)*1000:0;}
// dump 内存 n 字节为 hex(带 ASCII)
static void dumpmem(const char*tag, const void*p, int n){
  char b[600];int q=0;const char*t=tag;while(*t)b[q++]=*t++;
  b[q++]='@';unsigned long v=(unsigned long)p;b[q++]='0';b[q++]='x';
  {char tb[18];int m=0;unsigned long vv=v;if(!vv)tb[m++]='0';while(vv){int d=vv&0xf;tb[m++]=d<10?'0'+d:'a'+d-10;vv>>=4;}while(m)b[q++]=tb[--m];}
  b[q++]=' ';
  if(!p){b[q++]='(';b[q++]='0';b[q++]=')';b[q++]='\n';if(g_fd>=0)(void)write(g_fd,b,q);return;}
  const unsigned char*u=(const unsigned char*)p;
  for(int i=0;i<n && q<560;i++){ b[q++]="0123456789abcdef"[u[i]>>4]; b[q++]="0123456789abcdef"[u[i]&0xf]; if((i&3)==3)b[q++]=' ';}
  b[q++]='\n'; if(g_fd>=0)(void)write(g_fd,b,q);
}

typedef long(*fn4)(long,long,long,long);
static fn4 orig_dec=0;   // 0x7753c4
static int dec_calls=0;
static long my_dec(long w0,long bufA,long bufB,long a3){
  dec_calls++;
  if(dec_calls<=6){
    char h[64];snprintf(h,sizeof(h),"[7753c4] #%d w0=0x%lx t=%.0fms\n",dec_calls,(unsigned long)w0,now_ms());emit(h);
    // bufA/bufB 是栈缓冲, dump 前 48 字节
    if(bufA>0x100000000L && bufA<0x200000000L) dumpmem("  bufA", (void*)bufA, 48);
    if(bufB>0x100000000L && bufB<0x200000000L) dumpmem("  bufB", (void*)bufB, 48);
  }
  long r = orig_dec? orig_dec(w0,bufA,bufB,a3):0;
  if(dec_calls<=6){char h[48];snprintf(h,sizeof(h),"  → ret=0x%lx\n",(unsigned long)r);emit(h);}
  return r;
}

// 也 hook 数据收集器 774fec, dump 它返回的缓冲
static fn4 orig_gat=0;  // 0x774fec
static int gat_calls=0;
static long my_gat(long a0,long a1,long a2,long a3){
  gat_calls++;
  long r=orig_gat?orig_gat(a0,a1,a2,a3):0;
  if(gat_calls<=3){
    char h[64];snprintf(h,sizeof(h),"[774fec] #%d ret=0x%lx t=%.0fms\n",gat_calls,(unsigned long)r,now_ms());emit(h);
    if(r>0x100000000L && r<0x180000000L) dumpmem("  gathered", (void*)r, 64);
  }
  return r;
}

static intptr_t hsbc_slide(void){uint32_t n=_dyld_image_count();for(uint32_t i=0;i<n;i++){const char*nm=_dyld_get_image_name(i);if(nm&&strstr(nm,"hsbcchinax"))return _dyld_get_image_vmaddr_slide(i);}return 0;}

%ctor {
  g_t0=CFAbsoluteTimeGetCurrent();
  char path[256];snprintf(path,sizeof(path),"%s/hsbc_probe_%d.log",NSTemporaryDirectory().fileSystemRepresentation,getpid());
  FILE*f=fopen(path,"w");if(f)fclose(f); g_fd=open(path,O_WRONLY|O_APPEND);
  g_slide=hsbc_slide(); if(!g_slide){emit("no slide\n");return;}
  MSHookFunction((void*)(0x7753c4+g_slide),(void*)my_dec,(void**)&orig_dec);
  MSHookFunction((void*)(0x774fec+g_slide),(void*)my_gat,(void**)&orig_gat);
  emit("ctor: hooked 0x7753c4(决策) + 0x774fec(收集)\n");
}
