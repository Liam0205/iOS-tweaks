#!/bin/bash
# 部署 HSBCBypass.dylib 到设备 rootless MobileSubstrate, 启动 China, 观测探针日志
# 用法: ./deploytweak.sh [观察秒] [restore]
#   restore: 把 hsbcchinax 恢复为 pristine(去掉任何 binary patch)
set -u
PROJ=/home/liam/iOS-dev/iOS-tweaks/hsbcbypass
DYLIB=$PROJ/.theos/obj/debug/HSBCBypass.dylib
PRISTINE=$PROJ/app-binary/hsbcchinax
SSH="ssh -p 2215 -o StrictHostKeyChecking=no -o ConnectTimeout=6 mobile@localhost"
SECS="${1:-25}"
MODE="${2:-}"
# MODE=restore: 恢复 pristine app 二进制(无 patch)
# MODE=nopstore: 恢复 pristine 后, nop 掉安装点 0x346c74 的 str(使探针跳板写入的槽不被 App 覆盖)
WORK=/tmp/hsbcchinax.patched

[ -f "$DYLIB" ] || { echo "缺少 $DYLIB, 先 make"; exit 1; }

echo "=== 1. 推送 dylib(+plist) 到设备 ==="
scp -P 2215 -o StrictHostKeyChecking=no "$DYLIB" mobile@localhost:/tmp/HSBCBypass.dylib >/dev/null || { echo scp失败; exit 1; }
if [ "$MODE" = "restore" ]; then
  scp -P 2215 -o StrictHostKeyChecking=no "$PRISTINE" mobile@localhost:/tmp/hsbcchinax.pristine >/dev/null || { echo scp失败; exit 1; }
elif [ "$MODE" = "nopstore" ]; then
  # 从 pristine 生成: 0x346c74 str x9,[x8,#0xc8] (f9006509) -> nop (1f2003d5)
  python3 - "$PRISTINE" "$WORK" <<'PY'
import sys
src,dst=sys.argv[1],sys.argv[2]
d=bytearray(open(src,'rb').read())
off=0x346c74; old=bytes(d[off:off+4])
assert old==bytes.fromhex('096500f9'), f"意外原字节 {old.hex()} (期望 096500f9 = str x9,[x8,#0xc8])"
d[off:off+4]=bytes.fromhex('1f2003d5')  # nop
open(dst,'wb').write(d)
print(f"  patch 0x{off:x}: {old.hex()} -> 1f2003d5 (nop store x9->[x8,#0xc8])")
PY
  scp -P 2215 -o StrictHostKeyChecking=no "$WORK" mobile@localhost:/tmp/hsbcchinax.patched >/dev/null || { echo scp失败; exit 1; }
fi

$SSH "SECS=$SECS MODE='$MODE' bash -s" <<'DEV'
set -u
DL=/var/jb/Library/MobileSubstrate/DynamicLibraries
# 设备原生 ldid 签 dylib(sha256-only)
/var/jb/usr/bin/ldid -S /tmp/HSBCBypass.dylib
sudo -n cp /tmp/HSBCBypass.dylib "$DL/HSBCBypass.dylib"
sudo -n chown root:wheel "$DL/HSBCBypass.dylib"
# 写 plist(注入 China / HongKong)
sudo -n bash -c "cat > '$DL/HSBCBypass.plist'" <<'PLIST'
{ Filter = { Bundles = ( "cn.com.hsbc.hsbcchina", "hk.com.hsbc.hsbchkmobilebanking" ); }; }
PLIST
echo "  dylib 已部署: $(ls -l "$DL/HSBCBypass.dylib" | awk '{print $5}')B"

# 可选: 部署 pristine 或 nop-store patch 的 app 二进制
FW=$(sudo -n bash -c 'ls -d /var/containers/Bundle/Application/*/China.app/Frameworks/hsbcchinax.framework/hsbcchinax 2>/dev/null | head -1')
if [ "$MODE" = "restore" ] && [ -n "$FW" ]; then
  /var/jb/usr/bin/ldid -S /tmp/hsbcchinax.pristine
  sudo -n cp /tmp/hsbcchinax.pristine "$FW"
  sudo -n chown _installd:_installd "$FW"
  sudo -n /var/jb/basebin/jbctl rebuild_trustcache 2>/dev/null
  echo "  app 二进制已恢复 pristine + trustcache 重建"
elif [ "$MODE" = "nopstore" ] && [ -n "$FW" ]; then
  /var/jb/usr/bin/ldid -S /tmp/hsbcchinax.patched
  sudo -n cp /tmp/hsbcchinax.patched "$FW"
  sudo -n chown _installd:_installd "$FW"
  sudo -n /var/jb/basebin/jbctl rebuild_trustcache 2>/dev/null
  echo "  app 二进制已部署 nop-store patch + trustcache 重建"
fi

# 清旧进程 + 日志
killall -9 China 2>/dev/null; sleep 1
rm -f /var/mobile/Containers/Data/Application/*/tmp/hsbc_probe_* 2>/dev/null
CB=$(sudo -n ls -t /var/mobile/Library/Logs/CrashReporter/China-*.ips 2>/dev/null | head -1)

uiopen --bundle cn.com.hsbc.hsbcchina >/dev/null 2>&1
echo "  已启动, 观测 ${SECS}s..."
DIED=""
for ((t=1;t<=SECS;t++)); do
  sleep 1
  P=$(ps -eo pid,args 2>/dev/null | grep -E "China\.app/China( |$)" | grep -v appex | grep -v PlugIns | grep -v grep | awk '{print $1}')
  [ -z "$P" ] && [ -z "$DIED" ] && DIED=$t
done

echo "----- 结果 -----"
[ -n "$DIED" ] && echo "  主App进程在 ~${DIED}s 内消失" || echo "  主App进程存活 >=${SECS}s ✅"
# 探针日志
for f in $(ls -t /var/mobile/Containers/Data/Application/*/tmp/hsbc_probe_* 2>/dev/null | head -4); do
  PID=$(basename "$f" | sed 's/hsbc_probe_//;s/.log//')
  SZ=$(wc -c <"$f")
  echo "  === probe pid=$PID size=${SZ}B ==="
  head -60 "$f" | sed 's/^/    /'
  echo "    ...(tail)..."
  tail -12 "$f" | sed 's/^/    /'
done
# 新崩溃
CA=$(sudo -n ls -t /var/mobile/Library/Logs/CrashReporter/China-*.ips 2>/dev/null | head -1)
if [ -n "$CA" ] && [ "$CA" != "$CB" ]; then
  echo "  [新崩溃] $(basename "$CA")"
  sudo -n grep -oE "0x8BADF00D|watchdog[^\"]*|EXC_[A-Z_]+|SIG[A-Z]+|namespace\":\"[^\"]*|\"pc\":[0-9]+" "$CA" | sort -u | head -12 | sed 's/^/    /'
else
  echo "  [无新崩溃]"
fi
DEV