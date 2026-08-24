#!/bin/bash
# 参数化 patch→重签→部署→测试 hsbcchinax
# 用法: ./patchtest.sh <file_offset_hex> <new_bytes_hex(小端, 如 00008052)> [观察秒]
# 从 pristine app-binary/hsbcchinax 起始, 每次干净 patch (不累积)
set -u
PROJ=/home/liam/iOS-dev/iOS-tweaks/hsbcbypass
PRISTINE=$PROJ/app-binary/hsbcchinax
WORK=/tmp/hsbcchinax.patched
SSH="ssh -p 2215 -o StrictHostKeyChecking=no -o ConnectTimeout=6 mobile@localhost"
OFF="${1:?需要 file_offset(hex, 不带0x 或带都行)}"
NEW="${2:?需要 new_bytes(hex, 如 00008052)}"
SECS="${3:-25}"
OFF="${OFF#0x}"

echo "=== 1. 从 pristine patch: offset 0x$OFF <- $NEW ==="
python3 - "$PRISTINE" "$WORK" "$OFF" "$NEW" <<'PY'
import sys
src,dst,off,new=sys.argv[1],sys.argv[2],int(sys.argv[3],16),bytes.fromhex(sys.argv[4])
d=bytearray(open(src,'rb').read())
old=bytes(d[off:off+len(new)])
d[off:off+len(new)]=new
open(dst,'wb').write(d)
print(f"  old={old.hex()} -> new={new.hex()} @0x{off:x}")
PY
[ $? -ne 0 ] && { echo "patch 失败"; exit 1; }

echo "=== 2. 推送未签名 patch 到设备 (在设备上用原生 ldid 签, 保证 sha256-only 且被 trustcache 接受) ==="
scp -P 2215 -o StrictHostKeyChecking=no "$WORK" mobile@localhost:/tmp/hsbcchinax.patched >/dev/null || { echo "scp 失败"; exit 1; }

echo "=== 3+4. 设备端: 原生 ldid 重签 → 部署 → 重建 trustcache → 启动 → 观测 ==="
$SSH "SECS=$SECS bash -s" <<'DEV'
set -u
FW=$(sudo -n bash -c 'ls -d /var/containers/Bundle/Application/*/China.app/Frameworks/hsbcchinax.framework/hsbcchinax 2>/dev/null | head -1')
[ -z "$FW" ] && { echo "找不到 hsbcchinax 路径"; exit 1; }
echo "  目标: $FW"
# 用设备原生 ldid 签 (与可加载的 deployed 版同源, sha256-only)
/var/jb/usr/bin/ldid -S /tmp/hsbcchinax.patched
echo "  设备 ldid 签名: $(/var/jb/usr/bin/ldid -h /tmp/hsbcchinax.patched 2>/dev/null | grep -i 'CDHash=' | head -1)"
sudo -n cp /tmp/hsbcchinax.patched "$FW"
sudo -n chown _installd:_installd "$FW"
sudo -n /var/jb/basebin/jbctl rebuild_trustcache 2>/dev/null || sudo -n jbctl rebuild_trustcache 2>/dev/null
echo "  trustcache 已重建"

# 清理旧进程和探针日志
BINN=China
killall -9 "$BINN" 2>/dev/null; sleep 1
CDIR=$(ls -dt /var/mobile/Containers/Data/Application/*/tmp 2>/dev/null | while read d; do [ -e "$d/hsbc_probe_"* ] 2>/dev/null && echo "$d" && break; done)
rm -f /var/mobile/Containers/Data/Application/*/tmp/hsbc_probe_* 2>/dev/null
CB=$(sudo -n ls -t /var/mobile/Library/Logs/CrashReporter/China-*.ips 2>/dev/null | head -1)

uiopen --bundle cn.com.hsbc.hsbcchina >/dev/null 2>&1
LAUNCH=$(date +%s)
echo "  已启动, 观测 ${SECS}s..."

DIED=""
for ((t=1;t<=SECS;t++)); do
  sleep 1
  P=$(ps -eo pid,args 2>/dev/null | grep -E "China\.app/China( |$)" | grep -v appex | grep -v PlugIns | grep -v grep | awk '{print $1}')
  [ -z "$P" ] && [ -z "$DIED" ] && DIED=$t
done

echo "----- 结果 -----"
# 探针心跳: 每个 pid 最后一条
for f in $(ls -t /var/mobile/Containers/Data/Application/*/tmp/hsbc_probe_* 2>/dev/null | head -4); do
  PID=$(basename "$f" | sed 's/hsbc_probe_//;s/.log//')
  LAST=$(tail -1 "$f" 2>/dev/null)
  SZ=$(stat -f%z "$f" 2>/dev/null || wc -c <"$f")
  echo "  probe pid=$PID size=${SZ}B last: $LAST"
done
[ -n "$DIED" ] && echo "  主App进程在 ~${DIED}s 内消失" || echo "  主App进程存活 >=${SECS}s ✅"

# 新崩溃日志分类
CA=$(sudo -n ls -t /var/mobile/Library/Logs/CrashReporter/China-*.ips 2>/dev/null | head -1)
if [ -n "$CA" ] && [ "$CA" != "$CB" ]; then
  echo "  [新崩溃] $(basename "$CA")"
  sudo -n grep -oE "0x8BADF00D|watchdog transgression[^\"]*seconds|EXC_[A-Z_]+|SIG[A-Z]+|namespace\":\"[^\"]*" "$CA" | sort -u | head -8 | sed 's/^/    /'
else
  echo "  [无新崩溃] (静默退出或仍存活)"
fi
DEV