#!/bin/bash
# 部署并验证 HSBCBypass。
# 用法: ./verify.sh [冷启动次数] [每次观察秒数]
#
# 设备上有两处缓存要注意（都是本轮实测踩到的）：
#   1. /var/jb/usr/lib/TweakInject 下的 dylib 改内容不换名字，dyld 会报
#      CODESIGNING 并把进程杀掉。所以每次换一个新的文件名。
#   2. TweakInject 里其它 tweak（Choicy、Crane 等）的 plist 也会注入汇丰，
#      它们自己可能触发 ZDefend 的注入检测。这里只保留 HSBCBypass。
set -u
HOST="mobile@localhost"
PORT="${PORT:-22215}"
PROJ="$(cd "$(dirname "$0")" && pwd)"
DYLIB="$PROJ/.theos/obj/debug/HSBCBypass.dylib"
RUNS="${1:-3}"
SECS="${2:-40}"
CONT=$(ssh -o BatchMode=yes -p "$PORT" "$HOST" \
  'for d in /var/mobile/Containers/Data/Application/*/; do
     f="$d.com.apple.mobile_container_manager.metadata.plist"
     [ -f "$f" ] || continue
     id=$(plutil -extract MCMMetadataIdentifier raw "$f" 2>/dev/null)
     [ "$id" = "cn.com.hsbc.hsbcchina" ] && echo "$d"
   done' 2>/dev/null | head -1)
CONT="${CONT%/}"

[ -f "$DYLIB" ] || { echo "缺少 $DYLIB，先 make"; exit 1; }

NAME="HSBCBypass$(date +%H%M%S)"
scp -P "$PORT" -o BatchMode=yes -q "$DYLIB" "$HOST:/var/tmp/$NAME.dylib" || exit 1
scp -P "$PORT" -o BatchMode=yes -q "$PROJ/HSBCBypass.plist" "$HOST:/var/tmp/$NAME.plist" || exit 1

ssh -o BatchMode=yes -p "$PORT" "$HOST" "
D=/var/jb/usr/lib/TweakInject
# 只留这一份，其余 tweak 的 plist 全部关掉
for f in \"\$D\"/*.plist; do
  b=\$(basename \"\$f\")
  [ \"\$b\" = '$NAME.plist' ] || sudo -n mv \"\$f\" \"\$f.off\" 2>/dev/null
done
sudo -n cp /var/tmp/$NAME.dylib \"\$D/$NAME.dylib\"
sudo -n cp /var/tmp/$NAME.plist \"\$D/$NAME.plist\"
sudo -n chown root:wheel \"\$D/$NAME.dylib\" \"\$D/$NAME.plist\"
echo \"已部署 $NAME\"
" || exit 1

for n in $(seq 1 "$RUNS"); do
  ssh -o BatchMode=yes -p "$PORT" "$HOST" "
    killall -9 China 2>/dev/null; sleep 2
    uiopen --bundle cn.com.hsbc.hsbcchina >/dev/null 2>&1
    for i in \$(seq 1 $SECS); do
      sleep 1
      ps -eo args | grep -F 'China.app/China' | grep -v grep >/dev/null || { echo '第 \${i}s 退出'; exit 0; }
    done
    echo '存活 ${SECS}s'
  " | sed "s/^/冷启动 $n: /"
done

if [ -n "$CONT" ]; then
  scp -P "$PORT" -o BatchMode=yes -q "$HOST:$CONT/Library/Caches/hsbcbypass.log" /var/tmp/hsbc/final.log 2>/dev/null \
    && echo "日志: /var/tmp/hsbc/final.log" || echo "没有日志（release 构建本来就不写）"
fi
