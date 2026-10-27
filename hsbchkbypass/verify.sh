#!/bin/bash
# 部署并验证 HSBCHKBypass 探针。
# 用法: ./verify.sh [冷启动次数] [每次观察秒数]
#
# 设备上 mobile 用户的默认 shell 是 zsh，`*.dylib` 这类 glob 在没有匹配时会直接
# 报错并中断整条命令。所以远端一律用 `bash -s` 跑脚本，不要拼一长串引号。
#
# 另外两处缓存要注意：
#   1. /var/jb/usr/lib/TweakInject 下的 dylib 改内容不换名字，dyld 会报
#      CODESIGNING 并把进程杀掉。所以每次换一个新的文件名。
#   2. TweakInject 里其它 tweak 的 plist 也会注入进来，干扰判断。这里只保留本探针。
#      被改名的 plist 会记进 TweakInject/.disabled-by-verify，结束时（包括 Ctrl-C）
#      自动改回来。别让它把整台设备的 tweak 都留成禁用状态——SpringBoard 一重启，
#      所有 .off 一起生效，看起来就像"注入整体坏了"。
set -u
HOST="mobile@localhost"
PORT="${PORT:-22215}"
PROJ="$(cd "$(dirname "$0")" && pwd)"
# 签名后的 dylib 在 obj 根目录；obj/<arch> 下的是重签之前的那份，别用错了。
if [ -f "$PROJ/.theos/obj/debug/HSBCHKBypass.dylib" ]; then
  DYLIB="$PROJ/.theos/obj/debug/HSBCHKBypass.dylib"
else
  DYLIB="$PROJ/.theos/obj/HSBCHKBypass.dylib"
fi
RUNS="${1:-3}"
SECS="${2:-30}"
CONT="${CONT:-/var/mobile/Containers/Data/Application/A2267FB5-8887-41EE-A5B7-BE6748265D29}"

[ -f "$DYLIB" ] || { echo "缺少 $DYLIB，先 make"; exit 1; }

# 恢复被本脚本改名为 .off 的 plist。部署失败、观察中断、Ctrl-C 都要走到这里。
restore_plists() {
  ssh -o BatchMode=yes -p "$PORT" "$HOST" "bash -s" <<'RESTORE' 2>/dev/null
D=/var/jb/usr/lib/TweakInject
REC=$D/.disabled-by-verify
[ -f "$REC" ] || exit 0
n=0
while IFS= read -r b; do
  [ -n "$b" ] || continue
  if [ -e "$D/$b" ]; then continue; fi
  if sudo -n mv "$D/$b.off" "$D/$b" 2>/dev/null; then n=$((n+1)); fi
done < "$REC"
sudo -n rm -f "$REC"
echo "已恢复 $n 个 plist"
RESTORE
}
trap restore_plists EXIT INT TERM

NAME="HSBCHKBypass$(date +%H%M%S)"
scp -P "$PORT" -o BatchMode=yes -q "$DYLIB" "$HOST:/var/tmp/$NAME.dylib" || exit 1
scp -P "$PORT" -o BatchMode=yes -q "$PROJ/HSBCHKBypass.plist" "$HOST:/var/tmp/$NAME.plist" || exit 1

ssh -o BatchMode=yes -p "$PORT" "$HOST" "bash -s" <<EOF || exit 1
set -u
D=/var/jb/usr/lib/TweakInject
sudo -n rm -f \$D/HSBCHKBypass*.dylib \$D/HSBCHKBypass*.plist
sudo -n rm -f \$D/HSBCHKProbe*.dylib \$D/HSBCHKProbe*.plist
REC=\$D/.disabled-by-verify
printf '' | sudo -n tee \$REC >/dev/null 2>&1
for f in \$D/*.plist; do
  [ -e "\$f" ] || continue
  b=\$(basename "\$f")
  case "\$b" in
    *.off) continue ;;
    $NAME.plist|HSBCChinaBypass.plist) continue ;;
  esac
  if sudo -n mv "\$f" "\$f.off" 2>/dev/null; then
    echo "\$b" | sudo -n tee -a \$REC >/dev/null
  fi
done
sudo -n cp /var/tmp/$NAME.dylib \$D/$NAME.dylib
sudo -n cp /var/tmp/$NAME.plist \$D/$NAME.plist
sudo -n chown root:wheel \$D/$NAME.dylib \$D/$NAME.plist
sudo -n rm -f $CONT/Library/Caches/hsbchkbypass.log
echo "已部署 $NAME"
EOF

# 不在这里恢复：隔离要覆盖下面的冷启动。恢复交给脚本末尾的 trap，
# 无论正常结束、中途退出还是 Ctrl-C 都会执行。

for n in $(seq 1 "$RUNS"); do
  ssh -o BatchMode=yes -p "$PORT" "$HOST" "bash -s" <<EOF | sed "s/^/冷启动 $n: /"
killall -9 HongKong 2>/dev/null
sleep 2
uiopen --bundle hk.com.hsbc.hsbchkmobilebanking >/dev/null 2>&1
for i in \$(seq 1 $SECS); do
  sleep 1
  ps -eo args | grep -F 'HongKong.app/HongKong' | grep -v grep >/dev/null || { echo "第 \${i}s 退出"; exit 0; }
done
echo "存活 ${SECS}s"
EOF
done

OUT=/var/tmp/hk/log
mkdir -p "$OUT"
scp -P "$PORT" -o BatchMode=yes -q "$HOST:$CONT/Library/Caches/hsbchkbypass.log" "$OUT/final.log" 2>/dev/null \
  && echo "日志: $OUT/final.log" || echo "没有日志（release 构建本来就不写）"
