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
# debug 和 release 两份会同时存在，而 "make" 只更新 debug、"make package" 只更新 release。
# 这里取较新的那份，并把它的大小和修改时间打出来——0.0.170 那次就是部署到了几小时前的
# debug 构建，日志抬头还写着上一版，白跑了一轮实验。
D_DEBUG="$PROJ/.theos/obj/debug/HSBCHKBypass.dylib"
D_REL="$PROJ/.theos/obj/HSBCHKBypass.dylib"
if [ -f "$D_DEBUG" ] && { [ ! -f "$D_REL" ] || [ "$D_DEBUG" -nt "$D_REL" ]; }; then
  DYLIB="$D_DEBUG"
else
  DYLIB="$D_REL"
fi
RUNS="${1:-3}"
SECS="${2:-30}"
CONT="${CONT:-/var/mobile/Containers/Data/Application/A2267FB5-8887-41EE-A5B7-BE6748265D29}"

[ -f "$DYLIB" ] || { echo "缺少 $DYLIB，先 make"; exit 1; }
echo "使用构建: $DYLIB ($(stat -c %s "$DYLIB") 字节, $(stat -c %y "$DYLIB" | cut -d. -f1))"

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
# 进程外的观察者要在进程还在的时候就挂上去，所以这里抢着找 pid，
# 找到立刻交给 procwatch。找不到就退化成只看存活时间。
PW=""
for i in \$(seq 1 300); do
  P=\$(ps -eo pid,args | grep -F 'HongKong.app/HongKong' | grep -v grep | awk '{print \$1}' | head -1)
  if [ -n "\$P" ]; then
    PW=\$P
    /var/jb/usr/local/bin/procwatch "\$P" 8 > /var/mobile/hkout/pw_$n.txt 2>&1 &
    # 冷启动过程中截图：判断"界面到底有没有起来"只能看屏幕。
    ( sleep 2; simtouch screenshot /var/mobile/hkout/shot_$n.jpg >/dev/null 2>&1 ) &
    break
  fi
done
# 按 pid 统计存活时间。系统会在 App 死后再拉起一次，把两次的存活加起来会得出
# "活了 5-8 秒"这种假结论——这个坑在 Round 9 踩过。注意这条 heredoc 没有引号，
# 远端 shell 要用的 $ 全部得写成 \$，否则会在本机先展开。
sleep 0.3
FIRST=\$(ps -eo pid,args | grep -F 'HongKong.app/HongKong' | grep -v grep | awk '{print \$1}' | head -1)
LAST="\$FIRST"; T=0; CHANGES=0
for i in \$(seq 1 $SECS); do
  sleep 1
  CUR=\$(ps -eo pid,args | grep -F 'HongKong.app/HongKong' | grep -v grep | awk '{print \$1}' | head -1)
  if [ -n "\$FIRST" ] && [ "\$CUR" = "\$FIRST" ]; then T=\$((T+1)); fi
  if [ -n "\$CUR" ] && [ "\$CUR" != "\$LAST" ]; then CHANGES=\$((CHANGES+1)); fi
  LAST="\$CUR"
done
if [ -z "\$FIRST" ]; then
  echo "没抓到首个 pid"
elif [ "\$CHANGES" -gt 0 ]; then
  echo "首个 pid \$FIRST 只活到第 \${T}s（期间 pid 又出现过 \$CHANGES 次，那是系统重新拉起的另一个进程）"
else
  echo "首个 pid \$FIRST 存活 \${T}s（pid 没变过）"
fi
EOF
done

scp -P "$PORT" -o BatchMode=yes -q "$HOST:/var/mobile/hkout/pw_*.txt" /var/tmp/hk/log/ 2>/dev/null
for f in /var/tmp/hk/log/pw_*.txt; do
  [ -f "$f" ] && { echo "--- $f ---"; cat "$f"; }
done

OUT=/var/tmp/hk/log
mkdir -p "$OUT"
scp -P "$PORT" -o BatchMode=yes -q "$HOST:$CONT/Library/Caches/hsbchkbypass.log" "$OUT/final.log" 2>/dev/null \
  && echo "日志: $OUT/final.log" || echo "没有日志（release 构建本来就不写）"
