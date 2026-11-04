#!/bin/bash
# 部署当前 citicbypass 构建产物并重启 App。用法: ./deploy.sh [日志行数]
set -u
H=mobile@localhost
P=22315
LOG=/var/mobile/Containers/Data/Application/D6C7814E-C373-4DB7-8908-28A614D54FAF/Library/Caches/citicbypass.log
KEEP=${1:-0}

DYLIB=/home/safe/iOS-tweaks/citicbypass/.theos/obj/CITICBypass.dylib
PLIST=/home/safe/iOS-tweaks/citicbypass/CITICBypass.plist
[ -f "$DYLIB" ] || { echo "缺少 $DYLIB"; exit 1; }

NAME="CITICBypass$(date +%H%M%S)"
scp -P $P -o BatchMode=yes -q "$DYLIB" "$H:/var/tmp/$NAME.dylib" || exit 1
scp -P $P -o BatchMode=yes -q "$PLIST" "$H:/var/tmp/$NAME.plist" || exit 1

ssh -o BatchMode=yes -p $P $H "bash -s" <<EOF
set -e
D=/var/jb/usr/lib/TweakInject
sudo -n rm -f \$D/CITICBypass*.dylib \$D/CITICBypass*.plist
sudo -n cp /var/tmp/$NAME.dylib \$D/$NAME.dylib
sudo -n cp /var/tmp/$NAME.plist \$D/$NAME.plist
sudo -n chmod 755 \$D/$NAME.dylib
sudo -n rm -f /var/tmp/$NAME.dylib /var/tmp/$NAME.plist
sudo -n killall -9 CiticMobileBank 2>/dev/null || true
sleep 2
sudo -n rm -f $LOG
/var/jb/usr/bin/simtouch open com.citic.mobile
EOF

sleep 12
ssh -o BatchMode=yes -p $P $H "bash -s" <<EOF
PROC=\$(ps -ax | grep -c '[C]iticMobileBank')
echo "=== 进程数: \$PROC ==="
echo "=== 日志 ==="
if [ -f $LOG ]; then
  if [ "$KEEP" = "0" ]; then cat $LOG; else head -$KEEP $LOG; fi
else
  echo "无日志"
fi
EOF
