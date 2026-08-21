#!/bin/bash
# 可靠的 HSBC 主 App 测试工具 (在设备上运行)
# 用法: ssh -p 22215 mobile@localhost 'bash -s' -- <cn|hk> <观察秒数>
APP="${1:-cn}"
SECS="${2:-30}"

if [ "$APP" = "cn" ]; then
  BID="cn.com.hsbcchina"; BIN="China.app/China"
else
  BID="hk.com.hsbc.hsbchkmobilebanking"; BIN="HongKong.app/HongKong"
fi

# 精确匹配主 App 进程: 命令行以 <BIN> 结尾, 排除 .appex 扩展和 PlugIns
main_pid() {
  ps -eo pid,args 2>/dev/null | grep -E "$BIN( |\$)" | grep -v "\.appex" | grep -v PlugIns | grep -v grep | awk '{print $1}' | head -1
}
main_etime() {
  ps -eo etime,args 2>/dev/null | grep -E "$BIN( |\$)" | grep -v "\.appex" | grep -v PlugIns | grep -v grep | awk '{print $1}' | head -1
}

CB=$(ls -t /var/mobile/Library/Logs/CrashReporter/${1}*.ips 2>/dev/null | head -1)
BINNAME=$(basename "$BIN")
killall -9 "$BINNAME" 2>/dev/null; sleep 2
uiopen "$BID" >/dev/null 2>&1 || open "$BID" >/dev/null 2>&1
LAUNCH=$(date +%s)

DIED_AT=""
for ((t=1; t<=SECS; t++)); do
  sleep 1
  PID=$(main_pid)
  if [ -z "$PID" ]; then DIED_AT=$t; break; fi
done

if [ -n "$DIED_AT" ]; then
  echo "[RESULT] $BINNAME 主App 在 ~${DIED_AT}s 消失(退出或崩溃)"
else
  echo "[RESULT] $BINNAME 主App 存活 >=${SECS}s (etime=$(main_etime))"
fi

# 崩溃判定
CA=$(ls -t /var/mobile/Library/Logs/CrashReporter/${BINNAME}*.ips 2>/dev/null | head -1)
if [ -n "$CA" ] && [ "$CA" != "$CB" ]; then
  echo "[CRASH] 新崩溃: $(basename "$CA")"
else
  echo "[CRASH] 无新崩溃(若已消失则为正常exit退出)"
fi
