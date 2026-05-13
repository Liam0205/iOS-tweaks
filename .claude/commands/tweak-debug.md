---
description: "Build, deploy, and debug an iOS tweak on a jailbroken device with automated UI verification."
argument-hint: "<port> <tweak-dir> <bundle-id> [action]"
---

# /tweak-debug

Agent-driven tweak debug cycle. Spawns worker agents for autonomous steps, handles user interactions (unlock, Safe Mode) directly.

## Arguments

- `port`: SSH port (e.g., `2215`, `2216`)
- `tweak-dir`: Path to tweak project directory (e.g., `simtouch`, `abcbypass`)
- `bundle-id`: Target app bundle ID (e.g., `com.abc.mobile`, `com.apple.Preferences`)
- `action` (optional): `build`, `deploy`, `launch`, `check`, or full cycle if omitted

## Workflow

Execute the following phases. Use `Agent` tool for autonomous phases, handle interactive phases directly.

### Phase 1: Build + Deploy (Agent)

Spawn a worker agent with this prompt template:

```
Build and deploy the tweak at <tweak-dir>.

Environment:
- export THEOS=~/theos && export LD_LIBRARY_PATH=/home/linuxbrew/.linuxbrew/lib:$LD_LIBRARY_PATH
- SSH: ssh -p <port> mobile@localhost

Steps:
1. cd <tweak-dir> && make clean && make package
2. Find the latest .deb in packages/
3. scp -P <port> packages/<latest.deb> mobile@localhost:/var/jb/tmp/
4. ssh -p <port> mobile@localhost "sudo dpkg -i /var/jb/tmp/<latest.deb> && sbreload"
   (If tweak hooks backboardd, also: sudo killall backboardd)
5. Wait 10 seconds, then try: ssh -p <port> mobile@localhost "simtouch info"
6. Report: build success/fail, deploy success/fail, simtouch reachable or not

If build fails, report the full error output.
```

### Phase 2: Device Unlock (Interactive)

After agent returns, if device needs unlock, use **AskUserQuestion**:

> "请解锁 <port> 设备，解锁后继续调试。"

Then verify:
```bash
ssh -p <port> mobile@localhost "simtouch bbstatus"
```

- `hook=captured` → ready, proceed
- `hook=hooked` → ask user to touch screen once, then recheck

### Phase 3: Launch + Screenshot (Agent or direct)

Can be direct commands since they're quick:

```bash
ssh -p <port> mobile@localhost "simtouch open <bundle-id>"
sleep 2
ssh -p <port> mobile@localhost "simtouch screenshot /var/jb/tmp/simtouch/debug.jpg"
scp -P <port> mobile@localhost:/var/jb/tmp/simtouch/debug.jpg /tmp/debug.jpg
```

Then **Read** `/tmp/debug.jpg` to analyze the screenshot.

### Phase 4: Analyze + React (Main assistant)

Based on screenshot content:

| Observed | Action |
|----------|--------|
| App UI normal | Report success |
| Jailbreak detection dialog | Debug the bypass tweak — analyze hooks, modify code, loop back to Phase 1 |
| Safe Mode screen | **AskUserQuestion**: "设备进入 Safe Mode，请手动退出后确认。" Then investigate crash cause |
| Black screen | Device likely locked — go back to Phase 2 |
| App crash/not launching | Check syslog for crash reason |

For UI interaction during analysis:
```bash
ssh -p <port> mobile@localhost "simtouch tap <x> <y>"
ssh -p <port> mobile@localhost "simtouch waitfor 3000 /var/jb/tmp/simtouch/after.jpg"
scp -P <port> mobile@localhost:/var/jb/tmp/simtouch/after.jpg /tmp/after.jpg
```

## Key Rules

1. **Never assume screen state** — always screenshot before and after actions
2. **AskUserQuestion for physical interaction** — unlock, Safe Mode exit, cable reconnect
3. **Derive coordinates from screenshots** — don't guess tap positions
4. **Check .plist filter** — determines sbreload vs killall backboardd
5. **Report honestly** — if something fails, say so and explain why

## Reload Method Decision

Read the tweak's `.plist` filter file:
- Contains only `SpringBoard` → `sbreload` is sufficient
- Contains `backboardd` → need `sudo killall backboardd` (in addition to or instead of sbreload)

## Common Bundle IDs

| App | Bundle ID |
|-----|-----------|
| Settings | `com.apple.Preferences` |
| Safari | `com.apple.mobilesafari` |
| ABC (Agricultural Bank) | `com.abc.mobile` |
| App Store | `com.apple.AppStore` |

## Tweak-specific Notes

### abcbypass
- Filter: SpringBoard only
- Reload: sbreload
- Success criteria: ABC app opens without jailbreak detection alert

### simtouch
- Filter: SpringBoard + backboardd
- Reload: sbreload + killall backboardd (if backboardd code changed)
- Success criteria: simtouch CLI commands respond correctly
