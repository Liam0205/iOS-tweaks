# procwatch

从进程外观察目标进程的结束方式。进程内的探针只能看到"自己调用了哪些函数"，
看不到"进程最终是怎么没的"；这个工具补上那一半。

## 用法

```sh
procwatch <pid> [超时秒数]
```

输出示例：

```
task_for_pid(14867) → kr=5 (不可用)
注册时刻 uptime=2376731044ms
退出时刻 uptime=2376731521ms  fflags=0x84000000 退出状态 0x100  结束方式：正常退出，退出码 1
```

## 两个坑

- **`NOTE_EXITSTATUS` 不能省。** 只注册 `NOTE_EXIT` 时 `kevent` 返回的 `data`
  恒为 0，会被误读成"正常退出、退出码 0"。带上之后 `0x100` 才是"退出码 1"。
- `task_for_pid` 在越狱设备上未必可用（实测 iPhone 13 Pro / iOS 15.4.1 返回 `kr=5`），
  所以拿不到内存和线程快照，只有退出状态这类间接信号。

## 构建与部署

Linux 交叉编译要显式指定工具链的 ld64：

```sh
env -u PERL5LIB THEOS=/home/safe/theos make \
  ADDITIONAL_LDFLAGS="-B$THEOS/toolchain/linux/iphone/bin -fuse-ld=$THEOS/toolchain/linux/iphone/bin/ld"
scp -P 22215 .theos/obj/debug/procwatch mobile@localhost:/var/mobile/
ssh -p 22215 mobile@localhost "sudo mv /var/mobile/procwatch /var/jb/usr/local/bin/ && sudo chmod 755 /var/jb/usr/local/bin/procwatch"
```
