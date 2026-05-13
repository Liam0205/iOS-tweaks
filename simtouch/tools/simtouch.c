#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <CoreFoundation/CoreFoundation.h>

#define SOCKET_PATH "/var/jb/tmp/simtouch.sock"
#define BUF_SIZE 4096
#define PREFS_ID CFSTR("page.0x01.simtouch")
#define PREFS_NOTIFICATION CFSTR("page.0x01.simtouch.prefsChanged")

static int send_command(const char *cmd) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    char line[BUF_SIZE];
    snprintf(line, sizeof(line), "%s\n", cmd);

    if (write(fd, line, strlen(line)) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    char buf[BUF_SIZE];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) {
        fprintf(stderr, "no response\n");
        return 1;
    }

    buf[n] = '\0';
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = '\0';

    printf("%s\n", buf);

    return strncmp(buf, "OK", 2) == 0 ? 0 : 1;
}

static int set_enabled(int enabled) {
    CFBooleanRef val = enabled ? kCFBooleanTrue : kCFBooleanFalse;
    CFPreferencesSetAppValue(CFSTR("enabled"), val, PREFS_ID);
    CFPreferencesAppSynchronize(PREFS_ID);
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        PREFS_NOTIFICATION, NULL, NULL, true);
    printf("OK\n");
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  simtouch enable\n"
        "  simtouch disable\n"
        "  simtouch info\n"
        "  simtouch screenshot [path]\n"
        "  simtouch tap <x> <y>\n"
        "  simtouch swipe <x1> <y1> <x2> <y2> [ms] [curve]\n"
        "    curves: linear, easein, easeout, easeinout, bezier:cx1,cy1,cx2,cy2\n"
        "  simtouch longpress <x> <y> [ms]\n"
        "  simtouch keyinput <key>          (enter/tab/backspace/esc/space/delete/up/down/left/right/a-z/0-9)\n"
        "  simtouch keyinput text <string>  (paste via clipboard)\n"
        "  simtouch pinch <cx> <cy> <scale> [ms]  (scale>1 zoom in, <1 zoom out)\n"
        "  simtouch home\n"
        "  simtouch notif\n"
        "  simtouch cc\n"
        "  simtouch switcher\n"
        "  simtouch record <start [name]|stop|list|dump [name]|delete <name>>\n"
        "  simtouch replay [name] [speed]\n"
        "  simtouch open <bundle-id>          (launch app)\n"
        "  simtouch waitfor [timeout_ms] [path]  (wait for screen change, default 5000ms)\n"
    );
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "enable") == 0) return set_enabled(1);
    if (strcmp(argv[1], "disable") == 0) return set_enabled(0);

    char cmd[BUF_SIZE] = {0};
    for (int i = 1; i < argc; i++) {
        if (i > 1) strlcat(cmd, " ", sizeof(cmd));
        strlcat(cmd, argv[i], sizeof(cmd));
    }

    return send_command(cmd);
}
