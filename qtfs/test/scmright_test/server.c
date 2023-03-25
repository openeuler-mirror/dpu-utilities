#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include "uds.h"

static const char *HEAD = "write from server:\n";

int main(int argc, char **argv)
{
    char *path = NULL;
    if (argc != 2) {
        printf("Usage: %s pathtosock\n", argv[0]);
        return -EINVAL;
    }
    path=argv[1];
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("Fail to create socket: %s\n", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, strlen(path) + 1);
    socklen_t size = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;;
    unlink(path);
    printf("begin bind %s\n", addr.sun_path);
    int ret = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
        printf("Fail to bind socket: %s\n", strerror(errno));
        return ret;
    }
    printf("begin listen...\n");
    ret = listen(fd, 10);
    if (ret < 0) {
        printf("Fail to listen, %s\n", strerror(errno));
        close(fd);
        return ret;
    }
    size = sizeof(addr);
    while (1) {
        printf("try accept %s...\n", addr.sun_path);
        int new_fd = accept(fd, (struct sockaddr*)&addr, &size);
        if (new_fd < 0) {
            printf("Fail to accpet, %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        printf("try udsRecvFd...\n");
        int share_fd = udsRecvFd(new_fd, 0);
        if (share_fd) {
            printf("server write to share_fd[%d]\n", share_fd);
            write(share_fd, HEAD, strlen(HEAD));
        }
        printf("receive share_fd=%d\n", share_fd);
        char buf[PATH_MAX];
        while (1) {
            printf("try read from uds client...\n");
            ret = read(new_fd, buf, PATH_MAX);
            if (ret <= 0) {
                printf("closed: %s\n", strerror(errno));
                close(fd);
                close(new_fd);
                unlink(path);
                return -1;
            }
            buf[ret] = '\0';
            if (strncmp(buf, "quit", 4) == 0) {
                printf("receive quit\n");
                break;
            }
            printf("readmsg from client: %s\n", buf);
            write(share_fd, buf, ret);
        }
        close(share_fd);
        close(new_fd);
    }
    close(fd);
}