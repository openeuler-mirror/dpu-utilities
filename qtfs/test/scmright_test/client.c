#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <string.h>
#include "uds.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s pathtosock [pathtofile]\n", argv[0]);
        return -EINVAL;
    }
    char *path = argv[1];
    char *testfile = NULL;
    if (argc == 3) {
        testfile = argv[2];
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("Fail to create socket: %s\n", strerror(errno));
        return -1;
    }
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, strlen(path) + 1);
    printf("connect to %s\n", addr.sun_path);
    int ret = connect(fd, (struct sockaddr*)(&addr), sizeof(addr));
    if (ret < 0) {
        printf("Fail to connect: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    unlink(testfile);
    int share_fd;
    int pipefd[2];
    char buffer[1024];
    if (testfile == NULL) {
        printf("Into PIPE MODE: open pipe\n");
        if (pipe(pipefd) == -1) {
            fprintf(stderr, "Pipe failed\n");
            return -1;
        }
        share_fd = pipefd[1];
    } else {
        printf("Into REGULAR FILE MODE: open file %s\n", testfile);
        share_fd = open(testfile, O_RDWR | O_CREAT);
    }

    if (share_fd < 0) {
        printf("open failed, %s\n", strerror(errno));
        return -1;
    }
    printf("send share_fd[%d] to peer\n", share_fd);
    udsSendFd(fd, share_fd);
    char data[PATH_MAX];
    while (true) {
        printf("Input message to send: ");
        gets(data);
        if (strncmp(data,"quit",4) == 0) {
            break;
        }
        ret = write(fd, data, strlen(data));
        if (ret < 0) {
            printf("Fail to write,%s\n", strerror(errno));
        }
        if(testfile == NULL && read(pipefd[0], buffer, sizeof(buffer))) {
            printf("read from pipe: %s\n", buffer);
        }

    }
    close(fd);
    return 0;
}