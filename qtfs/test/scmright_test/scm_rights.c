#include <stdio.h>
# include <sys/socket.h>
# include <sys/ioctl.h>
# include <arpa/inet.h>
# include <netinet/ip.h>
# include <netinet/in.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>
# include <sys/un.h>
# include <netdb.h>
#include <fcntl.h>
#include <errno.h>
int
udsRecvFd(int sock, int fdflags)
{
    int byte = 0;
    struct iovec iov;
    struct msghdr msg;
    int fd = -1;
    ssize_t len;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd))];
    int fdflags_recvmsg = fdflags & O_CLOEXEC ? MSG_CMSG_CLOEXEC : 0;

    if ((fdflags & ~O_CLOEXEC) != 0) {
        errno = EINVAL;
        return -1;
    }

    /* send at least one char */
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &byte;
    iov.iov_len = 4;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    /* Initialize the payload: */
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = cmsg->cmsg_len;

    len = recvmsg(sock, &msg, fdflags_recvmsg);
    if (len < 0)
        return -1;

    cmsg = CMSG_FIRSTHDR(&msg);
    printf("recv msg type:%d SCM_RIGHTS:%d, byte:%d\n", cmsg->cmsg_type, SCM_RIGHTS, byte);
    /* be paranoiac */
    if (len == 0 || cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(fd))
        || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        /* fake errno: at end the file is not available */
        errno = len ? EACCES : ENOTCONN;
        return -1;
    }

    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));

    return fd;
}
int udsSendFd(int sock, int fd)
{
    char byte = 0;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd))];

    /* send at least one char */
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &byte;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    /* Initialize the payload: */
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = cmsg->cmsg_len;

    if (sendmsg(sock, &msg, 0) != iov.iov_len)
        return -1;
    return 0;
}