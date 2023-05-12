/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * qtfs licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Liqiang
 * Create: 2023-03-20
 * Description: 
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "rexec.h"
#include "rexec_sock.h"

int rexec_build_unix_connection(struct rexec_conn_arg *arg)
{
	const int sock_max_conn = 5;
	if (arg->cs > REXEC_SOCK_SERVER) {
		rexec_err("cs type %d is error.", arg->cs);
		return -1;
	}
	struct sockaddr_un sock_addr = {
		.sun_family = AF_UNIX,
	};
	int sock_fd = socket(AF_UNIX, arg->udstype, 0);

	if (sock_fd < 0) {
		rexec_err("As %s failed, socket fd: %d, errno:%d.",
				(arg->cs == REXEC_SOCK_CLIENT) ? "client" : "server",
				sock_fd, errno);
		return -1;
	}
	strncpy(sock_addr.sun_path, arg->sun_path, sizeof(sock_addr.sun_path));
	arg->sockfd = sock_fd;

	if (arg->cs == REXEC_SOCK_SERVER) {
		unlink(sock_addr.sun_path);
		if (bind(sock_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
			rexec_err("As server failed, bind error, errno:%d.",
					errno);
			goto close_and_return;
		}
		if (listen(sock_fd, sock_max_conn) < 0) {
			rexec_err("As server listen failed, errno:%d.", errno);
			goto close_and_return;
		}
	} else {
		if (connect(arg->sockfd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) < 0) {
			goto close_and_return;
		}
		arg->connfd = sock_fd;
		rexec_log("Connect to server successed, sun path:%s", arg->sun_path);
	}

	return 0;
close_and_return:
	rexec_log("close sockfd:%d and return", sock_fd);
	close(sock_fd);
	return -1;

}

int rexec_sock_step_accept(int sock_fd, int family)
{
	struct sockaddr_in in_addr;
	struct sockaddr_un un_addr;
	socklen_t len = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_un);
	int connfd;
	if (family == AF_INET) {
		connfd = accept(sock_fd, (struct sockaddr *)&in_addr, &len);
	} else {
		connfd = accept(sock_fd, (struct sockaddr *)&un_addr, &len);
	}
	if (connfd < 0) {
		rexec_err("Accept error:%d, errno:%d.", connfd, errno);
		return connfd;
	}
	if (family == AF_INET) {
		rexec_log("Accept success, ip:%s, port:%u",
				inet_ntoa(in_addr.sin_addr),
				ntohs(in_addr.sin_port));
	} else {
		rexec_log("Accept success, sun path:%s", un_addr.sun_path);
	}
	return connfd;
}

// send a normal msg
// or a SCM_RIGHTS fd
// or a normal msg and a SCM_RIGHTS fd
int rexec_sendmsg(int sockfd, char *msgbuf, int msglen, int scmfd)
{
    struct msghdr msg;
    struct cmsghdr *cmsg = NULL;
    struct iovec iov;
    char buf[CMSG_SPACE(sizeof(scmfd))];
    int ret;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *)msgbuf;
    iov.iov_len = msglen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    if (scmfd > 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(scmfd));
        /* Initialize the payload: */
        memcpy(CMSG_DATA(cmsg), &scmfd, sizeof(scmfd));
        msg.msg_controllen = cmsg->cmsg_len;
    } else {
        msg.msg_controllen = 0;
    }
    if ((ret = sendmsg(sockfd, &msg, 0)) != iov.iov_len) {
        return ret;
    }
    return ret;
}

int rexec_recvmsg(int sockfd, char *msgbuf, int len, int *scmfd, int flags)
{
    struct iovec iov;
    struct msghdr msg;
    int fd = -1;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd))];

    /* send at least one char */
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = msgbuf;
    iov.iov_len = len;
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

    int ret = recvmsg(sockfd, &msg, flags);
    if (ret < 0)
        return ret;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg != NULL) {
        memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
        *scmfd = fd;
    }
    return ret;
}


