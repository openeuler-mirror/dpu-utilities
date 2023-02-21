#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/types.h>

#include "uds_module.h"

#define uds_log(info, ...) \
	do { \
		time_t t; \
		struct tm *p; \
		time(&t); \
		p = localtime(&t); \
		printf("[%d/%02d/%02d %02d:%02d:%02d][LOG:%s:%3d]"info"\n", \
				p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
				p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
	} while (0);

#define uds_err(info, ...) \
	do { \
		time_t t; \
		struct tm *p; \
		time(&t); \
		p = localtime(&t); \
		printf("[%d/%02d/%02d %02d:%02d:%02d][LOG:%s:%3d]"info"\n", \
				p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
				p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
	} while (0);

static unsigned short uds_conn_get_sock_type(int sockfd)
{
    unsigned short type;
    int len = 2;
    int ret = getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &len);
    if (ret < 0) {
        uds_err("get sock type failed, fd:%d", sockfd);
        return (unsigned short)-1;
    }
    uds_log("fd:%d type:%d", sockfd, type);
    return type;
}

static int uds_conn_whitelist_check(const char *path)
{
	return 1;
}

int connect(int fd, const struct sockaddr *addrarg, socklen_t len)
{
	int sock_fd;
	typeof(connect) *libcconnect = NULL;
	int libcret;
	const struct sockaddr_un *addr = (const struct sockaddr_un *)addrarg;

	if (libcconnect == NULL) {
		libcconnect = dlsym(((void *) - 1l), "connect");
		if (libcconnect == NULL) {
			uds_err("can't find connect by dlsym.");
			return -1;
		}
	}

	libcret = (*libcconnect)(fd, addrarg, len);
	if (libcret == 0 || addr->sun_family != AF_UNIX) {
        // 如果本地connect成功，或者非UNIX DOMAIN SOCKET，都直接返回即可
		return libcret;
	}

    if (strlen(addr->sun_path) >= (UDS_SUN_PATH_LEN - strlen(UDS_PROXY_SUFFIX))) {
        uds_err("sun_path:<%s> len:%d is too large to add suffex:<%s>, so can't connect to uds proxy.",
                        addr->sun_path, strlen(addr->sun_path), UDS_PROXY_SUFFIX);
        return libcret;
    }

	uds_log("enter uds connect fd:%d sunpath:%s family:%d len:%d connect function:0x%lx", fd, addr->sun_path,
			addr->sun_family, len, libcconnect);
    // 本地未连接，且是uds链接
	if (!uds_conn_whitelist_check(addr->sun_path)) {
		uds_err("path:%s not in white list", addr->sun_path);
		return libcret;
	}

    // 尝试远端链接
	do {
		int ret;
		struct uds_proxy_remote_conn_req remoteconn;
		struct uds_proxy_remote_conn_rsp remotersp;
		struct sockaddr_un proxy = {.sun_family = AF_UNIX};
		sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sock_fd < 0) {
			uds_err("create socket failed");
			return libcret;
		}

		strncpy(proxy.sun_path, UDS_BUILD_CONN_ADDR, sizeof(proxy.sun_path));
		if ((*libcconnect)(sock_fd, (struct sockaddr *)&proxy, sizeof(struct sockaddr_un)) < 0) {
			uds_err("can't connect to uds proxy: %s", UDS_BUILD_CONN_ADDR);
			goto err_end;
		}
        // 这里type需要是第一个入参fd的type
		remoteconn.type = uds_conn_get_sock_type(fd);
        if (remoteconn.type == (unsigned short)-1) {
            remoteconn.type = SOCK_STREAM;
        }
		memset(remoteconn.sun_path, 0, sizeof(remoteconn.sun_path));
		strncpy(remoteconn.sun_path, addr->sun_path, sizeof(remoteconn.sun_path));
		ret = send(sock_fd, &remoteconn, sizeof(remoteconn), 0);
		if (ret <= 0) {
			uds_err("send remote connect request failed, ret:%d err:%s", ret, strerror(errno));
			goto err_end;
		}
		ret = recv(sock_fd, &remotersp, sizeof(remotersp), MSG_WAITALL);
		if (ret <= 0) {
			uds_err("recv remote connect replay failed, ret:%d err:%s", ret, strerror(errno));
			goto err_end;
		}
		if (remotersp.ret == 0) {
			goto err_end;
		}
	} while(0);

	close(sock_fd);

    struct sockaddr_un addr_proxy;
    int sun_len = strlen(addr->sun_path);
    memcpy(&addr_proxy, addr, sizeof(struct sockaddr_un));
    memcpy(&addr_proxy.sun_path[sun_len], UDS_PROXY_SUFFIX, strlen(UDS_PROXY_SUFFIX));
    addr_proxy.sun_path[sun_len + strlen(UDS_PROXY_SUFFIX)] = '\0';
	return (*libcconnect)(fd, addr_proxy, len);

err_end:
	close(sock_fd);
	return libcret;
}
