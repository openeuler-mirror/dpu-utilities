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
#include <pthread.h>
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
#include <dirent.h>
#include <glib.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/file.h>

#include "comm.h"
#include "uds_main.h"
#include "uds_event.h"

char *uds_log_str[UDS_LOG_MAX + 1] = {"NONE", "ERROR", "INFO", "UNKNOWN"};
struct uds_global_var g_uds_var;
struct uds_global_var *p_uds_var = &g_uds_var;
struct uds_event_global_var *g_event_var = NULL;
GHashTable *event_tmout_hash;

struct uds_event *uds_alloc_event()
{
	struct uds_event *p = (struct uds_event *)malloc(sizeof(struct uds_event));
	if (p == NULL) {
		uds_err("malloc failed.");
		return NULL;
	}
	memset(p, 0, sizeof(struct uds_event));
	return p;
}

int uds_event_insert(int efd, struct uds_event *event)
{
	struct epoll_event evt;
	evt.data.ptr = (void *)event;
	evt.events = EPOLLIN;
	if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, event->fd, &evt)) {
		uds_err("epoll ctl add fd:%d event failed.", event->fd);
		return -1;
	}
	return 0;
}

int uds_event_suspend(int efd, struct uds_event *event)
{
	int ret = epoll_ctl(efd, EPOLL_CTL_DEL, event->fd, NULL);
	if (ret != 0) {
		uds_err("failed to suspend fd:%d.", event->fd);
		return -1;
	}
	return 0;
}

int uds_event_delete(int efd, int fd)
{
	close(fd);
	return 0;
}

#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
int uds_event_tmout_item(gpointer key, gpointer value, gpointer data)
{
	struct uds_event *evt = (struct uds_event *)value;
	if (evt->tmout == 0) {
		uds_err("Unexpected time out value in fd:%d", key);
		goto clear;
	}
	evt->tmout--;
	if (evt->tmout > 0)
		return 0;

	uds_log("The connection was not established within 5s, the fd:%d wait was over due to a timeout.", key);
clear:
	close((int)key);
	free(evt);
	return 1;
}
#pragma GCC diagnostic pop

void uds_event_timeout_proc()
{
	g_hash_table_foreach_remove(event_tmout_hash, uds_event_tmout_item, NULL);
}

void uds_main_loop(int efd, struct uds_thread_arg *arg)
{
	int n = 0;
	int ret;
	struct uds_event *udsevt;
	struct epoll_event *evts = NULL;
	struct uds_event_global_var *p_event_var = arg->p_event_var;
	if (p_event_var == NULL) {
		uds_err("event variable invalid.");
		return;
	}

	evts = calloc(UDS_EPOLL_MAX_EVENTS, sizeof(struct epoll_event));
	if (evts == NULL) {
		uds_err("init calloc evts failed.");
		return;
	}
	if (uds_event_module_init(p_event_var) == EVENT_ERR) {
		uds_err("uds event module init failed, main loop not run.");
		free(evts);
		return;
	}
#ifdef QTFS_SERVER
	extern int engine_run;
	while (engine_run) {
#else
	while (1) {
#endif
		n = epoll_wait(efd, evts, UDS_EPOLL_MAX_EVENTS, 1000);
		if (n == 0) {
			uds_event_timeout_proc();
			continue;
		}
		if (n < 0) {
			uds_err("epoll wait return errcode:%d", n);
			continue;
		}
		arg->info.events += n;
		uds_event_pre_hook(p_event_var);
		for (int i = 0; i < n; i++) {
			udsevt = (struct uds_event *)evts[i].data.ptr;
			uds_log("event fd:%d events:%d tofree:%d", udsevt->fd, evts[i].events, udsevt->tofree);
			if (udsevt->handler == NULL) {
				uds_err("bad event, fd:%d handler is NULL.", udsevt->fd);
				continue;
			}
			// 预检查失败择不执行handler
			if (uds_event_pre_handler(udsevt) == EVENT_ERR) {
				continue;
			}
			ret = udsevt->handler(udsevt, efd, p_event_var);
			// 此处释放当前事件，peer事件需要handler里面释放
			if (ret == EVENT_DEL) {
				uds_del_event(udsevt);
			}
		}
		uds_event_post_hook(p_event_var);
	}
	free(evts);
	uds_log("main loop exit.");
	uds_event_module_fini(p_event_var);
	return;
}

#define UDS_MAX_LISTEN_NUM 64
int uds_build_tcp_connection(struct uds_conn_arg *arg)
{
	if (arg->cs > UDS_SOCKET_SERVER) {
		uds_err("cs type %d is error.", arg->cs);
		return -1;
	}
	struct sockaddr_in sock_addr = {
		.sin_family = AF_INET,
	};
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (sock_fd < 0) {
		uds_err("As %s failed, socket fd: %d, errno:%d.",
				(arg->cs == UDS_SOCKET_CLIENT) ? "client" : "server",
				sock_fd, errno);
		return -1;
	}
	arg->sockfd = sock_fd;

	if (arg->cs == UDS_SOCKET_SERVER) {
		sock_addr.sin_port = htons(p_uds_var->tcp.port);
		sock_addr.sin_addr.s_addr = inet_addr(p_uds_var->tcp.addr);
		if (bind(sock_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
			uds_err("As tcp server failed, bind error, errno:%d.",
					errno);
			goto close_and_return;
		}
		if (listen(sock_fd, UDS_MAX_LISTEN_NUM) < 0) {
			uds_err("As tcp server listen failed, errno:%d.", errno);
			goto close_and_return;
		}
	} else {
		sock_addr.sin_port = htons(p_uds_var->tcp.peerport);
		sock_addr.sin_addr.s_addr = inet_addr(p_uds_var->tcp.peeraddr);
		if (connect(arg->sockfd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_in)) < 0) {
			goto close_and_return;
		}
		arg->connfd = sock_fd;
		uds_log("Connect to tcp server successed, ip:%s port:%u", p_uds_var->tcp.peeraddr, p_uds_var->tcp.peerport);
	}

	return 0;
close_and_return:
	close(sock_fd);
	return -1;
}

int uds_build_unix_connection(struct uds_conn_arg *arg)
{
	if (arg->cs > UDS_SOCKET_SERVER) {
		uds_err("cs type %d is error.", arg->cs);
		return -1;
	}
	struct sockaddr_un sock_addr = {
		.sun_family = AF_UNIX,
	};
	int sock_fd = socket(AF_UNIX, arg->udstype, 0);

	if (sock_fd < 0) {
		uds_err("As %s failed, socket fd: %d, errno:%d.",
				(arg->cs == UDS_SOCKET_CLIENT) ? "client" : "server",
				sock_fd, errno);
		return -1;
	}
	strncpy(sock_addr.sun_path, arg->sun_path, sizeof(sock_addr.sun_path));
	arg->sockfd = sock_fd;

	if (arg->cs == UDS_SOCKET_SERVER) {
		unlink(sock_addr.sun_path);
		if (bind(sock_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
			uds_err("As uds server failed, bind error, errno:%d.",
					errno);
			goto close_and_return;
		}
		if (listen(sock_fd, UDS_MAX_LISTEN_NUM) < 0) {
			uds_err("As uds server listen failed, errno:%d.", errno);
			goto close_and_return;
		}
	} else {
		if (connect(arg->sockfd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) < 0) {
			goto close_and_return;
		}
		arg->connfd = sock_fd;
		uds_log("Connect to uds server successed, sun path:%s", arg->sun_path);
	}

	return 0;
close_and_return:
	uds_log("close sockfd:%d and return", sock_fd);
	close(sock_fd);
	return -1;

}

int uds_sock_step_accept(int sock_fd, int family)
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
		uds_err("Accept error:%d, errno:%d.", connfd, errno);
		return connfd;
	}
	if (family == AF_INET) {
		uds_log("Accept success, ip:%s, port:%u",
				inet_ntoa(in_addr.sin_addr),
				ntohs(in_addr.sin_port));
	} else {
		uds_log("Accept success, sun path:%s", un_addr.sun_path);
	}
	return connfd;
}

struct uds_event *uds_add_event(int fd, struct uds_event *peer, int (*handler)(void *, int, struct uds_event_global_var *), void *priv)
{
	struct uds_event *newevt = uds_alloc_event();
	int hash = fd % p_uds_var->work_thread_num;
	if (newevt == NULL || p_uds_var->efd[hash] <= 0) {
		uds_err("alloc event failed, efd:%d hash:%d", p_uds_var->efd[hash], hash);
		return NULL;
	}

	newevt->fd = fd;
	newevt->peer = peer; // 如果tcp回应，消息转回uds这个fd
	newevt->handler = handler;
	newevt->priv = priv;
	newevt->tofree = 0;
	newevt->tmout = 0;
	if (uds_event_insert(p_uds_var->efd[hash], newevt) != 0) {
		uds_del_event(newevt);
		return NULL;
	}
	return newevt;
}

struct uds_event *uds_add_pipe_event(int fd, int peerfd, int (*handler)(void *, int, struct uds_event_global_var *), void *priv)
{
	int hash = fd % p_uds_var->work_thread_num;
	struct uds_event *newevt = uds_alloc_event();
	if (newevt == NULL || p_uds_var->efd[hash] <= 0) {
		uds_err("alloc event failed, efd:%d", p_uds_var->efd[hash]);
		return NULL;
	}

	newevt->fd = fd;
	newevt->peerfd = peerfd; // 如果tcp回应，消息转回uds这个fd
	newevt->handler = handler;
	newevt->priv = priv;
	newevt->tofree = 0;
	newevt->pipe = 1;
	newevt->tmout = 0;
	if (uds_event_insert(p_uds_var->efd[hash], newevt) != 0) {
		uds_del_event(newevt);
		return NULL;
	}
	return newevt;
}

void uds_del_event(struct uds_event *evt)
{
	int hash = evt->fd % p_uds_var->work_thread_num;
	if (evt->pipe == 1 && evt->peerfd != -1) {
		// pipe是单向，peerfd没有epoll事件，所以直接关闭
		close(evt->peerfd);
		evt->peerfd = -1;
	}
	uds_event_delete(p_uds_var->efd[hash], evt->fd);
	free(evt);
	evt = NULL;
	return;
}

void uds_thread_diag_init(struct uds_thread_info *info)
{
	info->events = 0;
	info->fdnum = 0;
}

void *uds_proxy_thread(void *arg)
{
	struct uds_thread_arg *parg = (struct uds_thread_arg *)arg;
	// set thread name to "udsproxyd"
	prctl(PR_SET_NAME, (unsigned long)"udsproxyd");
	uds_thread_diag_init(&parg->info);
	uds_main_loop(parg->efd, parg);
	return NULL;
}

struct uds_event *uds_init_unix_listener(const char *addr, int (*handler)(void *, int, struct uds_event_global_var *))
{
	struct uds_event *udsevt;
	struct uds_conn_arg arg;
	struct uds_conn_arg *parg = &arg;

	parg->cs = UDS_SOCKET_SERVER;
	strncpy(parg->sun_path, addr, sizeof(parg->sun_path));
	parg->udstype = SOCK_STREAM;
	if (uds_build_unix_connection(parg) != 0)
		return NULL;
	udsevt = uds_add_event(parg->sockfd, NULL, handler, NULL);
	if (udsevt == NULL) {
		uds_err("add unix listener event failed.");
		return NULL;
	}
	return udsevt;
}

struct uds_event *uds_init_tcp_listener()
{
	struct uds_event *tcpevt;
	struct uds_conn_arg arg;
	struct uds_conn_arg *parg = &arg;
	parg->cs = UDS_SOCKET_SERVER;
	if (uds_build_tcp_connection(parg) != 0)
		return NULL;

	tcpevt = uds_add_event(parg->sockfd, NULL, uds_event_tcp_listener, NULL);
	if (tcpevt == NULL)
		return NULL;
	return tcpevt;
}

static inline void uds_rollback_efd(int *efd, int maxidx)
{
	for (int i = 0; i < maxidx; i++) {
		close(efd[i]);
	}
	return;
}

static int uds_thread_execute()
{
	pthread_t *thrd = (pthread_t *)malloc(sizeof(pthread_t) * p_uds_var->work_thread_num);
	if (thrd == NULL) {
		uds_err("thread info malloc failed.");
		return -1;
	}

	for (int i = 0; i < p_uds_var->work_thread_num; i++) {
		p_uds_var->work_thread[i].p_event_var = &g_event_var[i];
		p_uds_var->work_thread[i].efd = p_uds_var->efd[i];
		(void)pthread_create(&thrd[i], NULL, uds_proxy_thread, &p_uds_var->work_thread[i]);
	}
	p_uds_var->loglevel = UDS_LOG_NONE;
	for (int i = 0; i < p_uds_var->work_thread_num; i++)
		pthread_join(thrd[i], NULL);
	free(thrd);
	return 0;
}

void uds_thread_create()
{
	struct uds_conn_arg arg;
	struct uds_conn_arg *parg = &arg;
	struct uds_event *udsevt;
	struct uds_event *tcpevt;
	struct uds_event *diagevt;
	struct uds_event *logevt;
	int efd;
	int ret;

	for (int i = 0; i < p_uds_var->work_thread_num; i++) {
		efd = epoll_create1(0);
		if (efd == -1) {
			uds_rollback_efd(p_uds_var->efd, i);
			uds_err("epoll create1 failed, i:%d.", i);
			return;
		}
		p_uds_var->efd[i] = efd;
	}

	if ((udsevt = uds_init_unix_listener(UDS_BUILD_CONN_ADDR, uds_event_uds_listener)) == NULL)
		goto rollbackefd;

	if ((tcpevt = uds_init_tcp_listener()) == NULL)
		goto end;

	if ((diagevt = uds_init_unix_listener(UDS_DIAG_ADDR, uds_event_diag_info)) == NULL)
		goto end1;

	if ((logevt = uds_init_unix_listener(UDS_LOGLEVEL_UPD, uds_event_debug_level)) == NULL)
		goto end2;

	ret = uds_thread_execute();
	if (ret < 0) {
		uds_err("uds create thread failed.");
	}
	uds_del_event(logevt);
end2: 
	uds_del_event(diagevt);
end1:
	uds_del_event(tcpevt);
end:
	uds_del_event(udsevt);
rollbackefd:
	for (int i = 0; i < p_uds_var->work_thread_num; i++)
		close(p_uds_var->efd[i]);

	return;
}

int uds_env_prepare()
{
	DIR *dir;
	if (access(UDS_BUILD_CONN_ADDR, 0) == 0)
		return EVENT_OK;

	if ((dir = opendir(UDS_BUILD_CONN_DIR)) == NULL) {
		if (mkdir(UDS_BUILD_CONN_DIR, 0600) < 0) {
			uds_err("mkdir %s failed.", UDS_BUILD_CONN_DIR);
		}
	} else {
		closedir(dir);
	}
	return EVENT_OK;
}

int uds_hash_init()
{
	event_tmout_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (event_tmout_hash == NULL) {
		uds_err("g_hash_table_new failed.");
		return EVENT_ERR;
	}
	uds_log("init event time out hash");
	return EVENT_OK;
}

void uds_hash_destroy()
{
	g_hash_table_destroy(event_tmout_hash);
	event_tmout_hash = NULL;
	return;
}

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
int uds_hash_insert_dirct(GHashTable *table, int key, struct uds_event *value)
{
	if (g_hash_table_insert(table, (gpointer)key, value) == 0) {
		uds_err("Hash table key:%d value:0x%lx is already exist, update it.", key, value);
		return -1;
	}
	uds_log("Hash insert key:%d value:0x%lx", key, value);
	return 0;
}

void *uds_hash_lookup_dirct(GHashTable *table, int key)
{
	return (void *)g_hash_table_lookup(table, (gpointer)key);
}

int uds_hash_remove_dirct(GHashTable *table, int key)
{
	if (g_hash_table_remove(table, (gpointer)key) == 0) {
		uds_err("Remove key:%d from hash failed.", key);
		return -1;
	}
	return 0;
}
#pragma GCC diagnostic pop

static void uds_rlimit()
{
	struct rlimit lim;

	getrlimit(RLIMIT_NOFILE, &lim);
	uds_log("uds proxy fd cur limit:%d, change to:%d", lim.rlim_cur, UDS_FD_LIMIT);
	lim.rlim_cur = UDS_FD_LIMIT;
	setrlimit(RLIMIT_NOFILE, &lim);
	return;
}

// port invalid range 1024~65536
#define UDS_PORT_VALID(port) (port >= 1024 && port < 65536)
static int uds_glob_var_init(char *argv[])
{
	int myport = atoi(argv[3]);
	int peerport = atoi(argv[5]);
	memset(p_uds_var, 0, sizeof(struct uds_global_var));
	p_uds_var->logstr = uds_log_str;
	p_uds_var->work_thread_num = atoi(argv[1]);
	if (p_uds_var->work_thread_num <= 0 || p_uds_var->work_thread_num > UDS_WORK_THREAD_MAX) {
		uds_err("work thread num:%d is invalid.(must be 1~%d)", p_uds_var->work_thread_num, UDS_WORK_THREAD_MAX);
		return -1;
	}
	if (!UDS_PORT_VALID(myport) || !UDS_PORT_VALID(peerport)) {
		uds_err("local port:%d or peer port:%d invalid.(must be 1024~65535)", myport, peerport);
		return -1;
	}
	p_uds_var->efd = (int *)malloc(sizeof(int) * p_uds_var->work_thread_num);
	if (p_uds_var->efd == NULL) {
		uds_err("efd malloc failed, num:%d", p_uds_var->work_thread_num);
		return -1;
	}

	p_uds_var->work_thread = (struct uds_thread_arg *)malloc(sizeof(struct uds_thread_arg) * p_uds_var->work_thread_num);
	if (p_uds_var->work_thread == NULL) {
		uds_err("work thread var malloc failed.");
		return -1;
	}
	p_uds_var->tcp.port = atoi(argv[3]);
	strncpy(p_uds_var->tcp.addr, argv[2], sizeof(p_uds_var->tcp.addr) - 1);
	p_uds_var->tcp.peerport = atoi(argv[5]);
	strncpy(p_uds_var->tcp.peeraddr, argv[4], sizeof(p_uds_var->tcp.addr));

	uds_log("uds proxy param thread num:%d ip:%s port:%u peerip:%s port:%u",
			p_uds_var->work_thread_num, p_uds_var->tcp.addr, p_uds_var->tcp.port,
			 p_uds_var->tcp.peeraddr, p_uds_var->tcp.peerport);
	g_event_var = (struct uds_event_global_var *)malloc(sizeof(struct uds_event_global_var) * p_uds_var->work_thread_num);
	if (g_event_var == NULL) {
		uds_err("event variable malloc failed");
		return -1;
	}
	return 0;
}

static void uds_sig_pipe(int signum)
{
	return;
}

void uds_helpinfo(char *argv[])
{
	uds_err("Usage:");
	uds_err("	%s <thread nums> <addr> <port> <peeraddr> <peerport>.", argv[0]);
	uds_err("Param:");
	uds_err("  <thread nums> - numbers of work thread(currently only supports 1 thread)");
	uds_err("  <addr> - server ip address");
	uds_err("  <port> - port number");
	uds_err("  <peeraddr> - peer address");
	uds_err("  <peerport> - peer port");
	return;
}

int check_socket_lock(void)
{
	int lock_fd = open(UDS_LOCK_ADDR, O_RDONLY | O_CREAT, 0600);
	if (lock_fd == -1)
		return -EINVAL;

	return flock(lock_fd, LOCK_EX | LOCK_NB);
}

#ifdef QTFS_SERVER
int uds_proxy_main(int argc, char *argv[])
{
#else
int main(int argc, char *argv[])
{
	mode_t newmask = 0077;
	uds_log("change uds umask from:%o to %o", umask(newmask), newmask);
#endif
	p_uds_var->loglevel = UDS_LOG_INFO;
#define ARG_NUM 6
	if (argc != ARG_NUM) {
		uds_helpinfo(argv);
		return -1;
	}
	if (uds_env_prepare() != EVENT_OK) {
		uds_err("proxy prepare environment failed.");
		return -1;
	}

	if (check_socket_lock() < 0) {
		uds_err("another proxy running");
		return -1;
	}

	if (uds_hash_init() != EVENT_OK) {
		uds_err("proxy hash init failed.");
		return -1;
	}
	uds_rlimit();
	signal(SIGPIPE, uds_sig_pipe);
	if (uds_glob_var_init(argv) < 0) {
		uds_err("global var init failed.");
		uds_hash_destroy();
		return -1;
	}
	uds_thread_create();
	uds_hash_destroy();

	return 0;
}
