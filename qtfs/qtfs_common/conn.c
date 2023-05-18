/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/un.h>
#include <linux/file.h>

#include "comm.h"
#include "conn.h"
#include "log.h"
#include "req.h"
#include "symbol_wrapper.h"
#include "uds_module.h"

struct qtfs_pvar_ops_s *g_pvar_ops = NULL;
char qtfs_log_level[QTFS_LOGLEVEL_STRLEN] = {0};
char qtfs_conn_type[20] = QTFS_CONN_SOCK_TYPE;
int log_level = LOG_ERROR;
int qtfs_conn_max_conn = QTFS_MAX_THREADS;
struct qtinfo *qtfs_diag_info = NULL;
bool qtfs_epoll_mode = false; // true: support any mode; false: only support fifo

static atomic_t g_qtfs_conn_num;
static struct list_head g_vld_lst;
static struct list_head g_busy_lst;
static struct llist_head g_lazy_put_llst;
static struct mutex g_param_mutex;
int qtfs_mod_exiting = false;
struct qtfs_conn_var_s *qtfs_thread_var[QTFS_MAX_THREADS] = {NULL};
struct qtfs_conn_var_s *qtfs_epoll_var = NULL;
#ifdef QTFS_SERVER
struct qtfs_server_userp_s *qtfs_userps = NULL;
#endif
struct qtsock_wl_stru qtsock_wl;

// try to connect remote uds server, only for unix domain socket
#define QTFS_UDS_PROXY_SUFFIX ".proxy"
int qtfs_uds_proxy_build(struct socket *sock, struct sockaddr_un *addr, int len)
{
	int ret;
	struct uds_proxy_remote_conn_req req;
	struct uds_proxy_remote_conn_rsp rsp;
	struct sockaddr_un proxy = {.sun_family = AF_UNIX};
	struct socket *proxy_sock;
	struct msghdr msgs;
	struct msghdr msgr;
	struct kvec vec;

	ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &proxy_sock);
	if (ret) {
		qtfs_err("create proxy sock failed sun path:%s", addr->sun_path);
		return -EFAULT;
	}
	memset(proxy.sun_path, 0, sizeof(proxy.sun_path));
	strncpy(proxy.sun_path, UDS_BUILD_CONN_ADDR, strlen(UDS_BUILD_CONN_ADDR) + 1);
	ret = sock->ops->connect(proxy_sock, (struct sockaddr *)&proxy, sizeof(proxy), SOCK_NONBLOCK);
	if (ret) {
		qtfs_err("connect to uds proxy failed");
		goto err_end;
	}
	memset(req.sun_path, 0, sizeof(req.sun_path));
	strncpy(req.sun_path, addr->sun_path, sizeof(req.sun_path));
	memset(&msgs, 0, sizeof(struct msghdr));
	memset(&msgr, 0, sizeof(struct msghdr));
	req.type = sock->sk->sk_type;
	vec.iov_base = &req;
	vec.iov_len = sizeof(req);
	ret = kernel_sendmsg(proxy_sock, &msgs, &vec, 1, vec.iov_len);
	if (ret < 0) {
		qtfs_err("send remote connect request failed:%d", ret);
		goto err_end;
	}
	vec.iov_base = &rsp;
	vec.iov_len = sizeof(rsp);
	ret = kernel_recvmsg(proxy_sock, &msgr, &vec, 1, vec.iov_len, MSG_WAITALL);
	if (ret <= 0) {
		qtfs_err("recv remote connect response failed:%d", ret);
		goto err_end;
	}
	if (rsp.ret == 0) {
		goto err_end;
	}
	qtfs_info("try to build uds proxy successed, sun path:%s", addr->sun_path);

	sock_release(proxy_sock);
	return 0;
err_end:
	sock_release(proxy_sock);
	return -ECONNREFUSED;
}

static int qtfs_uds_remote_whitelist(const char *path)
{
	int i;
	int ret = 1;
	read_lock(&qtsock_wl.rwlock);
	for (i = 0; i < qtsock_wl.nums; i++) {
		if (strncmp(path, qtsock_wl.wl[i], strlen(qtsock_wl.wl[i])) == 0) {
			ret = 0;
			break;
		}
	}
	read_unlock(&qtsock_wl.rwlock);
	return ret;
}

static inline int qtfs_uds_is_proxy(void)
{
#define UDS_PROXYD_PRNAME "udsproxyd"
	if (strlen(current->comm) == strlen(UDS_PROXYD_PRNAME) &&
			strncmp(current->comm, UDS_PROXYD_PRNAME, strlen(UDS_PROXYD_PRNAME)) == 0)
		return 1;
	return 0;
}

int qtfs_uds_remote_connect_user(int fd, struct sockaddr __user *addr, int len)
{
	int sysret;
	int ret;
	int err;
	int slen;
	int un_headlen;
	struct fd f;
	struct socket *sock;
	struct sockaddr_un addr_un;
	struct sockaddr_un addr_proxy;

	sysret = qtfs_syscall_connect(fd, addr, len);
	// don't try remote uds connect if: 1.local connect successed; 2.this process is udsproxyd
	if (sysret == 0 || qtfs_uds_is_proxy())
		return sysret;
	// len is passed from syscall input args directly. it's trustworthy
	if (copy_from_user(&addr_un, addr, len)) {
		qtfs_err("copy sockaddr failed.");
		return sysret;
	}
	// don't try remote uds connect if sunpath not in whitelist
	if (qtfs_uds_remote_whitelist(addr_un.sun_path) != 0)
		return sysret;
	if (addr_un.sun_family != AF_UNIX)
		return sysret;
	un_headlen = sizeof(struct sockaddr_un) - sizeof(addr_un.sun_path);
	// 如果用户态给的参数长度不够，这里智能失败退出
	if (len < un_headlen || strlen(addr_un.sun_path) >= (len - un_headlen - strlen(QTFS_UDS_PROXY_SUFFIX))) {
		qtfs_err("failed to try connect remote uds server, sun path:%s too long to add suffix:%s",
				addr_un.sun_path, QTFS_UDS_PROXY_SUFFIX);
		return sysret;
	}
	qtfs_info("uds connect failed:%d try to remote connect:%s.", sysret, addr_un.sun_path);

	f = fdget(fd);
	if (f.file == NULL) {
		return -EBADF;
	}

	sock = sock_from_file(f.file, &err);
	if (!sock) {
		goto end;
	}
	// try to connect remote uds's proxy
	ret = qtfs_uds_proxy_build(sock, &addr_un, len);
	if (ret == 0) {
		memcpy(&addr_proxy, &addr_un, sizeof(struct sockaddr_un));
		slen = strlen(addr_proxy.sun_path);
		strncat(addr_proxy.sun_path, QTFS_UDS_PROXY_SUFFIX,sizeof(addr_proxy.sun_path) - strlen(addr_proxy.sun_path));
		addr_proxy.sun_path[slen + strlen(QTFS_UDS_PROXY_SUFFIX)] = '\0';
		if (copy_to_user(addr, &addr_proxy, (len > sizeof(struct sockaddr_un)) ? sizeof(struct sockaddr_un) : len)) {
			qtfs_err("copy to addr failed sunpath:%s", addr_proxy.sun_path);
			goto end;
		}
		sysret = qtfs_syscall_connect(fd, addr, len);
		qtfs_info("try remote connect sunpath:%s ret:%d", addr_un.sun_path, sysret);
		if (copy_to_user(addr, &addr_un, (len > sizeof(struct sockaddr_un)) ? sizeof(struct sockaddr_un) : len)) {
			qtfs_err("resume addr failed");
			goto end;
		}
	}

end:
	fdput(f);
	return sysret;
}

int qtfs_uds_remote_init(void)
{
	qtsock_wl.nums = 0;
	qtsock_wl.wl = (char **)kmalloc(sizeof(char *) * QTSOCK_WL_MAX_NUM, GFP_KERNEL);
	if (qtsock_wl.wl == NULL) {
		qtfs_err("failed to kmalloc wl, max num:%d", QTSOCK_WL_MAX_NUM);
		return -1;
	}
	rwlock_init(&qtsock_wl.rwlock);
	return 0;
}

void qtfs_uds_remote_exit(void)
{
	read_lock(&qtsock_wl.rwlock);
	if (qtsock_wl.wl) {
		kfree(qtsock_wl.wl);
		qtsock_wl.wl = NULL;
	}
	qtsock_wl.nums = 0;
	read_unlock(&qtsock_wl.rwlock);
	return;
}

int qtfs_conn_init(struct qtfs_conn_var_s *pvar)
{
	return pvar->conn_ops->conn_init(pvar);
}

void qtfs_conn_fini(struct qtfs_conn_var_s *pvar)
{
	return pvar->conn_ops->conn_fini(pvar);
}

int qtfs_conn_send(struct qtfs_conn_var_s *pvar)
{
	if (pvar->vec_send.iov_len > QTFS_MSG_LEN)
		return -EMSGSIZE;
	pvar->send_valid = pvar->vec_send.iov_len;
	return pvar->conn_ops->conn_send(pvar);
}

int do_qtfs_conn_recv(struct qtfs_conn_var_s *pvar, bool block)
{
	int ret = pvar->conn_ops->conn_recv(pvar, block);
	if (ret > 0) {
		pvar->recv_valid = ret;
	}
	return ret;
}

int qtfs_conn_recv_block(struct qtfs_conn_var_s *pvar)
{
	return do_qtfs_conn_recv(pvar, true);
}

int qtfs_conn_recv(struct qtfs_conn_var_s *pvar)
{
	int ret = do_qtfs_conn_recv(pvar, false);
	if (ret <= 0)
		msleep(1);

	return ret;
}

int qtfs_conn_var_init(struct qtfs_conn_var_s *pvar)
{
	pvar->vec_recv.iov_base = kmalloc(QTFS_MSG_LEN, GFP_KERNEL);
	if (pvar->vec_recv.iov_base == NULL) {
		qtfs_err("qtfs recv kmalloc failed, len:%lu.\n", QTFS_MSG_LEN);
		return QTFS_ERR;
	}
	pvar->vec_send.iov_base = kmalloc(QTFS_MSG_LEN, GFP_KERNEL);
	if (pvar->vec_send.iov_base == NULL) {
		qtfs_err("qtfs send kmalloc failed, len:%lu.\n", QTFS_MSG_LEN);
		kfree(pvar->vec_recv.iov_base);
		pvar->vec_recv.iov_base = NULL;
		return QTFS_ERR;
	}
	pvar->vec_recv.iov_len = QTFS_MSG_LEN;
	pvar->vec_send.iov_len = 0;
	memset(pvar->vec_recv.iov_base, 0, QTFS_MSG_LEN);
	memset(pvar->vec_send.iov_base, 0, QTFS_MSG_LEN);
	pvar->recv_valid = 0;
	pvar->send_valid = 0;
	INIT_LIST_HEAD(&pvar->lst);
	return QTFS_OK;
}

void qtfs_conn_var_fini(struct qtfs_conn_var_s *pvar)
{
	if (pvar->vec_recv.iov_base != NULL) {
		kfree(pvar->vec_recv.iov_base);
		pvar->vec_recv.iov_base = NULL;
	}
	if (pvar->vec_send.iov_base != NULL) {
		kfree(pvar->vec_send.iov_base);
		pvar->vec_send.iov_base = NULL;
	}

	return;
}

void qtfs_conn_msg_clear(struct qtfs_conn_var_s *pvar)
{
	memset(pvar->vec_recv.iov_base, 0, pvar->recv_valid);
	memset(pvar->vec_send.iov_base, 0, pvar->send_valid);
	pvar->recv_valid = 0;
	pvar->send_valid = 0;
#ifdef QTFS_CLIENT
	memset(pvar->who_using, 0, QTFS_FUNCTION_LEN);
#endif
	return;
}

void *qtfs_conn_msg_buf(struct qtfs_conn_var_s *pvar, int dir)
{
	struct qtreq *req = (dir == QTFS_SEND) ? pvar->vec_send.iov_base : pvar->vec_recv.iov_base;
	if (!req) {
		WARN_ON(1);
		return NULL;
	}
	return req->data;
}

// state machine
#define QTCONN_CUR_STATE(pvar) ((pvar->state == QTCONN_INIT) ? "INIT" : \
		((pvar->state == QTCONN_CONNECTING) ? "CONNECTING" : \
		((pvar->state == QTCONN_ACTIVE) ? "ACTIVE" : "UNKNOWN")))

static int qtfs_sm_connecting(struct qtfs_conn_var_s *pvar)
{
	int ret = QTERROR;

#ifdef QTFS_SERVER
	ret = pvar->conn_ops->conn_server_accept(pvar);
	if (ret == 0) {
		qtfs_info("qtfs sm connecting accept a new connection");
	} else {
		msleep(500);
	}
#endif
#ifdef QTFS_CLIENT
	int retry;
	qtfs_info("qtfs sm connecting wait for server thread:%d", pvar->cur_threadidx);
	retry = 3;
	while (qtfs_mod_exiting == false && retry-- > 0) {
		ret = pvar->conn_ops->conn_client_connect(pvar);
		if (ret == 0) {
			qtfs_info("qtfs sm connecting connect to a new connection.");
			break;
		}
		msleep(1);
	}
#endif

	return ret;
}

int qtfs_sm_active(struct qtfs_conn_var_s *pvar)
{
	int ret = 0;

	switch (pvar->state) {
		case QTCONN_ACTIVE:
			// do nothing
			break;
		case QTCONN_INIT:
			ret = qtfs_conn_init(pvar);
			if (ret) {
				qtfs_err("qtfs sm active init failed, ret:%d.", ret);
				break;
			}
			// dont break, just enter connecting state to process
			pvar->state = QTCONN_CONNECTING;
			qtfs_info("qtfs sm active connecting, threadidx:%d",
							pvar->cur_threadidx);
			// fall-through

		case QTCONN_CONNECTING:
			// accept(server) or connect(client)
			ret = qtfs_sm_connecting(pvar);
			if (ret == 0)
				pvar->state = QTCONN_ACTIVE;
			break;
		default:
			qtfs_err("qtfs sm active unknown state:%s.", QTCONN_CUR_STATE(pvar));
			ret = -EINVAL;
			break;
	}
	return ret;
}

int qtfs_sm_reconnect(struct qtfs_conn_var_s *pvar)
{
	int ret = QTOK;
	switch (pvar->state) {
		case QTCONN_INIT:
			WARN_ON(1);
			qtfs_err("qtfs sm reconnect state error!");
			ret = QTERROR;
			break;
		case QTCONN_ACTIVE:
			qtfs_conn_fini(pvar);
			ret = qtfs_conn_init(pvar);
			if (ret) {
				qtfs_err("qtfs sm active init failed, ret:%d.", ret);
				ret = QTERROR;
				break;
			}

			pvar->state = QTCONN_CONNECTING;
			qtfs_warn("qtfs sm reconnect thread:%d, state:%s.", pvar->cur_threadidx, QTCONN_CUR_STATE(pvar));
			// fall-through
		case QTCONN_CONNECTING:
			ret = qtfs_sm_connecting(pvar);
			if (ret == 0)
				pvar->state = QTCONN_ACTIVE;
			break;
		default:
			qtfs_err("qtfs sm reconnect unknown state:%s.", QTCONN_CUR_STATE(pvar));
			ret = QTERROR;
			break;
	}
	return ret;
}

int qtfs_sm_exit(struct qtfs_conn_var_s *pvar)
{
	int ret = QTOK;
	switch (pvar->state) {
		case QTCONN_INIT:
			// do nothing
			break;
		case QTCONN_ACTIVE:
		case QTCONN_CONNECTING:
			qtfs_conn_fini(pvar);
#ifdef QTFS_SERVER
			pvar->state = QTCONN_CONNECTING;
#endif
#ifdef QTFS_CLIENT
			pvar->state = QTCONN_INIT;
#endif
			qtfs_warn("qtfs sm exit thread:%d state:%s.", pvar->cur_threadidx, QTCONN_CUR_STATE(pvar));
			break;

		default:
			qtfs_err("qtfs sm exit unknown state:%s.", QTCONN_CUR_STATE(pvar));
			ret = QTERROR;
			break;
	}
	return ret;
}

int qtfs_mutex_lock_interruptible(struct mutex *lock)
{
	int ret;
	ret = mutex_lock_interruptible(lock);
	if (ret == 0) {
		// mutex lock successed, proc lazy put
		while (1) {
			struct llist_node *toput = llist_del_first(&g_lazy_put_llst);
			struct qtfs_conn_var_s *pvar;
			if (toput == NULL)
				break;
			pvar = llist_entry(toput, struct qtfs_conn_var_s, lazy_put);
			pvar->conn_ops->conn_msg_clear(pvar);
			list_move_tail(&pvar->lst, &g_vld_lst);
			qtfs_warn("qtfs pvar lazy put idx:%d.", pvar->cur_threadidx);
		}
	}
	return ret;
}

static void parse_param(void)
{
	// reserve for pcie conn type
	// default as socket type
	g_pvar_ops = &qtfs_conn_sock_pvar_ops;
	// calling conn specific parse_param
	g_pvar_ops->parse_param();
}

void qtfs_conn_param_init(void)
{
	INIT_LIST_HEAD(&g_vld_lst);
	INIT_LIST_HEAD(&g_busy_lst);
	init_llist_head(&g_lazy_put_llst);
	atomic_set(&g_qtfs_conn_num, 0);
	// parse module_param and choose specified channel
	// should set g_pvar_ops here
	parse_param();
	g_pvar_ops->param_init();

	mutex_init(&g_param_mutex);
	return;
}

void qtfs_conn_param_fini(void)
{
	struct list_head *plst;
	struct list_head *n;
	int ret;
	int conn_num;
	int i;

	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret) {
		qtfs_err("qtfs conn param finish mutex lock interrup failed, ret:%d.", ret);
		WARN_ON(1);
		return;
	}

	list_for_each_safe(plst, n, &g_vld_lst) {
		struct qtfs_conn_var_s *pvar = (struct qtfs_conn_var_s *)plst;
		pvar->conn_ops->conn_var_fini(pvar);
		qtfs_sm_exit((struct qtfs_conn_var_s *)plst);
		if (pvar->cur_threadidx < 0 || pvar->cur_threadidx >= QTFS_MAX_THREADS) {
			qtfs_err("qtfs free unknown threadidx %d", pvar->cur_threadidx);
		} else {
			qtfs_thread_var[pvar->cur_threadidx] = NULL;
			qtfs_info("qtfs free pvar idx:%d successed.", pvar->cur_threadidx);
		}
		list_del(&pvar->lst);
		kfree(pvar);
	}
	conn_num = atomic_read(&g_qtfs_conn_num);
	for (i = 0; i < conn_num; i++) {
		if (qtfs_thread_var[i] != NULL) {
			qtfs_err("qtfs param not free idx:%d holder:%s",
					qtfs_thread_var[i]->cur_threadidx,
					qtfs_thread_var[i]->who_using);
		}
	}
	mutex_unlock(&g_param_mutex);
	g_pvar_ops->param_fini();
}

struct qtfs_conn_var_s *_qtfs_conn_get_param(const char *func)
{
	struct qtfs_conn_var_s *pvar = NULL;
	int ret;
	int cnt = 0;

	if (qtfs_mod_exiting == true) {
		qtfs_warn("qtfs module is exiting, good bye!");
		return NULL;
	}

retry:
	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret) {
		qtfs_err("qtfs conn get param mutex lock interrup failed, ret:%d.", ret);
		return NULL;
	}
	if (!list_empty(&g_vld_lst))
		pvar = list_last_entry(&g_vld_lst, struct qtfs_conn_var_s, lst);
	if (pvar != NULL) {
		list_move_tail(&pvar->lst, &g_busy_lst);
	}
	mutex_unlock(&g_param_mutex);

	if (pvar != NULL) {
		int ret;
		if (pvar->state == QTCONN_ACTIVE && pvar->conn_ops->conn_connected(pvar) == false) {
			qtfs_warn("qtfs get param thread:%d disconnected, try to reconnect.", pvar->cur_threadidx);
			ret = qtfs_sm_reconnect(pvar);
		} else {
			ret = qtfs_sm_active(pvar);
		}
		if (ret != 0) {
			qtfs_conn_put_param(pvar);
			return NULL;
		}
		memcpy(pvar->who_using, func, (strlen(func) >= QTFS_FUNCTION_LEN - 1) ? (QTFS_FUNCTION_LEN - 1) : strlen(func));
		return pvar;
	}

	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret) {
		qtfs_err("qtfs conn get param mutex lock interrup failed, ret:%d.", ret);
		return NULL;
	}
	if (atomic_read(&g_qtfs_conn_num) >= qtfs_conn_max_conn) {
		mutex_unlock(&g_param_mutex);
		cnt++;
		msleep(1);
		if (cnt < QTFS_GET_PARAM_MAX_RETRY)
			goto retry;
		qtfs_err("qtfs get param failed, the concurrency specification has reached the upper limit");
		return NULL;
	}
	pvar = kmalloc(sizeof(struct qtfs_conn_var_s), GFP_KERNEL);
	if (pvar == NULL) {
		qtfs_err("qtfs get param kmalloc failed.\n");
		mutex_unlock(&g_param_mutex);
		return NULL;
	}
	memset(pvar, 0, sizeof(struct qtfs_conn_var_s));
	// initialize conn_pvar here
	g_pvar_ops->pvar_init(pvar);
	if (QTFS_OK != pvar->conn_ops->conn_var_init(pvar)) {
		qtfs_err("qtfs sock var init failed.\n");
		kfree(pvar);
		mutex_unlock(&g_param_mutex);
		return NULL;
	}

	memcpy(pvar->who_using, func, (strlen(func) >= QTFS_FUNCTION_LEN - 1) ? (QTFS_FUNCTION_LEN - 1) : strlen(func));
	pvar->cur_threadidx = atomic_read(&g_qtfs_conn_num);
	qtfs_info("qtfs create new param, cur conn num:%d\n", atomic_read(&g_qtfs_conn_num));

	qtfs_thread_var[pvar->cur_threadidx] = pvar;
	// add to busy list
	atomic_inc(&g_qtfs_conn_num);
	list_add(&pvar->lst, &g_busy_lst);

	pvar->state = QTCONN_INIT;
	pvar->seq_num = 0;

#ifdef QTFS_CLIENT
	mutex_unlock(&g_param_mutex);
	pvar->cs = QTFS_CONN_SOCK_CLIENT;
	ret = qtfs_sm_active(pvar);
	if (ret) {
		qtfs_err("qtfs get param active connection failed, ret:%d, curstate:%s", ret, QTCONN_CUR_STATE(pvar));
		// put to vld list
		qtfs_conn_put_param(pvar);
		return NULL;
	}
	qtfs_thread_var[pvar->cur_threadidx] = pvar;
#else
	pvar->cs = QTFS_CONN_SOCK_SERVER;
	if (!pvar->conn_ops->conn_inited(pvar)) {
		if (qtfs_sm_active(pvar)) {
			qtfs_err("qtfs get param active connection failed, ret:%d, curstate:%s", ret, QTCONN_CUR_STATE(pvar));
			// put to vld list
			mutex_unlock(&g_param_mutex);
			qtfs_conn_put_param(pvar);
			return NULL;
		}
		mutex_unlock(&g_param_mutex);
	} else {
		mutex_unlock(&g_param_mutex);
		pvar->state = QTCONN_CONNECTING;
		ret = qtfs_sm_active(pvar);
		if (ret) {
			qtfs_err("qtfs get param active connection failed, ret:%d curstate:%s", ret, QTCONN_CUR_STATE(pvar));
			qtfs_conn_put_param(pvar);
			return NULL;
		}
	}
#endif
	qtinfo_cntinc(QTINF_ACTIV_CONN);

	return pvar;
}

struct qtfs_conn_var_s *qtfs_epoll_establish_conn(void)
{
	struct qtfs_conn_var_s *pvar = NULL;
	int ret;

	pvar = qtfs_epoll_var;
	if (pvar) {
		if (pvar->state == QTCONN_ACTIVE && pvar->conn_ops->conn_connected(pvar) == false) {
			qtfs_warn("qtfs epoll get param thread:%d disconnected, try to reconnect.", pvar->cur_threadidx);
			ret = qtfs_sm_reconnect(pvar);
		} else {
			ret = qtfs_sm_active(pvar);
		}
		if (ret) {
			return NULL;
		}
		return pvar;
	}

	pvar = kmalloc(sizeof(struct qtfs_conn_var_s), GFP_KERNEL);
	if (pvar == NULL) {
		qtfs_err("qtfs get param kmalloc failed.\n");
		return NULL;
	}
	memset(pvar, 0, sizeof(struct qtfs_conn_var_s));
	qtfs_epoll_var = pvar;
	pvar->cur_threadidx = QTFS_EPOLL_THREADIDX;
	g_pvar_ops->pvar_init(pvar);
	if (QTFS_OK != pvar->conn_ops->conn_var_init(pvar)) {
		qtfs_err("qtfs sock var init failed.\n");
		kfree(pvar);
		return NULL;
	}
	pvar->state = QTCONN_INIT;

#ifdef QTFS_CLIENT
	pvar->cs = QTFS_CONN_SOCK_CLIENT;
#else
	pvar->cs = QTFS_CONN_SOCK_SERVER;
#endif
	ret = qtfs_sm_active(pvar);
	if (ret) {
		qtfs_err("qtfs epoll get param active new param failed, ret:%d state:%s", ret, QTCONN_CUR_STATE(pvar));
		return NULL;
	}

	qtfs_info("qtfs create new epoll param state:%s", QTCONN_CUR_STATE(pvar));
	return pvar;
}

void qtfs_conn_put_param(struct qtfs_conn_var_s *pvar)
{
	int ret;
	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret) {
		llist_add(&pvar->lazy_put, &g_lazy_put_llst);
		qtfs_warn("qtfs conn put param add to lazy list idx:%d, ret:%d.", pvar->cur_threadidx, ret);
		return;
	}
	pvar->conn_ops->conn_msg_clear(pvar);
	list_move_tail(&pvar->lst, &g_vld_lst);
	mutex_unlock(&g_param_mutex);
	return;
}

void qtfs_epoll_cut_conn(struct qtfs_conn_var_s *pvar)
{
	int ret = qtfs_sm_exit(pvar);
	if (ret) {
		qtfs_err("qtfs epoll put param exit failed, ret:%d state:%s", ret, QTCONN_CUR_STATE(pvar));
	}
	return;
}

void qtfs_conn_list_cnt(void)
{
	struct list_head *entry;
	struct qtfs_conn_var_s *pvar;
#ifdef QTFS_CLIENT
	int ret = 0;
	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret) {
		qtfs_err("qtfs conn put param mutex lock interrup failed, ret:%d.", ret);
		return;
	}
#endif
	qtfs_diag_info->pvar_busy = 0;
	qtfs_diag_info->pvar_vld = 0;
	memset(qtfs_diag_info->who_using, 0, sizeof(qtfs_diag_info->who_using));
	list_for_each(entry, &g_busy_lst) {
		qtfs_diag_info->pvar_busy++;
		pvar = (struct qtfs_conn_var_s *)entry;
		if (pvar->cur_threadidx < 0 || pvar->cur_threadidx >= QTFS_MAX_THREADS)
			continue;
		strncpy(qtfs_diag_info->who_using[pvar->cur_threadidx],
								qtfs_thread_var[pvar->cur_threadidx]->who_using, QTFS_FUNCTION_LEN);
	}
	list_for_each(entry, &g_vld_lst)
		qtfs_diag_info->pvar_vld++;
#ifdef QTFS_CLIENT
	mutex_unlock(&g_param_mutex);
#endif
	return;
}

