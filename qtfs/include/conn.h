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

#ifndef __QTFS_CONN_H__
#define __QTFS_CONN_H__

#include <linux/socket.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/types.h>
#include <linux/mount.h>
#include <net/inet_sock.h>

#include "comm.h"
#include "log.h"

#ifdef QTFS_SERVER
extern int qtfs_server_thread_run;
extern struct qtfs_server_userp_s *qtfs_userps;
#endif
extern char qtfs_conn_type[20];
extern char qtfs_server_ip[20];
extern int qtfs_server_port;
extern unsigned int qtfs_server_vsock_port;
extern unsigned int qtfs_server_vsock_cid;

extern struct qtfs_conn_var_s *qtfs_thread_var[QTFS_MAX_THREADS];
extern struct qtfs_conn_var_s *qtfs_epoll_var;
extern char qtfs_log_level[QTFS_LOGLEVEL_STRLEN];
extern int log_level;
extern struct qtinfo *qtfs_diag_info;
extern bool qtfs_epoll_mode;
extern struct qtfs_pvar_ops_s qtfs_conn_sock_pvar_ops;
extern struct qtfs_wl g_qtfs_wl;

struct qtfs_conn_var_s *_qtfs_conn_get_param(const char *);
static inline struct qtfs_conn_var_s *__qtfs_conn_get_param(const char *who_using)
{
	struct qtfs_conn_var_s *p = _qtfs_conn_get_param(who_using);
	if (IS_ERR_OR_NULL(p))
		return NULL;
	return p;
}
#define qtfs_conn_get_param(void) __qtfs_conn_get_param(__func__)
#define qtfs_conn_get_param_errcode(void) _qtfs_conn_get_param(__func__)

#define QTFS_CONN_SOCK_TYPE "socket"
#define QTFS_CONN_PCIE_TYPE "pcie"

#define QTFS_EPOLL_THREADIDX (QTFS_MAX_THREADS + 4)
#define QTCONN_IS_EPOLL_CONN(pvar) (pvar->cur_threadidx == QTFS_EPOLL_THREADIDX)
#define QTFS_SERVER_MAXCONN 2
#define QTFS_GET_PARAM_MAX_RETRY 10000

static inline long __must_check QTFS_PTR_ERR(__force const void *ptr)
{
	if (!ptr)
		return -EINVAL;
	return (long) ptr;
}

static inline bool qtfs_support_epoll(umode_t mode)
{
	return (qtfs_epoll_mode || S_ISFIFO(mode));
}

#define QTFS_SOCK_RCVTIMEO 1
#define QTFS_SOCK_SNDTIMEO 1

typedef enum {
	QTFS_CONN_SOCKET,
	QTFS_CONN_PCIE,
	QTFS_CONN_INVALID,
} qtfs_conn_mode_e;

typedef enum {
	QTFS_CONN_SOCK_SERVER,
	QTFS_CONN_SOCK_CLIENT,
} qtfs_conn_cs_e;

// 使用pvar的主题类型，为了更好区分类型，socket下server有主socket下建立多个链接
// 的需求，通过类型告知socket模块，且解藕conn层和下面的不同消息通道类型
typedef enum {
	QTFS_CONN_TYPE_QTFS,		// QTFS tunnel type
	QTFS_CONN_TYPE_EPOLL,		// EPOLL thread type
	QTFS_CONN_TYPE_FIFO,		// FIFO type
	QTFS_CONN_TYPE_INV,
} qtfs_conn_type_e;

struct qtfs_pcie_var_s {
	int srcid;
	int dstid;
};

struct qtfs_sock_var_s {
	struct socket *sock;
	struct socket *client_sock;
#ifdef QTFS_TEST_MODE
	char addr[20];
	unsigned short port;
#else
	// for vsock
	unsigned int vm_port;
	unsigned int vm_cid;
#endif
	struct msghdr msg_recv;
	struct msghdr msg_send;
};

struct qtfs_conn_ops_s {
	// conn message buffer initialization and releasement.
	int (*conn_var_init)(struct qtfs_conn_var_s *pvar);
	void (*conn_var_fini)(struct qtfs_conn_var_s *pvar);
	void (*conn_msg_clear)(struct qtfs_conn_var_s *pvar);
	void *(*get_conn_msg_buf)(struct qtfs_conn_var_s *pvar, int dir);

	// connection related ops
	int (*conn_init)(void *connvar, qtfs_conn_type_e type);
	void (*conn_fini)(void *connvar, qtfs_conn_type_e type);
	int (*conn_send)(void *connvar, void *buf, size_t len);
	int (*conn_recv)(void *connvar, void *buf, size_t len, bool block);
	int (*conn_server_accept)(void *connvar, qtfs_conn_type_e type);
	int (*conn_client_connect)(void *connvar);
	bool (*conn_inited)(void *connvar, qtfs_conn_type_e type);
	bool (*conn_connected)(void *connvar);
	void (*conn_recv_buff_drop)(void *connvar);
};

struct qtfs_pvar_ops_s {
	//  channel-specific parameter parsing function
	int (*parse_param)(void);
	// channel-specific global param init
	int (*param_init)(void);
	int (*param_fini)(void);
	// init pvar with channel specific ops
	int (*pvar_init)(void *connvar, struct qtfs_conn_ops_s **conn_ops, qtfs_conn_type_e type);
};
extern struct qtfs_pvar_ops_s *g_pvar_ops;

struct qtfs_conn_var_s {
	struct list_head lst;
	struct llist_node lazy_put;
	int cs;
	int cur_threadidx;
	int miss_proc;
	unsigned long seq_num;
	qtfs_conn_state_e state;
	qtfs_conn_type_e user_type; // type of pvar's user: qtfs/epoll deamon/fifo
	char who_using[QTFS_FUNCTION_LEN];
	union {
		struct qtfs_sock_var_s sock_var;
		struct qtfs_pcie_var_s pcie_var;
	} conn_var;
	struct qtfs_conn_ops_s *conn_ops;

	// use to memset buf
	unsigned long recv_valid;
	unsigned long send_valid;
	struct kvec vec_recv;
	struct kvec vec_send;
};

struct qtfs_wl_cap {
	unsigned int nums;
	char *item[QTFS_WL_MAX_NUM];
};

struct qtfs_wl {
	rwlock_t rwlock;
	struct qtfs_wl_cap cap[QTFS_WHITELIST_MAX];
};

int qtfs_conn_init(struct qtfs_conn_var_s *pvar);
void qtfs_conn_fini(struct qtfs_conn_var_s *pvar);
int qtfs_conn_send(struct qtfs_conn_var_s *pvar);
int qtfs_conn_recv(struct qtfs_conn_var_s *pvar);
int qtfs_conn_recv_block(struct qtfs_conn_var_s *pvar);

int qtfs_conn_var_init(struct qtfs_conn_var_s *pvar);
void qtfs_conn_var_fini(struct qtfs_conn_var_s *pvar);
void qtfs_conn_msg_clear(struct qtfs_conn_var_s *pvar);
void *qtfs_conn_msg_buf(struct qtfs_conn_var_s *pvar, int dir);

void qtfs_conn_param_init(void);
void qtfs_conn_param_fini(void);

void qtfs_conn_put_param(struct qtfs_conn_var_s *pvar);
struct qtfs_conn_var_s *qtfs_epoll_establish_conn(void);
void qtfs_epoll_cut_conn(struct qtfs_conn_var_s *pvar);

int qtfs_sm_active(struct qtfs_conn_var_s *pvar);
int qtfs_sm_reconnect(struct qtfs_conn_var_s *pvar);
int qtfs_sm_exit(struct qtfs_conn_var_s *pvar);

void qtfs_conn_list_cnt(void);

int qtfs_uds_remote_connect_user(int fd, struct sockaddr __user *addr, int len);

#endif
