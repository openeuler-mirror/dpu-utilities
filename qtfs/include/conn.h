/* SPDX-License-Identifier: GPL-2.0 */

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
extern int qtfs_conn_max_conn;
extern struct socket *qtfs_server_main_sock;
extern struct qtfs_conn_var_s *qtfs_thread_var[QTFS_MAX_THREADS];
extern struct qtfs_conn_var_s *qtfs_epoll_var;
extern char qtfs_log_level[QTFS_LOGLEVEL_STRLEN];
extern int log_level;
extern struct qtinfo *qtfs_diag_info;
extern bool qtfs_epoll_mode;
extern struct qtsock_wl_stru qtsock_wl;
extern struct qtfs_pvar_ops_s qtfs_conn_sock_pvar_ops;
#define qtfs_conn_get_param(void) _qtfs_conn_get_param(__func__)

#define QTFS_CONN_SOCK_TYPE "socket"
#define QTFS_CONN_PCIE_TYPE "pcie"

#define QTFS_EPOLL_THREADIDX (QTFS_MAX_THREADS + 4)
#define QTCONN_IS_EPOLL_CONN(pvar) (pvar->cur_threadidx == QTFS_EPOLL_THREADIDX)
#define QTFS_SERVER_MAXCONN 2

static inline bool err_ptr(void *ptr)
{
	if (!ptr)
		return true;
	if (IS_ERR(ptr))
		return true;
	
	return false;
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

struct qtfs_pcie_var_s {
	int srcid;
	int dstid;
};

struct qtfs_sock_var_s {
	struct socket *sock;
	struct socket *client_sock;
	char addr[20];
	unsigned short port;
};

struct qtfs_pvar_ops_s {
	//  channel-specific parameter parsing function
	int (*parse_param)(void);
	// channel-specific global param init
	int (*param_init)(void);
	int (*param_fini)(void);
	// init pvar with channel specific ops
	int (*pvar_init)(struct qtfs_conn_var_s *pvar);
};
extern struct qtfs_pvar_ops_s *g_pvar_ops;

struct qtfs_conn_ops_s {
	// conn message buffer initialization and releasement.
	int (*conn_var_init)(struct qtfs_conn_var_s *pvar);
	void (*conn_var_fini)(struct qtfs_conn_var_s *pvar);
	void (*conn_msg_clear)(struct qtfs_conn_var_s *pvar);
	void *(*get_conn_msg_buf)(struct qtfs_conn_var_s *pvar, int dir);

	// connection related ops
	int (*conn_init)(struct qtfs_conn_var_s *pvar);
	void (*conn_fini)(struct qtfs_conn_var_s *pvar);
	int (*conn_send)(struct qtfs_conn_var_s *pvar);
	int (*conn_recv)(struct qtfs_conn_var_s *pvar, bool block);
	int (*conn_server_accept)(struct qtfs_conn_var_s *pvar);
	int (*conn_client_connect)(struct qtfs_conn_var_s *pvar);
	bool (*conn_inited)(struct qtfs_conn_var_s *pvar);
	bool (*conn_connected)(struct qtfs_conn_var_s *pvar);
};

struct qtfs_conn_var_s {
	struct list_head lst;
	struct llist_node lazy_put;
	int cs;
	int cur_threadidx;
	int miss_proc;
	unsigned long seq_num;
	qtfs_conn_type_e state;
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
	struct msghdr msg_recv;
	struct msghdr msg_send;
};

struct qtsock_wl_stru {
	int nums;
	char **wl;
	rwlock_t rwlock;
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

struct qtfs_conn_var_s *_qtfs_conn_get_param(const char *);
void qtfs_conn_put_param(struct qtfs_conn_var_s *pvar);
struct qtfs_conn_var_s *qtfs_epoll_establish_conn(void);
void qtfs_epoll_cut_conn(struct qtfs_conn_var_s *pvar);

int qtfs_sm_active(struct qtfs_conn_var_s *pvar);
int qtfs_sm_reconnect(struct qtfs_conn_var_s *pvar);
int qtfs_sm_exit(struct qtfs_conn_var_s *pvar);

void qtfs_kallsyms_hack_init(void);
void qtfs_conn_list_cnt(void);

int qtfs_uds_remote_init(void);
void qtfs_uds_remote_exit(void);

int qtfs_uds_remote_connect_user(int fd, struct sockaddr __user *addr, int len);

#endif
