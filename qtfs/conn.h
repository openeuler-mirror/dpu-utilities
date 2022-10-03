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
extern char qtfs_server_ip[20];
extern int qtfs_server_port;
extern int qtfs_sock_max_conn;
extern struct socket *qtfs_server_main_sock;
extern struct qtfs_sock_var_s *qtfs_thread_var[QTFS_MAX_THREADS];
extern struct qtfs_sock_var_s *qtfs_epoll_var;
extern char qtfs_log_level[QTFS_LOGLEVEL_STRLEN];
extern int log_level;
extern struct qtinfo *qtfs_diag_info;
extern bool qtfs_epoll_mode;

#define qtfs_conn_get_param(void) _qtfs_conn_get_param(__func__)

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
	struct list_head lst;
	struct llist_node lazy_put;
	int cs;
	int cur_threadidx;
	int miss_proc;
	unsigned long seq_num;
	qtfs_conn_type_e state;
	char who_using[QTFS_FUNCTION_LEN];
	struct socket *sock;
	struct socket *client_sock;
	char addr[20];
	unsigned short port;

	// use to memset buf
	unsigned long recv_valid;
	unsigned long send_valid;
	struct kvec vec_recv;
	struct kvec vec_send;
	struct msghdr msg_recv;
	struct msghdr msg_send;
};

struct qtfs_conn_var_s {
	union {
		struct qtfs_pcie_var_s pcie;
		struct qtfs_sock_var_s sock;
	} mode;
	char *buf_recv;
	char *buf_send;
	int len_recv;
	int len_send;
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t qtfs_kallsyms_lookup_name;

struct qtfs_kallsyms {
	/* global vars define */
	unsigned long **sys_call_table;

	/* functions define */
	char * (*d_absolute_path)(const struct path *, char *, int);
	long (*do_unlinkat)(int, struct filename *);
	struct filename * (*getname_kernel)(const char *);
	struct filename * (*filename_parentat)(int, struct filename *, unsigned int,
				struct path *, struct qstr *, int *);
	struct dentry * (*__lookup_hash)(const struct qstr *, struct dentry *, unsigned int);
	long (*do_mount)(const char *, const char __user *, const char *, unsigned long, void *);
	int (*path_mount)(const char *, struct path *, const char *, unsigned long, void *);
	int (*path_umount)(struct path *, int);
	struct task_struct *(*find_get_task_by_vpid)(pid_t nr);
	int (*do_readlinkat)(int, const char __user *, char __user *, int);
	int (*do_renameat2)(int, const char __user *, int, const char __user *, unsigned int);
	long (*do_mkdirat)(int, const char __user *, umode_t);
	long (*do_rmdir)(int, struct filename *);
	struct filename * (*getname)(const char __user *);
	void (*ep_ptable_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);
	int (*user_statfs)(const char __user *, struct kstatfs *);
	int (*__close_fd)(struct files_struct *, int);
	int (*do_sys_open)(int, const char __user *, int ,umode_t);
	int (*do_epoll_ctl)(int, int, int, struct epoll_event *, bool);
	int (*do_epoll_wait)(int, struct epoll_event __user *, int, int);
	int (*do_linkat)(int, const char __user *, int, const char __user *, int);
	int (*mnt_get_count)(void *);
	long (*do_mknodat)(int, const char __user *, umode_t, unsigned int);
};

extern struct qtfs_kallsyms qtfs_kern_syms;

static inline bool qtfs_sock_connected(struct qtfs_sock_var_s *pvar)
{
	struct socket *sock = pvar->client_sock;
	__u8 tcpi_state;
	if (sock == NULL)
		return false;
	tcpi_state = inet_sk_state_load(sock->sk);
	if (tcpi_state == TCP_ESTABLISHED)
		return true;
	qtfs_warn("qtfs threadidx:%d tcpi state:%u(define:TCP_ESTABLISHED=1 is connected) disconnect!", pvar->cur_threadidx, tcpi_state);

	return false;
}

int qtfs_conn_init(int msg_mode, struct qtfs_sock_var_s *pvar);
void qtfs_conn_fini(int msg_mode, struct qtfs_sock_var_s *pvar);
int qtfs_conn_send(int msg_mode, struct qtfs_sock_var_s *pvar);
int qtfs_conn_recv(int msg_mode, struct qtfs_sock_var_s *pvar);
int qtfs_conn_recv_block(int msg_mode, struct qtfs_sock_var_s *pvar);

int qtfs_sock_var_init(struct qtfs_sock_var_s *pvar);
void qtfs_sock_var_fini(struct qtfs_sock_var_s *pvar);
void qtfs_sock_msg_clear(struct qtfs_sock_var_s *pvar);
void *qtfs_sock_msg_buf(struct qtfs_sock_var_s *pvar, int dir);

void qtfs_conn_param_init(void);
void qtfs_conn_param_fini(void);

struct qtfs_sock_var_s *_qtfs_conn_get_param(const char *);
void qtfs_conn_put_param(struct qtfs_sock_var_s *pvar);
struct qtfs_sock_var_s *qtfs_epoll_establish_conn(void);
void qtfs_epoll_cut_conn(struct qtfs_sock_var_s *pvar);

int qtfs_sm_active(struct qtfs_sock_var_s *pvar);
int qtfs_sm_reconnect(struct qtfs_sock_var_s *pvar);
int qtfs_sm_exit(struct qtfs_sock_var_s *pvar);

void qtfs_kallsyms_hack_init(void);
void qtfs_conn_list_cnt(void);

#endif
