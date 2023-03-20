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

#ifndef __QTFS_UDS_MAIN_H__
#define __QTFS_UDS_MAIN_H__

#include <time.h>

#include "uds_module.h"

#define UDS_EPOLL_MAX_EVENTS 64
#define UDS_WORK_THREAD_MAX 1 // Temporarily only supports 1 thread
#define UDS_FD_LIMIT 65536

extern struct uds_global_var *p_uds_var;
extern GHashTable *event_tmout_hash;

enum {
	UDS_LOG_NONE,
	UDS_LOG_ERROR,
	UDS_LOG_INFO,
	UDS_LOG_MAX,
};

#define uds_log(info, ...) \
	if (p_uds_var->loglevel >= UDS_LOG_INFO) {\
		time_t t; \
		struct tm *p; \
		time(&t); \
		p = localtime(&t); \
		printf("[%d/%02d/%02d %02d:%02d:%02d][LOG:%s:%3d]"info"\n", \
				p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
				p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
	}

#define uds_log2(info, ...) \
	if (p_uds_var->loglevel >= UDS_LOG_INFO) {\
		time_t t; \
		struct tm *p; \
		time(&t); \
		p = localtime(&t); \
		printf("[%d/%02d/%02d %02d:%02d:%02d][LOG:%s:%3d]"info"\n", \
				p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
				p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
	}

#define uds_err(info, ...) \
	if (p_uds_var->loglevel >= UDS_LOG_ERROR) {\
		time_t t; \
		struct tm *p; \
		time(&t); \
		p = localtime(&t); \
		printf("[%d/%02d/%02d %02d:%02d:%02d][ERROR:%s:%3d]"info"\n", \
				p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
				p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
	}

enum {
	UDS_THREAD_EPWAIT = 1, // epoll wait status
};
struct uds_thread_info {
	int fdnum;

	int events;
	int status;
};

struct uds_event_global_var {
	int cur;
	struct uds_event *tofree[UDS_EPOLL_MAX_EVENTS];
	char *msg_control;
	int msg_controllen;
	char *msg_control_send;
	int msg_controlsendlen;
	char *iov_base;
	int iov_len;
	char *iov_base_send;
	int iov_sendlen;
	char *buf;
	int buflen;
};

struct uds_event {
	int fd; /* 本事件由这个fd触发 */
	unsigned int tofree : 1, /* 1--in to free list; 0--not */
		     pipe : 1, // this is a pipe event
		     tmout : 4,
		     reserved : 26;
	union {
		struct uds_event *peer; /* peer event */
		int peerfd;		// scm pipe 场景单向导通，只需要一个fd即可
	};
	int (*handler)(void *, int, struct uds_event_global_var *); /* event处理函数 */
	void *priv; // private data
	char cpath[UDS_SUN_PATH_LEN];
	char spath[UDS_SUN_PATH_LEN];
};


struct uds_thread_arg {
	int efd;
	struct uds_event_global_var *p_event_var;
	struct uds_thread_info info;
};

struct uds_global_var {
	int work_thread_num;
	int *efd;
	struct uds_thread_arg *work_thread;
	int loglevel;
	char *logstr[UDS_LOG_MAX + 1];
	struct _tcp {
		char addr[20];
		unsigned short port;
		char peeraddr[20];
		unsigned short peerport;
	} tcp;
	struct _uds {
		char sun_path[UDS_SUN_PATH_LEN];
	} uds;
};
enum uds_cs {
	UDS_SOCKET_CLIENT = 1,
	UDS_SOCKET_SERVER,
};

struct uds_conn_arg {
	int cs;		// client(1) or server(2)

	int udstype; 	// DGRAM or STREAM
	char sun_path[UDS_SUN_PATH_LEN];
	int sockfd;
	int connfd;
};

struct uds_event *uds_add_event(int fd, struct uds_event *peer, int (*handler)(void *, int, struct uds_event_global_var *), void *priv);
struct uds_event *uds_add_pipe_event(int fd, int peerfd, int (*handler)(void *, int, struct uds_event_global_var *), void *priv);
int uds_sock_step_accept(int sockFd, int family);
int uds_build_tcp_connection(struct uds_conn_arg *arg);
int uds_build_unix_connection(struct uds_conn_arg *arg);
void uds_del_event(struct uds_event *evt);
int uds_event_suspend(int efd, struct uds_event *event);
int uds_event_insert(int efd, struct uds_event *event);
int uds_hash_insert_dirct(GHashTable *table, int key, struct uds_event *value);
void *uds_hash_lookup_dirct(GHashTable *table, int key);
void uds_hash_remove_dirct(GHashTable *table, int key);

#ifdef QTFS_SERVER
int uds_proxy_main(int argc, char *argv[]);
#endif
#endif
