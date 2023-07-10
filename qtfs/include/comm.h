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

#ifndef __QTFS_SERVER_COMM_H__
#define __QTFS_SERVER_COMM_H__

#include <linux/version.h>

#if (LINUX_VERSION_CODE == KERNEL_VERSION(4,19,90)) || (LINUX_VERSION_CODE == KERNEL_VERSION(4,19,36))
#define KVER_4_19 1
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
#define BEFORE_KVER_5_6 1
#endif

#define QTSOCK_WL_MAX_NUM 64
#define QTFS_WL_MAX_NUM 64 // QTFS server white list

#define QTFS_USERP_MAXSIZE 65536

#define QTFS_MAX_EPEVENTS_NUM 64

extern struct qtinfo *qtfs_diag_info;

#define QTFS_CLIENT_DEV "/dev/qtfs_client"
#define QTFS_SERVER_DEV "/dev/qtfs_server"

#define QTFS_IOCTL_MAGIC 'Q'
enum {
    _QTFS_IOCTL_EXEC,
    _QTFS_IOCTL_THREAD_RUN,
	_QTFS_IOCTL_EPFDSET,
	_QTFS_IOCTL_EPOLLT,
	_QTFS_IOCTL_EPOLL_THREAD_RUN,
	_QTFS_IOCTL_EXIT,

	_QTFS_IOCTL_ALLINFO,
	_QTFS_IOCTL_CLEARALL,

	_QTFS_IOCTL_LOG_LEVEL,
	_QTFS_IOCTL_EPOLL_SUPPORT,

	_QTFS_IOCTL_WL_ADD,
	_QTFS_IOCTL_WL_DEL,
	_QTFS_IOCTL_WL_GET,
};

#define QTFS_IOCTL_THREAD_INIT			_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EXEC)
#define QTFS_IOCTL_THREAD_RUN			_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_THREAD_RUN)
#define QTFS_IOCTL_EPFDSET				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EPFDSET)
#define QTFS_IOCTL_EPOLL_THREAD_INIT	_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EPOLLT)
#define QTFS_IOCTL_EPOLL_THREAD_RUN		_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EPOLL_THREAD_RUN)
#define QTFS_IOCTL_EXIT					_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EXIT)
#define QTFS_IOCTL_ALLINFO				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_ALLINFO)
#define QTFS_IOCTL_CLEARALL				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_CLEARALL)
#define QTFS_IOCTL_LOGLEVEL				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_LOG_LEVEL)
#define QTFS_IOCTL_EPOLL_SUPPORT		_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EPOLL_SUPPORT)
#define QTFS_IOCTL_WL_ADD				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_WL_ADD)
#define QTFS_IOCTL_WL_DEL				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_WL_DEL)
#define QTFS_IOCTL_WL_GET				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_WL_GET)

#define QTINFO_MAX_EVENT_TYPE 36 // look qtreq_type at req.h
#define QTFS_FUNCTION_LEN 64

#define QTFS_MAX_THREADS 16
#define QTFS_LOGLEVEL_STRLEN 6

struct qtfs_server_userp_s {
	size_t size;
	void *userp;
	void *userp2;
};


enum {
#if defined(QTFS_SERVER) || defined(server)
	QTFS_WHITELIST_OPEN,
	QTFS_WHITELIST_WRITE,
	QTFS_WHITELIST_READ,
	QTFS_WHITELIST_READDIR,
	QTFS_WHITELIST_MKDIR,
	QTFS_WHITELIST_RMDIR,
	QTFS_WHITELIST_CREATE,
	QTFS_WHITELIST_UNLINK,
	QTFS_WHITELIST_RENAME,
	QTFS_WHITELIST_SETATTR,
	QTFS_WHITELIST_SETXATTR,
	QTFS_WHITELIST_MOUNT,
	QTFS_WHITELIST_KILL,
#endif
	QTFS_WHITELIST_UDSCONNECT,
	QTFS_WHITELIST_MAX,
};

#define QTFS_PATH_MAX 4096
// user-kernel struct
struct qtfs_wl_item {
	unsigned int type : 10,	// use to add
				 len : 12,	// max len 4096
				 index : 10; // use to query or del (index of items)
	char *path; // path string
};

struct qtfs_thread_init_s {
	unsigned int thread_nums;
	struct qtfs_server_userp_s *userp;
};

struct qtreq_epoll_event {
	unsigned int events;
	unsigned long data;
};

struct qtfs_server_epoll_s {
	int epfd;
	unsigned int event_nums;
	struct epoll_event *events;
	struct epoll_event *kevents;
};

enum qtfs_errcode {
	QTOK = 0,
	QTERROR = 1,
	QTEXIT = 2,
};

struct qtsock_whitelist {
	unsigned int len;
	char data[0];
};

// qtinfo start
#if (defined(QTFS_CLIENT) || defined(client))
enum qtinfo_cnts {
	QTINF_ACTIV_CONN,
	QTINF_EPOLL_ADDFDS,
	QTINF_EPOLL_DELFDS,
	QTINF_EPOLL_FDERR,
	QTINF_SEQ_ERR,
	QTINF_RESTART_SYS,
	QTINF_TYPE_MISMATCH,
	QTINF_NUM,
};
#endif

#if defined(QTFS_SERVER) || defined(server)
enum qtinfo_cnts {
	QTINF_ACTIV_CONN,
	QTINF_EPOLL_ADDFDS,
	QTINF_EPOLL_DELFDS,
	QTINF_NUM,
};
#endif

#if (defined(QTFS_CLIENT) || defined(client) || defined(QTFS_SERVER) || defined(server))
// for connection state machine
typedef enum {
	QTCONN_INIT,
	QTCONN_CONNECTING,
	QTCONN_ACTIVE,
} qtfs_conn_type_e;

struct qtinfo_client {
	unsigned long cnts[QTINF_NUM];
	unsigned long recv_err[QTINFO_MAX_EVENT_TYPE];
	unsigned long send_err[QTINFO_MAX_EVENT_TYPE];
	unsigned long i_events[QTINFO_MAX_EVENT_TYPE];
	unsigned long o_events[QTINFO_MAX_EVENT_TYPE];
	unsigned long rsp_check[QTINFO_MAX_EVENT_TYPE]; // rsp check err cnts
};

struct qtinfo_server {
	unsigned long cnts[QTINF_NUM];
	unsigned long i_events[QTINFO_MAX_EVENT_TYPE];
	unsigned long o_events[QTINFO_MAX_EVENT_TYPE];
	unsigned long req_check[QTINFO_MAX_EVENT_TYPE]; // req check err cnts
};

struct qtinfo {
	union {
		struct qtinfo_client c;
		struct qtinfo_server s;
	};
	// all struct qtreq_xxx's size
	unsigned int req_size[QTINFO_MAX_EVENT_TYPE];
	unsigned int rsp_size[QTINFO_MAX_EVENT_TYPE];
	int log_level;
	int thread_state[QTFS_MAX_THREADS];
	char who_using[QTFS_MAX_THREADS][QTFS_FUNCTION_LEN];
	int epoll_state;
	int pvar_vld; // valid param's number
	int pvar_busy; // busy param's number
};

#define QTINFO_STATE(state) ((state == QTCONN_INIT) ? "INIT" : \
							((state == QTCONN_CONNECTING) ? "CONNECTING" : \
							((state == QTCONN_ACTIVE) ? "ACTIVE" : "UNKNOWN")))
#endif

//ko compile
#if (defined(QTFS_CLIENT) || defined(client))
static inline void qtinfo_clear(void)
{
	int i;
	for (i = QTINF_SEQ_ERR; i < QTINF_NUM; i++)
		qtfs_diag_info->c.cnts[i] = 0;
	memset(qtfs_diag_info->c.recv_err, 0, sizeof(qtfs_diag_info->c.recv_err));
	memset(qtfs_diag_info->c.send_err, 0, sizeof(qtfs_diag_info->c.send_err));
	memset(qtfs_diag_info->c.i_events, 0, sizeof(qtfs_diag_info->c.i_events));
	memset(qtfs_diag_info->c.o_events, 0, sizeof(qtfs_diag_info->c.o_events));
	return;
}
static inline void qtinfo_cntinc(enum qtinfo_cnts idx)
{
	if (idx >= QTINF_NUM)
		return;
	qtfs_diag_info->c.cnts[idx]++;
	return;
}
static inline void qtinfo_cntdec(enum qtinfo_cnts idx)
{
	if (idx >= QTINF_NUM || qtfs_diag_info->c.cnts[idx] == 0)
		return;
	qtfs_diag_info->c.cnts[idx]--;
	return;
}
static inline void qtinfo_recvinc(size_t idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.i_events[idx]++;
	return;
}
static inline void qtinfo_sendinc(size_t idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.o_events[idx]++;
	return;
}
static inline void qtinfo_recverrinc(size_t idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.recv_err[idx]++;
	return;
}
static inline void qtinfo_senderrinc(size_t idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.send_err[idx]++;
	return;
}
static inline void qtinfo_rspcheckinc(size_t idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.rsp_check[idx]++;
	return;
}
#endif

// ko compile
#if defined(QTFS_SERVER) || defined(server)
static inline void qtinfo_clear(void)
{
	memset(qtfs_diag_info->s.i_events, 0, sizeof(qtfs_diag_info->s.i_events));
	memset(qtfs_diag_info->s.o_events, 0, sizeof(qtfs_diag_info->s.o_events));
	return;
}
static inline void qtinfo_cntinc(enum qtinfo_cnts idx)
{
	if (idx >= QTINF_NUM)
		return;
	qtfs_diag_info->s.cnts[idx]++;
	return;
}
static inline void qtinfo_cntdec(enum qtinfo_cnts idx)
{
	if (idx >= QTINF_NUM || qtfs_diag_info->s.cnts[idx] == 0)
		return;
	qtfs_diag_info->s.cnts[idx]--;
	return;
}
static inline void qtinfo_recvinc(size_t idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->s.i_events[idx]++;
	return;
}
static inline void qtinfo_sendinc(size_t idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->s.o_events[idx]++;
	return;
}
static inline void qtinfo_reqcheckinc(size_t idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->s.req_check[idx]++;
	return;
}
#endif
// QTINFO END

#endif

