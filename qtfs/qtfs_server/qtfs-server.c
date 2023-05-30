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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/socket.h>

#include "conn.h"
#include "qtfs-server.h"
#include "comm.h"
#include "log.h"
#include "req.h"
#include "symbol_wrapper.h"

#define QTFS_EPOLL_TIMEO 1000 // unit ms
#define QTFS_EPOLL_RETRY_INTVL 500 // unit ms

int qtfs_server_thread_run = 1;
DEFINE_RWLOCK(g_userp_rwlock);
struct qtserver_fd_bitmap qtfs_fd_bitmap;

long qtfs_server_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

struct file_operations qtfs_misc_fops = {
	.owner=THIS_MODULE,
	.unlocked_ioctl = qtfs_server_misc_ioctl,
};

struct qtfs_server_epoll_s qtfs_epoll = {
	.epfd = -1,
	.event_nums = 0,
	.events = NULL,
	.kevents = NULL,
};
rwlock_t qtfs_epoll_rwlock;

struct whitelist* g_whitelist[QTFS_WHITELIST_MAX];
rwlock_t g_whitelist_rwlock;

long qtfs_server_epoll_thread(struct qtfs_conn_var_s *pvar)
{
	int n;
	struct qtreq_epollevt *req;
	struct qtrsp_epollevt *rsp;
	struct qtreq *head;
	int sendlen;
	int ret = 0;
	int i = 0;

	if (qtfs_epoll.epfd == -1) {
		qtfs_err("qtfs epoll wait error, epfd is invalid.");
		return QTERROR;
	}
	if (false == pvar->conn_ops->conn_connected(pvar)) {
		qtfs_warn("qtfs epoll thread disconnected, now try to reconnect.");
		ret = qtfs_sm_reconnect(pvar);
	} else {
		ret = qtfs_sm_active(pvar);
	}
	if (ret != QTOK) {
		qtfs_err("qtfs epoll thread connect state error, can't work.");
		msleep(QTFS_EPOLL_RETRY_INTVL);
		return QTERROR;
	}
	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	rsp = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_RECV);
	head = pvar->vec_send.iov_base;
	do {
		n = qtfs_syscall_epoll_wait(qtfs_epoll.epfd, qtfs_epoll.events, qtfs_epoll.event_nums, 0);
		if (n == 0) {
			msleep(1);
			break;
		}
		if (n < 0 || n > QTFS_MAX_EPEVENTS_NUM) {
			msleep(QTFS_EPOLL_RETRY_INTVL);
			qtfs_err("epoll get new events number failed:%d ", n);
			break;
		}
		qtfs_info(">>epoll get new events number:%d.", n);
		if (copy_from_user(qtfs_epoll.kevents, qtfs_epoll.events, sizeof(struct epoll_event) * n)) {
			qtfs_err("qtfs copy epoll events failed, events lost.");
			WARN_ON(1);
			break;
		}
		for (i = 0; i < n; i++) {
			req->events[i].data = qtfs_epoll.kevents[i].data;
			req->events[i].events = qtfs_epoll.kevents[i].events;
			qtfs_info("epoll thread head req:%lx.", (unsigned long)req);
		}
		req->event_nums = n;
		sendlen = sizeof(struct qtreq_epollevt) - sizeof(req->events) + n * sizeof(struct qtreq_epoll_event);
		if (sendlen > QTFS_REQ_MAX_LEN) {
			qtfs_err("qtfs epoll events size(%d) larger than qtfs message size.", sendlen);
			WARN_ON(1);
			break;
		}
		pvar->vec_send.iov_len = QTFS_MSG_LEN - (QTFS_REQ_MAX_LEN - sendlen);
		head->len = sendlen;
		head->type = QTFS_REQ_EPOLL_EVENT;
		ret = qtfs_conn_send(pvar);
		qtfs_info("qtfs send msg conn: sendlen:%lu ret:%d.",
				(unsigned long)pvar->vec_send.iov_len, ret);
		if (ret == -EPIPE) {
			qtfs_err("epoll wait send events failed get EPIPE, just wait new connection.");
			qtfs_sm_reconnect(pvar);
			break;
		}
		if (ret < 0) {
			qtfs_err("epoll wait send events failed, ret:%d.", ret);
			WARN_ON(1);
		}
retry:
		ret = qtfs_conn_recv_block(pvar);
		if (ret == -EAGAIN) {
			if (qtfs_server_thread_run == 0) {
				qtfs_warn("qtfs module exiting, goodbye!");
				return QTEXIT;
			}
			goto retry;
		}
		if (ret == -EPIPE) {
			qtfs_err("epoll recv events failed get EPIPE, just wait new connection.");
			qtfs_sm_reconnect(pvar);
			break;
		}
	}while (0);

	return (ret < 0) ? QTERROR : QTOK;
}

long qtfs_server_epoll_init(void)
{
	struct qtfs_conn_var_s *pvar = NULL;
	struct qtreq_epollevt *req;

	pvar = qtfs_epoll_establish_conn();
	if (pvar == NULL) {
		return QTERROR;
	}
	qtfs_epoll_var = pvar;

	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	qtfs_info("qtfs epoll events req size:%lu, events size:%lu, struct:%lu.",
				sizeof(struct qtreq_epollevt), sizeof(req->events),
				sizeof(struct qtreq_epoll_event));
	qtfs_info("qtfs epoll wait thread, epfd:%d nums:%d.",
							qtfs_epoll.epfd, qtfs_epoll.event_nums);

	return QTOK;
}

int qtfs_server_fd_bitmap_init(void)
{
	struct rlimit fd_rlim;
	if (qtfs_fd_bitmap.bitmap != NULL) {
		qtfs_info("free old bitmap");
		kfree(qtfs_fd_bitmap.bitmap);
		qtfs_fd_bitmap.bitmap = NULL;
		qtfs_fd_bitmap.nbits = 0;
	}
	// fd_rlim is get from current task struct, can be trusted
	fd_rlim = current->signal->rlim[RLIMIT_NOFILE];
	qtfs_info("task rlimit cur:%lu max:%lu", fd_rlim.rlim_cur, fd_rlim.rlim_max);
	qtfs_fd_bitmap.bitmap = (unsigned long *)kmalloc(BITS_TO_BYTES(fd_rlim.rlim_cur), GFP_KERNEL);
	if (qtfs_fd_bitmap.bitmap == NULL) {
		qtfs_err("kmalloc len:%lu failed.", BITS_TO_BYTES(fd_rlim.rlim_cur));
		return -1;
	}
	qtfs_fd_bitmap.nbits = fd_rlim.rlim_cur;
	bitmap_zero(qtfs_fd_bitmap.bitmap, qtfs_fd_bitmap.nbits);
	return 0;
}

long qtfs_server_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int i, len;
	long ret = 0;
	struct qtfs_conn_var_s *pvar;
	struct whitelist *tmp;
	struct qtfs_thread_init_s init_userp;
	switch (cmd) {
		case QTFS_IOCTL_THREAD_INIT:
			if (!write_trylock(&g_userp_rwlock)) {
				qtfs_err("try lock userps failed.");
				return QTERROR;
			}
			if (qtfs_server_fd_bitmap_init() < 0) {
				qtfs_err("fd bitmap init failed.");
				write_unlock(&g_userp_rwlock);
				return QTERROR;
			}
			if (copy_from_user(&init_userp, (void __user *)arg, sizeof(struct qtfs_thread_init_s))) {
				qtfs_err("qtfs ioctl thread init copy from user failed.");
				write_unlock(&g_userp_rwlock);
				return QTERROR;
			}
			if (qtfs_userps == NULL || init_userp.thread_nums > QTFS_MAX_THREADS || init_userp.thread_nums == 0) {
				qtfs_err("qtfs ioctl thread init userps invalid thread nums:%d.", init_userp.thread_nums);
				write_unlock(&g_userp_rwlock);
				return QTERROR;
			}
			memset(qtfs_userps, 0, QTFS_MAX_THREADS * sizeof(struct qtfs_server_userp_s));
			if (init_userp.thread_nums > QTFS_MAX_THREADS) {
				qtfs_err("qtfs ioctl thread init invalid input thread_num:%d", init_userp.thread_nums);
				write_unlock(&g_userp_rwlock);
				return QTERROR;
			}
			if (copy_from_user(qtfs_userps, (void __user *)init_userp.userp,
							init_userp.thread_nums * sizeof(struct qtfs_server_userp_s))) {
				qtfs_err("qtfs ioctl thread init copy from userp failed.");
				write_unlock(&g_userp_rwlock);
				return QTERROR;
			}
			for (i = 0; i < init_userp.thread_nums; i++) {
				if (qtfs_userps[i].size > QTFS_USERP_MAXSIZE || 
					!access_ok(qtfs_userps[i].userp, qtfs_userps[i].size) || 
					!access_ok(qtfs_userps[i].userp2, qtfs_userps[i].size)) {
					qtfs_err("userp set failed");
					ret = QTERROR;
					write_unlock(&g_userp_rwlock);
					break;
				}
				qtfs_info("userp set idx:%d size:%lu", i, qtfs_userps[i].size);
			}
			write_unlock(&g_userp_rwlock);
			break;
		case QTFS_IOCTL_THREAD_RUN:
			pvar = qtfs_conn_get_param();
			if (pvar == NULL)
				return QTERROR;
			ret = qtfs_conn_server_run(pvar);
			if (ret == QTEXIT) {
				qtfs_warn("qtfs thread idx:%d exit.", pvar->cur_threadidx);
				qtfs_sm_exit(pvar);
				qtinfo_cntdec(QTINF_ACTIV_CONN);
			}
			qtfs_conn_put_param(pvar);
			break;
		case QTFS_IOCTL_EPFDSET:
			write_lock(&qtfs_epoll_rwlock);
			if (qtfs_epoll.kevents != NULL) {
				kfree(qtfs_epoll.kevents);
				qtfs_epoll.kevents = NULL;
			}
			if (copy_from_user(&qtfs_epoll, (void __user *)arg, sizeof(struct qtfs_server_epoll_s))) {
				qtfs_err("copy epoll struct from arg failed.");
				ret = QTERROR;
				write_unlock(&qtfs_epoll_rwlock);
				break;
			}
			if (qtfs_epoll.event_nums > QTFS_MAX_EPEVENTS_NUM || qtfs_epoll.event_nums == 0) {
				qtfs_err("epoll arg set failed, event nums:%d too big", qtfs_epoll.event_nums);
				ret = QTERROR;
				write_unlock(&qtfs_epoll_rwlock);
				break;
			}
			if (qtfs_epoll.epfd < 3) {
				qtfs_err("epoll epfd set failed, epfd:%d should be greater than 2", qtfs_epoll.epfd);
				ret = QTERROR;
				write_unlock(&qtfs_epoll_rwlock);
				break;
			}
			if (!access_ok(qtfs_epoll.events, qtfs_epoll.event_nums * sizeof(struct epoll_event))) {
				qtfs_err("epoll events set failed, check pointer of qtfs_epoll.events failed");
				ret = QTERROR;
				write_unlock(&qtfs_epoll_rwlock);
				break;
			}
			qtfs_info("epoll arg set, epfd:%d event nums:%d events.",
						qtfs_epoll.epfd, qtfs_epoll.event_nums);
			qtfs_epoll.kevents = (struct epoll_event *)kmalloc(sizeof(struct epoll_event) *
							qtfs_epoll.event_nums, GFP_KERNEL);
			if (qtfs_epoll.kevents == NULL) {
				qtfs_err("epoll kernel events kmalloc failed.");
				ret = QTERROR;
				write_unlock(&qtfs_epoll_rwlock);
				break;
			}
			write_unlock(&qtfs_epoll_rwlock);
			break;
		case QTFS_IOCTL_EPOLL_THREAD_INIT:
			write_lock(&qtfs_epoll_rwlock);
			ret = qtfs_server_epoll_init();
			write_unlock(&qtfs_epoll_rwlock);
			break;
		case QTFS_IOCTL_EPOLL_THREAD_RUN:
			write_lock(&qtfs_epoll_rwlock);
			if (qtfs_epoll_var == NULL) {
				qtfs_err("qtfs epoll thread run failed, var is invalid.");
				ret = QTERROR;
				write_unlock(&qtfs_epoll_rwlock);
				break;
			}
			ret = qtfs_server_epoll_thread(qtfs_epoll_var);
			write_unlock(&qtfs_epoll_rwlock);
			if (ret == QTEXIT) {
				qtfs_info("qtfs epoll thread exit.");
				qtfs_epoll_cut_conn(qtfs_epoll_var);
			}
			break;
		case QTFS_IOCTL_EXIT:
			if (arg != 0 && arg != 1) {
				qtfs_err("qtfs exit input invalid, should be 0 or 1.");
				ret = QTERROR;
				break;
			}
			write_lock(&g_whitelist_rwlock);
			for (i = 0; i < QTFS_WHITELIST_MAX; i++) {
				if (g_whitelist[i] != NULL) {
					kfree(g_whitelist[i]);
					g_whitelist[i] = NULL;
				}
			}
			write_unlock(&g_whitelist_rwlock);
			qtfs_info("qtfs server threads run set to:%lu.", arg);
			qtfs_server_thread_run = arg;
			break;
		case QTFS_IOCTL_WHITELIST:
			if (copy_from_user(&len, (void __user *)arg, sizeof(int))) {
				qtfs_err("qtfs ioctl white init copy from user failed.");
				return QTERROR;
			}
			if (len <= 0 || len > QTFS_WL_MAX_NUM) {
				qtfs_err("qtfs ioctl white list len:%d invalid", len);
				return QTERROR;
			}
			tmp = (struct whitelist *)kmalloc(sizeof(struct whitelist) + sizeof(struct wl_item) * len, GFP_KERNEL);
			if (!tmp) {
				qtfs_err("qtfs ioctl whitelist alloc memory failed.");
				return QTERROR;
			}
			if (copy_from_user(tmp, (void __user *)arg, sizeof(struct whitelist) + sizeof(struct wl_item) * len)) {
				qtfs_err("qtfs ioctl white init copy from user failed.");
				kfree(tmp);
				return QTERROR;
			}
			if (tmp->type >= QTFS_WHITELIST_MAX) {
				qtfs_err("qtfs white list type :%d invalid.", tmp->type);
				kfree(tmp);
				return QTERROR;
			}
			if (tmp->len != len) {
				qtfs_err("memory of qtfs white list from engine was tampered.");
				kfree(tmp);
				return QTERROR;
			}
			write_lock(&g_whitelist_rwlock);
			if (g_whitelist[tmp->type] != NULL) {
				kfree(g_whitelist[tmp->type]);
				g_whitelist[tmp->type] = NULL;
			}
			g_whitelist[tmp->type] = tmp;
			for (i = 0; i < g_whitelist[tmp->type]->len; i++) {
				if (strnlen(g_whitelist[tmp->type]->wl[i].path, WHITELIST_MAX_PATH_LEN) != g_whitelist[tmp->type]->wl[i].len) {
					g_whitelist[tmp->type] = NULL;
					kfree(tmp);
					write_unlock(&g_whitelist_rwlock);
					return QTERROR;
				}
				qtfs_info("init %d list:%d %s", tmp->type, i, g_whitelist[tmp->type]->wl[i].path);
			}
			write_unlock(&g_whitelist_rwlock);
			break;
		case QTFS_IOCTL_ALLINFO:
		case QTFS_IOCTL_CLEARALL:
		case QTFS_IOCTL_LOGLEVEL:
		case QTFS_IOCTL_QTSOCK_WL_ADD:
		case QTFS_IOCTL_QTSOCK_WL_DEL:
		case QTFS_IOCTL_QTSOCK_WL_GET:
			ret = qtfs_misc_ioctl(file, cmd, arg);
			break;
		default:
			qtfs_err("qtfs misc ioctl unknown cmd:%u.", cmd);
			ret = QTERROR;
			break;
	}

	return ret;
}

static int __init qtfs_server_init(void)
{
	int i;
	qtfs_log_init(qtfs_log_level, sizeof(qtfs_log_level));
	if (qtfs_kallsyms_hack_init() != 0)
		return -1;
	rwlock_init(&g_whitelist_rwlock);
	rwlock_init(&qtfs_epoll_rwlock);

 	write_lock(&g_whitelist_rwlock);
	for (i = 0; i < QTFS_WHITELIST_MAX; i++) {
		g_whitelist[i] = NULL;
	}
	write_unlock(&g_whitelist_rwlock);

	qtfs_diag_info = (struct qtinfo *)kmalloc(sizeof(struct qtinfo), GFP_KERNEL);
	if (qtfs_diag_info == NULL) {
		qtfs_err("kmalloc qtfs diag info failed.");
		return -1;
	}
	memset(qtfs_diag_info, 0, sizeof(struct qtinfo));
	qtfs_userps = (struct qtfs_server_userp_s *)kmalloc(
				QTFS_MAX_THREADS * sizeof(struct qtfs_server_userp_s), GFP_KERNEL);
	if (qtfs_userps == NULL) {
		qtfs_err("kmalloc qtfs userps failed, nums:%d", QTFS_MAX_THREADS);
		kfree(qtfs_diag_info);
		return -1;
	}
	memset(qtfs_userps, 0, QTFS_MAX_THREADS * sizeof(struct qtfs_server_userp_s));
	qtfs_fd_bitmap.bitmap = NULL;
	qtfs_fd_bitmap.nbits = 0;
	qtfs_conn_param_init();
	if (qtfs_syscall_replace_start()) {
		qtfs_err("qtfs syscall replace failed.");
		goto err_syscall;
	}
	if (qtfs_misc_register()) {
		qtfs_err("qtfs misc device register failed.");
		goto err_misc;
	}
	if (qtfs_uds_remote_init()) {
		qtfs_err("qtfs uds remote initialization failed.");
		goto err;
	}
	return 0;
err:
	qtfs_misc_destroy();
err_misc:
	qtfs_syscall_replace_stop();
err_syscall:
	kfree(qtfs_userps);
	kfree(qtfs_diag_info);
	return -1;
}

static void __exit qtfs_server_exit(void)
{
	int i;
	qtfs_mod_exiting = true;
	qtfs_server_thread_run = 0;

	qtfs_conn_param_fini();

	if (qtfs_epoll_var != NULL) {
		qtfs_epoll_cut_conn(qtfs_epoll_var);
		qtfs_conn_fini(qtfs_epoll_var);
		qtfs_epoll_var->conn_ops->conn_var_fini(qtfs_epoll_var);
		kfree(qtfs_epoll_var);
		qtfs_epoll_var = NULL;
	}
	if (qtfs_diag_info != NULL) {
		kfree(qtfs_diag_info);
		qtfs_diag_info = NULL;
	}
	write_lock(&g_userp_rwlock);
	if (qtfs_userps != NULL) {
		kfree(qtfs_userps);
		qtfs_userps = NULL;
	}
	if (qtfs_fd_bitmap.bitmap != NULL) {
		kfree(qtfs_fd_bitmap.bitmap);
		qtfs_fd_bitmap.bitmap = NULL;
		qtfs_fd_bitmap.nbits = 0;
	}
	write_unlock(&g_userp_rwlock);

	write_lock(&g_whitelist_rwlock);
	for (i = 0; i < QTFS_WHITELIST_MAX; i++) {
		if (g_whitelist[i] != NULL) {
			kfree(g_whitelist[i]);
		}
	}
	write_unlock(&g_whitelist_rwlock);
	qtfs_misc_destroy();
	qtfs_uds_remote_exit();
	qtfs_syscall_replace_stop();
	qtfs_info("qtfs server exit done.\n");
	return;
}

#ifdef QTFS_TEST_MODE
module_param_string(qtfs_server_ip, qtfs_server_ip, sizeof(qtfs_server_ip), 0600);
MODULE_PARM_DESC(qtfs_server_ip, "qtfs server ip");
module_param(qtfs_server_port, int, 0600);
#else
module_param(qtfs_server_vsock_port, uint, 0600);
module_param(qtfs_server_vsock_cid, uint, 0600);
#endif

module_param(qtfs_conn_max_conn, int, 0600);
module_param_string(qtfs_log_level, qtfs_log_level, sizeof(qtfs_log_level), 0600);
module_param_string(qtfs_conn_type, qtfs_conn_type, sizeof(qtfs_conn_type), 0600);

module_init(qtfs_server_init);
module_exit(qtfs_server_exit);
MODULE_AUTHOR("liqiang64@huawei.com");
MODULE_LICENSE("GPL");
