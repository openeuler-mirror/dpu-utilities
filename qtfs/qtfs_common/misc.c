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

#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

#include "comm.h"
#include "log.h"
#include "req.h"
#include "conn.h"

struct qtfs_wl g_qtfs_wl;

extern struct file_operations qtfs_misc_fops;
struct mutex qtfs_diag_info_lock;

static struct miscdevice qtfs_misc_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
#ifndef QTFS_CLIENT
	.name	= "qtfs_server",
#else
	.name	= "qtfs_client",
#endif
	.fops	= &qtfs_misc_fops,
};

int qtfs_misc_register(void)
{
	int ret = misc_register(&qtfs_misc_dev);
	if (ret) {
		qtfs_err("qtfs misc register failed, ret:%d.", ret);
		return -EFAULT;
	}
	mutex_init(&qtfs_diag_info_lock);
	return 0;
}

void qtfs_misc_destroy(void)
{
	misc_deregister(&qtfs_misc_dev);
	return;
}

void qtfs_misc_flush_threadstate(void)
{
	int i;
	for (i = 0; i < QTFS_MAX_THREADS; i++) {
		if (qtfs_thread_var[i] == NULL) {
			qtfs_diag_info->thread_state[i] = -1;
			continue;
		}
		qtfs_diag_info->thread_state[i] = qtfs_thread_var[i]->state;
	}
	qtfs_diag_info->epoll_state = (qtfs_epoll_var == NULL) ? -1 : qtfs_epoll_var->state;
}

void qtfs_req_size(void)
{
	qtfs_diag_info->req_size[QTFS_REQ_NULL] = sizeof(struct qtreq);
	qtfs_diag_info->req_size[QTFS_REQ_IOCTL] = sizeof(struct qtreq_ioctl);
	qtfs_diag_info->req_size[QTFS_REQ_STATFS] = sizeof(struct qtreq_statfs);
	qtfs_diag_info->req_size[QTFS_REQ_MOUNT] = sizeof(struct qtreq_mount);
	qtfs_diag_info->req_size[QTFS_REQ_OPEN] = sizeof(struct qtreq_open);
	qtfs_diag_info->req_size[QTFS_REQ_CLOSE] = sizeof(struct qtreq_close);
	qtfs_diag_info->req_size[QTFS_REQ_READITER] = sizeof(struct qtreq_readiter);
	qtfs_diag_info->req_size[QTFS_REQ_WRITE] = sizeof(struct qtreq_write);
	qtfs_diag_info->req_size[QTFS_REQ_LOOKUP] = sizeof(struct qtreq_lookup);
	qtfs_diag_info->req_size[QTFS_REQ_READDIR] = sizeof(struct qtreq_readdir);
	qtfs_diag_info->req_size[QTFS_REQ_MKDIR] = sizeof(struct qtreq_mkdir);
	qtfs_diag_info->req_size[QTFS_REQ_RMDIR] = sizeof(struct qtreq_rmdir);
	qtfs_diag_info->req_size[QTFS_REQ_GETATTR] = sizeof(struct qtreq_getattr);
	qtfs_diag_info->req_size[QTFS_REQ_SETATTR] = sizeof(struct qtreq_setattr);
	qtfs_diag_info->req_size[QTFS_REQ_ICREATE] = sizeof(struct qtreq_icreate);
	qtfs_diag_info->req_size[QTFS_REQ_MKNOD] = sizeof(struct qtreq_mknod);
	qtfs_diag_info->req_size[QTFS_REQ_UNLINK] = sizeof(struct qtreq_unlink);
	qtfs_diag_info->req_size[QTFS_REQ_SYMLINK] = sizeof(struct qtreq_symlink);
	qtfs_diag_info->req_size[QTFS_REQ_LINK] = sizeof(struct qtreq_link);
	qtfs_diag_info->req_size[QTFS_REQ_GETLINK] = sizeof(struct qtreq_getlink);
	qtfs_diag_info->req_size[QTFS_REQ_RENAME] = sizeof(struct qtreq_rename);
	qtfs_diag_info->req_size[QTFS_REQ_XATTRLIST] = sizeof(struct qtreq_xattrlist);
	qtfs_diag_info->req_size[QTFS_REQ_XATTRGET] = sizeof(struct qtreq_xattrget);
	qtfs_diag_info->req_size[QTFS_REQ_SYSMOUNT] = sizeof(struct qtreq_sysmount);
	qtfs_diag_info->req_size[QTFS_REQ_SYSUMOUNT] = sizeof(struct qtreq_sysumount);
	qtfs_diag_info->req_size[QTFS_REQ_FIFOPOLL] = sizeof(struct qtreq_poll);
	qtfs_diag_info->req_size[QTFS_REQ_EPOLL_CTL] = sizeof(struct qtreq_epollctl);
	qtfs_diag_info->req_size[QTFS_REQ_EPOLL_EVENT] = sizeof(struct qtreq_epollevt);

	qtfs_diag_info->rsp_size[QTFS_REQ_NULL] = sizeof(struct qtreq);
	qtfs_diag_info->rsp_size[QTFS_REQ_IOCTL] = sizeof(struct qtrsp_ioctl);
	qtfs_diag_info->rsp_size[QTFS_REQ_STATFS] = sizeof(struct qtrsp_statfs);
	qtfs_diag_info->rsp_size[QTFS_REQ_MOUNT] = sizeof(struct qtrsp_mount);
	qtfs_diag_info->rsp_size[QTFS_REQ_OPEN] = sizeof(struct qtrsp_open);
	qtfs_diag_info->rsp_size[QTFS_REQ_CLOSE] = sizeof(struct qtrsp_close);
	qtfs_diag_info->rsp_size[QTFS_REQ_READITER] = sizeof(struct qtrsp_readiter);
	qtfs_diag_info->rsp_size[QTFS_REQ_WRITE] = sizeof(struct qtrsp_write);
	qtfs_diag_info->rsp_size[QTFS_REQ_LOOKUP] = sizeof(struct qtrsp_lookup);
	qtfs_diag_info->rsp_size[QTFS_REQ_READDIR] = sizeof(struct qtrsp_readdir);
	qtfs_diag_info->rsp_size[QTFS_REQ_MKDIR] = sizeof(struct qtrsp_mkdir);
	qtfs_diag_info->rsp_size[QTFS_REQ_RMDIR] = sizeof(struct qtrsp_rmdir);
	qtfs_diag_info->rsp_size[QTFS_REQ_GETATTR] = sizeof(struct qtrsp_getattr);
	qtfs_diag_info->rsp_size[QTFS_REQ_SETATTR] = sizeof(struct qtrsp_setattr);
	qtfs_diag_info->rsp_size[QTFS_REQ_ICREATE] = sizeof(struct qtrsp_icreate);
	qtfs_diag_info->rsp_size[QTFS_REQ_MKNOD] = sizeof(struct qtrsp_mknod);
	qtfs_diag_info->rsp_size[QTFS_REQ_UNLINK] = sizeof(struct qtrsp_unlink);
	qtfs_diag_info->rsp_size[QTFS_REQ_SYMLINK] = sizeof(struct qtrsp_symlink);
	qtfs_diag_info->rsp_size[QTFS_REQ_LINK] = sizeof(struct qtrsp_link);
	qtfs_diag_info->rsp_size[QTFS_REQ_GETLINK] = sizeof(struct qtrsp_getlink);
	qtfs_diag_info->rsp_size[QTFS_REQ_RENAME] = sizeof(struct qtrsp_rename);
	qtfs_diag_info->rsp_size[QTFS_REQ_XATTRLIST] = sizeof(struct qtrsp_xattrlist);
	qtfs_diag_info->rsp_size[QTFS_REQ_XATTRGET] = sizeof(struct qtrsp_xattrget);
	qtfs_diag_info->rsp_size[QTFS_REQ_SYSMOUNT] = sizeof(struct qtrsp_sysmount);
	qtfs_diag_info->rsp_size[QTFS_REQ_SYSUMOUNT] = sizeof(struct qtrsp_sysumount);
	qtfs_diag_info->rsp_size[QTFS_REQ_FIFOPOLL] = sizeof(struct qtrsp_poll);
	qtfs_diag_info->rsp_size[QTFS_REQ_EPOLL_CTL] = sizeof(struct qtrsp_epollctl);
	qtfs_diag_info->rsp_size[QTFS_REQ_EPOLL_EVENT] = sizeof(struct qtrsp_epollevt);
}

void qtfs_whitelist_initset(void)
{
	int type;
	rwlock_init(&g_qtfs_wl.rwlock);
	for (type = 0; type < QTFS_WHITELIST_MAX; type++) {
		memset(&g_qtfs_wl.cap[type], 0, sizeof(struct qtfs_wl_cap));
	}
	return;
}

static int qtfs_whitelist_dup_check(char *tar, struct qtfs_wl_cap *cap)
{
	int i;
	for (i = 0; i < cap->nums; i++) {
		if (strncmp(tar, cap->item[i], QTFS_PATH_MAX - 1) == 0)
			return 1;
	}
	return 0;
}

static int qtfs_whitelist_add(struct qtfs_wl_item *uitem)
{
	// uitem->type is checked
	struct qtfs_wl_cap *cap = &g_qtfs_wl.cap[uitem->type];
	write_lock(&g_qtfs_wl.rwlock);
	if (cap->nums >= QTFS_WL_MAX_NUM) {
		qtfs_err("qtfs add white list failed, nums:%u reach upper limit:%d", cap->nums, QTFS_WL_MAX_NUM);
		goto err_end;
	}
	cap->item[cap->nums] = (char *)kmalloc(uitem->len + 1, GFP_KERNEL);
	if (IS_ERR_OR_NULL(cap->item[cap->nums])) {
		qtfs_err("kmalloc error");
		goto err_end;
	}
	memset(cap->item[cap->nums], 0, uitem->len + 1);
	if (copy_from_user(cap->item[cap->nums], uitem->path, uitem->len) ||
			qtfs_whitelist_dup_check(cap->item[cap->nums], cap) == 1) {
		qtfs_err("copy from user failed or item is a duplicate, len:%u type:%u", uitem->len, uitem->type);
		kfree(cap->item[cap->nums]);
		cap->item[cap->nums] = NULL;
		goto err_end;
	}
	qtfs_info("Successed to add white list type:%u len:%u path:[%s]", uitem->type, uitem->len, cap->item[cap->nums]);
	cap->nums++;
	write_unlock(&g_qtfs_wl.rwlock);
	return 0;

err_end:
	write_unlock(&g_qtfs_wl.rwlock);
	return -1;
}

static int qtfs_whitelist_del(struct qtfs_wl_item *uitem)
{
	// type is checked
	struct qtfs_wl_cap *cap = &g_qtfs_wl.cap[uitem->type];
	write_lock(&g_qtfs_wl.rwlock);
	if (uitem->index >= cap->nums) {
		qtfs_err("White list del type:%u nums:%u, invalid index:%u", uitem->type, cap->nums, uitem->index);
		goto err_end;
	}
	// free target index
	kfree(cap->item[uitem->index]);
	cap->item[uitem->index] = NULL;
	if (cap->nums > 1) {
		// if nums > 1 move last one to fill the hole
		cap->item[uitem->index] = cap->item[cap->nums - 1];
		cap->item[cap->nums - 1] = NULL;
	}
	qtfs_info("white list del type:%u total nums:%u delindex:%u", uitem->type, cap->nums, uitem->index);

	cap->nums--;
	write_unlock(&g_qtfs_wl.rwlock);
	return 0;
err_end:
	write_unlock(&g_qtfs_wl.rwlock);
	return -1;
}

static int qtfs_whitelist_get(struct qtfs_wl_item *uitem)
{
	// type is checked
	struct qtfs_wl_cap *cap = &g_qtfs_wl.cap[uitem->type];
	int len;
	read_lock(&g_qtfs_wl.rwlock);
	if (uitem->index >= cap->nums) {
		qtfs_err("query white list invalid index:%u type:%u total nums:%u", uitem->index, uitem->type, cap->nums);
		goto err_end;
	}
	len = strlen(cap->item[uitem->index]);
	if (!access_ok(uitem->path, len)) {
		qtfs_err("white list query pointer of userspace is not valid type:%u index:%u len:%d", uitem->type, uitem->index, len);
		goto err_end;
	}
	if (copy_to_user(uitem->path, cap->item[uitem->index], len)) {
		qtfs_err("white list query copy to user failed, type:%u index:%u len:%d", uitem->type, uitem->index, len);
		goto err_end;
	}
	qtfs_info("white list query type:%u total nums:%u index:%u len:%d", uitem->type, cap->nums, uitem->index, len);
	read_unlock(&g_qtfs_wl.rwlock);
	return 0;

err_end:
	read_unlock(&g_qtfs_wl.rwlock);
	return -1;
}

void qtfs_whitelist_clearall(void)
{
	struct qtfs_wl_cap *cap = NULL;
	int type;
	int item;
	write_lock(&g_qtfs_wl.rwlock);
	for (type = 0; type < QTFS_WHITELIST_MAX; type++) {
		cap = &g_qtfs_wl.cap[type];
		for (item = 0; item < cap->nums; item++) {
			kfree(cap->item[item]);
			cap->item[item] = NULL;
		}
		cap->nums = 0;
	}
	write_unlock(&g_qtfs_wl.rwlock);
	return;
}

long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = QTOK;
	qtfs_info("qtfs client misc ioctl.");
	switch (cmd) {
		case QTFS_IOCTL_ALLINFO:
			mutex_lock(&qtfs_diag_info_lock);
			if (qtfs_diag_info == NULL) {
				qtfs_err("ioctl allinfo failed, qtfs_diag_info is invalid.");
				mutex_unlock(&qtfs_diag_info_lock);
				goto err_end;
			}
			qtfs_req_size();
			qtfs_diag_info->log_level = log_level;
			qtfs_misc_flush_threadstate();
			qtfs_conn_list_cnt();
			if (copy_to_user((void *)arg, qtfs_diag_info, sizeof(struct qtinfo))) {
				qtfs_err("ioctl allinfo copy to user failed.");
				mutex_unlock(&qtfs_diag_info_lock);
				goto err_end;
			}
			mutex_unlock(&qtfs_diag_info_lock);
			break;
		case QTFS_IOCTL_CLEARALL:
			mutex_lock(&qtfs_diag_info_lock);
			qtinfo_clear();
			mutex_unlock(&qtfs_diag_info_lock);
			break;
		case QTFS_IOCTL_LOGLEVEL: {
			char level_str[QTFS_LOGLEVEL_STRLEN] = {0};
			if (arg == 0 || copy_from_user(level_str, (void *)arg, QTFS_LOGLEVEL_STRLEN - 1)) {
				qtfs_err("ioctl set log level failed, arg:%lu.", arg);
				goto err_end;
			}
			ret = (long)qtfs_log_init(level_str, QTFS_LOGLEVEL_STRLEN);
			break;
		}
		case QTFS_IOCTL_EPOLL_SUPPORT:
			if (arg == 0) {
				qtfs_epoll_mode = false;
			} else {
				qtfs_epoll_mode = true;
			}
			break;
		case QTFS_IOCTL_WL_ADD: {
			struct qtfs_wl_item head;
			if (copy_from_user(&head, (void *)arg, sizeof(struct qtfs_wl_item))) {
				qtfs_err("ioctl wl add copy from user failed");
				goto err_end;
			}
			if (head.len == 0 || head.len == MAX_PATH_LEN || head.type >= QTFS_WHITELIST_MAX ||
					!access_ok(head.path, head.len)) {
				qtfs_err("ioctl wl add len:%u type:%u invalid", head.len, head.type);
				goto err_end;
			}
			if (qtfs_whitelist_add(&head) != 0) {
				qtfs_err("ioctl wl add failed!");
				goto err_end;
			}
			break;
		}
		case QTFS_IOCTL_WL_DEL:
		case QTFS_IOCTL_WL_GET: {
			struct qtfs_wl_item head;
			if (copy_from_user(&head, (void *)arg, sizeof(struct qtfs_wl_item))) {
				qtfs_err("ioctl wl del copy from user failed");
				goto err_end;
			}
			if (head.type >= QTFS_WHITELIST_MAX) {
				qtfs_err("ioctl wl del invalid type:%u", head.type);
				goto err_end;
			}
			if (cmd == QTFS_IOCTL_WL_DEL) {
				if (qtfs_whitelist_del(&head) != 0) {
					qtfs_err("ioctl wl del failed!");
					goto err_end;
				}
			} else {
				if (qtfs_whitelist_get(&head) != 0) {
					qtfs_err("ioctl wl get failed!");
					goto err_end;
				}
			}
			break;
		}
	}
	return ret;
err_end:
	return QTERROR;
}
