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

#include "conn.h"
#include "log.h"
#include "qtfs_utils.h"
#include "req.h"
#include "qtfs-mod.h"

#ifndef QTFS_CLIENT
#error "QTFS utils only use in qtfs client."
#endif

long qtfs_utils_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
long qtfs_capability_ioctl(struct qtfs_conn_var_s *pvar, struct file *file, unsigned int cmd, unsigned long arg);
long qtfs_syscall_ioctl(struct qtfs_conn_var_s *pvar, struct file *file, unsigned int cmd, unsigned long arg);

struct file_operations qtfs_utils_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = qtfs_utils_ioctl,
};

static struct miscdevice qtfs_utils_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "qtfs_utils",
	.fops = &qtfs_utils_fops,
};

int qtfs_utils_register(void)
{
	int ret = misc_register(&qtfs_utils_dev);

	if (ret) {
		qtfs_err("qtfs utils dev register failed, ret:%d", ret);
		return -EFAULT;
	}
	return 0;
}

void qtfs_utils_destroy(void)
{
	misc_deregister(&qtfs_utils_dev);

	return;
}

long qtfs_utils_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = -EINVAL;
	struct qtfs_conn_var_s *pvar = qtfs_conn_get_param();

	if (pvar == NULL) {
		qtfs_err("utils ioctl get pvar failed, cmd type:%c nr:%d", _IOC_TYPE(cmd), _IOC_NR(cmd));
		return -EFAULT;
	}
	switch (_IOC_TYPE(cmd)) {
		case QTUTIL_IOCTL_CAPA_MAGIC:
			ret = qtfs_capability_ioctl(pvar, file, cmd, arg);
			qtfs_info("utils capability ioctl nr:%d", _IOC_NR(cmd));
			break;

		case QTUTIL_IOCTL_SC_MAGIC:
			ret = qtfs_syscall_ioctl(pvar, file, cmd, arg);
			qtfs_info("utils syscall ioctl nr:%d", _IOC_NR(cmd));
			break;

		default:
			qtfs_err("Unsupport magic type:%c", _IOC_TYPE(cmd));
			break;
	}
	qtfs_conn_put_param(pvar);
	return ret;
}

long qtfs_capability_ioctl(struct qtfs_conn_var_s *pvar, struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = -ENOTSUPP;
	return ret;
}

static long qtfs_sc_kill(struct qtfs_conn_var_s *pvar, unsigned long arg)
{
	struct qtreq_sc_kill *req;
	struct qtrsp_sc_kill *rsp;
	struct qtsc_kill karg;

	if (copy_from_user(&karg, (void *)arg, sizeof(struct qtsc_kill))) {
		qtfs_err("copy args failed.");
		return -EINVAL;
	}
	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	req->pid = karg.pid;
	req->signum = karg.signum;
	rsp = qtfs_remote_run(pvar, QTFS_SC_KILL, sizeof(struct qtreq_sc_kill));
	if (IS_ERR_OR_NULL(rsp)) {
		qtfs_err("qtfs remote kill faile.");
		return -EFAULT;
	}
	qtfs_info("qtfs remote kill pid:%d sig:%d success:%ld", req->pid, req->signum, rsp->ret);
	return rsp->ret;
}

static long qtfs_sc_setaffinity(struct qtfs_conn_var_s *pvar, unsigned long arg)
{
	struct qtreq_sc_sched_affinity *req;
	struct qtrsp_sc_sched_affinity *rsp;
	struct qtsc_sched_affinity karg;

	if (copy_from_user(&karg, (void *)arg, sizeof(struct qtsc_sched_affinity))) {
		qtfs_err("copy args failed.");
		return -EINVAL;
	}

	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	req->type = SC_SET;
	req->pid = karg.pid;
	req->len = (karg.len > AFFINITY_MAX_LEN) ? AFFINITY_MAX_LEN : karg.len;
	if (copy_from_user(req->user_mask_ptr, karg.user_mask_ptr, req->len)) {
		qtfs_err("copy from user mask ptr failed, len:%u", karg.len);
		return -EFAULT;
	}
	rsp = qtfs_remote_run(pvar, QTFS_SC_SCHED_SETAFFINITY, sizeof(struct qtreq_sc_sched_affinity) + karg.len * sizeof(unsigned long));
	if (IS_ERR_OR_NULL(rsp)) {
		qtfs_err("qtfs remote set affinit failed, pid:%d len:%u", karg.pid, karg.len);
		return -EFAULT;
	}
	qtfs_info("qtfs remote set affinity successed pid:%d len:%u return:%ld", karg.pid, karg.len, rsp->ret);
	return rsp->ret;
}

static long qtfs_sc_getaffinity(struct qtfs_conn_var_s *pvar, unsigned long arg)
{
	struct qtreq_sc_sched_affinity *req;
	struct qtrsp_sc_sched_affinity *rsp;
	struct qtsc_sched_affinity karg;

	if (copy_from_user(&karg, (void *)arg, sizeof(struct qtsc_sched_affinity))) {
		qtfs_err("copy args failed.");
		return -EINVAL;
	}

	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	req->type = SC_GET;
	req->pid = karg.pid;
	req->len = (karg.len > AFFINITY_MAX_LEN) ? AFFINITY_MAX_LEN : karg.len;
	rsp = qtfs_remote_run(pvar, QTFS_SC_SCHED_GETAFFINITY, sizeof(struct qtreq_sc_sched_affinity));
	if (IS_ERR_OR_NULL(rsp)) {
		qtfs_err("qtfs remote get affinit failed, pid:%d len:%u", karg.pid, karg.len);
		return -EFAULT;
	}
	// len == 0 means failed
	if (rsp->len <= 0 || rsp->len > req->len ||
			copy_to_user(karg.user_mask_ptr, rsp->user_mask_ptr, rsp->len)) {
		qtfs_err("copy user mask ptr failed rsp len:%u valid len:%u", rsp->len, karg.len);
		return -EINVAL;
	}
	return rsp->ret;
}

long qtfs_syscall_ioctl(struct qtfs_conn_var_s *pvar, struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = -EINVAL;

	switch (cmd) {
		case QTUTIL_SC_KILL:
			ret = qtfs_sc_kill(pvar, arg);
			break;

		case QTUTIL_SC_SCHED_SETAFFINITY:
			ret = qtfs_sc_setaffinity(pvar, arg);
			break;

		case QTUTIL_SC_SCHED_GETAFFINITY:
			ret = qtfs_sc_getaffinity(pvar, arg);
			break;

		default:
			qtfs_err("syscall ioctl not support magic:%c number:%d", _IOC_TYPE(cmd), _IOC_NR(cmd));
			break;
	}
	return ret;
}

