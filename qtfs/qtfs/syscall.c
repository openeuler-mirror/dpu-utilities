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

#include <linux/compiler_types.h>
#include <linux/syscalls.h>
#include <linux/trace_events.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/eventpoll.h>
#include <linux/atomic.h>

#include "conn.h"
#include "qtfs-mod.h"
#include "symbol_wrapper.h"

static long qtfs_remote_mount(char __user *dev_name, char __user *dir_name, char __user *type,
		unsigned long flags, void __user *data);
static int qtfs_remote_umount(char __user *name, int flags);

#ifdef BEFORE_KVER_5_6
static inline int ep_op_has_event(int op)
{
	return op != EPOLL_CTL_DEL;
}
#endif

static char *qtfs_copy_mount_string(const void __user *data)
{
	return data ? strndup_user(data, PATH_MAX) : NULL;
}

static inline int qtfs_fstype_judgment(char __user *dir)
{
	struct path path;
	int ret;

	ret = user_path_at(AT_FDCWD, dir, LOOKUP_FOLLOW, &path);
	if (ret)
		return 0;

	if (path.mnt && path.mnt->mnt_sb &&
			path.mnt->mnt_sb->s_type && path.mnt->mnt_sb->s_type->name &&
			strcmp(path.mnt->mnt_sb->s_type->name, QTFS_FSTYPE_NAME) == 0) {
		qtfs_info("qtfs fstype judge <%s> is qtfs.\n", path.dentry->d_iname);
		path_put(&path);
		return 1;
	}
	path_put(&path);

	return 0;
}

/* if this dir is root node of qtfs */
static inline int qtfs_root_judgment(char __user *dir)
{
	struct dentry *dentry;
	struct path path;
	int ret = 0;

	ret = user_path_at(AT_FDCWD, dir, LOOKUP_FOLLOW, &path);
	if (ret)
		return 0;

	dentry = path.dentry;
	if (dentry->d_parent == dentry)
		ret = 1;
	path_put(&path);

	return ret;
}

static void do_epoll_ctl_remote(int op, struct epoll_event __user *event, struct file *file)
{
	struct qtreq_epollctl *req;
	struct qtrsp_epollctl *rsp;
	struct qtfs_conn_var_s *pvar = qtfs_conn_get_param();
	struct private_data *priv = file->private_data;
	struct epoll_event tmp;

	if (pvar == NULL) {
		qtfs_err("qtfs do epoll ctl remote get pvar failed.");
		return;
	}
	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	req->fd = priv->fd;
	req->op = op;
	if (ep_op_has_event(op) && copy_from_user(&tmp, event, sizeof(struct epoll_event))) {
		qtfs_err("qtfs do epoll ctl remote copy from user failed.");
		qtfs_conn_put_param(pvar);
		return;
	}
	req->event.events = tmp.events;
	req->event.data = (__u64)file;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_EPOLL_CTL, sizeof(struct qtreq_epollctl));
	if (IS_ERR_OR_NULL(rsp) || rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs do epoll ctl remote failed.");
		qtfs_conn_put_param(pvar);
		qtinfo_cntinc(QTINF_EPOLL_FDERR);
		return;
	}
	if (op == EPOLL_CTL_ADD) {
		qtinfo_cntinc(QTINF_EPOLL_ADDFDS);
	} else {
		qtinfo_cntinc(QTINF_EPOLL_DELFDS);
	}
	qtfs_info("qtfs do epoll ctl remote success, fd:%d.", req->fd);
	qtfs_conn_put_param(pvar);
	return;
}

int qtfs_epoll_ctl_remote(int op, int fd, struct epoll_event __user * event)
{
	struct fd f;
	struct file *file;
	struct private_data *priv;
	int ret = 0;
	f = fdget(fd);
	if (!f.file) {
		return -1;
	}
	file = f.file;
	if (strcmp(file->f_path.mnt->mnt_sb->s_type->name, QTFS_FSTYPE_NAME) != 0) {
		ret = 0;
		goto end;
	}
	if (!qtfs_support_epoll(file->f_inode->i_mode)) {
		char *fullname = (char *)kmalloc(MAX_PATH_LEN, GFP_KERNEL);
		if (!fullname) {
			ret = -1;
			goto end;
		}
		memset(fullname, 0, MAX_PATH_LEN);
		if (qtfs_fullname(fullname, file->f_path.dentry, MAX_PATH_LEN) < 0) {
			qtfs_err("qtfs fullname failed\n");
			kfree(fullname);
			ret = -1;
			goto end;
		}
		qtfs_info("qtfs remote epoll not support file:%s mode:%o.", fullname, file->f_inode->i_mode);
		kfree(fullname);
		ret = -1;
		goto end;
	}

	priv = file->private_data;
	if (priv == NULL) {
		qtfs_err("epoll ctl remote failed, private data invalid.");
		ret = -1;
		goto end;
	}

	qtfs_info("qtfs qtfs remote epoll file:%s mode:%x file can poll.",
				file->f_path.dentry->d_iname, file->f_inode->i_mode);
	do_epoll_ctl_remote(op, event, file);

end:
	fdput(f);
	return ret;
}

__SYSCALL_DEFINEx(4, _qtfs_epoll_ctl, int, epfd, int, op, int, fd,
	struct epoll_event __user *, event)
{
	int ret = -1;

	ret = qtfs_epoll_ctl_remote(op, fd, event);
	if (!ret) {
		return qtfs_syscall_epoll_ctl(epfd, op, fd, event);
	} else {
		return -1;
	}
}

__SYSCALL_DEFINEx(5, _qtfs_mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	char *kernel_dev;
	void *options = NULL;

	// if both dev_name and dir_name are qtfs, it is a remote mount operator.
	kernel_type = qtfs_copy_mount_string(type);
	ret = PTR_ERR(kernel_type);
	if (IS_ERR(kernel_type))
		goto out_type;

	kernel_dev = qtfs_copy_mount_string(dev_name);
	ret = PTR_ERR(kernel_dev);
	if (IS_ERR(kernel_dev))
		goto out_dev;

	options = qtfs_copy_mount_string(data);
	ret = PTR_ERR(options);
	if (IS_ERR(options))
		goto out_data;

	// if both dev_name and dir_name are qtfs, it is a remote mount operator,
	if (qtfs_fstype_judgment(dir_name) == 1) {
		ret = qtfs_remote_mount(kernel_dev, dir_name, kernel_type, flags, options);
		goto remote_mount;
	}

	ret = qtfs_syscall_mount(dev_name, dir_name, type, flags, data);

remote_mount:
	kfree(options);
out_data:
	kfree(kernel_dev);
out_dev:
	kfree(kernel_type);
out_type:
	return ret;
}

__SYSCALL_DEFINEx(2, _qtfs_umount, char __user *, name, int, flags)
{
	// basic validate checks done first
	if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
		return -EINVAL;

	/* if umount path is qtfs and not qtfs root, then do remote umount */
	if (qtfs_fstype_judgment(name) && !qtfs_root_judgment(name)) {
		return qtfs_remote_umount(name, flags);
	}

	return qtfs_syscall_umount(name, flags);
}

int qtfs_dir_to_qtdir(char *dir, char *qtdir, size_t len)
{
	int ret = 0;
	struct path path;

	if (strlen(dir) + 1 > len) {
		strlcpy(qtdir, dir, len);
		return -EINVAL;
	}
	ret = kern_path(dir, 0, &path);
	if (ret) {
		strlcpy(qtdir, dir, len);
		return 0;
	}
	if (strcmp(path.mnt->mnt_sb->s_type->name, QTFS_FSTYPE_NAME)) {
		strlcpy(qtdir, dir, len);
	} else {
		ret = qtfs_fullname(qtdir, path.dentry, len);
	}
	path_put(&path);
	return ret;
}

static size_t qtfs_strlen(const char *s)
{
	if (s == NULL)
		return 0;
	return strlen(s);
}

static long qtfs_remote_mount(char *dev_name, char __user *dir_name, char *type,
		unsigned long flags, void *data)
{
	struct qtfs_conn_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_sysmount *req;
	struct qtrsp_sysmount *rsp = NULL;
	char *kernel_dir;
	int ret;
	size_t totallen;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}
	kernel_dir = qtfs_copy_mount_string(dir_name);
	if (IS_ERR_OR_NULL(kernel_dir)) {
		qtfs_conn_put_param(pvar);
		return -EINVAL;
	}
	totallen = qtfs_strlen(dev_name) + qtfs_strlen(kernel_dir) + qtfs_strlen(type) + qtfs_strlen(data) + 4;
	if (totallen > sizeof(req->buf)) {
		qtfs_err("qtfs remote mount devname:%s, dir_name:%s failed, options too long.\n", dev_name, kernel_dir);
		kfree(kernel_dir);
		qtfs_conn_put_param(pvar);
		return -EINVAL;
	}

	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	if (dev_name != NULL) {
		qtfs_dir_to_qtdir(dev_name, req->buf, sizeof(req->buf));
		req->d.dev_len = strlen(dev_name) + 1;
	} else {
		req->d.dev_len = 0;
	}

	qtfs_dir_to_qtdir(kernel_dir, &req->buf[req->d.dev_len], sizeof(req->buf) - req->d.dev_len);
	req->d.dir_len = strlen(&req->buf[req->d.dev_len]) + 1;
	if (type != NULL) {
		strlcpy(&req->buf[req->d.dev_len + req->d.dir_len], type, strlen(type) + 1);
		req->d.type_len = strlen(type) + 1;
	} else {
		req->d.type_len = 0;
	}

	if (data != NULL) {
		req->d.data_len = strlen(data) + 1;
		strlcpy(&req->buf[req->d.dev_len + req->d.dir_len + req->d.type_len], data, strlen(data) + 1);
	} else {
		req->d.data_len = 0;
	}
	req->d.flags = flags;

	rsp = qtfs_remote_run(pvar, QTFS_REQ_SYSMOUNT, sizeof(struct qtreq_sysmount) - sizeof(req->buf) + totallen);
	if (IS_ERR_OR_NULL(rsp)) {
		kfree(kernel_dir);
		qtfs_conn_put_param(pvar);
		return QTFS_PTR_ERR(rsp);
	}
	if (rsp->errno < 0) {
		qtfs_err("qtfs remote mount failed, devname:%s dir_name:%s type:%s, data:%s, flags(0x%lx), errno:%d\n",
				dev_name, kernel_dir, type, (char *)data, flags, rsp->errno);
	} else {
		qtfs_info("qtfs remote mount success devname:%s dir_name:%s type:%s, data:%s, flags(0x%lx)\n",
				dev_name, kernel_dir, type, (char *)data, flags);
	}

	kfree(kernel_dir);
	ret = rsp->errno;
	qtfs_conn_put_param(pvar);
	return ret;
}

static int qtfs_remote_umount(char __user *name, int flags)
{
	struct qtfs_conn_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_sysumount *req;
	struct qtrsp_sysumount *rsp;
	char *kernel_name;
	int ret;

	if (pvar == NULL) {
		qtfs_err("qtfs remote umount get pvar failed.");
		return -EINVAL;
	}
	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	kernel_name = qtfs_copy_mount_string(name);
	if (IS_ERR_OR_NULL(kernel_name)) {
		qtfs_conn_put_param(pvar);
		return QTFS_PTR_ERR(kernel_name);
	}
	req->flags = flags;
	qtfs_dir_to_qtdir(kernel_name, req->buf, sizeof(req->buf));
	qtfs_info("qtfs remote umount string:%s reqbuf:%s", (kernel_name == NULL) ? "INVALID":kernel_name, req->buf);

	rsp = qtfs_remote_run(pvar, QTFS_REQ_SYSUMOUNT, sizeof(struct qtreq_sysumount) - sizeof(req->buf) + strlen(req->buf));
	if (IS_ERR_OR_NULL(rsp)) {
		kfree(kernel_name);
		qtfs_conn_put_param(pvar);
		return QTFS_PTR_ERR(rsp);
	}
	if (rsp->errno)
		qtfs_err("qtfs remote umount failed, errno:%d\n", rsp->errno);
	
	kfree(kernel_name);
	ret = rsp->errno;
	qtfs_conn_put_param(pvar);
	return ret;
}

static atomic_t replace_available = ATOMIC_INIT(1);

int qtfs_syscall_init(void)
{
	if (!atomic_dec_and_test(&replace_available)) {
		atomic_inc(&replace_available);
		return -EBUSY;
	}

	symbols_origin[SYMBOL_SYSCALL_MOUNT] = qtfs_kern_syms.sys_call_table[__NR_mount];
	symbols_origin[SYMBOL_SYSCALL_UMOUNT] = qtfs_kern_syms.sys_call_table[__NR_umount2];
	symbols_origin[SYMBOL_SYSCALL_EPOLL_CTL] = qtfs_kern_syms.sys_call_table[__NR_epoll_ctl];
#ifdef __x86_64__
	make_rw((unsigned long)qtfs_kern_syms.sys_call_table);
	qtfs_kern_syms.sys_call_table[__NR_mount] = (unsigned long *)__x64_sys_qtfs_mount;
	qtfs_kern_syms.sys_call_table[__NR_umount2] = (unsigned long *)__x64_sys_qtfs_umount;
	qtfs_kern_syms.sys_call_table[__NR_epoll_ctl] = (unsigned long *)__x64_sys_qtfs_epoll_ctl;
	make_ro((unsigned long)qtfs_kern_syms.sys_call_table);
#endif
#ifdef __aarch64__
	// disable write protection
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL);
	qtfs_kern_syms.sys_call_table[__NR_mount] = (unsigned long *)__arm64_sys_qtfs_mount;
	qtfs_kern_syms.sys_call_table[__NR_umount2] = (unsigned long *)__arm64_sys_qtfs_umount;
	qtfs_kern_syms.sys_call_table[__NR_epoll_ctl] = (unsigned long *)__arm64_sys_qtfs_epoll_ctl;
	// enable write protection
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL_RO);
#endif
	qtfs_debug("qtfs use qtfs_mount instead of mount and umount\n");
	qtfs_debug("qtfs use qtfs_epoll_ctl instead of epoll_ctl\n");
	return 0;
}

int qtfs_syscall_fini(void)
{
#ifdef __x86_64__
	make_rw((unsigned long)qtfs_kern_syms.sys_call_table);
	qtfs_kern_syms.sys_call_table[__NR_mount] = (unsigned long *)symbols_origin[SYMBOL_SYSCALL_MOUNT];
	qtfs_kern_syms.sys_call_table[__NR_umount2] = (unsigned long *)symbols_origin[SYMBOL_SYSCALL_UMOUNT];
	qtfs_kern_syms.sys_call_table[__NR_epoll_ctl] = (unsigned long *)symbols_origin[SYMBOL_SYSCALL_EPOLL_CTL];
	/*set mkdir syscall to the original one */
	make_ro((unsigned long)qtfs_kern_syms.sys_call_table);
#endif
#ifdef __aarch64__
	// disable write protection
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL);
	qtfs_kern_syms.sys_call_table[__NR_mount] = (unsigned long *)symbols_origin[SYMBOL_SYSCALL_MOUNT];
	qtfs_kern_syms.sys_call_table[__NR_umount2] = (unsigned long *)symbols_origin[SYMBOL_SYSCALL_UMOUNT];
	qtfs_kern_syms.sys_call_table[__NR_epoll_ctl] = (unsigned long *)symbols_origin[SYMBOL_SYSCALL_EPOLL_CTL];
	// enable write protection
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL_RO);
#endif
	qtfs_info("qtfs mount umount and epoll_ctl resumed\n");
	atomic_inc(&replace_available);
	return 0;
}
