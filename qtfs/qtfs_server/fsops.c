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

#include <linux/fs.h>
#include <linux/stddef.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/poll.h>
#include <linux/fs_struct.h>
#include <asm-generic/ioctls.h>
#include <asm-generic/termbits.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/uio.h>
#include <linux/blkdev.h>
#include <linux/version.h>
#include <linux/if_tun.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
#include <linux/fdtable.h>
#endif

#include "conn.h"
#include "qtfs-server.h"
#include "req.h"
#include "log.h"
#include "fsops.h"
#include "comm.h"
#include "symbol_wrapper.h"
#include "qtfs_check.h"

#define REQ(arg) (arg->data)
#define RSP(arg) (arg->out)
#define USERP(arg) (arg->userp)
DEFINE_MUTEX(fd_bitmap_lock);

enum {
	WHITELIST_MATCH_PREFIX = 0,
	WHITELIST_MATCH_EXACT,
};

static inline int qtfs_white_list_match(char *path, char *wl, int wl_len, int match_type)
{
	if (strncmp(path, wl, wl_len))
		return 0;
	switch (match_type) {
		case WHITELIST_MATCH_PREFIX:
			if (wl[wl_len - 1] != '/' && path[wl_len] != '\0' && path[wl_len] != '/')
				return 0;
			break;
		case WHITELIST_MATCH_EXACT:
			if (path[wl_len] != '\0')
				return 0;
			break;
		default:
			return 0;
	}
	// match success
	return 1;
}

static bool _in_white_list(char *path, int type, int match_type)
{
	int i, in_wl = -1;
	char *str;
	struct qtfs_wl_cap *cap;

	str = strstr(path, "/..");
	if (str != NULL && (str[3] == '\0' || str[3] =='/')) {
		return false;
	}

	read_lock(&g_qtfs_wl.rwlock);
	cap = &g_qtfs_wl.cap[type];
	for (i = 0; i < cap->nums; i++) {
		if (qtfs_white_list_match(path, cap->item[i], strlen(cap->item[i]), match_type)) {
			in_wl = i;
			break;
		}
	}
	read_unlock(&g_qtfs_wl.rwlock);
	return in_wl != -1;
}

static bool in_white_list(char *path, int type)
{
	return _in_white_list(path, type, WHITELIST_MATCH_PREFIX);
}

static bool in_white_list_exact(char *path, int type)
{
	return _in_white_list(path, type, WHITELIST_MATCH_EXACT);
}

static inline void qtfs_inode_info_fill(struct inode_info *ii, struct inode *inode)
{
	ii->mode = inode->i_mode;
	ii->i_opflags = inode->i_opflags;
	ii->i_uid = inode->i_uid;
	ii->i_gid = inode->i_gid;
	ii->i_flags = inode->i_flags;
	ii->i_ino = inode->i_ino;
	ii->i_rdev = inode->i_rdev;
	ii->i_size = inode->i_size;
	ii->atime = inode->i_atime;
	ii->mtime = inode->i_mtime;
	ii->ctime = inode->i_ctime;
	ii->i_bytes = inode->i_bytes;
	ii->i_blkbits = inode->i_blkbits;
	ii->i_write_hint = inode->i_write_hint;
	ii->i_blocks = inode->i_blocks;
	ii->i_state = inode->i_state;
	ii->dirtied_when = inode->dirtied_when;
	ii->dirtied_time_when = inode->dirtied_time_when;
	ii->i_generation = inode->i_generation;
	return;
}

#define QTFS_IOCTL_HANDLE_WITH_BREAK(rspsize)\
	{\
		ret = copy_from_user(rsp->buf, userp->userp, rspsize);\
		if (ret) {\
			qtfs_err("cmd:%d copy_from_user failed with:%d\n", req->d.cmd, ret);\
			rsp->errno = -EFAULT;\
			goto err;\
		}\
		rsp->size = rspsize;\
		break;\
	}
static int handle_ioctl(struct qtserver_arg *arg)
{
	unsigned long ioctl_arg;
	int ret;
	int iret;
	struct qtreq_ioctl *req = (struct qtreq_ioctl *)REQ(arg);
	struct qtrsp_ioctl *rsp = (struct qtrsp_ioctl *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	mutex_lock(&fd_bitmap_lock);
	if (req->d.fd < 0 || qtfs_fd_bitmap.bitmap == NULL || req->d.fd > qtfs_fd_bitmap.nbits || !test_bit(req->d.fd, qtfs_fd_bitmap.bitmap)) {
		mutex_unlock(&fd_bitmap_lock);
		qtfs_err("ioctl invalid fd:%d", req->d.fd);
		rsp->ret = QTFS_ERR;
		rsp->size = 0;
		rsp->errno = -EINVAL;
		return sizeof(struct qtrsp_ioctl) - sizeof(rsp->buf);
	}
	mutex_unlock(&fd_bitmap_lock);

	if (req->d.argtype) {
		ioctl_arg = req->d.arg;
	} else {
		if (req->d.size) {
			if (req->d.size <= 0 || req->d.size > sizeof(req->path) || req->d.size >= userp->size) {
				rsp->errno = -EINVAL;
				goto err;
			}
			ret = copy_to_user(userp->userp, req->path, req->d.size);
			if (ret) {
				qtfs_err("cmd:%d copy_to_user failed with:%d", req->d.cmd, ret);
				rsp->errno = -EFAULT;
				goto err;
			}
		}
		ioctl_arg = (unsigned long)userp->userp;
	}
	iret = qtfs_syscall_ioctl(req->d.fd, req->d.cmd, ioctl_arg);
	if (iret) {
		qtfs_err("ioctl fd:%d cmd:%d failed with %d", req->d.fd, req->d.cmd, iret);
		rsp->errno = iret;
		goto err;
	}
	qtfs_info("ioctl fd:%d cmd:%d argtype:%d arg:%lx size:%u successed", req->d.fd, req->d.cmd, req->d.argtype, req->d.arg, req->d.size);
	switch (req->d.cmd) {
		case TUNSETPERSIST:
		case TUNSETIFF:
		case TCSETS:
		case FS_IOC_FSSETXATTR:
		case SIOCADDMULTI:
		case SIOCBRADDBR:
		case SIOCBRDELBR:
		case SIOCBRADDIF:
		case SIOCBRDELIF:
		case SIOCDELMULTI:
		case SIOCDEVPRIVATE:
		case SIOCETHTOOL:
		case SIOCSIFFLAGS:
		case SIOCSIFHWADDR:
		case SIOCSIFMTU:
		case SIOCSIFNAME:
			rsp->size = 0;
			break;
		case FS_IOC_FSGETXATTR:
			QTFS_IOCTL_HANDLE_WITH_BREAK(sizeof(struct fsxattr));
		case TCGETS:
			QTFS_IOCTL_HANDLE_WITH_BREAK(sizeof(struct ktermios));
		case SIOCGIFHWADDR:
		case SIOCGIFADDR:
		case SIOCGIFFLAGS:
		case SIOCGIFINDEX:
		case SIOCGIFMTU:
		case TUNGETIFF:
			QTFS_IOCTL_HANDLE_WITH_BREAK(sizeof(struct ifreq));
		case SIOCGIFVLAN:
			QTFS_IOCTL_HANDLE_WITH_BREAK(sizeof(struct vlan_ioctl_args));
		default:
			rsp->errno = -EOPNOTSUPP;
			goto err;
	}
	rsp->ret = QTFS_OK;
	rsp->errno = iret;
	return sizeof(struct qtrsp_ioctl) - sizeof(rsp->buf) + rsp->size;
err:
	rsp->ret = QTFS_ERR;
	rsp->size = 0;
	return sizeof(struct qtrsp_ioctl) - sizeof(rsp->buf);
}

static int handle_statfs(struct qtserver_arg *arg)
{
	int ret;
	struct qtreq_statfs *req = (struct qtreq_statfs *)REQ(arg);
	struct qtrsp_statfs *rsp = (struct qtrsp_statfs *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	if (strlen(req->path) + 1 > userp->size) {
		qtfs_err("invalid msg");
		rsp->errno = -EINVAL;
		goto err_end;
	}
	ret = copy_to_user(userp->userp, req->path, strlen(req->path) + 1);
	if (ret) {
		rsp->errno = -EFAULT;
		goto err_end;
	}

	ret = qtfs_syscall_statfs((char *)userp->userp, userp->userp2);
	if (ret) {
		qtfs_err("qtfs server handle statfs path:%s failed with ret:%d.\n", req->path, ret);
		rsp->errno = ret;
		goto err_end;
	} else {
		qtfs_info("qtfs server handle statfs path:%s success.\n", req->path);
		rsp->ret = QTFS_OK;
	}
	if (copy_from_user(&rsp->kstat, userp->userp2, sizeof(struct kstatfs))) {
		qtfs_err("copy statfs to kstatfs failed");
		rsp->errno = -EFAULT;
		goto err_end;
	}
	return sizeof(struct qtrsp_statfs);
err_end:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_statfs);
}

static int handle_mount(struct qtserver_arg *arg)
{
	struct path path;
	int ret;
	struct qtreq_mount *req = (struct qtreq_mount *)REQ(arg);
	struct qtrsp_mount *rsp = (struct qtrsp_mount *)RSP(arg);
	if (!in_white_list(req->path, QTFS_WHITELIST_MOUNT)) {
		rsp->ret = QTFS_ERR;
		rsp->errno = -EPERM;
		return sizeof(rsp);
	}

	ret = kern_path(req->path, LOOKUP_DIRECTORY, &path);
	if (ret) {
		qtfs_err("handle mount path:%s kern_path failed, ret: %d.\n", req->path, ret);
		rsp->ret = QTFS_ERR;
		rsp->errno = -EINVAL;
	} else {
		rsp->ret = QTFS_OK;
		qtfs_info("handle mount path:%s success.\n", req->path);
		path_put(&path);
	}
	return sizeof(rsp);
}

int handle_open(struct qtserver_arg *arg)
{
	int fd;
	int ret;
	struct qtreq_open *req = (struct qtreq_open *)REQ(arg);
	struct qtrsp_open *rsp = (struct qtrsp_open *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	if (!in_white_list(req->path, QTFS_WHITELIST_OPEN) || qtfs_fd_bitmap.bitmap == NULL) {
		qtfs_err("handle open path:%s not permited", req->path);
		rsp->ret = QTFS_ERR;
		rsp->fd = -EACCES;
		return sizeof(struct qtrsp_open);
	}
	if (strlen(req->path) + 1 > userp->size) {
		qtfs_err("path len invalid.");
		rsp->ret = QTFS_ERR;
		rsp->fd = -EFAULT;
		return sizeof(struct qtrsp_open);
	}

	ret = copy_to_user(userp->userp, req->path, strlen(req->path)+1);
	if (ret) {
		qtfs_err("handle open copy to user failed, ret:%d path:%s", ret, req->path);
		rsp->ret = QTFS_ERR;
		rsp->fd = -EFAULT;
		return sizeof(struct qtrsp_open);
	}
	fd = qtfs_syscall_openat(AT_FDCWD, (char *)userp->userp, req->flags, req->mode);
	if (fd == -EEXIST) {
		qtfs_err("handle open file <<%s>> flags:%llx mode:%o, opened:failed %d, do again\n", req->path, req->flags, req->mode, fd);
		req->flags &= ~(O_CREAT | O_EXCL);
		fd = qtfs_syscall_openat(AT_FDCWD, (char *)userp->userp, req->flags, req->mode);
	}
	if (fd < 0 || fd > qtfs_fd_bitmap.nbits) {
		if (fd != -ENOENT) {
			qtfs_err("handle open file <<%s>>flags:%llx mode:%o, opened:failed %d\n", req->path, req->flags, req->mode, fd);
		} else {
			qtfs_info("handle open file <<%s>>flags:%llx mode:%o, opened:failed - file not exist\n", req->path, req->flags, req->mode);
		}
		rsp->ret = QTFS_ERR;
		rsp->fd = (fd < 0) ? fd : -EINVAL;
		return sizeof(struct qtrsp_open);
	}
	mutex_lock(&fd_bitmap_lock);
	__set_bit(fd, qtfs_fd_bitmap.bitmap);
	mutex_unlock(&fd_bitmap_lock);
	rsp->ret = QTFS_OK;
	rsp->fd = fd;
	return sizeof(struct qtrsp_open);
}

int handle_close(struct qtserver_arg *arg)
{
	struct qtreq_close *req = (struct qtreq_close *)REQ(arg);
	struct qtrsp_close *rsp = (struct qtrsp_close *)RSP(arg);

	// fd >= 3 is valid
	if (req->fd <= 2) {
		qtfs_err("handle close an invalid fd:%d.", req->fd);
		WARN_ON(1);
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_close);
	}
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0))
	rsp->ret = qtfs_kern_syms.__close_fd(current->files, req->fd);
#else
	rsp->ret = close_fd(req->fd);
#endif
	mutex_lock(&fd_bitmap_lock);
	if (req->fd > qtfs_fd_bitmap.nbits || qtfs_fd_bitmap.bitmap == NULL || !test_bit(req->fd, qtfs_fd_bitmap.bitmap)) {
		qtfs_err("close fd:%d bitmap is notset", req->fd);
	} else {
		__clear_bit(req->fd, qtfs_fd_bitmap.bitmap);
	}
	mutex_unlock(&fd_bitmap_lock);
	qtfs_info("handle close file, fd:%d ret:%d", req->fd, rsp->ret);
	return sizeof(struct qtrsp_close);
}

static int handle_readiter(struct qtserver_arg *arg)
{
	struct file *file = NULL;
	char *pathbuf, *fullname;
	int idx = 0;
	int ret = 0;
	int block_size;
	size_t maxlen;
	int len;
	off_t seek;
	struct qtreq_readiter *req = (struct qtreq_readiter *)REQ(arg);
	struct qtrsp_readiter *rsp = (struct qtrsp_readiter *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	mutex_lock(&fd_bitmap_lock);
	if (req->fd < 0 || qtfs_fd_bitmap.bitmap == NULL || req->fd > qtfs_fd_bitmap.nbits || !test_bit(req->fd, qtfs_fd_bitmap.bitmap)) {
		mutex_unlock(&fd_bitmap_lock);
		qtfs_err("unset bitmap fd:%d is error request, fd limit:%u", req->fd, qtfs_fd_bitmap.nbits);
		rsp->d.errno = -EINVAL;
		goto early_end;
	}
	mutex_unlock(&fd_bitmap_lock);
	file = fget(req->fd);
	if (IS_ERR_OR_NULL(file)) {
		qtfs_err("handle readiter error, open failed.\n");
		rsp->d.errno = -ENOENT;
		goto early_end;
	}
	if (file->f_flags & O_DIRECT) {
		if (file->f_inode->i_sb->s_bdev != NULL && file->f_inode->i_sb->s_bdev->bd_disk != NULL 
			&& file->f_inode->i_sb->s_bdev->bd_disk->queue != NULL) {
				block_size = bdev_logical_block_size(file->f_inode->i_sb->s_bdev);
		} else {
			rsp->d.ret = QTFS_ERR;
			rsp->d.errno = -EINVAL;
			rsp->d.len = 0;
			goto end;
		}
		if (req->len % block_size != 0) {
			rsp->d.ret = QTFS_ERR;
			rsp->d.errno = -EINVAL;
			rsp->d.len = 0;
			goto end;
		}
		maxlen = (req->len >= sizeof(rsp->readbuf)) ? (block_size * (sizeof(rsp->readbuf) /block_size)) : req->len;
	} else {
		maxlen = (req->len >= sizeof(rsp->readbuf)) ? (sizeof(rsp->readbuf) - 1) : req->len;
	}

	pathbuf = __getname();
	if (pathbuf == NULL) {
		qtfs_err("readiter whitelist judge error: failed to get pathbuf.\n");
		rsp->d.ret = QTFS_ERR;
		rsp->d.errno = -ENOENT;
		goto end;
	}
	fullname = file_path(file, pathbuf, PATH_MAX);
	if (IS_ERR_OR_NULL(fullname) || !in_white_list(fullname, QTFS_WHITELIST_READ)) {
		qtfs_err("read iter path not in whitelist.\n");
		__putname(pathbuf);
		rsp->d.ret = QTFS_ERR;
		rsp->d.errno = -ENOENT;
		goto end;
	}
	qtfs_info("handle readiter file:<%s> len:%lu pos:%lld", fullname, req->len, req->pos);
	__putname(pathbuf);

	if (file->f_mode & FMODE_LSEEK) {
		seek = qtfs_syscall_lseek(req->fd, req->pos, SEEK_SET);
		if (seek < 0) {
			qtfs_err("handle read set lseek pos:%lld failed, fd:%d ret:%ld", req->pos, req->fd, seek);
			rsp->d.ret = QTFS_ERR;
			rsp->d.errno = seek;
			fput(file);
			return sizeof(struct qtrsp_readiter) - sizeof(rsp->readbuf);
		}
	}
	fput(file);

	rsp->d.ret = QTFS_OK;
	while (maxlen > 0) {
		len = (maxlen > userp->size) ? userp->size : maxlen;
		ret = qtfs_syscall_read(req->fd, userp->userp, len);
		if (ret < 0) {
			qtfs_err("read fd:%d failed:%d", req->fd, ret);
			rsp->d.ret = QTFS_ERR;
			break;
		}
		if (ret == 0) {
			rsp->d.end = 1;
			break;
		}
		maxlen -= len;
		if (copy_from_user(&rsp->readbuf[idx], userp->userp, ret)) {
			qtfs_err("copy from user failed fd:%d len:%d", req->fd, ret);
			rsp->d.end = 1;
			rsp->d.ret = QTFS_ERR;
			break;
		}
		idx += ret;
		rsp->d.len += ret;
		if (ret < len) {
			rsp->d.end = 1;
			break;
		}
	}

	qtfs_info("read fd:%d len:%ld %s errno:%d", req->fd, rsp->d.len,
			(rsp->d.ret == QTFS_OK) ? "Successed" : "Failed", rsp->d.errno);

	return sizeof(struct qtrsp_readiter) - sizeof(rsp->readbuf) + ((rsp->d.len < 0) ? 0 : rsp->d.len);
end:
	fput(file);
	return sizeof(struct qtrsp_readiter) - sizeof(rsp->readbuf) + ((rsp->d.len < 0) ? 0 : rsp->d.len);
early_end:
	rsp->d.ret = QTFS_ERR;
	rsp->d.len = 0;
	return sizeof(struct qtrsp_readiter) - sizeof(rsp->readbuf);
}

static int handle_write(struct qtserver_arg *arg)
{
	struct file *file = NULL;
	char *pathbuf, *fullname;
	int block_size;
	struct qtreq_write *req = (struct qtreq_write *)REQ(arg);
	struct qtrsp_write *rsp = (struct qtrsp_write *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	int idx = 0, leftlen = 0, ret = 0, len = 0;
	off_t seek;

	mutex_lock(&fd_bitmap_lock);
	if (req->d.fd < 0 || qtfs_fd_bitmap.bitmap == NULL || req->d.fd > qtfs_fd_bitmap.nbits || !test_bit(req->d.fd, qtfs_fd_bitmap.bitmap)) {
		mutex_unlock(&fd_bitmap_lock);
		qtfs_err("unset bitmap fd:%d is error request, fd limit:%u", req->d.fd, qtfs_fd_bitmap.nbits);
		goto early_end;
	}
	mutex_unlock(&fd_bitmap_lock);
	file = fget(req->d.fd);
	if (IS_ERR_OR_NULL(file)) {
		qtfs_err("qtfs handle write error, open failed.\n");
		goto early_end;
	}
	if (file->f_flags & O_DIRECT) {
		if (file->f_inode->i_sb->s_bdev != NULL && file->f_inode->i_sb->s_bdev->bd_disk != NULL 
			&& file->f_inode->i_sb->s_bdev->bd_disk->queue != NULL) {
			block_size = bdev_logical_block_size(file->f_inode->i_sb->s_bdev);
		} else {
			rsp->ret = QTFS_ERR;
			rsp->len = -EINVAL;
			goto end;
		}
		if (req->d.total_len % block_size != 0) {
			rsp->ret = QTFS_ERR;
			rsp->len = -EINVAL;
			goto end;
		}
		leftlen = block_size * (req->d.buflen / block_size);
	} else {
		leftlen = req->d.buflen;
	}
	if (leftlen < 0 || leftlen > sizeof(req->path_buf)) {
		qtfs_err("invalid buflen :%d", leftlen);
		rsp->ret = QTFS_ERR;
		rsp->len = -EINVAL;
		goto end;
	}
	pathbuf = __getname();
	if (pathbuf == NULL) {
		qtfs_err("write whitelist judge error: failed to get pathbuf.\n");
		rsp->ret = QTFS_ERR;
		rsp->len = 0;
		goto end;
	}
	fullname = file_path(file, pathbuf, PATH_MAX);
	if (IS_ERR_OR_NULL(fullname) || !in_white_list(fullname, QTFS_WHITELIST_WRITE)) {
		__putname(pathbuf);
		rsp->ret = QTFS_ERR;
		rsp->len = 0;
		goto end;
	}
	qtfs_info("handle write fd:%d file:<%s>, write len:%d before pos:%lld mode:%o flags:%x", req->d.fd, fullname,
				leftlen, req->d.pos, file->f_mode, file->f_flags);
	__putname(pathbuf);

	if (file->f_mode & FMODE_LSEEK) {
		seek = qtfs_syscall_lseek(req->d.fd, req->d.pos, SEEK_SET);
		if (seek < 0) {
			qtfs_err("handle write set lseek pos:%lld failed, fd:%d ret:%ld", req->d.pos, req->d.fd, seek);
			rsp->ret = QTFS_ERR;
			rsp->len = seek;
			fput(file);
			return sizeof(struct qtrsp_write);
		}
	}
	fput(file);

	rsp->ret = QTFS_OK;
	while (leftlen > 0) {
		len = (leftlen > userp->size) ? userp->size : leftlen;
		leftlen -= len;
		if (copy_to_user(userp->userp, &req->path_buf[idx], len)) {
			qtfs_err("copy to user failed len:%d idx:%d", len, idx);
			rsp->ret = QTFS_ERR;
			break;
		}
		idx += len;
		ret = qtfs_syscall_write(req->d.fd, userp->userp, len);
		if (ret <= 0) {
			qtfs_err("write failed ret:%d", ret);
			rsp->ret = QTFS_ERR;
			break;
		}
		rsp->len += ret;
	}

	qtfs_info("write fd:%d len:%ld %s", req->d.fd, rsp->len, (rsp->ret == QTFS_OK) ? "Successed" : "Failed");
	return sizeof(struct qtrsp_write);
end:
	fput(file);
	return sizeof(struct qtrsp_write);
early_end:
	rsp->ret = QTFS_ERR;
	rsp->len = 0;
	return sizeof(struct qtrsp_write);
}

static int handle_lookup(struct qtserver_arg *arg)
{
	struct path path;
	struct inode *inode;
	struct qtreq_lookup *req = (struct qtreq_lookup *)REQ(arg);
	struct qtrsp_lookup *rsp = (struct qtrsp_lookup *)RSP(arg);
	int ret;
	ret = kern_path(req->fullname, 0, &path);
	if (ret) {
		qtfs_info("qtfs handle lookup(%s) kern_path failed, ret%d.\n", req->fullname, ret);
		rsp->errno = (ret == -ENOENT ? 0 : ret);
		rsp->ret = QTFS_ERR;
	} else {
		inode = path.dentry->d_inode;
		rsp->ret = QTFS_OK;
		qtfs_inode_info_fill(&rsp->inode_info, inode);
		qtfs_debug("handle lookup name:%s, mode:%o ino:%lu", req->fullname, rsp->inode_info.mode, rsp->inode_info.i_ino);
		path_put(&path);
	}
	return sizeof(struct qtrsp_lookup);
}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
static bool qtfs_filldir(struct dir_context *ctx, const char *name, int namelen,
		loff_t offset, u64 ino, unsigned int d_type)
#else
static int qtfs_filldir(struct dir_context *ctx, const char *name, int namelen,
		loff_t offset, u64 ino, unsigned int d_type)
#endif
{
	struct qtfs_dirent64 *dirent, *prev;
	struct qtfs_getdents *buf = container_of(ctx, struct qtfs_getdents, ctx);
	int reclen = ALIGN(offsetof(struct qtfs_dirent64, d_name) + namelen + 1, sizeof(u64));
	int prev_reclen;

	if (reclen > buf->count || !buf->dir || !name)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
		return false;
#else
		return -EINVAL;
#endif

	prev_reclen = buf->prev_reclen;
	dirent = buf->dir;
	prev = (void *)dirent - prev_reclen;
	prev->d_off = offset;
	dirent->d_ino = ino;
	dirent->d_reclen = reclen;
	dirent->d_type = d_type;
	memcpy(dirent->d_name, name, namelen);

	buf->prev_reclen = reclen;
	buf->dir = (void *)dirent + reclen;
	buf->count -= reclen;
	buf->vldcnt++;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return true;
#else
	return 0;
#endif
}

static int handle_readdir(struct qtserver_arg *arg)
{
	struct file *file = NULL;
	struct qtreq_readdir *req = (struct qtreq_readdir *)REQ(arg);
	struct qtrsp_readdir *rsp = (struct qtrsp_readdir *)RSP(arg);
	int ret;
	struct qtfs_getdents buf = {
		.ctx.actor = qtfs_filldir,
		.ctx.pos = req->pos,
		.prev_reclen = 0,
		.count = req->count,
		.dir = (struct qtfs_dirent64 *)rsp->dirent,
		.vldcnt = 0,
	};
	
	if (!in_white_list(req->path, QTFS_WHITELIST_READDIR)) {
		rsp->d.ret = QTFS_ERR;
		rsp->d.vldcnt = 0;
		return sizeof(struct qtrsp_readdir) - sizeof(rsp->dirent);
	}
	file = filp_open(req->path, O_RDONLY|O_NONBLOCK|O_DIRECTORY, 0);
	if (IS_ERR_OR_NULL(file)) {
		qtfs_err("handle readdir error, filp:<%s> open failed.\n", req->path);
		rsp->d.ret = QTFS_ERR;
		rsp->d.vldcnt = 0;
		return sizeof(struct qtrsp_readdir) - sizeof(rsp->dirent);
	}
	file->f_pos = req->pos;
	ret = iterate_dir(file, &buf.ctx);
	rsp->d.pos = file->f_pos;
	rsp->d.ret = QTFS_OK;
	rsp->d.vldcnt = buf.vldcnt;
	rsp->d.over = (req->pos == rsp->d.pos) ? 1 : 0;
	qtfs_info("handle readdir ret:%d, pos:%lld path:%s, valid count:%d, leftcount:%d validbyte:%lu\n",
			ret, req->pos, req->path, buf.vldcnt, buf.count, sizeof(rsp->dirent) - buf.count);
	filp_close(file, NULL);

	return sizeof(struct qtrsp_readdir) - buf.count;
}

static int handle_mkdir(struct qtserver_arg *arg)
{
	struct qtreq_mkdir *req = (struct qtreq_mkdir *)REQ(arg);
	struct qtrsp_mkdir *rsp = (struct qtrsp_mkdir *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	struct inode *inode;
	struct path path;
	int ret;
	int len;

	if (!in_white_list(req->path, QTFS_WHITELIST_MKDIR)) {
		rsp->errno = -EFAULT;
		goto err;
	}
	len = strlen(req->path);
	if (len < 0 || len + 1 > userp->size || len >= sizeof(req->path)) {
		qtfs_err("path len invalid:%d.", len);
		rsp->errno = -EFAULT;
		goto err;
		
	}
	if (copy_to_user(userp->userp, req->path, len + 1)) {
		qtfs_err("handle mkdir copy to userp failed.\n");
		rsp->errno = -EFAULT;
		goto err;
	}
	rsp->errno = qtfs_syscall_mkdirat(AT_FDCWD, userp->userp, req->mode);
	if (rsp->errno < 0) {
		qtfs_err("handle mkdir path:%s failed with ret:%d.", req->path, rsp->errno);
		goto err;
	}
	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle mkdir failed in kern path, ret:%d.\n", ret);
		rsp->errno = -EFAULT;
		goto err;
	} else {
		inode = d_inode(path.dentry);
		qtfs_inode_info_fill(&rsp->inode_info, inode);
		path_put(&path);
	}
	rsp->ret = QTFS_OK;
	qtfs_info("handle mkdir path:%s success.", req->path);
	return sizeof(struct qtrsp_mkdir);

err:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_mkdir);
}

static int handle_rmdir(struct qtserver_arg *arg)
{
	struct qtreq_rmdir *req = (struct qtreq_rmdir *)REQ(arg);
	struct qtrsp_rmdir *rsp = (struct qtrsp_rmdir *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	int len;
	
	if (!in_white_list(req->path, QTFS_WHITELIST_RMDIR)) {
		rsp->errno = -EFAULT;
		goto err;
	}
	len = strlen(req->path);
	if (len < 0 || len + 1 > userp->size || len >= sizeof(req->path)) {
		qtfs_err("len invalid:%d", len);
		rsp->errno = -EFAULT;
		goto err;
	}
	if (copy_to_user(userp->userp, req->path, len + 1)) {
		qtfs_err("handle rmdir copy to userp failed.\n");
		rsp->errno = -EFAULT;
		goto err;
	}
	rsp->errno = qtfs_syscall_rmdir(userp->userp);
	if (rsp->errno < 0) {
		qtfs_err("handle rmdir error:%d.", rsp->errno);
		goto err;
	}
	qtfs_info("handle rmdir path:%s success.", req->path);
	rsp->ret = QTFS_OK;
	return sizeof(struct qtrsp_rmdir);

err:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_rmdir);
}

static int handle_getattr(struct qtserver_arg *arg)
{
	struct qtreq_getattr *req = (struct qtreq_getattr *)REQ(arg);
	struct qtrsp_getattr *rsp = (struct qtrsp_getattr *)RSP(arg);
	struct path path;
	int ret;

	qtfs_debug("handle getattr path:%s\n", req->path);
	ret = kern_path(req->path, 0, &path);
	if (ret) {
		rsp->errno = ret;
		qtfs_err("handle getattr path:%s failed, ret:%d %s\n", req->path, ret, (ret != -ENOENT) ? "." : "file not exist");
		goto failed;
	}

	ret = vfs_getattr(&path, &rsp->stat, req->request_mask, req->query_flags);
	if (ret) {
		qtfs_err("vfs getattr path:%s ret:%d\n", req->path, ret);
		rsp->errno = ret;
		path_put(&path);
		goto failed;
	}
	rsp->ret = QTFS_OK;
	path_put(&path);
	qtfs_debug("handle getattr:<%s> blksize:%u size:%lld mode:%o ino:%llu req_mask:%x req_flags:%u.\n", req->path, rsp->stat.blksize,
			rsp->stat.size, rsp->stat.mode, rsp->stat.ino, req->request_mask, req->query_flags);
	return sizeof(struct qtrsp_getattr);

failed:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_getattr);
}

static int handle_setattr(struct qtserver_arg *arg)
{
	struct qtreq_setattr *req = (struct qtreq_setattr *)REQ(arg);
	struct qtrsp_setattr *rsp = (struct qtrsp_setattr *)RSP(arg);
	struct inode *inode = NULL;
	struct path path;
	int ret;
	
	if (!in_white_list(req->path, QTFS_WHITELIST_SETATTR)) {
		rsp->ret = QTFS_ERR;
		rsp->errno = -ENOENT;
		return sizeof(struct qtrsp_setattr);
	}

	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle setattr path:%s failed in kern_path with %d\n", req->path, ret);
		rsp->ret = QTFS_ERR;
		rsp->errno = -ENOENT;
		return sizeof(struct qtrsp_setattr);
	}
	inode = path.dentry->d_inode;
	if (req->attr.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID)) {
		req->attr.ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID |
				ATTR_MODE);
		req->attr.ia_mode = inode->i_mode;
		if (inode->i_mode & S_ISUID) {
			req->attr.ia_valid |= ATTR_MODE;
			req->attr.ia_mode &= ~S_ISUID;
		}
		if ((inode->i_mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
			req->attr.ia_valid |= ATTR_MODE;
			req->attr.ia_mode &= ~S_ISGID;
		}
	}
	if (!req->attr.ia_valid) {
		rsp->ret = QTFS_OK;
		path_put(&path);
		return sizeof(struct qtrsp_setattr);
	}

	inode_lock(inode);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
	rsp->errno = notify_change(&init_user_ns, path.dentry, &req->attr, NULL);
#else
	rsp->errno = notify_change(path.dentry, &req->attr, NULL);
#endif
	if (rsp->errno < 0) {
		rsp->ret = QTFS_ERR;
		qtfs_err("handle setattr, path:<%s> failed with %d.\n", req->path, ret);
		goto end;
	}

	qtfs_info("handle setattr iattr success iavalid:%u mode:%o size:%lld\n",
			req->attr.ia_valid, req->attr.ia_mode, req->attr.ia_size);
	rsp->ret = QTFS_OK;

end:
	inode_unlock(inode);
	path_put(&path);
	return sizeof(struct qtrsp_setattr);
}

int handle_icreate(struct qtserver_arg *arg)
{
	struct file *file = NULL;
	struct inode *inode;
	struct qtreq_icreate *req = (struct qtreq_icreate *)REQ(arg);
	struct qtrsp_icreate *rsp = (struct qtrsp_icreate *)RSP(arg);
	
	if (!in_white_list(req->path, QTFS_WHITELIST_CREATE)) {
		rsp->ret = QTFS_ERR;
		rsp->errno = -ENOENT;
		return sizeof(struct qtrsp_icreate);
	}

	file = filp_open(req->path, O_CREAT, req->mode);
	if (IS_ERR_OR_NULL(file)) {
		qtfs_err("handle icreate filp:<%s> failed in open.\n", req->path);
		rsp->ret = QTFS_ERR;
		rsp->errno = QTFS_PTR_ERR(file);
		return sizeof(struct qtrsp_icreate);
	}
	inode = file->f_inode;
	qtfs_inode_info_fill(&rsp->inode_info, inode);
	filp_close(file, NULL);
	rsp->ret = QTFS_OK;
	qtfs_info("handle icreate path:%s success, inode mode:%ho\n", req->path,
			rsp->inode_info.mode);
	return sizeof(struct qtrsp_icreate);
}

static int handle_mknod(struct qtserver_arg *arg)
{
	struct qtreq_mknod *req = (struct qtreq_mknod *)REQ(arg);
	struct qtrsp_mknod *rsp = (struct qtrsp_mknod *)RSP(arg);
	struct dentry *dent = NULL;
	struct path path;
	int error;
	unsigned int flags = LOOKUP_DIRECTORY;
	
	if (!in_white_list(req->path, QTFS_WHITELIST_CREATE)) {
		rsp->ret = QTFS_ERR;
		rsp->errno = -ENOENT;
		return sizeof(struct qtrsp_mknod);
	}

retry:
	dent = kern_path_create(AT_FDCWD, req->path, &path, flags);
	if (IS_ERR_OR_NULL(dent)) {
		rsp->ret = QTFS_ERR;
		rsp->errno = QTFS_PTR_ERR(dent);
		qtfs_info("handle mknod path:<%s>, mode:%o in kern_path_create with ret:%ld\n", req->path, req->mode, QTFS_PTR_ERR(dent));
		return sizeof(struct qtrsp_mknod);
	}

	if (!IS_POSIXACL(path.dentry->d_inode))
		req->mode &= ~current_umask();
	error = security_path_mknod(&path, dent, req->mode, req->dev);
	if (!error)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
		error = vfs_mknod(&init_user_ns, path.dentry->d_inode, dent, req->mode, req->dev);
#else
		error = vfs_mknod(path.dentry->d_inode, dent, req->mode, req->dev);
#endif
	done_path_create(&path, dent);
	if (error == -ESTALE && !(flags & LOOKUP_REVAL)) {
		flags |= LOOKUP_REVAL;
		qtfs_debug("retry mknod.\n");
		rsp->errno = error;
		goto retry;
	}
	qtfs_inode_info_fill(&rsp->inode_info, dent->d_inode);
	rsp->ret = QTFS_OK;
	qtfs_info("handle mknod path:<%s>, mode:%o success\n", req->path, req->mode);
	rsp->errno = 0;
	return sizeof(struct qtrsp_mknod);
}

int handle_unlink(struct qtserver_arg *arg)
{
	struct qtreq_unlink *req = (struct qtreq_unlink *)REQ(arg);
	struct qtrsp_unlink *rsp = (struct qtrsp_unlink *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	int len;

	if (!in_white_list(req->path, QTFS_WHITELIST_UNLINK)) {
		rsp->errno = -ENOENT;
		return sizeof(struct qtrsp_unlink);
	}
	len = strlen(req->path);
	if (len < 0 || len + 1 > userp->size || len >= sizeof(req->path)) {
		qtfs_err("len invalid:%d", len);
		rsp->errno = -EFAULT;
		return sizeof(struct qtrsp_unlink);
	}
	if (copy_to_user(userp->userp, req->path, len + 1)) {
		qtfs_err("handle unlink copy to userp failed.");
		rsp->errno = -EFAULT;
		return sizeof(struct qtrsp_unlink);
	}

	rsp->errno = qtfs_syscall_unlink(userp->userp);
	if (rsp->errno < 0) {
		qtfs_err("handle unlink failed, errno:%d\n", rsp->errno);
	} else {
		qtfs_info("handle unlink path:%s success\n", req->path);
	}
	return sizeof(struct qtrsp_unlink);
}

int handle_link(struct qtserver_arg *arg)
{
	char *oldname, *newname;
	struct qtreq_link *req = (struct qtreq_link *)REQ(arg);
	struct qtrsp_link *rsp = (struct qtrsp_link *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	oldname = req->path;
	newname = req->path + req->d.oldlen;
	if (strlen(oldname) >= sizeof(req->path) || req->d.oldlen >= sizeof(req->path) ||
		strlen(oldname) + strlen(newname) >= sizeof(req->path) ||
		strlen(oldname) < 0 || strlen(newname) < 0) {
		qtfs_err("invalid path oldname or newname during handle_link");
		rsp->errno = -EFAULT;
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_link);
	}
	if (strlen(oldname) + 1 > userp->size || strlen(newname) + 1 > userp->size ||
		copy_to_user(userp->userp, oldname, strlen(oldname) + 1) ||
		copy_to_user(userp->userp2, newname, strlen(newname) + 1)) {
		qtfs_err("handle link failed in copy to userp.\n");
		rsp->errno = -EFAULT;
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_link);
	}

	rsp->errno = qtfs_syscall_linkat(AT_FDCWD, userp->userp, AT_FDCWD, userp->userp2, 0);
	qtfs_info("handle link new:%s old:%s return %d\n", newname, oldname, rsp->errno);
	rsp->ret = rsp->errno == 0 ? QTFS_OK : QTFS_ERR;
	return sizeof(struct qtrsp_link);
}

int handle_symlink(struct qtserver_arg *arg)
{
	char *oldname, *newname;
	struct qtreq_symlink *req = (struct qtreq_symlink *)REQ(arg);
	struct qtrsp_symlink *rsp = (struct qtrsp_symlink *)RSP(arg);
	int error;
	struct dentry *dentry;
	struct path path;
	unsigned int lookup_flags = 0;

	if (req->d.newlen >= sizeof(req->path) || req->d.newlen + req->d.oldlen > sizeof(req->path)) {
		qtfs_err("newlen:%lu oldlen:%lu is too big", req->d.newlen, req->d.oldlen);
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_symlink);
	}
	newname = req->path;
	oldname = &req->path[req->d.newlen];
retry:
	dentry = kern_path_create(AT_FDCWD, newname, &path, lookup_flags);
	error = QTFS_PTR_ERR(dentry);
	if (IS_ERR_OR_NULL(dentry)) {
		rsp->ret = QTFS_ERR;
		qtfs_err("handle_symlink: newname(%s), oldname(%s) in kern_path_create %d\n", newname, oldname, error);
		return sizeof(struct qtrsp_symlink);
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
	rsp->errno = vfs_symlink(&init_user_ns, path.dentry->d_inode, dentry, oldname);
#else
	rsp->errno = vfs_symlink(path.dentry->d_inode, dentry, oldname);
#endif
	done_path_create(&path, dentry);
	if (rsp->errno == -ESTALE && !(lookup_flags & LOOKUP_REVAL)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	rsp->ret = QTFS_OK;
	qtfs_info("handle_symlink: newname(%s), oldname(%s) success\n", newname, oldname);
	qtfs_inode_info_fill(&rsp->inode_info, dentry->d_inode);
	return sizeof(struct qtrsp_symlink);
}

int handle_getlink(struct qtserver_arg *arg)
{
	struct qtreq_getlink *req = (struct qtreq_getlink *)REQ(arg);
	struct qtrsp_getlink *rsp = (struct qtrsp_getlink *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	if (strlen(req->path) < 0 || strlen(req->path) + 1 > sizeof(req->path) || copy_to_user(userp->userp, req->path, strlen(req->path) + 1)) {
		qtfs_err("handle getlink<%s> copy to userp failed.\n", req->path);
		rsp->errno = -EFAULT;
		goto err_handle;
	}
	rsp->errno = qtfs_syscall_readlinkat(AT_FDCWD, userp->userp, userp->userp2, userp->size);
	if (rsp->errno < 0 || rsp->errno > MAX_PATH_LEN) {
		qtfs_err("handle getlink<%s> do readlinkat failed, errno:%d\n", req->path, rsp->errno);
		goto err_handle;
	}
	if (copy_from_user(rsp->path, userp->userp2, rsp->errno)) {
		qtfs_err("handle getlink<%s> copy from user failed, len:%d.", req->path, rsp->errno);
		rsp->errno = -EFAULT;
		goto err_handle;
	}
	rsp->ret = QTFS_OK;
	qtfs_info("handle getlink<%s> ok, len:%d link:%s.", req->path, rsp->errno, rsp->path);
	return sizeof(struct qtrsp_getlink) - sizeof(rsp->path) + strlen(rsp->path) + 1;

err_handle:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_getlink) - sizeof(rsp->path);
}

int handle_rename(struct qtserver_arg *arg)
{
	struct qtreq_rename *req = (struct qtreq_rename *)REQ(arg);
	struct qtrsp_rename *rsp = (struct qtrsp_rename *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	
	if (!in_white_list(req->path, QTFS_WHITELIST_RENAME)) {
		rsp->errno = -ENOENT;
		goto err_handle;
	}
	if (strlen(req->path) + 1 > sizeof(req->path) || req->d.oldlen >= sizeof(req->path) ||
		strlen(req->path) + strlen(&req->path[req->d.oldlen]) >= sizeof(req->path) ||
		strlen(req->path) + 1 > userp->size || strlen(&req->path[req->d.oldlen]) + 1 > userp->size) {
		qtfs_err("invalid req msg");
		rsp->errno = -EFAULT;
		goto err_handle;
	}
	if (copy_to_user(userp->userp, req->path, strlen(req->path) + 1) ||
		copy_to_user(userp->userp2, &req->path[req->d.oldlen], strlen(&req->path[req->d.oldlen]) + 1)) {
		qtfs_err("handle rename copy to userp failed.\n");
		rsp->errno = -EFAULT;
		goto err_handle;
	}
	rsp->errno = qtfs_syscall_renameat2(AT_FDCWD, userp->userp, AT_FDCWD, userp->userp2, 0);

err_handle:
	rsp->ret = (rsp->errno < 0) ? QTFS_ERR : QTFS_OK;
	qtfs_info("handle rename oldname:%s newname:%s ret:%d %s", req->path, &req->path[req->d.oldlen], rsp->errno,
			(rsp->errno < 0) ? "failed" : "successed");
	return sizeof(struct qtrsp_rename);
}

int handle_xattrlist(struct qtserver_arg *arg)
{
	struct qtreq_xattrlist *req = (struct qtreq_xattrlist *)REQ(arg);
	struct qtrsp_xattrlist *rsp = (struct qtrsp_xattrlist *)RSP(arg);
	struct path path;
	int ret = 0;
	ssize_t size = 0, buffer_size = 0;
	int i = 0;

	buffer_size = (req->buffer_size > sizeof(rsp->name)) ? sizeof(rsp->name) : req->buffer_size;
	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle xattr list path error.\n");
		rsp->d.size = -ENOENT;
		goto err_handle;
	}
	size = vfs_listxattr(path.dentry, buffer_size == 0 ? NULL : rsp->name, buffer_size);
	path_put(&path);
	if (size < 0) {
		qtfs_err("handle list xattr failed, errno:%ld.\n", size);
		rsp->d.size = size;
		goto err_handle;
	}
	if (size == 0) {
		rsp->d.size = size;
		goto err_handle;
	}
	rsp->d.ret = QTFS_OK;
	rsp->d.size = size;
	while (i < size) {
		qtfs_info("handle list xattr result:%s\n", &rsp->name[i]);
		i += strlen(&rsp->name[i]) + 1;
	}
	return sizeof(struct qtrsp_xattrlist);

err_handle:
	rsp->d.ret = QTFS_ERR;
	return sizeof(struct qtrsp_xattrlist);
}

int handle_xattrset(struct qtserver_arg *arg)
{
	struct qtreq_xattrset *req = (struct qtreq_xattrset *)REQ(arg);
	struct qtrsp_xattrset *rsp = (struct qtrsp_xattrset *)RSP(arg);
	struct path path;
	int ret = 0;

	if (!in_white_list(req->buf, QTFS_WHITELIST_SETXATTR)) {
		rsp->errno = -ENOENT;
		goto err_handle;
	}

	ret = kern_path(req->buf, 0, &path);
	if (ret) {
		qtfs_err("handle xattrset path error, file:%s.\n", req->buf);
		rsp->errno = -ENOENT;
		goto err_handle;
	}
	if (req->d.pathlen + req->d.namelen + req->d.valuelen > sizeof(req->buf) - 3) {
		qtfs_err("invalid len:%lu %lu %lu", req->d.pathlen, req->d.namelen, req->d.valuelen);
		rsp->errno = -EFAULT;
		path_put(&path);
		goto err_handle;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
	rsp->errno = vfs_setxattr(&init_user_ns, path.dentry, &req->buf[req->d.pathlen], &req->buf[req->d.pathlen + req->d.namelen], req->d.valuelen, req->d.flags);
#else
	rsp->errno = vfs_setxattr(path.dentry, &req->buf[req->d.pathlen], &req->buf[req->d.pathlen + req->d.namelen], req->d.valuelen, req->d.flags);
#endif
	qtfs_info("handle xattrset path:%s name:%s value:%s ret:%d size:%lu flags:%d", req->buf,
					&req->buf[req->d.pathlen], &req->buf[req->d.pathlen + req->d.namelen], rsp->errno,
					req->d.valuelen, req->d.flags);
	path_put(&path);
	return sizeof(struct qtrsp_xattrset);

err_handle:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_xattrset);
}

int handle_xattrget(struct qtserver_arg *arg)
{
	struct qtreq_xattrget *req = (struct qtreq_xattrget *)REQ(arg);
	struct qtrsp_xattrget *rsp = (struct qtrsp_xattrget *)RSP(arg);
	struct path path;
	int ret = 0;
	ssize_t error = 0;
	int len = 0;
	char *kvalue = NULL;

	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle xattrget path error.\n");
		rsp->d.errno = -ENOENT;
		goto err_handle;
	}

	if (req->d.size > 0) {
		if (req->d.size > XATTR_SIZE_MAX)
			req->d.size = XATTR_SIZE_MAX;

		if (req->d.pos > req->d.size) {
			rsp->d.errno = -EINVAL;
			path_put(&path);
			goto err_handle;
		}
		kvalue = (char *)kvzalloc(req->d.size, GFP_KERNEL);
		if (!kvalue) {
			qtfs_err("handle xattrget kvzalloc failed, size:%d.\n", req->d.size);
			rsp->d.errno = -ENOMEM;
			path_put(&path);
			goto err_handle;
		}
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
	error = vfs_getxattr(&init_user_ns, path.dentry, req->d.prefix_name, kvalue, req->d.size);
#else
	error = vfs_getxattr(path.dentry, req->d.prefix_name, kvalue, req->d.size);
#endif
	path_put(&path);
	if (error > 0) {
		if (req->d.pos >= error) {
			rsp->d.size = 0;
			rsp->d.pos = req->d.pos;
			goto end;
		}
		qtfs_info("handle getxattr: path:%s prefix name:%s : (%s - 0x%llx), size:%ld, reqpos:%d\n", req->path, req->d.prefix_name, kvalue, (__u64)kvalue, error, req->d.pos);
		len = (error - req->d.pos) > sizeof(rsp->buf) ? sizeof(rsp->buf) : (error - req->d.pos);
		rsp->d.size = len;
		if (req->d.size > 0) {
			memcpy(rsp->buf, &kvalue[req->d.pos], len);
		}
		rsp->d.pos = req->d.pos + len;
	} else {
		rsp->d.errno = error;
		kvfree(kvalue);
		goto err_handle;
	}
end:
	qtfs_info("handle getxattr successed file:%s result:%s", req->path, rsp->buf);
	kvfree(kvalue);
	rsp->d.ret = QTFS_OK;
	return sizeof(struct qtrsp_xattrget) - sizeof(rsp->buf) + len;

err_handle:
	rsp->d.ret = QTFS_ERR;
	qtfs_err("handle getxattr failed, file:%s", req->path);
	return sizeof(struct qtrsp_xattrget) - sizeof(rsp->buf);
}

int handle_syscall_mount(struct qtserver_arg *arg)
{
	struct qtreq_sysmount *req = (struct qtreq_sysmount *)REQ(arg);
	struct qtrsp_sysmount *rsp = (struct qtrsp_sysmount *)RSP(arg);
	char *dev_name, *dir_name, *type;
	char *udir_name = NULL;
	void *data_page;
	char *udev_name = NULL;
	char *utype = NULL;
	char *udata = NULL;
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	if (req->d.dev_len + req->d.dir_len + req->d.type_len + req->d.data_len > sizeof(req->buf) - 4) {
		qtfs_err("invalid msglen:%lu %lu %lu %lu", req->d.dev_len, req->d.dir_len, req->d.type_len, req->d.data_len);
		rsp->errno = -EINVAL;
		goto end;
	}
	dev_name = req->d.dev_len == 0 ? NULL : req->buf;
	dir_name = &req->buf[req->d.dev_len];
	type = req->d.type_len == 0 ? NULL : &req->buf[req->d.dev_len + req->d.dir_len];
	if (req->d.data_len != 0)
		data_page = &req->buf[req->d.dev_len + req->d.dir_len + req->d.type_len];
	else
		data_page = NULL;

	if (strlen(dir_name) >= (userp->size / 2) ||
		(dev_name != NULL && strlen(dev_name) >= (userp->size / 2)) ||
		(type != NULL && strlen(type) >= (userp->size / 2)) ||
		(data_page != NULL && strlen(data_page) >= (userp->size / 2))) {
		qtfs_err("mount str len is too big dirname:%lu devname:%lu type:%lu data:%lu",
				strlen(dir_name), (dev_name == NULL) ? 0 : strlen(dev_name),
				(type == NULL) ? 0 : strlen(type),
				(data_page == NULL) ? 0 : strlen(data_page));
		rsp->errno = -EINVAL;
		goto end;
	}
	udir_name = userp->userp;
	udev_name = (dev_name == NULL) ? NULL : ((char *)userp->userp + userp->size / 2);
	utype = (type == NULL) ? NULL : userp->userp2;
	udata = (data_page == NULL) ? NULL : ((char *)userp->userp + userp->size / 2);

	if (copy_to_user(udir_name, dir_name, strlen(dir_name) + 1) ||
		(dev_name != NULL && copy_to_user(udev_name, dev_name, strlen(dev_name) + 1)) ||
		(type != NULL && copy_to_user(utype, type, strlen(type) + 1)) ||
		(data_page != NULL && copy_to_user(udata, data_page, strlen(data_page) + 1))) {
		qtfs_err("syscall mount failed to copy to user");
		rsp->errno = -ENOMEM;
		goto end;
	}

	qtfs_info("handle syscall mount devname:%s dirname:%s type:%s data:%s\n", dev_name, dir_name, type,
			(data_page == NULL) ? "nil" : (char *)data_page);
	rsp->errno = qtfs_syscall_mount(udev_name, udir_name, utype, req->d.flags, udata);
	if (rsp->errno < 0)
		qtfs_err("handle syscall mount failed devname:%s dirname:%s type:%s data:%s, errno:%d\n",
				dev_name, dir_name, type, (char *)data_page, rsp->errno);

end:
	return sizeof(struct qtrsp_sysmount);
}

int handle_syscall_umount(struct qtserver_arg *arg)
{
	struct qtreq_sysumount *req = (struct qtreq_sysumount *)REQ(arg);
	struct qtrsp_sysumount *rsp = (struct qtrsp_sysumount *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	qtfs_info("handle umount path:%s\n", req->buf);
	if (strlen(req->buf) + 1 > userp->size || strlen(req->buf) >= sizeof(req->buf)) {
		qtfs_err("invalid msg");
		rsp->errno = -EINVAL;
		return sizeof(struct qtrsp_sysumount);
	}
	if (copy_to_user(userp->userp, req->buf, strlen(req->buf) + 1)) {
		rsp->errno = -ENOMEM;
		return sizeof(struct qtrsp_sysumount);
	}
	rsp->errno = qtfs_syscall_umount(userp->userp, req->flags);
	if (rsp->errno)
		qtfs_err("umount(%s) failed, errno:%d\n", req->buf, rsp->errno);
	//dont need to path_put here.
	return sizeof(struct qtrsp_sysumount);
}

#ifdef KVER_4_19
static bool qtfs_pipe_empty(struct pipe_inode_info *pipe)
{
	int nrbufs;

	nrbufs = pipe->nrbufs;
	return nrbufs <= 0;
}

static bool qtfs_pipe_full(struct pipe_inode_info *pipe)
{
	int nrbufs;

	nrbufs = pipe->nrbufs;
	return nrbufs >= pipe->buffers;
}
#else
static bool qtfs_pipe_empty(struct pipe_inode_info *pipe)
{
	unsigned int head, tail;

	head = READ_ONCE(pipe->head);
	tail = READ_ONCE(pipe->tail);

	return pipe_empty(head, tail);
}

static bool qtfs_pipe_full(struct pipe_inode_info *pipe)
{
	unsigned int head, tail;

	head = READ_ONCE(pipe->head);
	tail = READ_ONCE(pipe->tail);

	return pipe_full(head, tail, pipe->max_usage);
}
#endif

int handle_fifopoll(struct qtserver_arg *arg)
{
	struct qtreq_poll *req = (struct qtreq_poll *)REQ(arg);
	struct qtrsp_poll *rsp = (struct qtrsp_poll *)RSP(arg);
	struct file *filp = NULL;
	struct pipe_inode_info *pipe;
	struct inode *inode;
	__poll_t mask;
	struct poll_wqueues table;
	poll_table *pt;

	filp = fget(req->fd);
	if (!filp) {
		rsp->mask = EPOLLERR;
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_poll);
	}
	inode = filp->f_inode;
	if (!S_ISFIFO(inode->i_mode)) {
		msleep(1);
		poll_initwait(&table);
		pt = &table.pt;
		mask = vfs_poll(filp, pt);
		poll_freewait(&table);
		goto end;
	}
	pipe = filp->private_data;
	if (pipe == NULL) {
		qtfs_err("file :%s pipe data is NULL.", filp->f_path.dentry->d_iname);
		rsp->ret = QTFS_ERR;
		rsp->mask = EPOLLERR;
		fput(filp);
		return sizeof(struct qtrsp_poll);
	}
	mask = 0;
	if (filp->f_mode & FMODE_READ) {
		if (!qtfs_pipe_empty(pipe))
			mask |= EPOLLIN | EPOLLRDNORM;
		if (!pipe->writers && filp->f_version != pipe->w_counter)
			mask |= EPOLLHUP;
	}

	if (filp->f_mode & FMODE_WRITE) {
		if (!qtfs_pipe_full(pipe))
			mask |= EPOLLOUT | EPOLLWRNORM;
		if (!pipe->readers)
			mask |= EPOLLERR;
	}
end:
	rsp->mask = mask;
	rsp->ret = QTFS_OK;

	qtfs_info("handle fifo poll f_mode:%o: %s get poll mask 0x%x\n",
			filp->f_mode, filp->f_path.dentry->d_iname, rsp->mask);
	fput(filp);
	return sizeof(struct qtrsp_poll);
}

int handle_epollctl(struct qtserver_arg *arg)
{
	struct qtreq_epollctl *req = (struct qtreq_epollctl *)REQ(arg);
	struct qtrsp_epollctl *rsp = (struct qtrsp_epollctl *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s*)USERP(arg);
	int ret;
	struct epoll_event evt;

	evt.data = (__u64)req->event.data;
	evt.events = req->event.events;
	if (copy_to_user(userp->userp, &evt, sizeof(struct epoll_event))) {
		qtfs_err("copy to user failed.");
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_epollctl);
	}
	ret = qtfs_syscall_epoll_ctl(qtfs_epoll.epfd, req->op, req->fd, userp->userp);
	if (ret < 0) {
		qtfs_err("handle do epoll ctl failed, ret:%d.", ret);
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_epollctl);
	}
	qtinfo_cntinc((req->op == EPOLL_CTL_ADD) ? QTINF_EPOLL_ADDFDS : QTINF_EPOLL_DELFDS);
	rsp->ret = QTFS_OK;
	qtfs_info("handle do epoll ctl success, fd:%d op:%x poll_t:%x.",
			req->fd, req->op, (unsigned)req->event.events);

	return sizeof(struct qtrsp_epollctl);
}

int handle_llseek(struct qtserver_arg *arg)
{
	struct qtreq_llseek *req = (struct qtreq_llseek *)REQ(arg);
	struct qtrsp_llseek *rsp = (struct qtrsp_llseek *)RSP(arg);

	qtfs_info("llseek get req fd:%d, off:%lld whence:%d.", req->fd, req->off, req->whence);
	rsp->off = qtfs_syscall_lseek(req->fd, req->off, req->whence);
	if (rsp->off < 0) {
		qtfs_err("llseek ksys lseek return :%ld failed, req fd:%d off:%lld whence:%d.",
					rsp->off, req->fd, req->off, req->whence);
		rsp->ret = QTFS_ERR;
		goto end;
	}
	rsp->ret = QTFS_OK;
end:
	return sizeof(struct qtrsp_llseek);
}

int handle_exit(struct qtserver_arg *arg)
{
	return 0;
}

int handle_null(struct qtserver_arg *arg)
{
	qtfs_err("unknown events.");
	return 0;
}

int remotesc_kill(struct qtserver_arg *arg)
{
	struct qtreq_sc_kill *req = (struct qtreq_sc_kill *)REQ(arg);
	struct qtrsp_sc_kill *rsp = (struct qtrsp_sc_kill *)RSP(arg);
	char tskcomm[TASK_COMM_LEN] = {0};
	struct task_struct *t = qtfs_kern_syms.find_get_task_by_vpid((pid_t)req->pid);
	if (req->signum == 0)
		goto result;
	if (!t) {
		qtfs_err("Failed to get task by pid:%d", req->pid);
		rsp->ret = -EINVAL;
		goto end;
	}
	get_task_comm(tskcomm, t);
	if (!in_white_list_exact(tskcomm, QTFS_WHITELIST_KILL)) {
		qtfs_err("Failed to kill pid:%d, comm:%s not in kill white list", req->pid, tskcomm);
		rsp->ret = -EPERM;
		goto end;
	}
result:
	rsp->ret = qtfs_syscall_kill(req->pid, req->signum);
	qtfs_info("Recv remote kill request, pid:%d signum:%d ret:%ld", req->pid, req->signum, rsp->ret);
end:
	return sizeof(struct qtrsp_sc_kill);
}

int remotesc_sched_getaffinity(struct qtserver_arg *arg)
{
	struct qtreq_sc_sched_affinity *req = (struct qtreq_sc_sched_affinity *)REQ(arg);
	struct qtrsp_sc_sched_affinity *rsp = (struct qtrsp_sc_sched_affinity *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s*)USERP(arg);

	if (req->len > AFFINITY_MAX_LEN) {
		qtfs_err("invalid len:%lu", req->len);
		rsp->ret = -EINVAL;
		rsp->len = 0;
		goto end;
	}
	rsp->ret = qtfs_syscall_sched_getaffinity(req->pid, req->len, userp->userp);
	if (rsp->ret < 0) {
		qtfs_err("get affinity failed ret:%ld", rsp->ret);
		rsp->len = 0;
		goto end;
	}
	if (copy_from_user(rsp->user_mask_ptr, userp->userp, req->len)) {
		qtfs_err("copy affinity failed");
		rsp->len = 0;
		rsp->ret = -EFAULT;
		goto end;
	}
	rsp->len = req->len;
	qtfs_info("pid:%d get affinity successed", req->pid);
	return sizeof(struct qtrsp_sc_sched_affinity) + rsp->len * sizeof(unsigned long);

end:
	return sizeof(struct qtrsp_sc_sched_affinity);
}

int remotesc_sched_setaffinity(struct qtserver_arg *arg)
{
	struct qtreq_sc_sched_affinity *req = (struct qtreq_sc_sched_affinity *)REQ(arg);
	struct qtrsp_sc_sched_affinity *rsp = (struct qtrsp_sc_sched_affinity *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s*)USERP(arg);

	if (req->len > AFFINITY_MAX_LEN || req->len < 0) {
		qtfs_err("invalid len:%lu", req->len);
		rsp->ret = -EINVAL;
		rsp->len = 0;
		goto end;
	}
	if (copy_to_user(userp->userp, req->user_mask_ptr, req->len)) {
		qtfs_err("copy to user failed len:%lu", req->len);
		rsp->ret = -EFAULT;
		rsp->len = 0;
		goto end;
	}
	rsp->ret = qtfs_syscall_sched_setaffinity(req->pid, req->len, userp->userp);
	if (rsp->ret < 0) {
		qtfs_err("set affinity failed, ret:%ld pid:%d len:%lu", rsp->ret, req->pid, req->len);
		goto end;
	}
	qtfs_info("set affinity successed mask:%lx%lx", req->user_mask_ptr[0], req->user_mask_ptr[1]);
end:
	return sizeof(struct qtrsp_sc_sched_affinity);
}

static struct qtserver_ops qtfs_server_handles[] = {
	{QTFS_REQ_NULL,			req_check_none,		handle_null,		"null"},
	{QTFS_REQ_MOUNT,		req_check_mount,	handle_mount,		"mount"},
	{QTFS_REQ_OPEN,			req_check_open,		handle_open,		"open"},
	{QTFS_REQ_CLOSE,		req_check_close,	handle_close,		"close"},
	{QTFS_REQ_READ,			req_check_none,		handle_null,		"read"},
	{QTFS_REQ_READITER,		req_check_readiter,	handle_readiter,	"readiter"},
	{QTFS_REQ_WRITE,		req_check_write,	handle_write,		"write"},
	{QTFS_REQ_LOOKUP,		req_check_lookup,	handle_lookup,		"lookup"},
	{QTFS_REQ_READDIR,		req_check_readdir,	handle_readdir,		"readdir"},
	{QTFS_REQ_MKDIR,		req_check_mkdir,	handle_mkdir,		"mkdir"},
	{QTFS_REQ_RMDIR,		req_check_rmdir,	handle_rmdir,		"rmdir"},
	{QTFS_REQ_GETATTR,		req_check_getattr,	handle_getattr,		"getattr"},
	{QTFS_REQ_SETATTR,		req_check_setattr,	handle_setattr,		"setattr"},
	{QTFS_REQ_ICREATE,		req_check_icreate,	handle_icreate,		"icreate"},
	{QTFS_REQ_MKNOD,		req_check_mknod,	handle_mknod,		"mknod"},
	{QTFS_REQ_UNLINK,		req_check_unlink,	handle_unlink,		"unlink"},
	{QTFS_REQ_SYMLINK,		req_check_symlink,	handle_symlink,		"symlink"},
	{QTFS_REQ_LINK,			req_check_link,		handle_link,		"link"},
	{QTFS_REQ_GETLINK,		req_check_getlink,	handle_getlink,		"getlink"},
	{QTFS_REQ_READLINK,		req_check_readlink,	handle_null,		"readlink"},
	{QTFS_REQ_RENAME,		req_check_rename,	handle_rename,		"rename"},

	{QTFS_REQ_XATTRLIST,	req_check_xattrlist,	handle_xattrlist,	"xattrlist"},
	{QTFS_REQ_XATTRGET,		req_check_xattrget,		handle_xattrget,	"xattrget"},
	{QTFS_REQ_XATTRSET,		req_check_xattrset,		handle_xattrset,	"xattrset"},

	{QTFS_REQ_SYSMOUNT,		req_check_sysmount,		handle_syscall_mount,	"sysmount"},
	{QTFS_REQ_SYSUMOUNT,	req_check_sysumount,	handle_syscall_umount,	"sysumount"},
	{QTFS_REQ_FIFOPOLL,		req_check_fifopoll,		handle_fifopoll,		"fifo_poll"},

	{QTFS_REQ_STATFS,		req_check_statfs,		handle_statfs,		"statfs"},
	{QTFS_REQ_IOCTL,		req_check_ioctl,		handle_ioctl,		"ioctl"},

	{QTFS_REQ_EPOLL_CTL,	req_check_epoll_ctl,	handle_epollctl,	"epollctl"},
	{QTFS_REQ_EPOLL_EVENT,	req_check_none,			NULL,			"epollevent"},

	{QTFS_REQ_LLSEEK,		req_check_llseek,		handle_llseek,		"llseek"},

	// remote syscall or capability
	{QTFS_SC_KILL,			req_check_sc_kill,		remotesc_kill,		"remotesc_kill"},
	{QTFS_SC_SCHED_GETAFFINITY,	req_check_sc_sched_getaffinity,	remotesc_sched_getaffinity,	"sched_getaffinity"},
	{QTFS_SC_SCHED_SETAFFINITY,	req_check_sc_sched_setaffinity,	remotesc_sched_setaffinity, "sched_setaffinity"},

	{QTFS_REQ_EXIT,			req_check_none,			handle_exit,	"exit"}, // keep this handle at the end
};

int qtfs_conn_server_run(struct qtfs_conn_var_s *pvar)
{
	int ret;
	struct qtreq *req;
	struct qtreq *rsp;
	unsigned long totalproc = 0;

	req = pvar->vec_recv.iov_base;
	rsp = pvar->vec_send.iov_base;
	do {
		ret = qtfs_conn_recv_block(pvar);
		if (ret == -EPIPE) {
			qtfs_err("qtfs server thread recv EPIPE, restart the connection.");
			qtfs_sm_reconnect(pvar);
			break;
		}
		if (ret < 0)
			break;
		if (req->type >= QTFS_REQ_INV) {
			qtfs_err("qtfs server recv unknown operate type:%d\n", req->type);
			rsp->type = req->type;
			rsp->len = 0;
			rsp->err = QTFS_ERR;
		} else {
			struct qtserver_arg arg;
			arg.data = req->data;
			arg.out = rsp->data;
			if (qtfs_server_handles[req->type].precheck((void *)req->data) == QTFS_CHECK_ERR) {
				rsp->type = req->type;
				rsp->len = 0;
				rsp->err = QTFS_ERR;
				qtinfo_reqcheckinc(req->type);
				qtfs_err("qtfs server req type:%u precheck failed.", req->type);
				goto out;
			}
			read_lock(&g_userp_rwlock);
			arg.userp = &qtfs_userps[pvar->cur_threadidx];
			if (arg.userp->userp == NULL || arg.userp->userp2 == NULL)
				qtfs_err("server run userp or userp2 is invalid");
			rsp->len = qtfs_server_handles[req->type].handle(&arg);
			read_unlock(&g_userp_rwlock);
			rsp->type = req->type;
			rsp->err = QTFS_OK;
			totalproc++;
			qtinfo_recvinc(req->type);
		}
		if (rsp->len > QTFS_REQ_MAX_LEN) {
			qtfs_crit("handle rsp len error type:%d len:%lu", rsp->type, rsp->len);
			WARN_ON(1);
			rsp->len = QTFS_REQ_MAX_LEN - 1;
			rsp->err = QTFS_ERR;
		}
out:
		rsp->seq_num = req->seq_num;
		pvar->vec_send.iov_len = QTFS_MSG_LEN - QTFS_REQ_MAX_LEN + rsp->len;
		qtfs_debug("Server thread:%d count:%lu recv len:%d type:%d(%s) seq_num:%lu, reqlen:%lu, resp len:%lu, rsp threadidx:%d.\n",
				pvar->cur_threadidx, totalproc, ret, req->type, (req->type >= QTFS_REQ_INV) ? "null" : qtfs_server_handles[req->type].str,
				req->seq_num, req->len, pvar->vec_send.iov_len, pvar->cur_threadidx);
		ret = qtfs_conn_send(pvar);
		if (ret == -EPIPE) {
			qtfs_err("qtfs server send get EPIPE, just restart the connection\n");
			qtfs_sm_reconnect(pvar);
			break;
		}
		if (ret < 0) {
			qtfs_err("conn send failed, ret:%d\n", ret);
			WARN_ON(1);
		}
		qtinfo_sendinc(rsp->type);
	} while(0);

	return (ret < 0) ? QTERROR : QTOK;
}

