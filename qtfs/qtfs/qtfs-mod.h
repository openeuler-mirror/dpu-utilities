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

#ifndef __QTFS_INCLUDE_H__
#define __QTFS_INCLUDE_H__

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/errno.h>
#include <asm/current.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/dirent.h>

#include "comm.h"
#include "log.h"
#include "req.h"


#define QTFS_MAXLEN			8
#define QTFS_MAX_FILES		32
#define QTFS_MAX_BLOCKSIZE	512

#define QTFS_FSTYPE_NAME "qtfs"

extern struct kmem_cache *qtfs_inode_priv_cache;

struct private_data {
	int fd;
};

struct qtfs_inode_priv {
	unsigned int files;
	wait_queue_head_t readq;
	wait_queue_head_t writeq;
};

enum {
	QTFS_ROOT_INO		= 1,
	QTFS_IPC_INIT_INO	= 0xEFFFFFFFU,
	QTFS_UTS_INIT_INO	= 0xEFFFFFFEU,
	QTFS_USER_INIT_INO	= 0xEFFFFFFDU,
	QTFS_PID_INIT_INO	= 0xEFFFFFFCU,
	QTFS_CGROUP_INIT_INO	= 0xEFFFFFFBU,
	QTFS_TIME_INIT_INO	= 0xEFFFFFFAU,
	QTFS_IMA_INIT_INO	= 0xEFFFFFF9U,
};

struct qtfs_inode {
	mode_t mode;
	uint64_t i_no;
	uint64_t d_no;
	char *peer_path;
	union {
		uint64_t file_size;
		uint64_t dir_childrens;
	};
	struct list_head entry;
};

struct qtfs_fs_info {
	char peer_path[NAME_MAX];
	char *mnt_path;

	enum qtfs_type type;
};

struct qtfs_dir_entry {
	struct list_head node;
	char filename[NAME_MAX];
	struct qtfs_inode *priv;
};

struct qtfs_file_blk {
	uint8_t busy;
	mode_t mode;
	uint8_t idx;

	union {
		uint8_t file_size;
		uint8_t dir_children;
	};
	char data[0];
};

struct qtmiss_ops {
	int type;
	// return int is output len.
	int (*misshandle) (struct qtreq *);
	char str[32];
};

static inline int qtfs_fullname(char *fullname, struct dentry *d, size_t buflen)
{
	struct qtfs_fs_info *fsinfo = NULL;
	int len = 0;
	char *name = NULL;
	char *ret = NULL;

	if (!d) {
		qtfs_info("%s: get dentry fullname NULL\n", __func__);
		return -1;
	}
	if (buflen < MAX_PATH_LEN) {
		qtfs_err("%s: failed to get fullname dure to small buflen:%lu\n", __func__, buflen);
		return -1;
	}
	
	name = __getname();
	if (!name) {
		return -1;
	}
	ret = dentry_path_raw(d, name, MAX_PATH_LEN);
	if (IS_ERR_OR_NULL(ret)) {
		qtfs_err("qtfs fullname failed:%ld\n", QTFS_PTR_ERR(ret));
		__putname(name);
		return -1;
	}

	if (d && d->d_sb && d->d_sb->s_fs_info) {
		fsinfo = d->d_sb->s_fs_info;
	} else {
		qtfs_err("%s: failed to get private fs_info\n", __func__);
		__putname(name);
		return -1;
	}
	if (strcmp(fsinfo->peer_path, "/")) {
		/* if peer_path is not root '/' */
		len = strlcpy(fullname, fsinfo->peer_path, MAX_PATH_LEN);
	}
	if (len + strlen(ret) >= MAX_PATH_LEN - 1) {
		qtfs_err("qtfs fullname may reach max len:%d reallen:%ld path:%s", len, strlen(fullname), fullname);
		__putname(name);
		return -1;
	}
	len += strlcpy(&fullname[len], ret, MAX_PATH_LEN - len);
	if (strcmp(fullname, "/")) {
		if (fullname[strlen(fullname) - 1] == '/')
			fullname[strlen(fullname) - 1] = '\0';
	}
	__putname(name);
	return len;
}

#define QTFS_FULLNAME(fullname, d, buflen) \
	if (qtfs_fullname(fullname, d, buflen)<0) { \
		qtfs_err("qtfs fullname failed\n"); \
		qtfs_conn_put_param(pvar); \
		return -EINVAL; \
	}

extern const struct xattr_handler qtfs_xattr_user_handler;
extern const struct xattr_handler qtfs_xattr_trusted_handler;
extern const struct xattr_handler qtfs_xattr_security_handler;
extern const struct xattr_handler qtfs_xattr_hurd_handler;
extern struct qtinfo *qtfs_diag_info;
extern int qtfs_mod_exiting;

void qtfs_kill_sb(struct super_block *sb);
struct dentry *qtfs_fs_mount(struct file_system_type *fs_type,
							int flags, const char *dev_name,
							void *data);
void *qtfs_remote_run(struct qtfs_conn_var_s *pvar, unsigned int type, unsigned int len);
int qtfs_misc_register(void);
void qtfs_misc_destroy(void);
long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int qtfs_missmsg_proc(struct qtfs_conn_var_s *pvar);
int qtfs_utils_register(void);
void qtfs_utils_destroy(void);

#endif

