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

#ifndef __QTFS_OPS_H__
#define __QTFS_OPS_H__

#include <linux/fs.h>
#include <linux/version.h>

#include "qtfs-mod.h"

extern struct inode_operations qtfs_proc_inode_ops;
extern struct file_operations qtfs_proc_file_ops;
extern struct inode_operations qtfs_proc_sym_ops;

enum qtfs_type qtfs_get_type(char *str);
bool is_sb_proc(struct super_block *sb);

struct inode *qtfs_iget(struct super_block *sb, struct inode_info *ii);
const char *qtfs_getlink(struct dentry *dentry,
					struct inode *inode, struct delayed_call *done);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
int qtfs_getattr(struct user_namespace *mnt_userns, const struct path *, struct kstat *, u32, unsigned int);
#else
int qtfs_getattr(const struct path *, struct kstat *, u32, unsigned int);
#endif
struct dentry * qtfs_lookup(struct inode *, struct dentry *, unsigned int);

#endif
