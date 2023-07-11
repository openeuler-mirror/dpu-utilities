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

#ifndef __QTFS_CHECK_H__
#define __QTFS_CHECK_H__

#include "req.h"

enum {
	QTFS_CHECK_OK,
	QTFS_CHECK_ERR,
};

int req_check_none(void *in);
int req_check_mount(void *in);
int req_check_open(void *in);
int req_check_close(void *in);
int req_check_readiter(void *in);
int req_check_write(void *in);
int req_check_lookup(void *in);
int req_check_readdir(void *in);
int req_check_mkdir(void *in);
int req_check_rmdir(void *in);
int req_check_getattr(void *in);
int req_check_setattr(void *in);
int req_check_icreate(void *in);
int req_check_mknod(void *in);
int req_check_unlink(void *in);
int req_check_symlink(void *in);
int req_check_link(void *in);
int req_check_getlink(void *in);
int req_check_readlink(void *in);
int req_check_rename(void *in);
int req_check_xattrlist(void *in);
int req_check_xattrget(void *in);
int req_check_xattrset(void *in);
int req_check_sysmount(void *in);
int req_check_sysumount(void *in);
int req_check_fifopoll(void *in);
int req_check_statfs(void *in);
int req_check_ioctl(void *in);
int req_check_epoll_ctl(void *in);
int req_check_llseek(void *in);
int req_check_sc_kill(void *in);
int req_check_sc_sched_getaffinity(void *in);
int req_check_sc_sched_setaffinity(void *in);

#endif

