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

#ifndef __QTFS_SERVER_H__
#define __QTFS_SERVER_H__

extern int qtfs_server_thread_run;
extern struct qtfs_server_epoll_s qtfs_epoll;
extern int qtfs_mod_exiting;
extern rwlock_t g_userp_rwlock;
extern struct qtserver_fd_bitmap qtfs_fd_bitmap;

struct qtserver_arg {
	char *data;
	char *out;
	struct qtfs_server_userp_s *userp;
};

struct qtserver_ops {
	int type;
	int (*precheck) (void *); // check req from socket recv
	// return int is output len.
	int (*handle) (struct qtserver_arg *);
	char str[32];
};

struct qtserver_fd_bitmap {
	unsigned int nbits;
	unsigned long *bitmap;
};

int qtfs_conn_server_run(struct qtfs_conn_var_s *pvar);
long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int qtfs_misc_register(void);
void qtfs_misc_destroy(void);
long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
void qtfs_whitelist_clearall(void);
void qtfs_whitelist_initset(void);

#endif
