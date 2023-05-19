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
extern struct whitelist* g_whitelist[QTFS_WHITELIST_MAX];
extern rwlock_t g_whitelist_rwlock;
extern rwlock_t g_userp_rwlock;

struct qtserver_arg {
	char *data;
	char *out;
	struct qtfs_server_userp_s *userp;
};

struct qtserver_ops {
	int type;
	// return int is output len.
	int (*handle) (struct qtserver_arg *);
	char str[32];
};

int qtfs_conn_server_run(struct qtfs_conn_var_s *pvar);
long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int qtfs_misc_register(void);
void qtfs_misc_destroy(void);
long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif
