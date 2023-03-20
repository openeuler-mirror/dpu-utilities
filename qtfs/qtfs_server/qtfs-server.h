/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __QTFS_SERVER_H__
#define __QTFS_SERVER_H__

extern int qtfs_server_thread_run;
extern struct qtfs_server_epoll_s qtfs_epoll;
extern int qtfs_mod_exiting;
extern struct whitelist* whitelist[QTFS_WHITELIST_MAX];

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

int qtfs_sock_server_run(struct qtfs_sock_var_s *pvar);
long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int qtfs_misc_register(void);
void qtfs_misc_destroy(void);
long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif
