/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __QTFS_SYMBOL_WRAPPER_H__
#define __QTFS_SYMBOL_WRAPPER_H__

#include <linux/version.h>
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t qtfs_kallsyms_lookup_name;

struct qtfs_kallsyms {
	unsigned long **sys_call_table;

	char *(*d_absolute_path)(const struct path *, char *, int);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 10, 0))
	int (*__close_fd)(struct files_struct *, int);
#endif
	struct task_struct *(*find_get_task_by_vpid)(pid_t nr);
};

extern struct qtfs_kallsyms qtfs_kern_syms;
void qtfs_kallsyms_hack_init(void);

#ifdef QTFS_CLIENT
enum {
	SYMBOL_SYSCALL_MOUNT,
	SYMBOL_SYSCALL_UMOUNT,
	SYMBOL_SYSCALL_EPOLL_CTL,
	SYMBOL_MAX_NUM,
};
extern unsigned long *symbols_origin[SYMBOL_MAX_NUM];
#endif

noinline long qtfs_syscall_umount(char __user *name, int flags);
noinline long qtfs_syscall_mount(char __user *dev_name, char __user *dir_name,
			char __user *type, unsigned long flags, void __user *data);
noinline long qtfs_syscall_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event);
noinline long qtfs_syscall_unlink(const char __user *pathname);
noinline int qtfs_syscall_readlinkat(int dfd, const char __user *path,
			char __user *buf, int bufsiz);
noinline int qtfs_syscall_renameat2(int olddfd, const char __user *oldname,
			int newdfd, const char __user *newname, unsigned int flags);
noinline long qtfs_syscall_mkdirat(int dfd, const char __user *pathname, umode_t mode);
noinline long qtfs_syscall_rmdir(const char __user *pathname);
noinline int qtfs_syscall_statfs(const char __user *path, struct statfs __user *buf);
noinline int qtfs_syscall_openat(int dfd, const char __user *filename, int flags,
			umode_t mode);
noinline int qtfs_syscall_epoll_wait(int epfd, struct epoll_event __user *events,
			int maxevents, int timout);
noinline int qtfs_syscall_linkat(int olddfd, const char __user *oldname,
			int newdfd, const char __user *newname, int flags);
noinline long qtfs_syscall_mknodat(int dfd, const char __user *filename, umode_t mode,
			unsigned int dev);
noinline off_t qtfs_syscall_lseek(unsigned int fd, off_t offset, unsigned int whence);
long qtfs_syscall_kill(pid_t pid, int sig);
long qtfs_syscall_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
long qtfs_syscall_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
#endif

