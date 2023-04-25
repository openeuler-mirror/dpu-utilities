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
int qtfs_kallsyms_hack_init(void);

#ifdef QTFS_CLIENT
enum {
	SYMBOL_SYSCALL_MOUNT,
	SYMBOL_SYSCALL_UMOUNT,
	SYMBOL_SYSCALL_EPOLL_CTL,
	SYMBOL_SYSCALL_CONNECT,
	SYMBOL_MAX_NUM,
};
#endif
#ifdef QTFS_SERVER
enum {
	SYMBOL_SYSCALL_CONNECT,
	SYMBOL_MAX_NUM,
};
#endif
extern unsigned long *symbols_origin[SYMBOL_MAX_NUM];

#ifdef __x86_64__
// make the page writeable
static inline int make_rw(unsigned long address)
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte |= _PAGE_RW;
	return 0;
}

// make the page write protected
static inline int make_ro(unsigned long address)
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte &= ~_PAGE_RW;
	return 0;
}
#endif

#ifdef __aarch64__
extern void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
extern unsigned long start_rodata, end_rodata;
#define section_size (end_rodata - start_rodata)
#endif

int qtfs_syscall_replace_start(void);
void qtfs_syscall_replace_stop(void);

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
long qtfs_syscall_write(unsigned int fd, const char __user *buf, size_t count);
long qtfs_syscall_read(unsigned int fd, char __user *buf, size_t count);

long qtfs_syscall_kill(pid_t pid, int sig);
long qtfs_syscall_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
long qtfs_syscall_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
long qtfs_syscall_connect(int fd, struct sockaddr __user *uservaddr, int addrlen);
#endif

