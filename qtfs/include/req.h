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

#ifndef __QTFS_REQ_STRUCT_DEF_H__
#define __QTFS_REQ_STRUCT_DEF_H__

#include <linux/fs.h>
#include <linux/statfs.h>
#include <uapi/linux/limits.h>
#include "log.h"

enum qtreq_type {
	QTFS_REQ_NULL,
	QTFS_REQ_MOUNT,
	QTFS_REQ_OPEN,
	QTFS_REQ_CLOSE,
	QTFS_REQ_READ,
	QTFS_REQ_READITER, // 5
	QTFS_REQ_WRITE,
	QTFS_REQ_LOOKUP,
	QTFS_REQ_READDIR,
	QTFS_REQ_MKDIR,
	QTFS_REQ_RMDIR, // 10
	QTFS_REQ_GETATTR,
	QTFS_REQ_SETATTR,
	QTFS_REQ_ICREATE,
	QTFS_REQ_MKNOD,
	QTFS_REQ_UNLINK, // 15
	QTFS_REQ_SYMLINK,
	QTFS_REQ_LINK,
	QTFS_REQ_GETLINK,
	QTFS_REQ_READLINK,
	QTFS_REQ_RENAME, // 20

	QTFS_REQ_XATTRLIST,
	QTFS_REQ_XATTRGET,
	QTFS_REQ_XATTRSET,

	QTFS_REQ_SYSMOUNT,
	QTFS_REQ_SYSUMOUNT, // 25
	QTFS_REQ_FIFOPOLL,

	QTFS_REQ_STATFS,
	QTFS_REQ_IOCTL,

	QTFS_REQ_EPOLL_CTL,

	QTFS_REQ_EPOLL_EVENT,

	QTFS_REQ_LLSEEK,

	// REMOTE SYSCALL
	QTFS_SC_KILL,
	QTFS_SC_SCHED_GETAFFINITY,
	QTFS_SC_SCHED_SETAFFINITY,

	QTFS_REQ_EXIT, // exit server thread
	QTFS_REQ_INV,
};
#define QTFS_REQ_TYPEVALID(type) (type < QTFS_REQ_INV && type >= QTFS_REQ_NULL)


enum qtreq_ret {
	QTFS_OK,
	QTFS_ERR,
};

enum qtfs_type {
	QTFS_NORMAL,
	QTFS_PROC,
	QTFS_SYS, // for sysfs
};

struct qtfs_dirent64 {
	u64		d_ino;
	s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	unsigned char	resv[5];
	char		d_name[];
};

#define NBYTES 256
#define ISCHR(x) ((x >= 32 && x <= 126))
static inline void qtfs_nbytes_print(unsigned char *buf, int bytes)
{
	int i = 0;
	qtfs_info("nbyts:%d->", bytes);
	for (; i < bytes; i++) {
		if (ISCHR(buf[i])) {
			qtfs_info("addr:0x%lx, %x(%c)\n", (unsigned long)&buf[i], buf[i], buf[i]);
		} else
			qtfs_info("addr:0x%lx, %x\n", (unsigned long)&buf[i], buf[i]);
	}
}


#define QTFS_SEND 0
#define QTFS_RECV 1

// maximum possible length, can be increased according to the actual situation
#define NAME_MAX	255
#define MAX_PATH_LEN PATH_MAX
#define MAX_ELSE_LEN (1024 * 128)
#define QTFS_REQ_MAX_LEN (MAX_PATH_LEN + MAX_ELSE_LEN)

#define MAX_BUF 4096

// QTFS_TAIL_LEN解释：
// 私有数据结构最大长度为QTFS_REQ_MAX_LEN，超出就越界了
// 一般有变长buf要求的，把变长buf放在末尾
// 其长度定义为QTFS_REQ_MAX_LEN减去前面所有成员结构长度
// 尾部变长数组长度自定义的，整体结构体长度不能超出最大长度
#define QTFS_TAIL_LEN(head) (QTFS_REQ_MAX_LEN - sizeof(head))

// QTFS_SEND_SIZE解释：
// 用来发送的数据结构buf为固定大小QTFS_REQ_MAX_LEN
// 但是我们大多数时候只使用了少量的bytes
// 只需要发送有效数据，所以私有数据结构一般采取一些关键
// 字段，加一个动态buf的组合方式，buf放在结构体末尾
// 当传输时，只传输关键字段和动态buf的有效长度，可以用这个宏
// 来计算所需发送的有效长度
// 如果结构体定义不是：关键字段+字符串buf的模式，则不能用这个宏
// 因为这个宏使用了strlen来测量末尾有效长度
#define QTFS_SEND_SIZE(stru, tailstr) sizeof(stru) - sizeof(tailstr) + strlen(tailstr) + 1

struct qtreq {
	unsigned int type; // operation type
	unsigned int err;
	unsigned long seq_num; // check code
	size_t len;
	char data[QTFS_REQ_MAX_LEN]; // operation's private data
};

#define QTFS_MSG_LEN sizeof(struct qtreq)
#define QTFS_MSG_HEAD_LEN (QTFS_MSG_LEN - QTFS_REQ_MAX_LEN)

struct qtreq_ioctl {
	struct qtreq_ioctl_len {
		unsigned int cmd;
		unsigned int size;
		int fd;
	} d;

	char path[QTFS_TAIL_LEN(struct qtreq_ioctl_len)];
};

struct qtrsp_ioctl {
	int ret;
	int errno;
	unsigned int size;

	char buf[MAX_PATH_LEN];
};

struct qtreq_statfs {
	char path[MAX_PATH_LEN];	// include file name
};

struct qtrsp_statfs {
	struct kstatfs kstat;
	int ret;
	int errno;
};

struct qtreq_mount {
	char path[MAX_PATH_LEN];	// include file name
};
struct qtrsp_mount {
	int ret;
};

struct qtreq_open {
	__u64 flags;
	unsigned int mode;
	char path[MAX_PATH_LEN];
};

struct qtrsp_open {
	int fd;
	int ret;
};

struct qtreq_close {
	int fd;
};

struct qtrsp_close {
	int ret;
};

struct qtreq_readiter {
	size_t len;
	long long pos;
	int fd;
};

struct qtrsp_readiter {
	struct qtrsp_readiter_len {
		int ret;
		ssize_t len;
		int errno;
		int end;
	} d;
	char readbuf[QTFS_TAIL_LEN(struct qtrsp_readiter_len)];
};

struct qtreq_write {
	struct qtreq_write_len {
		int buflen;
		long long pos;
		int fd;
		long long flags;
		long long mode;
		long long total_len;
	} d;
	// fullname and writebuf
	char path_buf[QTFS_TAIL_LEN(struct qtreq_write_len)];
};

struct qtrsp_write {
	int ret;
	ssize_t len; // 成功写入的长度
};

struct qtreq_mmap {
	char path[MAX_PATH_LEN];
};

struct qtrsp_mmap {
	int ret;
};

struct qtreq_lookup {
	char fullname[MAX_PATH_LEN];
};

struct inode_info {
	unsigned int mode;
	unsigned short i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	unsigned long i_ino;

	dev_t i_rdev;
	long long i_size;

	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;

	unsigned short		i_bytes;
	u8					i_blkbits;
	u8					i_write_hint;
	blkcnt_t			i_blocks;

	unsigned long		i_state;
	unsigned long		dirtied_when;	/* jiffies of first dirtying */
	unsigned long		dirtied_time_when;

	__u32			i_generation;
};

struct qtrsp_lookup {
	int ret;
	int errno;
	struct inode_info inode_info;
};

struct qtreq_readdir {
	int count;
	loff_t pos;
	char path[MAX_PATH_LEN];
};

struct qtrsp_readdir {
	struct qtrsp_readdir_len {
		int ret;
		int vldcnt;
		int over; // 是否已经全部获取完成
		loff_t pos;
	} d;
	char dirent[QTFS_TAIL_LEN(struct qtrsp_readdir_len)];
};

struct qtreq_mkdir {
	umode_t mode;
	char path[MAX_PATH_LEN];
};

struct qtrsp_mkdir {
	int ret;
	int errno;
	struct inode_info inode_info;
};

struct qtreq_rmdir {
	char path[MAX_PATH_LEN];
};

struct qtrsp_rmdir {
	int ret;
	int errno;
};

struct qtreq_getattr {
	u32 request_mask;
	unsigned int query_flags;
	char path[MAX_PATH_LEN];
};

struct qtrsp_getattr {
	int ret;
	int errno;
	struct kstat stat;
};

struct qtreq_setattr {
	struct iattr attr;
	char path[MAX_PATH_LEN];
};

struct qtrsp_setattr {
	int ret;
	int errno;
};

struct qtreq_icreate {
	umode_t mode;
	bool excl;
	char path[MAX_PATH_LEN];
};

struct qtrsp_icreate {
	int ret;
	int errno;
	struct inode_info inode_info;
};

struct qtreq_mknod {
	umode_t mode;
	dev_t dev;
	char path[MAX_PATH_LEN];
};

struct qtrsp_mknod {
	int ret;
	int errno;
	struct inode_info inode_info;
};

struct qtreq_unlink {
	char path[MAX_PATH_LEN];
};

struct qtrsp_unlink {
	int errno;
};

struct qtreq_symlink {
	struct qtreq_symlink_len {
		int newlen;
		int oldlen;
	} d;
	char path[QTFS_TAIL_LEN(struct qtreq_symlink_len)];
};

struct qtrsp_symlink {
	int ret;
	int errno;
	struct inode_info inode_info;
};

struct qtreq_link {
	struct qtreq_link_len {
		int newlen;
		int oldlen;
	} d;
	char path[QTFS_TAIL_LEN(struct qtreq_link_len)];
};

struct qtrsp_link {
	int ret;
	int errno;
	struct inode_info inode_info;
};

struct qtreq_getlink {
	char path[MAX_PATH_LEN];
};

struct qtrsp_getlink {
	int ret;
	int errno;
	char path[MAX_PATH_LEN];
};

struct qtreq_readlink {
	char path[MAX_PATH_LEN];
};

struct qtrsp_readlink {
	int ret;
	int errno;
	int len;
	char path[MAX_PATH_LEN];
};

struct qtreq_rename {
	struct qtreq_rename_len {
		int oldlen;
		int newlen;
		unsigned int flags;
	}d;
	char path[QTFS_TAIL_LEN(struct qtreq_rename_len)];
};

struct qtrsp_rename {
	int ret;
	int errno;
};

// xattr def
#define QTFS_XATTR_LEN 64
struct qtreq_xattrlist {
	size_t buffer_size;
	char path[MAX_PATH_LEN];
};

struct qtrsp_xattrlist {
	struct qtrsp_xattrlist_len {
		int ret;
		ssize_t size;
	}d;
	char name[QTFS_TAIL_LEN(struct qtrsp_xattrlist_len)];
};

struct qtreq_xattrget {
	struct qtreq_xattrget_len {
		int pos;
		int size; // 请求最多可以读取多少字节
		char prefix_name[QTFS_XATTR_LEN];
	}d;
	char path[QTFS_TAIL_LEN(struct qtreq_xattrget_len)];
};

struct qtrsp_xattrget {
	struct qtrsp_xattrget_len {
		int ret;
		int errno;
		ssize_t size;
		int pos;
	}d;
	char buf[QTFS_TAIL_LEN(struct qtrsp_xattrget_len)];
};

struct qtreq_xattrset {
	struct qtreq_xattrset_len {
		size_t size;
		int flags;
		int pathlen;
		int namelen;
		int valuelen;
	} d;
	/* buf: file path + name + value */
	char buf[QTFS_TAIL_LEN(struct qtreq_xattrset_len)];
};

struct qtrsp_xattrset {
	int ret;
	int errno;
};
// xattr end

struct qtreq_sysmount {
	struct qtreq_sysmount_len {
		int dev_len;
		int dir_len;
		int type_len;
		int data_len;
		unsigned long flags;
	} d;
	char buf[QTFS_TAIL_LEN(struct qtreq_sysmount_len)];
};

struct qtrsp_sysmount {
	int errno;
};

struct qtreq_sysumount {
	int flags;
	char buf[MAX_PATH_LEN];
};

struct qtrsp_sysumount {
	int errno;
};

struct qtreq_poll {
	int fd;
	int qproc;
};

struct qtrsp_poll {
	int ret;
	__poll_t mask;
};


struct qtreq_epollctl {
	int fd;
	int op;
	struct qtreq_epoll_event event;
};

struct qtrsp_epollctl {
	int ret;
};


// server epoll 通知 client
#define QTFS_EPOLL_MAX_EVENTS 128
struct qtreq_epollevt {
	int event_nums;
	struct qtreq_epoll_event events[QTFS_EPOLL_MAX_EVENTS];
};

struct qtrsp_epollevt {
	int ret;
};

struct qtreq_llseek {
	loff_t off;
	int whence;
	int fd;
};

struct qtrsp_llseek {
	int ret;
	off_t off;
};

struct qtreq_sc_kill {
	int pid;
	int signum;
};

struct qtrsp_sc_kill {
	long ret;
};

enum {
	SC_GET = 0,
	SC_SET,
};
#define AFFINITY_MAX_LEN (8192 / BITS_PER_LONG) // max cpu nums 8192
struct qtreq_sc_sched_affinity {
	int type; // 0-get or 1-set
	int pid;
	unsigned int len;
	unsigned long user_mask_ptr[0];
};

struct qtrsp_sc_sched_affinity {
	long ret;
	int len;
	unsigned long user_mask_ptr[0];
};
#endif
