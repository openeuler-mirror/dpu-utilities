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


#include "req.h"
#include "qtfs_check.h"

/*
	检查原则：
	1. 基本数据类型，据实严格判断合法范围，有数组、指针操作的注意数组越界或指针飞踩；
	2. 字符串类型，基本的判断在长度范围内要有结束符，多个字符串拼接的，每一段起始和
		结束都能被结束符分开。
	
*/

// string类型基本防护，在max范围内最后一个字符必须是结束符，防止越界访问
static inline bool check_string(char *str, size_t max)
{
	if (max == 0)
		return false;
	if (str[max - 1] != '\0')
		return true;
	return false;
}

static inline bool check_fd(int fd)
{
#define FILENO_STDERR 2
	if (fd <= FILENO_STDERR)
		return true;
	return false;
}

#define TOREQ (typeof(req))in;
#define TORSP (typeof(rsp))in;
int req_check_none(void *in)
{
	return QTFS_CHECK_OK;
}

int req_check_mount(void *in)
{
	struct qtreq_mount *req = TOREQ;

	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_open(void *in)
{
	struct qtreq_open *req = TOREQ;

	// flags 和 mode如果错误syscall会报错，不会有安全风险
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_close(void *in)
{
	struct qtreq_close *req = TOREQ;
	if (check_fd(req->fd))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_readiter(void *in)
{
	struct qtreq_readiter *req = TOREQ;
	if (check_fd(req->fd))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_write(void *in)
{
	struct qtreq_write *req = TOREQ;
	if (check_fd(req->d.fd) || req->d.buflen > sizeof(req->path_buf))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_lookup(void *in)
{
	struct qtreq_lookup *req = TOREQ;
	if (check_string(req->fullname, sizeof(req->fullname)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_readdir(void *in)
{
	struct qtreq_readdir *req = TOREQ;
	struct qtrsp_readdir *rsp = TORSP;
	if (req->count != sizeof(rsp->dirent) || check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_mkdir(void *in)
{
	struct qtreq_mkdir *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_rmdir(void *in)
{
	struct qtreq_rmdir *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_getattr(void *in)
{
	struct qtreq_getattr *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_setattr(void *in)
{
	struct qtreq_setattr *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)) || req->attr.ia_file != NULL)
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_icreate(void *in)
{
	struct qtreq_icreate *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_mknod(void *in)
{
	struct qtreq_mknod *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_unlink(void *in)
{
	struct qtreq_unlink *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_symlink(void *in)
{
	struct qtreq_symlink *req = TOREQ;
	int total_len = sizeof(req->path);
	if (req->d.newlen + req->d.oldlen >= total_len ||
			req->d.newlen == 0 || req->d.oldlen == 0)
		return QTFS_CHECK_ERR;
	if (check_string(req->path, req->d.newlen) ||
			check_string(&req->path[req->d.newlen], req->d.oldlen))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_link(void *in)
{
	struct qtreq_link *req = TOREQ;
	int total_len = sizeof(req->path);
	if (req->d.oldlen + req->d.newlen > total_len ||
			req->d.oldlen == 0 || req->d.newlen == 0)
		return QTFS_CHECK_ERR;
	if (check_string(req->path, req->d.oldlen) ||
			check_string(&req->path[req->d.oldlen], req->d.oldlen))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_getlink(void *in)
{
	struct qtreq_getlink *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_rename(void *in)
{
	struct qtreq_rename *req = TOREQ;
	int total_len = sizeof(req->path);
	if (req->d.oldlen + req->d.newlen > total_len ||
			req->d.oldlen == 0 || req->d.newlen == 0)
		return QTFS_CHECK_ERR;
	if (check_string(req->path, req->d.oldlen) ||
			check_string(&req->path[req->d.oldlen], req->d.oldlen))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}
int req_check_xattrlist(void *in)
{
	struct qtreq_xattrlist *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_xattrget(void *in)
{
	struct qtreq_xattrget *req = TOREQ;
	if (check_string(req->d.prefix_name, sizeof(req->d.prefix_name)) ||
			check_string(req->path, PATH_MAX))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_xattrset(void *in)
{
	struct qtreq_xattrset *req = TOREQ;
	if (req->d.pathlen == 0 || req->d.namelen == 0 ||
			req->d.pathlen + req->d.namelen + req->d.valuelen > sizeof(req->buf))
		return QTFS_CHECK_ERR;
	if (check_string(req->buf, req->d.pathlen) ||
			check_string(&req->buf[req->d.pathlen], req->d.namelen) ||
			check_string(&req->buf[req->d.pathlen + req->d.namelen], req->d.valuelen))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_sysmount(void *in)
{
	int pos = 0;
	struct qtreq_sysmount *req = TOREQ;
	if (req->d.dev_len + req->d.dir_len + req->d.type_len + req->d.data_len > sizeof(req->buf))
		return QTFS_CHECK_ERR;
	if (req->d.dir_len == 0)
		return QTFS_CHECK_ERR;
	if (check_string(req->buf, req->d.dev_len))
		return QTFS_CHECK_ERR;
	pos += req->d.dev_len;
	if (check_string(&req->buf[pos], req->d.dir_len))
		return QTFS_CHECK_ERR;
	pos += req->d.dir_len;
	if (check_string(&req->buf[pos], req->d.type_len))
		return QTFS_CHECK_ERR;
	pos += req->d.type_len;
	if (check_string(&req->buf[pos], req->d.data_len))
		return QTFS_CHECK_ERR;

	return QTFS_CHECK_OK;
}

int req_check_sysumount(void *in)
{
	struct qtreq_sysumount *req = TOREQ;
	if (check_string(req->buf, sizeof(req->buf)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_fifopoll(void *in)
{
	struct qtreq_poll *req = TOREQ;
	if (check_fd(req->fd))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_statfs(void *in)
{
	struct qtreq_statfs *req = TOREQ;
	if (check_string(req->path, sizeof(req->path)))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_ioctl(void *in)
{
	struct qtreq_ioctl *req = TOREQ;
	if (req->d.argtype != 0 && req->d.argtype != 1)
		return QTFS_CHECK_ERR;
	if (req->d.size > sizeof(req->path) || check_fd(req->d.fd))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_epoll_ctl(void *in)
{
	struct qtreq_epollctl *req = TOREQ;
	if (check_fd(req->fd))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_llseek(void *in)
{
	struct qtreq_llseek *req = TOREQ;
	if (check_fd(req->fd))
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_sc_kill(void *in)
{
	return QTFS_CHECK_OK;
}

int req_check_sc_sched_getaffinity(void *in)
{
	struct qtreq_sc_sched_affinity *req = TOREQ;
	if (req->len > AFFINITY_MAX_LEN || req->len == 0)
		return QTFS_CHECK_ERR;
	return QTFS_CHECK_OK;
}

int req_check_sc_sched_setaffinity(void *in)
{
	return req_check_sc_sched_getaffinity(in);
}
