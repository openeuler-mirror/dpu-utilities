/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * qtfs licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Liqiang
 * Create: 2023-03-20
 * Description: 
 *******************************************************************************/

#ifndef __QTINFO_H__
#define __QTINFO_H__


enum qtfs_req_type
{
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

	QTFS_REQ_EXIT,
	QTFS_REQ_INV,
};

#define MAX_QTINFO_TYPE_STR_LEN 20

struct qtinfo_type_str {
	enum qtfs_req_type type;
	char str[MAX_QTINFO_TYPE_STR_LEN];
};

#endif

