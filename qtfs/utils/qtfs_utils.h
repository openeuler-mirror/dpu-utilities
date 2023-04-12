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

#ifndef __QTFS_UTILS_H__
#define __QTFS_UTILS_H__

#define QTFS_UTILS_DEV "/dev/qtfs_utils"

// QTFS provide some remote capability
#define QTUTIL_IOCTL_CAPA_MAGIC 'U'
enum {
	_QTUTIL_IOCTL_CAPA_PORT_INUSE,
};
#define QTUTIL_CAPA(CAP) _IO(QTUTIL_IOCTL_CAPA_MAGIC, CAP)
#define QTUTIL_CAPA_PORT_INUSE		QTUTIL_CAPA(_QTUTIL_IOCTL_CAPA_PORT_INUSE)

// QTFS provide some remote syscalls
#define QTUTIL_IOCTL_SC_MAGIC 'S'
enum {
	_QTUTIL_IOCTL_SYSCALL_KILL,
	_QTUTIL_IOCTL_SYSCALL_SCHED_SETAFFINITY,
	_QTUTIL_IOCTL_SYSCALL_SCHED_GETAFFINITY,
};
#define QTUTIL_SYSCALL(SC) _IO(QTUTIL_IOCTL_SC_MAGIC, SC)
#define QTUTIL_SC_KILL					QTUTIL_SYSCALL(_QTUTIL_IOCTL_SYSCALL_KILL)
#define QTUTIL_SC_SCHED_SETAFFINITY		QTUTIL_SYSCALL(_QTUTIL_IOCTL_SYSCALL_SCHED_SETAFFINITY)
#define QTUTIL_SC_SCHED_GETAFFINITY		QTUTIL_SYSCALL(_QTUTIL_IOCTL_SYSCALL_SCHED_GETAFFINITY)

struct qtsc_kill {
	int pid;
	int signum;
};

// sched getaffinity and set affinity
struct qtsc_sched_affinity {
	int pid;
	unsigned int len;
	unsigned long *user_mask_ptr;
};


#endif

