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

#ifndef __QTFS_SERVER_FSOPS_H__
#define __QTFS_SERVER_FSOPS_H__

struct qtfs_getdents {
	struct dir_context ctx;
	int vldcnt;
	struct qtfs_dirent64 * dir;
	int prev_reclen;
	int count;
};

#endif
