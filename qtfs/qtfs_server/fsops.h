/* SPDX-License-Identifier: GPL-2.0 */

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
