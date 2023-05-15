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

#include <linux/time.h>
#include <linux/fs_struct.h>
#include <linux/statfs.h>
#include <linux/pagemap.h>
#include <linux/mpage.h>
#include <linux/wait.h>
#include "conn.h"
#include "qtfs-mod.h"
#include "req.h"

#include "log.h"
#include "ops.h"

static int miss_open(struct qtreq *miss)
{
	struct qtrsp_open *missrsp = (struct qtrsp_open *)miss->data;
	struct qtreq_close *req;
	struct qtrsp_close *rsp;
	struct qtfs_conn_var_s *pvar = NULL;
	if (missrsp->ret == QTFS_ERR)
		return QTFS_OK; // no need to close

	pvar = qtfs_conn_get_param();
	if (pvar == NULL) {
		qtfs_err("qtfs miss open pvar invalid.");
		return QTFS_ERR;
	}
	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);
	req->fd = missrsp->fd;
	qtfs_err("miss open proc fd:%d.", req->fd);
	rsp = qtfs_remote_run(pvar, QTFS_REQ_CLOSE, sizeof(struct qtreq_close));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return QTFS_ERR;
	}

	qtfs_conn_put_param(pvar);
	return QTFS_OK;
}

static struct qtmiss_ops qtfs_miss_handles[] = {
	{QTFS_REQ_NULL,			NULL,		"null"},
	{QTFS_REQ_MOUNT,		NULL,		"mount"},
	{QTFS_REQ_OPEN,			miss_open,	"open"},
};

int qtfs_missmsg_proc(struct qtfs_conn_var_s *pvar)
{
	struct qtreq *req = (struct qtreq *)pvar->vec_send.iov_base;
	struct qtreq *rsp = (struct qtreq *)pvar->vec_recv.iov_base;
	int ret;
	qtfs_err("qtfs miss message proc req type:%u rsp type:%u.", req->type, rsp->type);
	if (rsp->type > QTFS_REQ_OPEN) {
		qtfs_err("qtfs miss message proc failed, type:%u invalid, req type:%u.", rsp->type, req->type);
		return -EINVAL;
	}
	if (qtfs_miss_handles[rsp->type].misshandle == NULL) {
		qtfs_err("qtfs miss message proc not support:%u, req type:%u.", rsp->type, req->type);
		return -ESRCH;
	}
	ret = qtfs_miss_handles[rsp->type].misshandle(rsp);
	if (ret != QTFS_OK) {
		qtfs_err("qtfs miss message proc failed, req type:%u rsp type:%u.", req->type, rsp->type);
	}
	return ret;
}
