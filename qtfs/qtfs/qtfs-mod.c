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

#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
#include <linux/sched/task.h>
#endif
#include "conn.h"

#include "qtfs-mod.h"
#include "syscall.h"
#include "symbol_wrapper.h"

static struct file_system_type qtfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= QTFS_FSTYPE_NAME,
	.mount		= qtfs_fs_mount,
	.kill_sb	= qtfs_kill_sb,
};
MODULE_ALIAS_FS("qtfs");
struct kmem_cache *qtfs_inode_priv_cache;
struct task_struct *g_qtfs_epoll_thread = NULL;

/*
 * 转发框架层：
 *				1. 调用者先在pvar里预留框架头后，填好自己的私有发送数据。
 				2. 框架负责填充框架头，将整体消息发到对端。
 				3. 等待对端执行完回复。
 				4. 将接收buf的私有数据段首指针返回给调用者，完成文件操作层的通信。
 */
void *qtfs_remote_run(struct qtfs_conn_var_s *pvar, unsigned int type, unsigned int len)
{
	int ret;
	unsigned long retrytimes = 0;
	struct qtreq *req = (struct qtreq *)pvar->vec_send.iov_base;
	struct qtreq *rsp = (struct qtreq *)pvar->vec_recv.iov_base;
	if (req == NULL || type >= QTFS_REQ_INV) {
		qtfs_err("qtfs remote run failed, req is NULL type:%u.\n", type);
		return NULL;
	}
	pvar->seq_num++;
	req->type = type;
	req->len = len;
	req->seq_num = pvar->seq_num;

	pvar->conn_ops->conn_recv_buff_drop(&pvar->conn_var);
	// 调用qtfs_remote_run之前，调用者应该先把消息在iov_base里面封装好
	// 如果不是socket通信，则是在其他通信模式定义的buf里，消息协议统一
	// 都是struct qtreq *xx
	// 给server发一个消息
	pvar->vec_send.iov_len = QTFS_MSG_HEAD_LEN + len;
	ret = qtfs_conn_send(pvar);
	if (ret == -EPIPE) {
		qtfs_err("qtfs remote run thread:%d send get EPIPE, try reconnect.", pvar->cur_threadidx);
		qtfs_sm_reconnect(pvar);
	}
	if (ret <= 0) {
		qtfs_err("qtfs remote run send failed, ret:%d pvar sendlen:%lu.", ret, pvar->vec_send.iov_len);
		qtinfo_senderrinc(req->type);
	}
	qtinfo_sendinc(type);

	// wait for response
retry:
	ret = qtfs_conn_recv_block(pvar);
	if (ret == -EAGAIN)
		goto retry;
	if (ret > 0 && req->seq_num != rsp->seq_num) {
		qtinfo_cntinc(QTINF_SEQ_ERR);
		qtfs_debug("qtfs remote run recv msg mismatch type:%d, ret:%d pvaridx:%d req:%lu rsp:%lu.",
					req->type, ret, pvar->cur_threadidx, req->seq_num, rsp->seq_num);
		qtinfo_recvinc(rsp->type);
		if (pvar->miss_proc == 0) {
			pvar->miss_proc = 1;
			qtfs_missmsg_proc(pvar);
			pvar->miss_proc = 0;
		}
		goto retry;
	}
	if (ret == -ERESTARTSYS) {
		if (retrytimes == 0) {
			qtinfo_cntinc(QTINF_RESTART_SYS);
			qtinfo_recverrinc(req->type);
		}
		retrytimes++;
		msleep(1);
		goto retry;
	}
	if (ret < 0) {
		qtfs_err("qtfs remote run error, ret:%d.", ret);
		qtinfo_recverrinc(req->type);
		return NULL;
	}
	if (retrytimes > 0)
		qtfs_debug("qtfs remote run retry times:%lu.", retrytimes);
	qtinfo_recvinc(rsp->type);

	if (rsp->err == QTFS_ERR) {
		qtfs_err("qtfs remote run error, req errcode:%d type:%u len:%lu\n", req->err, req->type, req->len);
		return NULL;
	}
	return pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_RECV);
}

static int qtfs_epoll_thread(void *data)
{
	struct qtfs_conn_var_s *pvar = NULL;
	struct qtreq_epollevt *req;
	struct qtrsp_epollevt *rsp;
	struct qtreq *head;
	int ret;
	struct inode *inode;
	struct file *file;
	int i;

connecting:
	while (qtfs_mod_exiting == false) {
		pvar = qtfs_epoll_establish_conn();
		if (pvar != NULL)
			break;
		msleep(500);
	}
	if (pvar == NULL) {
		goto end;
	}
	qtfs_info("qtfs epoll thread establish a new connection.");
	req = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_RECV);
	rsp = pvar->conn_ops->get_conn_msg_buf(pvar, QTFS_SEND);

	// init ack head only once
	do {
		head = pvar->vec_send.iov_base;
		pvar->vec_send.iov_len = QTFS_MSG_HEAD_LEN + sizeof(struct qtrsp_epollevt);
		head->type = QTFS_REQ_EPOLL_EVENT;
		head->len = sizeof(struct qtrsp_epollevt);
		rsp->ret = QTFS_OK;
	} while (0);

	while (!kthread_should_stop()) {
		ret = qtfs_conn_recv(pvar);
		if (ret == -EPIPE || pvar->conn_ops->conn_connected(&pvar->conn_var) == false)
			goto connecting;
		if (ret < 0 || req->event_nums <= 0 || req->event_nums >= QTFS_MAX_EPEVENTS_NUM) {
			continue;
		}
		qtfs_debug("epoll thread recv %d events.", req->event_nums);
		for (i = 0; i < req->event_nums; i++) {
			// events[i].data is *file ptr
			file = (struct file *)req->events[i].data;
			if (IS_ERR_OR_NULL(file)) {
				qtfs_err("epoll thread event file invalid!");
				continue;
			}
			inode = file->f_inode;
			// 暂时只支持fifo文件的epoll
			if (inode == NULL || !qtfs_support_epoll(inode->i_mode)) {
				qtfs_err("epoll thread event file not a fifo.");
				continue;
			}
			do {
				struct qtfs_inode_priv *priv = inode->i_private;
				__poll_t key;
				if (req->events[i].events & EPOLLHUP)
					key = EPOLLHUP;
				else
					key = EPOLLIN | EPOLLRDNORM;
				if (priv == NULL) {
					qtfs_err("epoll epoll wake up file error, inode priv is invalid.");
					WARN_ON(1);
				} else {
					wake_up_interruptible_sync_poll(&priv->readq, key);
				}
			} while (0);
		}
		ret = qtfs_conn_send(pvar);
		if (ret < 0)
			qtfs_err("conn send failed, ret:%d\n", ret);
	}
end:
	g_qtfs_epoll_thread = NULL;
	return 0;
}

struct file_operations qtfs_misc_fops = {
	.owner=THIS_MODULE,
	.unlocked_ioctl	= qtfs_misc_ioctl,
};

static int __init qtfs_init(void)
{
	int ret;
	qtfs_log_init(qtfs_log_level, sizeof(qtfs_log_level));

	if (qtfs_kallsyms_hack_init() != 0)
		return -1;

	ret = register_filesystem(&qtfs_fs_type);
	if (ret != 0) {
		qtfs_err("QTFS file system register failed, ret:%d.\n", ret);
		return -1;
	}
	qtfs_inode_priv_cache = kmem_cache_create("qtfs_inode_priv",
					sizeof(struct qtfs_inode_priv),
					0,
					(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
					NULL);
	if (!qtfs_inode_priv_cache) {
		qtfs_err("qtfs inode priv cache create failed.\n");
		ret = -ENOMEM;
		goto cache_create_err;
	}
	qtfs_conn_param_init();
	g_qtfs_epoll_thread = kthread_run(qtfs_epoll_thread, NULL, "qtfs_epoll");
	if (IS_ERR_OR_NULL(g_qtfs_epoll_thread)) {
		qtfs_err("qtfs epoll thread run failed.\n");
		ret = QTFS_PTR_ERR(g_qtfs_epoll_thread);
		goto epoll_thread_err;
	}
	qtfs_diag_info = (struct qtinfo *)kmalloc(sizeof(struct qtinfo), GFP_KERNEL);
	if (qtfs_diag_info == NULL) {
		qtfs_err("kmalloc qtfs diag info failed.");
		ret = -ENOMEM;
		goto diag_malloc_err;
	} else {
		memset(qtfs_diag_info, 0, sizeof(struct qtinfo));
	}
	ret = qtfs_misc_register();
	if (ret) {
		goto misc_register_err;
	}
	ret = qtfs_syscall_replace_start();
	if (ret) {
		goto syscall_replace_err;
	}
	ret = qtfs_syscall_init();
	if (ret) {
		goto syscall_init_err;
	}
	ret = qtfs_utils_register();
	if (ret) {
		goto utils_register_err;
	}
	qtfs_info("QTFS file system register success!\n");
	return 0;
utils_register_err:
	qtfs_syscall_fini();
syscall_init_err:
	qtfs_syscall_replace_stop();
syscall_replace_err:
	qtfs_misc_destroy();
misc_register_err:
	kfree(qtfs_diag_info);
diag_malloc_err:
	kthread_stop(g_qtfs_epoll_thread);
epoll_thread_err:
	qtfs_conn_param_fini();
cache_create_err:
	unregister_filesystem(&qtfs_fs_type);
	return ret;
}

static void __exit qtfs_exit(void)
{
	int ret;
	qtfs_mod_exiting = true;

	if (g_qtfs_epoll_thread) {
		kthread_stop(g_qtfs_epoll_thread);
	}

	qtfs_conn_param_fini();
	qtfs_misc_destroy();
	if (qtfs_epoll_var != NULL) {
		qtfs_epoll_cut_conn(qtfs_epoll_var);
		qtfs_epoll_var->conn_ops->conn_var_fini(qtfs_epoll_var);
		kfree(qtfs_epoll_var);
		qtfs_epoll_var = NULL;
	}
	qtfs_whitelist_initset();

	kfree(qtfs_diag_info);
	qtfs_diag_info = NULL;
	qtfs_syscall_fini();

	ret = unregister_filesystem(&qtfs_fs_type);
	if (ret != 0) {
		qtfs_err("QTFS file system unregister failed, ret:%d.\n", ret);
	}
	qtfs_utils_destroy();
	kmem_cache_destroy(qtfs_inode_priv_cache);
	qtfs_syscall_replace_stop();
	qtfs_info("QTFS file system unregister success!\n");
	return;
}

module_init(qtfs_init);
module_exit(qtfs_exit);
MODULE_AUTHOR("liqiang64@huawei.com");
MODULE_LICENSE("GPL");
