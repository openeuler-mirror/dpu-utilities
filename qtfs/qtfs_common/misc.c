/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/uaccess.h>

#include "comm.h"
#include "log.h"
#include "req.h"
#include "conn.h"

extern struct file_operations qtfs_misc_fops;

static struct miscdevice qtfs_misc_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
#ifndef QTFS_CLIENT
	.name	= "qtfs_server",
#else
	.name	= "qtfs_client",
#endif
	.fops	= &qtfs_misc_fops,
};

int qtfs_misc_register(void)
{
	int ret = misc_register(&qtfs_misc_dev);
	if (ret) {
		qtfs_err("qtfs misc register failed, ret:%d.", ret);
		return -EFAULT;
	}
	return 0;
}

void qtfs_misc_destroy(void)
{
	misc_deregister(&qtfs_misc_dev);
	return;
}

void qtfs_misc_flush_threadstate(void)
{
	int i;
	for (i = 0; i < QTFS_MAX_THREADS; i++) {
		if (qtfs_thread_var[i] == NULL) {
			qtfs_diag_info->thread_state[i] = -1;
			continue;
		}
		qtfs_diag_info->thread_state[i] = qtfs_thread_var[i]->state;
	}
	qtfs_diag_info->epoll_state = (qtfs_epoll_var == NULL) ? -1 : qtfs_epoll_var->state;
}

void qtfs_req_size(void)
{
	qtfs_diag_info->req_size[QTFS_REQ_NULL] = sizeof(struct qtreq);
	qtfs_diag_info->req_size[QTFS_REQ_IOCTL] = sizeof(struct qtreq_ioctl);
	qtfs_diag_info->req_size[QTFS_REQ_STATFS] = sizeof(struct qtreq_statfs);
	qtfs_diag_info->req_size[QTFS_REQ_MOUNT] = sizeof(struct qtreq_mount);
	qtfs_diag_info->req_size[QTFS_REQ_OPEN] = sizeof(struct qtreq_open);
	qtfs_diag_info->req_size[QTFS_REQ_CLOSE] = sizeof(struct qtreq_close);
	qtfs_diag_info->req_size[QTFS_REQ_READITER] = sizeof(struct qtreq_readiter);
	qtfs_diag_info->req_size[QTFS_REQ_WRITE] = sizeof(struct qtreq_write);
	qtfs_diag_info->req_size[QTFS_REQ_LOOKUP] = sizeof(struct qtreq_lookup);
	qtfs_diag_info->req_size[QTFS_REQ_READDIR] = sizeof(struct qtreq_readdir);
	qtfs_diag_info->req_size[QTFS_REQ_MKDIR] = sizeof(struct qtreq_mkdir);
	qtfs_diag_info->req_size[QTFS_REQ_RMDIR] = sizeof(struct qtreq_rmdir);
	qtfs_diag_info->req_size[QTFS_REQ_GETATTR] = sizeof(struct qtreq_getattr);
	qtfs_diag_info->req_size[QTFS_REQ_SETATTR] = sizeof(struct qtreq_setattr);
	qtfs_diag_info->req_size[QTFS_REQ_ICREATE] = sizeof(struct qtreq_icreate);
	qtfs_diag_info->req_size[QTFS_REQ_MKNOD] = sizeof(struct qtreq_mknod);
	qtfs_diag_info->req_size[QTFS_REQ_UNLINK] = sizeof(struct qtreq_unlink);
	qtfs_diag_info->req_size[QTFS_REQ_SYMLINK] = sizeof(struct qtreq_symlink);
	qtfs_diag_info->req_size[QTFS_REQ_LINK] = sizeof(struct qtreq_link);
	qtfs_diag_info->req_size[QTFS_REQ_GETLINK] = sizeof(struct qtreq_getlink);
	qtfs_diag_info->req_size[QTFS_REQ_READLINK] = sizeof(struct qtreq_readlink);
	qtfs_diag_info->req_size[QTFS_REQ_RENAME] = sizeof(struct qtreq_rename);
	qtfs_diag_info->req_size[QTFS_REQ_XATTRLIST] = sizeof(struct qtreq_xattrlist);
	qtfs_diag_info->req_size[QTFS_REQ_XATTRGET] = sizeof(struct qtreq_xattrget);
	qtfs_diag_info->req_size[QTFS_REQ_SYSMOUNT] = sizeof(struct qtreq_sysmount);
	qtfs_diag_info->req_size[QTFS_REQ_SYSUMOUNT] = sizeof(struct qtreq_sysumount);
	qtfs_diag_info->req_size[QTFS_REQ_FIFOPOLL] = sizeof(struct qtreq_poll);
	qtfs_diag_info->req_size[QTFS_REQ_EPOLL_CTL] = sizeof(struct qtreq_epollctl);
	qtfs_diag_info->req_size[QTFS_REQ_EPOLL_EVENT] = sizeof(struct qtreq_epollevt);

	qtfs_diag_info->rsp_size[QTFS_REQ_NULL] = sizeof(struct qtreq);
	qtfs_diag_info->rsp_size[QTFS_REQ_IOCTL] = sizeof(struct qtrsp_ioctl);
	qtfs_diag_info->rsp_size[QTFS_REQ_STATFS] = sizeof(struct qtrsp_statfs);
	qtfs_diag_info->rsp_size[QTFS_REQ_MOUNT] = sizeof(struct qtrsp_mount);
	qtfs_diag_info->rsp_size[QTFS_REQ_OPEN] = sizeof(struct qtrsp_open);
	qtfs_diag_info->rsp_size[QTFS_REQ_CLOSE] = sizeof(struct qtrsp_close);
	qtfs_diag_info->rsp_size[QTFS_REQ_READITER] = sizeof(struct qtrsp_readiter);
	qtfs_diag_info->rsp_size[QTFS_REQ_WRITE] = sizeof(struct qtrsp_write);
	qtfs_diag_info->rsp_size[QTFS_REQ_LOOKUP] = sizeof(struct qtrsp_lookup);
	qtfs_diag_info->rsp_size[QTFS_REQ_READDIR] = sizeof(struct qtrsp_readdir);
	qtfs_diag_info->rsp_size[QTFS_REQ_MKDIR] = sizeof(struct qtrsp_mkdir);
	qtfs_diag_info->rsp_size[QTFS_REQ_RMDIR] = sizeof(struct qtrsp_rmdir);
	qtfs_diag_info->rsp_size[QTFS_REQ_GETATTR] = sizeof(struct qtrsp_getattr);
	qtfs_diag_info->rsp_size[QTFS_REQ_SETATTR] = sizeof(struct qtrsp_setattr);
	qtfs_diag_info->rsp_size[QTFS_REQ_ICREATE] = sizeof(struct qtrsp_icreate);
	qtfs_diag_info->rsp_size[QTFS_REQ_MKNOD] = sizeof(struct qtrsp_mknod);
	qtfs_diag_info->rsp_size[QTFS_REQ_UNLINK] = sizeof(struct qtrsp_unlink);
	qtfs_diag_info->rsp_size[QTFS_REQ_SYMLINK] = sizeof(struct qtrsp_symlink);
	qtfs_diag_info->rsp_size[QTFS_REQ_LINK] = sizeof(struct qtrsp_link);
	qtfs_diag_info->rsp_size[QTFS_REQ_GETLINK] = sizeof(struct qtrsp_getlink);
	qtfs_diag_info->rsp_size[QTFS_REQ_READLINK] = sizeof(struct qtrsp_readlink);
	qtfs_diag_info->rsp_size[QTFS_REQ_RENAME] = sizeof(struct qtrsp_rename);
	qtfs_diag_info->rsp_size[QTFS_REQ_XATTRLIST] = sizeof(struct qtrsp_xattrlist);
	qtfs_diag_info->rsp_size[QTFS_REQ_XATTRGET] = sizeof(struct qtrsp_xattrget);
	qtfs_diag_info->rsp_size[QTFS_REQ_SYSMOUNT] = sizeof(struct qtrsp_sysmount);
	qtfs_diag_info->rsp_size[QTFS_REQ_SYSUMOUNT] = sizeof(struct qtrsp_sysumount);
	qtfs_diag_info->rsp_size[QTFS_REQ_FIFOPOLL] = sizeof(struct qtrsp_poll);
	qtfs_diag_info->rsp_size[QTFS_REQ_EPOLL_CTL] = sizeof(struct qtrsp_epollctl);
	qtfs_diag_info->rsp_size[QTFS_REQ_EPOLL_EVENT] = sizeof(struct qtrsp_epollevt);
}

long qtfs_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = QTOK;
	qtfs_info("qtfs client misc ioctl.");
	switch (cmd) {
		case QTFS_IOCTL_ALLINFO:
			if (qtfs_diag_info == NULL) {
				qtfs_err("ioctl allinfo failed, qtfs_diag_info is invalid.");
				break;
			}
			qtfs_req_size();
			qtfs_diag_info->log_level = log_level;
			qtfs_misc_flush_threadstate();
			qtfs_conn_list_cnt();
			if (copy_to_user((void *)arg, qtfs_diag_info, sizeof(struct qtinfo))) {
				qtfs_err("ioctl allinfo copy to user failed.");
			}
			break;
		case QTFS_IOCTL_CLEARALL:
			qtinfo_clear();
			break;
		case QTFS_IOCTL_LOGLEVEL:
		{
			char level_str[QTFS_LOGLEVEL_STRLEN] = {0};
			if (arg == 0 || copy_from_user(level_str, (void *)arg, QTFS_LOGLEVEL_STRLEN - 1)) {
				qtfs_err("ioctl set log level failed, arg:%lu.", arg);
				break;
			}
			ret = (long)qtfs_log_init(level_str);
			break;
		}
		case QTFS_IOCTL_EPOLL_SUPPORT:
		{
			if (arg == 0) {
				qtfs_epoll_mode = false;
			} else {
				qtfs_epoll_mode = true;
			}
			break;
		}
		case QTFS_IOCTL_QTSOCK_WL_ADD: {
			struct qtsock_whitelist *name;
			struct qtsock_whitelist head;
			read_lock(&qtsock_wl.rwlock);
			if (qtsock_wl.nums >= QTSOCK_WL_MAX_NUM) {
				qtfs_err("qtsock white list num:%d cant add any more.", qtsock_wl.nums);
				read_unlock(&qtsock_wl.rwlock);
				goto err_end;
			}
			read_unlock(&qtsock_wl.rwlock);
			if (copy_from_user(&head, (void *)arg, sizeof(struct qtsock_whitelist))) {
				qtfs_err("ioctl qtsock wl add copy from user failed");
				goto err_end;
			}
			if (head.len >= PATH_MAX - sizeof(struct qtsock_whitelist)) {
				qtfs_err("len too big:%d!", head.len);
				goto err_end;
			}
			name = __getname();
			memset(name, 0, PATH_MAX);
			if (copy_from_user(name, (void *)arg, sizeof(struct qtsock_whitelist) + head.len)) {
				qtfs_err("ioctl qtsock failed");
				__putname(name);
				goto err_end;
			}
			write_lock(&qtsock_wl.rwlock);
			qtsock_wl.wl[qtsock_wl.nums] = (char *)kmalloc(name->len + 1, GFP_KERNEL);
			if (qtsock_wl.wl[qtsock_wl.nums] == NULL) {
				qtfs_err("kmalloc qtsock white list failed, len:%d.", name->len + 1);
				write_unlock(&qtsock_wl.rwlock);
				__putname(name);
				goto err_end;
			}
			memset(qtsock_wl.wl[qtsock_wl.nums], 0, name->len + 1);
			memcpy(qtsock_wl.wl[qtsock_wl.nums], name->data, name->len);
			qtsock_wl.nums++;
			write_unlock(&qtsock_wl.rwlock);
			qtfs_info("add white list len:%d str:%s successed in idx:%d", name->len, name->data, qtsock_wl.nums - 1);
			__putname(name);
			break;
		}
		case QTFS_IOCTL_QTSOCK_WL_DEL:
		{
			int index;
			if (copy_from_user(&index, (void *)arg, sizeof(int))) {
				qtfs_err("qtsock white list delete copy from user failed");
				goto err_end;
			}
			if (index >= QTSOCK_WL_MAX_NUM || index < 0) {
				qtfs_err("qtsock white list delete index:%d invalid, total items:%d", index, qtsock_wl.nums);
				goto err_end;
			}
			write_lock(&qtsock_wl.rwlock);
			// clear all white list
			if (qtsock_wl.nums > 0 && index < qtsock_wl.nums) {
				kfree(qtsock_wl.wl[index]);
				qtsock_wl.wl[index] = NULL;
				if (qtsock_wl.nums > 1) {
					qtsock_wl.wl[index] = qtsock_wl.wl[qtsock_wl.nums - 1];
				}
				qtsock_wl.nums--;
			} else {
				qtfs_err("failed to delete items:%d current items number:%d", index, qtsock_wl.nums);
				write_unlock(&qtsock_wl.rwlock);
				goto err_end;
			}
			write_unlock(&qtsock_wl.rwlock);
			break;
		}
		case QTFS_IOCTL_QTSOCK_WL_GET:
		{
			int index;
			struct qtsock_whitelist *name;
			if (copy_from_user(&index, (void *)arg, sizeof(int))) {
				qtfs_err("qtsock white list delete copy from user failed");
				goto err_end;
			}
			if (index >= QTSOCK_WL_MAX_NUM || index < 0) {
				qtfs_err("qtsock white list delete index:%d invalid", index);
				goto err_end;
			}
			name = __getname();
			memset(name, 0, PATH_MAX);
			read_lock(&qtsock_wl.rwlock);
			if (index >= qtsock_wl.nums) {
				qtfs_err("qtsock get info failed, index:%d is invalid:%d", index, qtsock_wl.nums);
				read_unlock(&qtsock_wl.rwlock);
				__putname(name);
				goto err_end;
			}
			name->len = strlen(qtsock_wl.wl[index]);
			memcpy(name->data, qtsock_wl.wl[index], name->len);
			read_unlock(&qtsock_wl.rwlock);
			if (copy_to_user((void *)arg, name, sizeof(struct qtsock_whitelist) + name->len)) {
				qtfs_err("copy to user failed");
				__putname(name);
				goto err_end;
			}
			qtfs_info("qtsock wl get index:%d wl:%s", index, name->data);
			__putname(name);
			break;
		}
	}
	return ret;
err_end:
	return QTERROR;
}
