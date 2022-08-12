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
	qtfs_diag_info->req_size[QTFS_REQ_READ] = sizeof(struct qtreq_read);
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
	qtfs_diag_info->rsp_size[QTFS_REQ_READ] = sizeof(struct qtrsp_read);
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
	}
	return ret;
}
