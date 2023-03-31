/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/time.h>
#include <linux/xattr.h>
#include <linux/version.h>

#include "conn.h"
#include "qtfs-mod.h"
#include "req.h"
#include "log.h"

ssize_t qtfs_xattr_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct qtreq_xattrlist *req;
	struct qtrsp_xattrlist *rsp;
	struct qtfs_conn_var_s *pvar = qtfs_conn_get_param();
	ssize_t ret;

	if (!pvar) {
		qtfs_err("qtfs_xattr_list Failed to get qtfs sock var");
		return 0;
	}

	if (dentry == NULL) {
		qtfs_err("qtfs_xattr_list dentry is NULL.");
		qtfs_conn_put_param(pvar);
		return 0;
	}

	req = qtfs_conn_msg_buf(pvar, QTFS_SEND);
	if (qtfs_fullname(req->path, dentry) < 0) {
		qtfs_err("qtfs fullname failed");
		qtfs_conn_put_param(pvar);
		return 0;
	}
	req->buffer_size = buffer_size;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_XATTRLIST, QTFS_SEND_SIZE(struct qtreq_xattrlist, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_err("qtfs_xattr_list remote run failed.");
		qtfs_conn_put_param(pvar);
		return 0;
	}
	
	if (rsp->d.ret == QTFS_ERR) {
		qtfs_err("qtfs_xattr_list failed with ret:%d.", rsp->d.ret);
		ret = rsp->d.size;
		qtfs_conn_put_param(pvar);
		return ret;
	}
	ret = rsp->d.size;
	if (buffer != NULL) {
		memcpy(buffer, rsp->name, buffer_size);
	}
	qtfs_conn_put_param(pvar);
	return ret;
}

static int qtfs_xattr_set(const struct xattr_handler *handler,
		    struct dentry *dentry, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags);

static int
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
qtfs_xattr_user_set(const struct xattr_handler *handler,
			struct user_namespace *mnt_userns,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
#else
qtfs_xattr_user_set(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
#endif

{
	return qtfs_xattr_set(handler, unused, inode, name, value, size, flags);
}

static int
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
qtfs_xattr_trusted_set(const struct xattr_handler *handler,
			struct user_namespace *mnt_userns,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
#else
qtfs_xattr_trusted_set(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
#endif
{
	return qtfs_xattr_set(handler, unused, inode, name, value, size, flags);
}

static int
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
qtfs_xattr_security_set(const struct xattr_handler *handler,
			struct user_namespace *mnt_userns,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
#else
qtfs_xattr_security_set(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
#endif
{
	return qtfs_xattr_set(handler, unused, inode, name, value, size, flags);
}

static int qtfs_xattr_set(const struct xattr_handler *handler,
		    struct dentry *dentry, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
{
	struct qtreq_xattrset *req;
	struct qtrsp_xattrset *rsp;
	struct qtfs_conn_var_s *pvar = qtfs_conn_get_param();
	int ret;

	if (!pvar) {
		qtfs_err("failed to get qtfs sock var");
		return -ENOMEM;
	}
	if (dentry == NULL) {
		qtfs_conn_put_param(pvar);
		return -ENOENT;
	}
	req = qtfs_conn_msg_buf(pvar, QTFS_SEND);
	if (qtfs_fullname(req->buf, dentry) < 0) {
		qtfs_err("xattr set get fullname failed.");
		qtfs_conn_put_param(pvar);
		return -EFAULT;
	}
	req->d.size = size;
	req->d.flags = flags;
	req->d.pathlen = strlen(req->buf) + 1;
	req->d.namelen = strlen(name) + strlen(handler->prefix) + 1;
	qtfs_info("xattr set path:%s name:%s size:%lu", req->buf, name, size);
	if (req->d.pathlen + req->d.namelen + strlen(handler->prefix) + size > sizeof(req->buf)) {
		qtfs_err("xattr set namelen:%d size:%lu is too long", req->d.namelen, size);
		qtfs_conn_put_param(pvar);
		return -EFAULT;
	}
	strncpy(&req->buf[req->d.pathlen], handler->prefix, strlen(handler->prefix));
	strcat(&req->buf[req->d.pathlen], name);
	memcpy(&req->buf[req->d.pathlen + req->d.namelen], value, size);
	rsp = qtfs_remote_run(pvar, QTFS_REQ_XATTRSET, sizeof(struct qtreq_xattrset) - sizeof(req->buf) + req->d.pathlen + req->d.namelen + req->d.size);
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->errno < 0) {
		qtfs_err("xattr set failed file:%s name:%s", req->buf, name);
	} else {
		qtfs_info("xattr set successed file:%s name:%s", req->buf, name);
	}
	ret = rsp->errno;
	qtfs_conn_put_param(pvar);
	return ret;
}

static int qtfs_xattr_get(const struct xattr_handler *handler,
			struct dentry *dentry, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	struct qtreq_xattrget *req;
	struct qtrsp_xattrget *rsp;
	struct qtfs_conn_var_s *pvar = qtfs_conn_get_param();
	size_t leftlen = size;
	char *buf = (char *)buffer;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var");
		return 0;
	}

	if (dentry == NULL) {
		qtfs_err("xattr get dentry is NULL.");
		qtfs_conn_put_param(pvar);
		return 0;
	}

	req = qtfs_conn_msg_buf(pvar, QTFS_SEND);
	if (qtfs_fullname(req->path, dentry) < 0) {
		qtfs_err("qtfs fullname failed");
		qtfs_conn_put_param(pvar);
		return 0;
	}

	if (strlen(handler->prefix) + strlen(name) <= (sizeof(req->d.prefix_name) - 1)) {
		strcpy(req->d.prefix_name, handler->prefix);
		strcat(req->d.prefix_name, name);
	} else {
		qtfs_err("strcpy len too long");
		qtfs_conn_put_param(pvar);
		return 0;
	}

	rsp = qtfs_conn_msg_buf(pvar, QTFS_RECV);
	do {
		req->d.pos = rsp->d.pos;
		req->d.size = size;
		rsp = qtfs_remote_run(pvar, QTFS_REQ_XATTRGET, QTFS_SEND_SIZE(struct qtreq_xattrget, req->path));
		if (IS_ERR(rsp) || rsp == NULL) {
			qtfs_err("rsp invalid, file:%s", req->path);
			qtfs_conn_put_param(pvar);
			return PTR_ERR(rsp);
		}
		if (rsp->d.ret == QTFS_ERR || (size !=0 && (rsp->d.size > req->d.size || leftlen < rsp->d.size))) {
			qtfs_err("ret:%d rsp size:%ld req size:%d leftlen:%lu", rsp->d.ret, rsp->d.size,
					req->d.size, leftlen);
			goto err_end;
		}
		if (size > 0 && rsp->d.size <= leftlen) {
			memcpy(&buf[size - leftlen], rsp->buf, rsp->d.size);
		}
		leftlen -= rsp->d.size;
	} while (leftlen > 0 && rsp->d.size > 0);
	qtfs_info("qtfs getxattr success:<<%s>>", buf);

	qtfs_conn_put_param(pvar);

	return size - leftlen;

err_end:
	qtfs_conn_put_param(pvar);
	return -ENODATA;
}

const struct xattr_handler qtfs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.get	= qtfs_xattr_get,
	.set	= qtfs_xattr_user_set,
};

const struct xattr_handler qtfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.get	= qtfs_xattr_get,
	.set	= qtfs_xattr_trusted_set,
};

const struct xattr_handler qtfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= qtfs_xattr_get,
	.set	= qtfs_xattr_security_set,
};

#ifndef KVER_4_19
static int
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
qtfs_xattr_hurd_set(const struct xattr_handler *handler,
			struct user_namespace *mnt_userns,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
#else
qtfs_xattr_hurd_set(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
#endif
{
	return qtfs_xattr_set(handler, unused, inode, name, value, size, flags);
}

const struct xattr_handler qtfs_xattr_hurd_handler = {
	.prefix	= XATTR_HURD_PREFIX,
	.get	= qtfs_xattr_get,
	.set	= qtfs_xattr_hurd_set,
};
#endif
