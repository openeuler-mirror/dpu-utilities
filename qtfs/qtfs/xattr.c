#include <linux/time.h>
#include <linux/xattr.h>

#include "conn.h"
#include "qtfs-mod.h"
#include "req.h"
#include "log.h"

static bool qtfs_xattr_list(struct dentry *dentry)
{
	struct qtreq_xattrlist *req;
	struct qtrsp_xattrlist *rsp;
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	bool ret;

	if (!pvar) {
		qtfs_err("qtfs_xattr_list Failed to get qtfs sock var");
		return -EINVAL;
	}

	if (dentry == NULL) {
		qtfs_err("qtfs_xattr_list dentry is NULL.");
		qtfs_conn_put_param(pvar);
		return false;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	if (qtfs_fullname(req->path, dentry) < 0) {
		qtfs_err("qtfs fullname failed");
		qtfs_conn_put_param(pvar);
		return false;
	}

	rsp = qtfs_remote_run(pvar, QTFS_REQ_XATTRLIST, strlen(req->path) + 1);
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_err("qtfs_xattr_list remote run failed.");
		qtfs_conn_put_param(pvar);
		return false;
	}
	
	if (rsp->d.ret == QTFS_ERR) {
		qtfs_err("qtfs_xattr_list failed with ret:%d.", rsp->d.ret);
		ret = rsp->d.result;
		qtfs_conn_put_param(pvar);
		return ret;
	}
	ret = rsp->d.result;
	qtfs_conn_put_param(pvar);
	return ret;
}

static bool qtfs_xattr_user_list(struct dentry *dentry)
{
	return qtfs_xattr_list(dentry);
}

static bool qtfs_xattr_trusted_list(struct dentry *dentry)
{
	return qtfs_xattr_list(dentry);
}

static bool qtfs_xattr_security_list(struct dentry *dentry)
{
	return qtfs_xattr_list(dentry);
}

static bool qtfs_xattr_hurd_list(struct dentry *dentry)
{
	return qtfs_xattr_list(dentry);
}

static int qtfs_xattr_get(const struct xattr_handler *handler,
			struct dentry *dentry, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	struct qtreq_xattrget *req;
	struct qtrsp_xattrget *rsp;
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	size_t leftlen = size;
	char *buf = (char *)buffer;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var");
		return 0;
	}
	if (buf == NULL || size <= 0) {
		qtfs_conn_put_param(pvar);
		return 0;
	}

	if (dentry == NULL) {
		qtfs_conn_put_param(pvar);
		return 0;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
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

	rsp = qtfs_sock_msg_buf(pvar, QTFS_RECV);
	do {
		req->d.pos = rsp->d.pos;
		req->d.size = size;
		rsp = qtfs_remote_run(pvar, QTFS_REQ_XATTRGET, QTFS_SEND_SIZE(struct qtreq_xattrget, req->path));
		 if (IS_ERR(rsp) || rsp == NULL) {
			qtfs_conn_put_param(pvar);
			return PTR_ERR(rsp);
		}
		if (rsp->d.ret == QTFS_ERR || rsp->d.size > req->d.size || leftlen < rsp->d.size) {
			goto err_end;
		}
		if (rsp->d.size > 0 && rsp->d.size <= leftlen) {
			memcpy(&buf[size - leftlen], rsp->buf, rsp->d.size);
		} else {
			qtfs_err("qtfs xattr get error <%s>, rsp size:%ld leftlen:%lu", req->path, rsp->d.size, leftlen);
			break;
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
	.list	= qtfs_xattr_user_list,
	.get	= qtfs_xattr_get,
	//.set	= qtfs_xattr_set,
};

const struct xattr_handler qtfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= qtfs_xattr_trusted_list,
	.get	= qtfs_xattr_get,
	//.set	= qtfs_xattr_set,
};

const struct xattr_handler qtfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.list	= qtfs_xattr_security_list,
	.get	= qtfs_xattr_get,
	//.set	= qtfs_xattr_set,
};

const struct xattr_handler qtfs_xattr_hurd_handler = {
	.prefix	= XATTR_HURD_PREFIX,
	.list	= qtfs_xattr_hurd_list,
	.get	= qtfs_xattr_get,
	//.set	= qtfs_xattr_set,
};
