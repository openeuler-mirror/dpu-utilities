#include <linux/time.h>
#include <linux/fs_struct.h>
#include <linux/statfs.h>
#include <linux/pagemap.h>
#include <linux/mpage.h>
#include <linux/wait.h>
#include <asm-generic/ioctls.h>
#include <asm-generic/termbits.h>


#include "conn.h"
#include "qtfs-mod.h"
#include "req.h"
#include "log.h"
#include "ops.h"

#define CURRENT_TIME(inode) (current_time(inode))
static struct inode_operations qtfs_inode_ops;
static struct inode_operations qtfs_symlink_inode_ops;
struct inode *qtfs_iget(struct super_block *sb, struct inode_info *ii);
extern ssize_t qtfs_xattr_list(struct dentry *dentry, char *buffer, size_t buffer_size);
int qtfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_statfs *req;
	struct qtrsp_statfs *rsp;
	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	rsp = qtfs_sock_msg_buf(pvar, QTFS_RECV);

	QTFS_FULLNAME(req->path, dentry);
	rsp = qtfs_remote_run(pvar, QTFS_REQ_STATFS, QTFS_SEND_SIZE(struct qtreq_statfs, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return -EINVAL;
	}
	if (rsp->ret == QTFS_ERR) {
		int ret = rsp->errno;
		qtfs_err("qtfs statfs failed. %d", rsp->errno);
		qtfs_conn_put_param(pvar);
		return ret;
	}
	qtfs_info("%s: get path %s\n", __func__, req->path);
	memcpy(buf, &(rsp->kstat), sizeof(struct kstatfs));
	qtfs_conn_put_param(pvar);
	return 0;
}

static const struct super_operations qtfs_ops = {
	.statfs = qtfs_statfs,
};

static inline struct qtfs_fs_info *qtfs_priv_byinode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	return sb->s_fs_info;
}

static inline char *qtfs_mountpoint_path_init(struct dentry *dentry, struct path *path, char *mnt_file)
{
	char *name = NULL;
	char *ret;
	char *mnt_point;
	int len;
	struct qtfs_fs_info *fsinfo = qtfs_priv_byinode(d_inode(dentry));
	if (fsinfo && fsinfo->mnt_path) {
		return fsinfo->mnt_path;
	}
	name = __getname();
	path_get(path);
	ret = qtfs_kern_syms.d_absolute_path(path, name, MAX_PATH_LEN);
	qtfs_debug("mntfile:%s absolute:%s", mnt_file, ret);
	if (err_ptr(ret)) {
		qtfs_err("d_absolute_path failed:%ld", PTR_ERR(ret));
	} else {
		if (strcmp(mnt_file, "/")) {
			mnt_point = strstr(ret, mnt_file);
			qtfs_info("mnt point:%s", mnt_point);
			if (mnt_point) {
				*mnt_point = '\0';
			} else {
				qtfs_err("Failed to get mount root path");
			}
		}
		len = strlen(ret);
		fsinfo->mnt_path = (char *)kmalloc(len + 1, GFP_KERNEL);
		if (fsinfo->mnt_path) {
			strlcpy(fsinfo->mnt_path, ret, len + 1);
		}
		qtfs_debug("d_absolute_path get mnt path:%s", fsinfo->mnt_path);
	}
	path_put(path);
	__putname(name);
	return fsinfo->mnt_path;
}

int qtfs_readdir(struct file *filp, struct dir_context *ctx)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_readdir *req;
	struct qtrsp_readdir *rsp;
	struct qtfs_dirent64 *dirent = NULL;
	int idx;
	int ret;
	int namelen;
	int dircnt;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var");
		return -EINVAL;
	}

	if (ctx->pos == -1) {
		qtfs_conn_put_param(pvar);
		return -ENOENT;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	rsp = qtfs_sock_msg_buf(pvar, QTFS_RECV);
	QTFS_FULLNAME(req->path, filp->f_path.dentry);
	req->count = sizeof(rsp->dirent);
	req->pos = ctx->pos;

	rsp = qtfs_remote_run(pvar, QTFS_REQ_READDIR, QTFS_SEND_SIZE(struct qtreq_readdir, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->d.ret == QTFS_ERR) {
		qtfs_err("qtfs readdir failed.");
		qtfs_conn_put_param(pvar);
		return -EFAULT;
	}

	idx = 0;
	dircnt = rsp->d.vldcnt;
	while (dircnt--) {
		dirent = (struct qtfs_dirent64 *)&rsp->dirent[idx];
		namelen = strlen(dirent->d_name);
		ret = dir_emit(ctx, dirent->d_name, namelen,
					dirent->d_ino, dirent->d_type);
		idx += dirent->d_reclen;
		qtfs_debug("qtfs readdir direntoff:0x%lx name:<%s>, ret:%d, reclen:%u namelen:%d, ino:%llu type:%d",
				(void *)dirent - (void *)rsp->dirent, dirent->d_name, ret, dirent->d_reclen, namelen, dirent->d_ino, dirent->d_type);
	}

	ctx->pos = (rsp->d.over) ? -1 : rsp->d.pos;
	qtfs_info("qtfs readdir<%s> success ret:%d vldcnt:%d over:%d pos:%lld.",
			req->path, rsp->d.ret, rsp->d.vldcnt, rsp->d.over, ctx->pos);
	qtfs_conn_put_param(pvar);
	return 0;
}

int qtfs_open(struct inode *inode, struct file *file)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_open *req;
	struct qtrsp_open *rsp;
	struct private_data *data = NULL;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var");
		return -EINVAL;
	}
	data = (struct private_data *)kmalloc(sizeof(struct private_data), GFP_KERNEL);
	if (err_ptr(data)) {
		qtfs_err("qtfs_open alloc private_data failed: %ld", PTR_ERR(data));
		qtfs_conn_put_param(pvar);
		return -ENOMEM;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, file->f_path.dentry);

	req->flags = file->f_flags;
	req->mode = file->f_mode;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_OPEN, QTFS_SEND_SIZE(struct qtreq_open, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		qtfs_err("qtfs open:%s failed, f_mode:%o flag:%x", req->path, file->f_mode, file->f_flags);
		return -EINVAL;
	}

	if (rsp->ret == QTFS_ERR) {
		int err = rsp->fd;
		if (rsp->fd != -ENOENT) {
			qtfs_err("qtfs_open failed with %d ret:%d", rsp->fd, rsp->ret);
		} else {
			qtfs_info("qtfs_open file %s failed, not exist.", req->path);
		}
		qtfs_conn_put_param(pvar);
		return err;
	}
	qtfs_info("qtfs open:%s success, f_mode:%o flag:%x, fd:%d", req->path, file->f_mode, file->f_flags, rsp->fd);
	data->fd = rsp->fd;
	WARN_ON(file->private_data);
	file->private_data = data;
	qtfs_conn_put_param(pvar);

	return 0;
}

int qtfs_dir_open(struct inode *inode, struct file *file)
{
	qtfs_info("qtfs dir open enter: %s.", file->f_path.dentry->d_iname);
	return 0;
}

int qtfs_dir_release(struct inode *inode, struct file *file)
{
	qtfs_info("qtfs dir release enter: %s.", file->f_path.dentry->d_iname);
	return 0;
}

int qtfs_release(struct inode *inode, struct file *file)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_close *req;
	struct qtrsp_close *rsp;
	struct private_data *private = NULL;
	int ret;

	if (pvar == NULL) {
		qtfs_err("qtfs release pvar invalid.");
		return -EFAULT;
	}

	if (err_ptr(file)) {
		qtfs_err("qtfs release: invalid file: 0x%llx", (__u64)file);
		qtfs_conn_put_param(pvar);
		return -EINVAL;
	}
	
	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	private = (struct private_data *)file->private_data;

	if (err_ptr(private)) {
		qtfs_err("qtfs_close(%s): invalid private_data pointer:%ld", file->f_path.dentry->d_iname, PTR_ERR(private));
		WARN_ON(1);
		qtfs_conn_put_param(pvar);
		return -EFAULT;
	}
	req->fd = private->fd;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_CLOSE, sizeof(struct qtreq_close));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_err("qtfs release fd:%d failed, rsp is invalid.", req->fd);
		ret = PTR_ERR(rsp);
		goto end;
	}
	qtfs_info("qtfs release success fd:%d ret:%d %s", req->fd, rsp->ret, (rsp->ret == QTFS_ERR) ? "failed" : "success");
	ret = rsp->ret;
end:
	qtfs_conn_put_param(pvar);
	kfree(file->private_data);
	file->private_data = NULL;
	return ret;
}

ssize_t qtfs_readiter(struct kiocb *kio, struct iov_iter *iov)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_readiter *req;
	struct qtrsp_readiter *rsp;
	int reqlen;
	size_t leftlen = iov_iter_count(iov);
	size_t allcnt = leftlen;
	size_t tocnt = 0;
	ssize_t ret;
	struct private_data *private = NULL;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);

	private = (struct private_data *)kio->ki_filp->private_data;
	if (err_ptr(private)) {
		qtfs_err("qtfs_readiter(%s): invalid private_data pointer:%ld", kio->ki_filp->f_path.dentry->d_iname, PTR_ERR(private));
		qtfs_conn_put_param(pvar);
		return -ENOMEM;
	}

	req->fd = private->fd;
	if (req->fd <= 0) {
		qtfs_err("qtfs_readiter: invalid file(%d)", req->fd);
		qtfs_conn_put_param(pvar);
		return -EINVAL;
	}
	reqlen = sizeof(struct qtreq_readiter);

	do {
		req->len = leftlen;
		req->pos = kio->ki_pos;
		rsp = qtfs_remote_run(pvar, QTFS_REQ_READITER, reqlen);
		if (IS_ERR(rsp) || rsp == NULL) {
			qtfs_conn_put_param(pvar);
			return PTR_ERR(rsp);
		}
		if (rsp->d.ret == QTFS_ERR || rsp->d.len <= 0) {
			if (rsp->d.len != 0)
				qtfs_info("qtfs readiter error.");
			ret = (ssize_t)rsp->d.len;
			qtfs_conn_put_param(pvar);
			return ret;
		}
		tocnt = copy_to_iter(rsp->readbuf, rsp->d.len, iov);
		if (rsp->d.len != tocnt) {
			qtfs_err("copy to iter failed, errno:%ld", tocnt);
			qtfs_conn_put_param(pvar);
			return allcnt - leftlen + tocnt;
		}

		leftlen -= rsp->d.len;
		kio->ki_pos += rsp->d.len;
	} while (leftlen > 0 && rsp->d.len >= sizeof(rsp->readbuf) - 1);
	qtfs_info("qtfs readiter over, leftlen:%lu, reqlen:%lu, fullname:<%s>, ino:%lu, pos:%lld, iovcnt:%lu(%lu)\n", leftlen,
				req->len, kio->ki_filp->f_path.dentry->d_iname, kio->ki_filp->f_inode->i_ino, kio->ki_pos, iov_iter_count(iov), iov->iov->iov_len);

	qtfs_conn_put_param(pvar);
	return allcnt - leftlen;
}

ssize_t qtfs_writeiter(struct kiocb *kio, struct iov_iter *iov)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_write *req;
	struct qtrsp_write *rsp;
	char *wrbuf = NULL;
	int wrbuflen;
	int maxbuflen;
	size_t len = iov_iter_count(iov);
	size_t leftlen = len;
	struct private_data *private = NULL;
	ssize_t ret;
	struct file *filp;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var.");
		return -EINVAL;
	}
	if (len <= 0) {
		qtfs_conn_put_param(pvar);
		return len;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	filp = kio->ki_filp;
	private = (struct private_data *)filp->private_data;
	if (err_ptr(private)) {
		qtfs_err("qtfs_write(%s): invalid private_data pointer:%ld", filp->f_path.dentry->d_iname, PTR_ERR(private));
		qtfs_conn_put_param(pvar);
		return -ENOMEM;
	}
	
	req->d.fd = private->fd;
	if (req->d.fd < 0) {
		qtfs_err("qtfs_write: invalid file(%d)", req->d.fd);
		qtfs_conn_put_param(pvar);
		return -EINVAL;
	}
	req->d.mode = filp->f_mode;
	req->d.flags = filp->f_flags;

	wrbuf = req->path_buf;
	maxbuflen = sizeof(req->path_buf);
	do {
		wrbuflen = (leftlen >= maxbuflen) ? (maxbuflen - 1) : leftlen;
		req->d.buflen = wrbuflen;
		req->d.pos = kio->ki_pos;
		if (copy_from_iter(wrbuf, wrbuflen, iov) == 0) {
			qtfs_err("qtfs write copy from iter failed, len:%d.", wrbuflen);
			qtfs_conn_put_param(pvar);
			return -EFAULT;
		}
		rsp = qtfs_remote_run(pvar, QTFS_REQ_WRITE, sizeof(struct qtreq_write) - sizeof(req->path_buf) + wrbuflen);
		if (IS_ERR(rsp) || rsp == NULL) {
			qtfs_conn_put_param(pvar);
			return PTR_ERR(rsp);
		}
		if (rsp->ret == QTFS_ERR || rsp->len <= 0) {
			qtfs_err("qtfs write remote error, errno:%ld, leftlen:%lu.", rsp->len, leftlen);
			ret = rsp->len;
			qtfs_conn_put_param(pvar);
			return ret;
		}
		if (rsp->len != wrbuflen) {
			WARN_ON(1);
		}
		kio->ki_pos += rsp->len;
		leftlen -= wrbuflen;
	} while (leftlen);

	do {
		struct inode *inode = kio->ki_filp->f_inode;
		struct qtfs_inode_priv *priv = inode->i_private;
		if (S_ISFIFO(inode->i_mode))
			wake_up_interruptible_sync_poll(&priv->readq, EPOLLIN | EPOLLRDNORM);
		if (S_ISCHR(inode->i_mode)) {
			wake_up_interruptible_poll(&priv->readq, EPOLLIN);
			qtfs_err("writeiter file:%s char:<%s> wakup poll.", filp->f_path.dentry->d_iname, req->path_buf);
		}
	} while (0);
	qtfs_info("qtfs write %s over, leftlen:%lu.", filp->f_path.dentry->d_iname, leftlen);
	qtfs_conn_put_param(pvar);
	return len - leftlen;
}

loff_t qtfs_llseek(struct file *file, loff_t off, int whence)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_llseek *req;
	struct qtrsp_llseek *rsp;
	loff_t ret;
	struct private_data *priv = NULL;
	
	qtfs_info("qtfs llseek off:%lld, whence:%d.", off, whence);
	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var.");
		return -EINVAL;
	}
	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);

	priv = (struct private_data *)file->private_data;
	req->off = off;
	req->whence = whence;
	req->fd = priv->fd;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_LLSEEK, sizeof(struct qtreq_llseek));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		qtfs_err("Failed to remote run llseek.");
		return PTR_ERR(rsp);
	}
	if (rsp->ret != QTFS_OK) {
		qtfs_conn_put_param(pvar);
		return rsp->off;
	}
	file->f_pos = rsp->off;
	ret = rsp->off;
	qtfs_conn_put_param(pvar);
	qtfs_info("qtfs llseek successed, cur seek pos:%lld.", ret);
	return ret;
}

static void qtfs_vma_close(struct vm_area_struct *vma)
{
	qtfs_info("qtfs vma close enter.");
	filemap_write_and_wait(vma->vm_file->f_mapping);
}

static vm_fault_t qtfs_vm_fault(struct vm_fault *vmf)
{
	vm_fault_t ret = filemap_fault(vmf);

	qtfs_info("qtfs vm ops fault enter, filemap fault:0x%x, pgoff:%lu.", ret, vmf->pgoff);
	return ret;
}

static void qtfs_map_pages(struct vm_fault *vmf,
		pgoff_t start_pgoff, pgoff_t end_pgoff)
{
	qtfs_info("qtfs map pages enter, pgoff:%lu start:%lu end:%lu.", vmf->pgoff, start_pgoff, end_pgoff);

	filemap_map_pages(vmf, start_pgoff, end_pgoff);
	return;
}

static vm_fault_t qtfs_page_mkwrite(struct vm_fault *vmf)
{
	qtfs_info("qtfs page mkwrite enter.");
	return filemap_page_mkwrite(vmf);
}

static const struct vm_operations_struct qtfs_file_vm_ops = {
	.fault = qtfs_vm_fault,
	.map_pages = qtfs_map_pages,
	.close = qtfs_vma_close,
	.page_mkwrite = qtfs_page_mkwrite,
};

int qtfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	qtfs_info("qtfs mmap enter.");

	if (IS_DAX(file_inode(file))) {
		qtfs_info("qtfs mmap is dax mmap.");
	}
	file_accessed(file);
	vma->vm_ops = &qtfs_file_vm_ops;
	return 0;
}

int qtfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	qtfs_info("qtfs fsync enter.");
	return 0;
}

long qtfs_do_ioctl(struct file *filp, unsigned int cmd, unsigned long arg, unsigned int size)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_ioctl *req;
	struct qtrsp_ioctl *rsp;
	unsigned int len = 0;
	int ret = -EINVAL;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var");
		return -EINVAL;
	}

	WARN_ON(size >= MAX_PATH_LEN);
	if (size >= MAX_PATH_LEN) {
		qtfs_conn_put_param(pvar);
		return -ENOMEM;
	}
	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	rsp = qtfs_sock_msg_buf(pvar, QTFS_RECV);

	QTFS_FULLNAME(req->path, filp->f_path.dentry);

	req->d.cmd = cmd;
	if (size > 0) {
		req->d.offset = ALIGN(strlen(req->path) + 1, 64);
		ret = copy_from_user(req->path + req->d.offset, (char __user *)arg, size);
		if (ret) {
			qtfs_err("%s: copy_from_user %p, 0x%lx, %u failed.", __func__, req->path + req->d.offset, arg, size);
			goto out;
		}
		len = sizeof(struct qtreq_ioctl) - sizeof(req->path) + req->d.offset + size;
		req->d.size = size;
	} else {
		len = sizeof(struct qtreq_ioctl) - sizeof(req->path) + strlen(req->path) + 1;
	}

	rsp = qtfs_remote_run(pvar, QTFS_REQ_IOCTL, len);
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs ioctl cmd:0x%x failed. %d", cmd, rsp->errno);
		ret = rsp->errno;
		qtfs_conn_put_param(pvar);
		return ret;
	}

	qtfs_info("qtfs do ioctl cmd:0x%x success, path: %s size:%u, rsp size:%u", cmd, req->path, size, rsp->size);
	ret = rsp->errno;
	if (rsp->size > 0)
		ret = copy_to_user((char __user *)arg, rsp->buf, size);
out:
	qtfs_conn_put_param(pvar);
	return (long)ret;
}

long qtfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch(cmd) {
		case FS_IOC_FSGETXATTR:
		case TCGETS:
			return qtfs_do_ioctl(filp, cmd, arg, 0);
		case FS_IOC_FSSETXATTR:
			return qtfs_do_ioctl(filp, cmd, arg, sizeof(struct fsxattr));
		case TCSETS:
			return qtfs_do_ioctl(filp, cmd, arg, sizeof(struct ktermios));
		default: {
			char *fullname = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
			if (!fullname)
				return -ENOMEM;
			memset(fullname, 0, MAX_PATH_LEN);
			qtfs_fullname(fullname, filp->f_path.dentry);
			qtfs_err("qtfs ioctl get not support cmd:%d file:%s TCGETS:%d", cmd, fullname, TCGETS);
			kfree(fullname);
			return -EOPNOTSUPP;
		}
	}
}

loff_t qtfs_dir_file_llseek(struct file *file, loff_t offset, int whence)
{
	qtfs_info("qtfs generic file llseek: %s.", file->f_path.dentry->d_iname);
	return generic_file_llseek(file, offset, whence);
}

ssize_t qtfs_dir_read_dir(struct file *filp, char __user *buf, size_t siz, loff_t *ppos)
{
	qtfs_err("qtfs generic read dir: %s.", filp->f_path.dentry->d_iname);
	return generic_read_dir(filp, buf, siz, ppos);
}

static struct file_operations qtfs_dir_ops = {
	.owner = THIS_MODULE,
	.iterate_shared = qtfs_readdir,
	.unlocked_ioctl = qtfs_ioctl,
	.open = qtfs_dir_open,
	.release = qtfs_dir_release,
	.llseek = qtfs_dir_file_llseek,
	.read = qtfs_dir_read_dir,
};

static __poll_t
qtfsfifo_poll(struct file *filp, poll_table *wait)
{
	struct qtfs_inode_priv *priv = filp->f_inode->i_private;
	__poll_t mask = 0;
	struct list_head *p;
	struct qtfs_sock_var_s *pvar;
	struct qtreq_poll *req;
	struct qtrsp_poll *rsp;
	struct private_data *fpriv = (struct private_data *)filp->private_data;

	poll_wait(filp, &priv->readq, wait);

	p = &priv->readq.head;

	if (fpriv->fd < 0) {
		qtfs_err("fifo poll priv file invalid.");
		return 0;
	}
	pvar = qtfs_conn_get_param();
	if (pvar == NULL) {
		qtfs_err("qtfs fifo poll get param failed.");
		return 0;
	}
	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	req->fd = fpriv->fd;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_FIFOPOLL, sizeof(struct qtreq_poll));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return 0;
	}
	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs fifo poll remote run error.");
		qtfs_conn_put_param(pvar);
		return 0;
	}
	mask = rsp->mask;

	qtfs_info("fifo poll success mask:%x, qproc:%lx key:%x head:%lx next:%lx pre:%lx",
			mask, (unsigned long)wait->_qproc, (unsigned)wait->_key, (unsigned long)p,
			(unsigned long)p->next, (unsigned long)p->prev);
	qtfs_conn_put_param(pvar);
	return mask;
}

struct file_operations qtfsfifo_ops = {
	.read_iter = qtfs_readiter,
	.write_iter = qtfs_writeiter,
	.open = qtfs_open,
	.release = qtfs_release,
	.llseek = no_llseek,
	.poll = qtfsfifo_poll,
};

static struct file_operations qtfs_file_ops = {
	.read_iter = qtfs_readiter,
	.write_iter = qtfs_writeiter,
	.open = qtfs_open,
	.release = qtfs_release,
	.mmap = qtfs_mmap,
	.llseek = qtfs_llseek,
	.fsync = qtfs_fsync,
	.unlocked_ioctl = qtfs_ioctl,
	.poll = qtfsfifo_poll,
};


static int qtfs_readpage(struct file *file, struct page *page)
{
	void *kaddr = NULL;
	loff_t offset = page->index << PAGE_SHIFT;
	qtfs_info("qtfs readpage enter, page pos:%lld.", offset);

	kaddr = kmap_atomic(page);
	kernel_read(file, kaddr, PAGE_SIZE, &offset);
	flush_dcache_page(page);
	kunmap_atomic(kaddr);
	SetPageUptodate(page);
	unlock_page(page);

	return 0;
}

#ifndef KVER_4_19
static struct page **qtfs_alloc_pages(unsigned int nr)
{
	struct page **pages = kzalloc(nr * (sizeof(struct page *)), GFP_KERNEL);
	if (pages == NULL) {
		qtfs_err("qtfs alloc pages failed.");
		return NULL;
	}
	return pages;
}

static void qtfs_free_pages(struct page **pages)
{
	kfree(pages);
}

static void qtfs_readahead(struct readahead_control *rac)
{
	int i;
	unsigned int nr_pages = readahead_count(rac);
	struct page **pages = qtfs_alloc_pages(nr_pages);
	qtfs_info("qtfs readahead.");

	nr_pages = __readahead_batch(rac, pages, nr_pages);

	for (i = 0; i < nr_pages; i++) {
		qtfs_readpage(rac->file, pages[i]);
	}
	qtfs_free_pages(pages);
	return;
}
#endif

static int qtfs_writepage(struct page *page, struct writeback_control *wbc)
{
	qtfs_info("qtfs write page.");
	return 0;
}

static int qtfs_writepages(struct address_space *mapping,
			struct writeback_control *wbc)
{
	qtfs_info("qtfs write pages.");
	return 0;
}

static int qtfs_setpagedirty(struct page *page)
{
	qtfs_info("qtfs set page dirty.");
	__set_page_dirty_nobuffers(page);
	return 0;
}

static const struct address_space_operations qtfs_aops = {
	.readpage = qtfs_readpage,
#ifndef KVER_4_19
	.readahead = qtfs_readahead,
#endif
	.writepage = qtfs_writepage,
	.writepages = qtfs_writepages,
	.set_page_dirty = qtfs_setpagedirty,
};

int qtfs_new_entry(struct inode *inode, struct dentry *dentry)
{
	struct dentry *d = NULL;

	if (!inode)
		return -ENOMEM;

	d_drop(dentry);
	d = d_splice_alias(inode, dentry);
	if (IS_ERR(d)) {
		return PTR_ERR(d);
	}
	if (d)
		dput(d);
	return 0;
}

int qtfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_mkdir *req = NULL;
	struct qtrsp_mkdir *rsp = NULL;
	int ret;
	struct inode *inode;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var.");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, dentry);

	req->mode = mode;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_MKDIR, QTFS_SEND_SIZE(struct qtreq_mkdir, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs mkdir failed %d.", rsp->errno);
		ret = rsp->errno;
		qtfs_conn_put_param(pvar);
		return ret;
	}
	inode = qtfs_iget(dentry->d_sb, &(rsp->inode_info));
	ret = qtfs_new_entry(inode, dentry);
	qtfs_info("mkdir path:%s success.", req->path);
	qtfs_conn_put_param(pvar);
	return ret;
}

int qtfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_icreate *req;
	struct qtrsp_icreate *rsp;
	struct inode *inode;
	int ret = 0;
	int ret2 = 0;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var.");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, dentry);

	req->mode = mode;
	req->excl = excl;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_ICREATE, QTFS_SEND_SIZE(struct qtreq_icreate, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}

	if (rsp->ret == QTFS_ERR) {
		ret = rsp->errno;
		qtfs_err("qtfs icreate failed %d.", rsp->errno);
		qtfs_conn_put_param(pvar);
		return ret;
	}
	ret = rsp->errno;
	inode = qtfs_iget(dentry->d_sb, &(rsp->inode_info));
	ret2 = qtfs_new_entry(inode, dentry);

	qtfs_info("qtfs icreate get ret:%d, mode:%ho.", rsp->errno, rsp->inode_info.mode);
	qtfs_conn_put_param(pvar);
	return ret ? ret : ret2;
}

int qtfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_mknod *req;
	struct qtrsp_mknod *rsp;
	struct inode *inode;
	int ret = 0;
	int ret2 = 0;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, dentry);

	req->mode = mode;
	req->dev = dev;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_MKNOD, sizeof(struct qtreq_mknod) - sizeof(req->path) + strlen(req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs mknod failed %d.", rsp->errno);
		ret = rsp->errno;
		qtfs_conn_put_param(pvar);
		return ret;
	}
	ret = rsp->errno;
	qtfs_info("qtfs mknod success, path:<%s>.\n", req->path);
	inode = qtfs_iget(dentry->d_sb, &(rsp->inode_info));
	ret2 = qtfs_new_entry(inode, dentry);
	qtfs_conn_put_param(pvar);
	return ret ? ret : ret2;
}

static void qtfs_inode_priv_alloc(struct inode *inode)
{
	struct qtfs_inode_priv *priv = kmem_cache_alloc(qtfs_inode_priv_cache, GFP_KERNEL);
	if (priv == NULL) {
		qtfs_err("qtfs inode priv alloc kmem cache alloc failed.");
		return;
	}
	inode->i_private = priv;
	priv->files = 0;
	init_waitqueue_head(&priv->readq);
	init_waitqueue_head(&priv->writeq);
	return;
}

static void qtfs_init_inode(struct super_block *sb, struct inode *inode, struct inode_info *ii)
{
	inode->i_sb = sb;
	inode->i_mode = ii->mode;
	inode->i_ino = ii->i_ino;
	inode->i_size = ii->i_size;
	inode->i_atime = ii->atime;
	inode->i_mtime = ii->mtime;
	inode->i_ctime = ii->ctime;

	if (S_ISLNK(inode->i_mode)) {
		if (is_sb_proc(sb)) {
			qtfs_info("inode link ops set to qtfs_proc_sym_ops.");
			inode->i_op = &qtfs_proc_sym_ops;
		} else {
			inode->i_op = &qtfs_symlink_inode_ops;
		}
	} else {
		if (is_sb_proc(sb)) {
			inode->i_op = &qtfs_proc_inode_ops;
		} else {
			inode->i_op = &qtfs_inode_ops;
		}
	}
	inode->i_mapping->a_ops = &qtfs_aops;

	if (S_ISDIR(ii->mode)) {
		inode->i_fop = &qtfs_dir_ops;
	} else if (S_ISREG(ii->mode)) {
		inode->i_fop = &qtfs_file_ops;
	} else if (S_ISFIFO(ii->mode)) {
		inode->i_fop = &qtfsfifo_ops;
	} else {
		inode->i_fop = &qtfs_file_ops;
	}
	qtfs_inode_priv_alloc(inode);
	return;
}

struct inode *qtfs_iget(struct super_block *sb, struct inode_info *ii)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;
	qtfs_init_inode(sb, inode, ii);
	return inode;
}

struct dentry *qtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_lookup *req;
	struct qtrsp_lookup *rsp;
	struct inode *inode;
	struct dentry *d = NULL;
	int ret;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var");
		return NULL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	ret = qtfs_fullname(req->fullname, child_dentry);
	if (ret < 0) {
		qtfs_err("qtfs lookup get fullname failed, too many path layers, <%s>!", req->fullname);
		goto err_end;
	}
	rsp = qtfs_remote_run(pvar, QTFS_REQ_LOOKUP, strlen(req->fullname));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return (void *)rsp;
	}
	if (rsp->ret != QTFS_OK) {
		qtfs_info("qtfs fs lookup failed, path:<%s> not exist at peer.\n", req->fullname);
		d = ERR_PTR(rsp->errno);
		qtfs_conn_put_param(pvar);
		return d;
	}
	inode = qtfs_iget(parent_inode->i_sb, &(rsp->inode_info));
	if (inode == NULL)
		goto err_end;
	d = d_splice_alias(inode, child_dentry);
	qtfs_debug("qtfs lookup fullname:%s mode:%o(rsp:%o), ino:%lu(rsp:%lu).",
			req->fullname, inode->i_mode, rsp->inode_info.mode, inode->i_ino, rsp->inode_info.i_ino);

	qtfs_conn_put_param(pvar);
	return d;

err_end:
	qtfs_conn_put_param(pvar);
	return NULL;
}
int qtfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_rmdir *req;
	struct qtrsp_rmdir *rsp;
	int ret;
	struct inode *inode = d_inode(dentry);

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, dentry);

	rsp = qtfs_remote_run(pvar, QTFS_REQ_RMDIR, QTFS_SEND_SIZE(struct qtreq_rmdir, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}

	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs rmdir <%s> failed, errno:%d.\n", req->path, rsp->errno);
		ret = rsp->errno;
		qtfs_conn_put_param(pvar);
		return ret;
	}
	qtfs_info("qtfs rmdir success:<%s>.\n", req->path);
	qtfs_conn_put_param(pvar);
	if (inode->i_nlink > 0)
                drop_nlink(inode);
        d_invalidate(dentry);
	return 0;
}

int qtfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct qtreq_unlink *req;
	struct qtrsp_unlink *rsp;
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	int ret;
	struct inode *inode = d_inode(dentry);

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, dentry);
	qtfs_info("qtfs unlink %s.\n", req->path);

	rsp = qtfs_remote_run(pvar, QTFS_REQ_UNLINK, QTFS_SEND_SIZE(struct qtreq_unlink, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->errno < 0) {
		qtfs_err("qtfs unlink %s failed, errno:%d\n", req->path, rsp->errno);
	} else {
		qtfs_info("qtfs unlink %s success\n", req->path);
		inode->i_ctime = dir->i_ctime;
		inode_dec_link_count(inode);
	}
	ret = rsp->errno;
	qtfs_conn_put_param(pvar);
	if (inode->i_nlink > 0)
                drop_nlink(inode);
        d_invalidate(dentry);
	return ret;
}

int qtfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_link *req;
	struct qtrsp_link *rsp;
	int error;
	struct inode *inode = d_inode(old_dentry);
	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, old_dentry);
	req->d.oldlen = strlen(req->path) + 1;
	QTFS_FULLNAME(req->path + req->d.oldlen, new_dentry);
	req->d.newlen = strlen(req->path + req->d.oldlen) + 1;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_LINK, sizeof(struct qtreq_link) - sizeof(req->path) + req->d.newlen + req->d.oldlen);
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs link failed %d\n", rsp->errno);
		error = rsp->errno;
		goto err_end;
	}
	inode->i_ctime = current_time(inode);
	inode_inc_link_count(inode);
	ihold(inode);
	d_instantiate(new_dentry, inode);
	qtfs_info("qtfs link success, old:%s new:%s", req->path, req->path + req->d.oldlen);
	qtfs_conn_put_param(pvar);
	return 0;

err_end:
	qtfs_conn_put_param(pvar);
	return error;
}

int qtfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_symlink *req;
	struct qtrsp_symlink *rsp;
	struct inode *inode;
	int error;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, dentry);
	req->d.newlen = strlen(req->path) + 1;
	if (req->d.newlen + strlen(symname) + 1 > sizeof(req->path)) {
		qtfs_conn_put_param(pvar);
		qtfs_err("qtfs symlink path name too long\n");
		return -EINVAL;
	}
	strncpy(&req->path[req->d.newlen], symname, sizeof(req->path) - req->d.newlen - 1);

	req->d.oldlen = strlen(&req->path[req->d.newlen]) + 1;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_SYMLINK, sizeof(struct qtreq_symlink) - sizeof(req->path) + req->d.newlen + req->d.oldlen);
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs symlink failed %d\n", rsp->errno);
		error = rsp->errno;
		goto err_end;
	}
	inode = qtfs_iget(dentry->d_sb, &(rsp->inode_info));
	error = qtfs_new_entry(inode, dentry);
	qtfs_info("qtfs symlink success, path:%s symname:%s", req->path, symname);
	qtfs_conn_put_param(pvar);
	return error;

err_end:
	qtfs_conn_put_param(pvar);
	return error;
}

int qtfs_getattr(const struct path *path, struct kstat *stat, u32 req_mask, unsigned int flags)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_getattr *req;
	struct qtrsp_getattr *rsp;
	struct inode *inode = path->dentry->d_inode;
	int ret;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, path->dentry);
	req->request_mask = req_mask;
	req->query_flags = flags;

	(void)qtfs_mountpoint_path_init(path->dentry, (struct path*)path, req->path);
	rsp = qtfs_remote_run(pvar, QTFS_REQ_GETATTR, QTFS_SEND_SIZE(struct qtreq_getattr, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->ret) {
		qtfs_err("qtfs getattr <%s> failed.errno: %d %s\n", req->path, rsp->errno,
				(rsp->errno != -ENOENT) ? "." : "file not exist");
		ret = rsp->errno;
		qtfs_conn_put_param(pvar);
		return ret;
	}
	*stat = rsp->stat;
	qtfs_debug("qtfs getattr success:<%s> blksiz:%u size:%lld mode:%o ino:%llu pathino:%lu. %s\n", req->path, rsp->stat.blksize,
			rsp->stat.size, rsp->stat.mode, rsp->stat.ino, inode->i_ino, rsp->stat.ino != inode->i_ino ? "delete current inode" : "");
	if (inode->i_ino != rsp->stat.ino || inode->i_mode != rsp->stat.mode) {
		if (inode->i_nlink > 0){
			drop_nlink(inode);
		}
		d_invalidate(path->dentry);
	}
	qtfs_conn_put_param(pvar);
	return 0;
}

int qtfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_setattr *req;
	struct qtrsp_setattr *rsp;
	int ret;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	QTFS_FULLNAME(req->path, dentry);
	req->attr = *attr;
	req->attr.ia_file = NULL;
	qtfs_info("iattr iavalid:%u mode:0x%o size:%lld file:0x%lx\n",
			req->attr.ia_valid, req->attr.ia_mode, req->attr.ia_size, (unsigned long)req->attr.ia_file);
	rsp = qtfs_remote_run(pvar, QTFS_REQ_SETATTR, QTFS_SEND_SIZE(struct qtreq_setattr, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs setattr <%s> failed. %d\n", req->path, rsp->errno);
		ret = rsp->errno;
		qtfs_conn_put_param(pvar);
		return ret;
	}
	qtfs_info("qtfs setattr <%s> success.\n", req->path);
	qtfs_conn_put_param(pvar);
	return 0;
}
const char *qtfs_getlink(struct dentry *dentry,
						struct inode *inode, struct delayed_call *done)
{
	struct qtfs_sock_var_s *pvar = NULL;
	struct qtreq_getlink *req;
	struct qtrsp_getlink *rsp;
	int len = 0;
	struct qtfs_fs_info *fsinfo = qtfs_priv_byinode(inode);
	char *link = NULL;

	link = READ_ONCE(inode->i_link);
	if (link) {
		qtfs_info("qtfs get link cache.\n");
		return link;
	}

	if (dentry == NULL) {
		return ERR_PTR(-ECHILD);
	}
	pvar = qtfs_conn_get_param();

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return ERR_PTR(-EINVAL);
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	if (qtfs_fullname(req->path, dentry) < 0) {
		qtfs_err("qtfs fullname failed\n");
		qtfs_conn_put_param(pvar);
		return ERR_PTR(-EINVAL);
	}
	rsp = qtfs_remote_run(pvar, QTFS_REQ_GETLINK, QTFS_SEND_SIZE(struct qtreq_getlink, req->path));
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return (void *)rsp;
	}
	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs getlink <%s> failed. %d\n", req->path, rsp->errno);
		qtfs_conn_put_param(pvar);
		return ERR_PTR(-ENOENT);
	}
	if (fsinfo->mnt_path)
		len = strlen(fsinfo->mnt_path) + strlen(rsp->path) + 1;
	else
		len = strlen(rsp->path) + 1;
	link = kmalloc(len, GFP_KERNEL);
	if (!link) {
		qtfs_conn_put_param(pvar);
		return ERR_PTR(-ENOMEM);
	}
	memset(link, 0, len);
	if (rsp->path[0] == '/' && fsinfo->mnt_path)
		strcat(link, fsinfo->mnt_path);
	strcat(link, rsp->path);
	qtfs_info("get link success <%s>\n", link);

	set_delayed_call(done, kfree_link, link);
	qtfs_conn_put_param(pvar);
	return link;
}

int qtfs_rename(struct inode *old_dir, struct dentry *old_dentry,
					struct inode *new_dir, struct dentry *new_dentry,
					unsigned int flags)
{
	struct qtreq_rename *req;
	struct qtrsp_rename *rsp;
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	int ret;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	req->d.oldlen = qtfs_fullname(req->path, old_dentry);
	if (req->d.oldlen < 0) {
		qtfs_err("qtfs fullname failed\n");
		qtfs_conn_put_param(pvar);
		return -EINVAL;
	}
	req->d.oldlen += 1;
	req->d.newlen = qtfs_fullname(&req->path[req->d.oldlen], new_dentry);
	if (req->d.newlen < 0) {
		qtfs_err("qtfs fullname failed\n");
		qtfs_conn_put_param(pvar);
		return -EINVAL;
	}
	req->d.newlen += 1;
	req->d.flags = flags;

	rsp = qtfs_remote_run(pvar, QTFS_REQ_RENAME, sizeof(struct qtreq_rename) - sizeof(req->path) + req->d.oldlen + req->d.newlen);
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}

	if (rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs rename failed,errno:%d\n", rsp->errno);
	} else {
		qtfs_info("qtfs rename success, oldname:%s newname:%s flags:%x\n", req->path, &req->path[req->d.oldlen], flags);
	}
	ret = rsp->errno;
	qtfs_conn_put_param(pvar);
	return ret;
}

static struct inode_operations qtfs_inode_ops = {
	.create = qtfs_create,
	.lookup = qtfs_lookup,
	.mkdir = qtfs_mkdir,
	.rmdir = qtfs_rmdir,
	.unlink = qtfs_unlink,
	.symlink = qtfs_symlink,
	.link = qtfs_link,
	.mknod = qtfs_mknod,
	.getattr = qtfs_getattr,
	.setattr = qtfs_setattr,
	.rename = qtfs_rename,
	.listxattr = qtfs_xattr_list,
};

static struct inode_operations qtfs_symlink_inode_ops = {
	.get_link = qtfs_getlink,
	.getattr = qtfs_getattr,
	.setattr = qtfs_setattr,
	.listxattr = qtfs_xattr_list,
};

const struct xattr_handler *qtfs_xattr_handlers[] = {
	&qtfs_xattr_user_handler,
	&qtfs_xattr_trusted_handler,
	&qtfs_xattr_security_handler,
#ifndef KVER_4_19
	&qtfs_xattr_hurd_handler,
#endif
	NULL
};

static int qtfs_fill_super(struct super_block *sb, void *priv_data, int silent)
{
	struct inode *root_inode;
	int mode = S_IFDIR;
	int err;
	struct qtfs_fs_info *priv = (struct qtfs_fs_info *)priv_data;

	root_inode = new_inode(sb);
	root_inode->i_ino = 1;

	inode_init_owner(root_inode, NULL, mode);
	root_inode->i_sb = sb;
	if (priv->type == QTFS_PROC) {
		qtfs_info("qtfs type: proc\n");
		root_inode->i_op = &qtfs_proc_inode_ops;
	} else {
		qtfs_info("qtfs type: normal\n");
		root_inode->i_op = &qtfs_inode_ops;
	}
	root_inode->i_fop = &qtfs_dir_ops;
	root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime = CURRENT_TIME(root_inode);

	sb->s_xattr = qtfs_xattr_handlers;
	err = super_setup_bdi(sb);
	if (err) {
		qtfs_err("qtfs fill super bdi setup err:%d.\n", err);
	}
	sb->s_fs_info = priv;
	sb->s_op = &qtfs_ops;
	sb->s_time_gran = 1;

	sb->s_root = d_make_root(root_inode);
	return 0;
}

struct dentry *qtfs_fs_mount(struct file_system_type *fs_type,
								int flags, const char *dev_name, void *data)
{
	struct qtreq_mount *req = NULL;
	struct qtrsp_mount *rsp = NULL;
	struct dentry *ret;
	struct qtfs_fs_info *priv = NULL;
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return ERR_PTR(-ENXIO);
	}

	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	strlcpy(req->path, dev_name, PATH_MAX);
	rsp = qtfs_remote_run(pvar, QTFS_REQ_MOUNT, strlen(dev_name));
	if (IS_ERR(rsp) || rsp == NULL || rsp->ret != QTFS_OK) {
		qtfs_err("qtfs fs mount failed, path:<%s> not exist at peer.\n", dev_name);
		qtfs_conn_put_param(pvar);
		return ERR_PTR(-ENOENT);
	}

	priv = (struct qtfs_fs_info *)kmalloc(sizeof(struct qtfs_fs_info), GFP_KERNEL);
	if (err_ptr(priv)) {
		qtfs_err("qtfs priv kmalloc failed:%ld\n", PTR_ERR(priv));
		qtfs_conn_put_param(pvar);
		return ERR_PTR(-ENOMEM);
	}

	memset(priv, 0, sizeof(struct qtfs_fs_info));
	priv->type = qtfs_get_type((char *)data);
	strlcpy(priv->peer_path, dev_name, NAME_MAX);
	priv->mnt_path = NULL;

	ret = mount_nodev(fs_type, flags, (void *)priv, qtfs_fill_super);
	if (err_ptr(ret)) {
		qtfs_err("mount qtfs error.\n");
	} else {
		qtfs_info("mount qtfs success dev name:%s.\n", dev_name);
	}

	qtfs_conn_put_param(pvar);
	return ret;
}

void qtfs_kill_sb(struct super_block *sb)
{
	qtfs_info("qtfs superblock deleted.\n");
	kill_anon_super(sb);
}

