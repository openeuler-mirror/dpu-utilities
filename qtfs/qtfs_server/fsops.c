#include <linux/fs.h>
#include <linux/stddef.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <linux/init_syscalls.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/poll.h>
#include <linux/fs_struct.h>

#include "conn.h"
#include "qtfs-server.h"
#include "req.h"
#include "log.h"
#include "fsops.h"
#include "comm.h"

#define REQ(arg) (arg->data)
#define RSP(arg) (arg->out)
#define USERP(arg) (arg->userp)

static inline void qtfs_inode_info_fill(struct inode_info *ii, struct inode *inode)
{
	ii->mode = inode->i_mode;
	ii->i_opflags = inode->i_opflags;
	ii->i_uid = inode->i_uid;
	ii->i_gid = inode->i_gid;
	ii->i_flags = inode->i_flags;
	ii->i_ino = inode->i_ino;
	ii->i_rdev = inode->i_rdev;
	ii->i_size = inode->i_size;
	ii->atime = inode->i_atime;
	ii->mtime = inode->i_mtime;
	ii->ctime = inode->i_ctime;
	ii->i_bytes = inode->i_bytes;
	ii->i_blkbits = inode->i_blkbits;
	ii->i_write_hint = inode->i_write_hint;
	ii->i_blocks = inode->i_blocks;
	ii->i_state = inode->i_state;
	ii->dirtied_when = inode->dirtied_when;
	ii->dirtied_time_when = inode->dirtied_time_when;
	ii->i_generation = inode->i_generation;
	return;
}

static int handle_ioctl(struct qtserver_arg *arg)
{
	int ret;
	int iret;
	struct file *file;
	struct qtreq_ioctl *req = (struct qtreq_ioctl *)REQ(arg);
	struct qtrsp_ioctl *rsp = (struct qtrsp_ioctl *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	file = filp_open(req->path, O_RDONLY, 0);
	if (err_ptr(file)) {
		qtfs_err("handle ioctl error, path:<%s> failed.\n", req->path);
		rsp->ret = QTFS_ERR;
		rsp->size = 0;
		rsp->errno = -ENOENT;
		return sizeof(struct qtrsp_ioctl) - sizeof(rsp->buf);
	}

	switch (req->d.cmd) {
	case FS_IOC_FSGETXATTR:
		iret = file->f_op->unlocked_ioctl(file, req->d.cmd, (unsigned long)userp->userp);
		if (iret) {
			qtfs_err("fsgetxattr ioctl failed with %d\n", iret);
			rsp->errno = iret;
			goto err;
		}
		ret = copy_from_user(rsp->buf, userp->userp, sizeof(struct fsxattr));
		if (ret) {
			qtfs_err("fsgetxattr copy_from_user failed with %d\n", ret);
			rsp->errno = ret;
			goto err;
		}
		rsp->ret = QTFS_OK;
		rsp->errno = iret;
		rsp->size = sizeof(struct fsxattr);
		filp_close(file, NULL);
		return sizeof(struct qtrsp_ioctl) - sizeof(rsp->buf) + sizeof(struct fsxattr);
	case FS_IOC_FSSETXATTR:
		if (req->d.size <= 0) {
			rsp->errno = -EINVAL;
			goto err;
		}
		ret = copy_to_user(userp->userp, req->path+req->d.offset, req->d.size);
		if (ret) {
			qtfs_err("fssetxattr copy_to_user failed with %d\n", ret);
			rsp->errno = ret;
			goto err;
		}
		iret = file->f_op->unlocked_ioctl(file, req->d.cmd, (unsigned long)userp->userp);
		if (iret) {
			qtfs_err("fssetxattr ioctl failed with %d\n", iret);
			rsp->errno = iret;
			goto err;
		}
		rsp->ret = QTFS_OK;
		rsp->errno = iret;
		rsp->size = 0;
		filp_close(file, NULL);
		return sizeof(struct qtrsp_ioctl) - sizeof(rsp->buf);
	default:
		rsp->errno = -EOPNOTSUPP;
		goto err;
	}
err:
	rsp->ret = QTFS_ERR;
	rsp->size = 0;
	filp_close(file, NULL);
	return sizeof(struct qtrsp_ioctl) - sizeof(rsp->buf);
}

static int handle_statfs(struct qtserver_arg *arg)
{
	int ret;
	struct qtreq_statfs *req = (struct qtreq_statfs *)REQ(arg);
	struct qtrsp_statfs *rsp = (struct qtrsp_statfs *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	ret = copy_to_user(userp->userp, req->path, strlen(req->path)+1);
	if (ret) {
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_statfs);
	}

	ret = qtfs_kern_syms.user_statfs((char *)userp->userp, &(rsp->kstat));
	if (ret) {
		qtfs_err("qtfs server handle statfs path:%s failed with ret:%d.\n", req->path, ret);
		rsp->ret = QTFS_ERR;
	} else {
		qtfs_info("qtfs server handle statfs path:%s success.\n", req->path);
		rsp->ret = QTFS_OK;
	}
	rsp->errno = ret;
	return sizeof(struct qtrsp_statfs);
}

static int handle_mount(struct qtserver_arg *arg)
{
	struct path path;
	int ret;
	struct qtreq_mount *req = (struct qtreq_mount *)REQ(arg);
	struct qtrsp_mount *rsp = (struct qtrsp_mount *)RSP(arg);

	ret = kern_path(req->path, LOOKUP_DIRECTORY, &path);
	if (ret) {
		qtfs_err("handle mount path:%s not exist.\n", req->path);
		rsp->ret = QTFS_ERR;
	} else {
		rsp->ret = QTFS_OK;
		qtfs_info("handle mount path:%s success.\n", req->path);
		path_put(&path);
	}
	return sizeof(rsp->ret);
}

int handle_open(struct qtserver_arg *arg)
{
	int fd;
	int ret;
	struct fd f;
	struct file *file = NULL;
	struct qtreq_open *req = (struct qtreq_open *)REQ(arg);
	struct qtrsp_open *rsp = (struct qtrsp_open *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	ret = copy_to_user(userp->userp, req->path, strlen(req->path)+1);
	if (ret) {
		qtfs_err("handle open copy to user failed, ret:%d userp:%lx path:%s", ret, (unsigned long)userp->userp, req->path);
		rsp->ret = QTFS_ERR;
		rsp->fd = -EFAULT;
		return sizeof(struct qtrsp_open);
	}
	fd = qtfs_kern_syms.do_sys_open(AT_FDCWD, (char *)userp->userp, req->flags, req->mode);
	if (fd == -EEXIST) {
		qtfs_err("handle open file <<%s>> flags:%llx mode:%o, opened:failed %d, do again\n", req->path, req->flags, req->mode, fd);
		req->flags &= ~(O_CREAT | O_EXCL);
		fd = qtfs_kern_syms.do_sys_open(AT_FDCWD, (char *)userp->userp, req->flags, req->mode);
	}
	if (fd < 0) {
		if (fd != -ENOENT) {
			qtfs_err("handle open file <<%s>>flags:%llx mode:%o, opened:failed %d\n", req->path, req->flags, req->mode, fd);
		} else {
			qtfs_info("handle open file <<%s>>flags:%llx mode:%o, opened:failed - file not exist\n", req->path, req->flags, req->mode);
		}
		rsp->ret = QTFS_ERR;
		rsp->fd = fd;
		rsp->file = 0;
		return sizeof(struct qtrsp_open);
	}

	f = fdget(fd);
	file = f.file;
	if (err_ptr(file)) {
		rsp->ret = QTFS_ERR;
		rsp->fd = PTR_ERR(file);
		// must close_fd(fd)?
		WARN_ON(1);
		qtfs_err("handle open get file pointer of <<%s>> error, fd:%d file err:%d.", req->path, fd, rsp->fd);
		// XXX: fileclose here?
	} else {
		rsp->ret = QTFS_OK;
		rsp->file = (__u64)file;
		rsp->fd = fd;
	}
	qtfs_info("handle open file :%s fd:%d filep:%lx.", req->path, fd, (unsigned long)rsp->file);
	fdput(f);
	return sizeof(struct qtrsp_open);
}

int handle_close(struct qtserver_arg *arg)
{
	struct qtreq_close *req = (struct qtreq_close *)REQ(arg);
	struct qtrsp_close *rsp = (struct qtrsp_close *)RSP(arg);

	// fd >= 3 is valid
	if (req->fd <= 2) {
		qtfs_err("handle close an invalid fd:%d.", req->fd);
		WARN_ON(1);
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_close);
	}

	rsp->ret = qtfs_kern_syms.__close_fd(current->files, req->fd);
	qtfs_info("handle close file, fd:%d ret:%d", req->fd, rsp->ret);
	return sizeof(struct qtrsp_close);
}

static int handle_readiter(struct qtserver_arg *arg)
{
	struct file *file = NULL;
	struct qtreq_readiter *req = (struct qtreq_readiter *)REQ(arg);
	struct qtrsp_readiter *rsp = (struct qtrsp_readiter *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	size_t maxlen = (req->len >= sizeof(rsp->readbuf)) ? (sizeof(rsp->readbuf) - 1) : req->len;

	file = (struct file *)req->file;
	if (err_ptr(file)) {
		qtfs_err("handle readiter error, open failed, file:%p.\n", file);
		rsp->d.ret = QTFS_ERR;
		rsp->d.len = 0;
		rsp->d.errno = -ENOENT;
		return sizeof(struct qtrsp_readiter) - sizeof(rsp->readbuf) + rsp->d.len;
	}
	if (file->f_op->read) {
		int idx = 0;
		int ret = 0;
		do {
			if (idx + userp->size < maxlen) {
				ret = file->f_op->read(file, userp->userp, userp->size, &req->pos);
			} else {
				ret = file->f_op->read(file, userp->userp, maxlen - idx, &req->pos);
			}
			if (ret <= 0)
				break;
			if (copy_from_user(&rsp->readbuf[idx], userp->userp, ret)) {
				qtfs_err("readiter copy from user failed.");
				break;
			}
			rsp->d.len += ret;
			idx += ret;
		} while (ret > 0 && idx < maxlen);
		if (ret < 0) {
			qtfs_err("handle readiter ret:%d.", ret);
			rsp->d.len = ret;
		}
	} else {
		rsp->d.len = kernel_read(file, rsp->readbuf, maxlen, &req->pos);
	}
	if (rsp->d.len > maxlen || rsp->d.len < 0) {
		rsp->d.ret = QTFS_ERR;
		rsp->d.errno = (int)rsp->d.len;
	} else {
		rsp->d.ret = QTFS_OK;
	}

	qtfs_info("handle readiter file:<%s>, len:%lu, rsplen:%ld, pos:%lld, ret:%d errno:%d.\n",
			file->f_path.dentry->d_iname, req->len, rsp->d.len, req->pos, rsp->d.ret, rsp->d.errno);
	return sizeof(struct qtrsp_readiter) - sizeof(rsp->readbuf) + rsp->d.len;
}

static int handle_write(struct qtserver_arg *arg)
{
	struct file *file = NULL;
	struct qtreq_write *req = (struct qtreq_write *)REQ(arg);
	struct qtrsp_write *rsp = (struct qtrsp_write *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	int idx = 0, leftlen = 0, ret = 0, len = 0;

	file = (struct file *)req->d.file;
	if (err_ptr(file)) {
		qtfs_err("qtfs handle write error, filp:<%p> open failed.\n", file);
		rsp->ret = QTFS_ERR;
		rsp->len = 0;
		return sizeof(struct qtrsp_write);
	}

	file->f_mode = req->d.mode;
	file->f_flags = req->d.flags;
	if (file->f_op->write) {
		leftlen = req->d.buflen;
		rsp->len = 0;
		while (leftlen > 0) {
			len = leftlen > userp->size ? userp->size : leftlen;
			if (copy_to_user(userp->userp, &req->path_buf[idx], len)) {
				qtfs_err("write copy to userp failed.\n");
				rsp->len = -EFAULT;
				break;
			}
			ret = file->f_op->write(file, userp->userp, len, &req->d.pos);
			if (ret < 0) {
				rsp->len = ret;
				break;
			}
			leftlen -= ret;
			idx += ret;
			rsp->len += ret;
		}
	} else {
		rsp->len = kernel_write(file, req->path_buf, req->d.buflen, &req->d.pos);
	}
	rsp->ret = (rsp->len <= 0) ? QTFS_ERR : QTFS_OK;
	qtfs_info("handle write file<%s> %s, write len:%ld pos:%lld mode:%o flags:%x.", file->f_path.dentry->d_iname,
			(rsp->ret == QTFS_ERR) ? "failed" : "succeded", rsp->len, req->d.pos, file->f_mode, file->f_flags);
	return sizeof(struct qtrsp_write);
}

static int handle_lookup(struct qtserver_arg *arg)
{
	struct path path;
	struct inode *inode;
	struct qtreq_lookup *req = (struct qtreq_lookup *)REQ(arg);
	struct qtrsp_lookup *rsp = (struct qtrsp_lookup *)RSP(arg);
	int ret;
	ret = kern_path(req->fullname, 0, &path);
	if (ret) {
		qtfs_info("qtfs handle lookup(%s) not exist, ret%d.\n", req->fullname, ret);
		rsp->ret = QTFS_ERR;
	} else {
		inode = path.dentry->d_inode;
		rsp->ret = QTFS_OK;
		qtfs_inode_info_fill(&rsp->inode_info, inode);
		qtfs_debug("handle lookup name:%s, mode:%o ino:%lu", req->fullname, rsp->inode_info.mode, rsp->inode_info.i_ino);
		path_put(&path);
	}
	return sizeof(struct qtrsp_lookup);
}

static int qtfs_filldir(struct dir_context *ctx, const char *name, int namelen,
		loff_t offset, u64 ino, unsigned int d_type)
{
	struct qtfs_dirent64 *dirent, *prev;
	struct qtfs_getdents *buf = container_of(ctx, struct qtfs_getdents, ctx);
	int reclen = ALIGN(offsetof(struct qtfs_dirent64, d_name) + namelen + 1, sizeof(u64));
	int prev_reclen;

	if (reclen > buf->count)
		return -EINVAL;

	prev_reclen = buf->prev_reclen;
	dirent = buf->dir;
	prev = (void *)dirent - prev_reclen;
	prev->d_off = offset;
	dirent->d_ino = ino;
	dirent->d_reclen = reclen;
	dirent->d_type = d_type;
	memcpy(dirent->d_name, name, namelen);

	buf->prev_reclen = reclen;
	buf->dir = (void *)dirent + reclen;
	buf->count -= reclen;
	buf->vldcnt++;
	return 0;
}

static int handle_readdir(struct qtserver_arg *arg)
{
	struct file *file = NULL;
	struct qtreq_readdir *req = (struct qtreq_readdir *)REQ(arg);
	struct qtrsp_readdir *rsp = (struct qtrsp_readdir *)RSP(arg);
	int ret;
	struct qtfs_getdents buf = {
		.ctx.actor = qtfs_filldir,
		.ctx.pos = req->pos,
		.prev_reclen = 0,
		.count = req->count,
		.dir = (struct qtfs_dirent64 *)rsp->dirent,
		.vldcnt = 0,
	};
	file = filp_open(req->path, O_RDONLY|O_NONBLOCK|O_DIRECTORY, 0);
	if (err_ptr(file)) {
		qtfs_err("handle readdir error, filp:<%s> open failed.\n", req->path);
		rsp->d.ret = QTFS_ERR;
		rsp->d.vldcnt = 0;
		return sizeof(struct qtrsp_readdir) - sizeof(rsp->dirent);
	}
	file->f_pos = req->pos;
	ret = iterate_dir(file, &buf.ctx);
	rsp->d.pos = file->f_pos;
	rsp->d.ret = QTFS_OK;
	rsp->d.vldcnt = buf.vldcnt;
	rsp->d.over = (req->pos == rsp->d.pos) ? 1 : 0;
	qtfs_info("handle readdir ret:%d, pos:%lld path:%s, valid count:%d, leftcount:%d validbyte:%lu\n",
			ret, req->pos, req->path, buf.vldcnt, buf.count, sizeof(rsp->dirent) - buf.count);
	filp_close(file, NULL);

	return sizeof(struct qtrsp_readdir) - buf.count;
}

static int handle_mkdir(struct qtserver_arg *arg)
{
	struct qtreq_mkdir *req = (struct qtreq_mkdir *)REQ(arg);
	struct qtrsp_mkdir *rsp = (struct qtrsp_mkdir *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);
	struct inode *inode;
	struct path path;
	int ret;

	if (copy_to_user(userp->userp, req->path, strlen(req->path) + 1)) {
		qtfs_err("handle mkdir copy to userp failed.\n");
		rsp->errno = -EFAULT;
		goto err;
	}
	rsp->errno = qtfs_kern_syms.do_mkdirat(AT_FDCWD, userp->userp, req->mode);
	if (rsp->errno < 0) {
		qtfs_err("handle mkdir failed with ret:%d.", rsp->errno);
		goto err;
	}
	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle mkdir failed in kern path, ret:%d.\n", ret);
	} else {
		inode = d_inode(path.dentry);
		qtfs_inode_info_fill(&rsp->inode_info, inode);
		path_put(&path);
	}
	rsp->ret = QTFS_OK;
	qtfs_info("handle mkdir path:%s success.", req->path);
	return sizeof(struct qtrsp_mkdir);

err:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_mkdir);
}

static int handle_rmdir(struct qtserver_arg *arg)
{
	struct qtreq_rmdir *req = (struct qtreq_rmdir *)REQ(arg);
	struct qtrsp_rmdir *rsp = (struct qtrsp_rmdir *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	if (copy_to_user(userp->userp, req->path, strlen(req->path) + 1)) {
		qtfs_err("handle rmdir copy to userp failed.\n");
		rsp->errno = -EFAULT;
		goto err;
	}
	rsp->errno = qtfs_kern_syms.do_rmdir(AT_FDCWD, qtfs_kern_syms.getname(userp->userp));
	if (rsp->errno < 0) {
		qtfs_err("handle rmdir error:%d.", rsp->errno);
		goto err;
	}
	qtfs_info("handle rmdir path:%s success.", req->path);
	rsp->ret = QTFS_OK;
	return sizeof(struct qtrsp_rmdir);

err:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_rmdir);
}

static int handle_getattr(struct qtserver_arg *arg)
{
	struct qtreq_getattr *req = (struct qtreq_getattr *)REQ(arg);
	struct qtrsp_getattr *rsp = (struct qtrsp_getattr *)RSP(arg);
	struct path path;
	int ret;

	qtfs_debug("handle getattr path:%s\n", req->path);
	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle getattr path:%s failed, ret:%d %s\n", req->path, ret, (ret != -ENOENT) ? "." : "file not exist");
		goto failed;
	}

	ret = vfs_getattr(&path, &rsp->stat, req->request_mask, req->query_flags);
	if (ret) {
		qtfs_err("vfs getattr path:%s ret:%d\n", req->path, ret);
		rsp->errno = ret;
		path_put(&path);
		goto failed;
	}
	rsp->ret = QTFS_OK;
	path_put(&path);
	qtfs_debug("handle getattr:<%s> blksize:%u size:%lld mode:%o ino:%llu req_mask:%x req_flags:%u.\n", req->path, rsp->stat.blksize,
			rsp->stat.size, rsp->stat.mode, rsp->stat.ino, req->request_mask, req->query_flags);
	return sizeof(struct qtrsp_getattr);

failed:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_getattr);
}

static int handle_setattr(struct qtserver_arg *arg)
{
	struct qtreq_setattr *req = (struct qtreq_setattr *)REQ(arg);
	struct qtrsp_setattr *rsp = (struct qtrsp_setattr *)RSP(arg);
	struct inode *inode = NULL;
	struct path path;
	int ret;

	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle setattr path:%s failed in kern_path with %d\n", req->path, ret);
		rsp->ret = QTFS_ERR;
		rsp->errno = -ENOENT;
		return sizeof(struct qtrsp_setattr);
	}
	inode = path.dentry->d_inode;
	inode_lock(inode);
	rsp->errno = notify_change(path.dentry, &req->attr, NULL);
	if (rsp->errno < 0) {
		rsp->ret = QTFS_ERR;
		qtfs_err("handle setattr, path:<%s> failed with %d.\n", req->path, ret);
		goto end;
	}

	qtfs_info("handle setattr iattr success iavalid:%u mode:%o size:%lld file:0x%lx\n",
			req->attr.ia_valid, req->attr.ia_mode, req->attr.ia_size, (unsigned long)req->attr.ia_file);
	rsp->ret = QTFS_OK;

end:
	inode_unlock(inode);
	path_put(&path);
	return sizeof(struct qtrsp_setattr);
}

int handle_icreate(struct qtserver_arg *arg)
{
	struct file *file = NULL;
	struct inode *inode;
	struct qtreq_icreate *req = (struct qtreq_icreate *)REQ(arg);
	struct qtrsp_icreate *rsp = (struct qtrsp_icreate *)RSP(arg);

	file = filp_open(req->path, O_CREAT, req->mode);
	if (err_ptr(file)) {
		qtfs_err("handle icreate filp:<%s> failed in open.\n", req->path);
		rsp->ret = QTFS_ERR;
		rsp->errno = PTR_ERR(file);
		return sizeof(struct qtrsp_icreate);
	}
	inode = file->f_inode;
	qtfs_inode_info_fill(&rsp->inode_info, inode);
	filp_close(file, NULL);
	rsp->ret = QTFS_OK;
	qtfs_info("handle icreate path:%s success, inode mode:%ho\n", req->path,
			rsp->inode_info.mode);
	return sizeof(struct qtrsp_icreate);
}

static int handle_mknod(struct qtserver_arg *arg)
{
	struct qtreq_mknod *req = (struct qtreq_mknod *)REQ(arg);
	struct qtrsp_mknod *rsp = (struct qtrsp_mknod *)RSP(arg);
	struct dentry *dent = NULL;
	struct path path;
	int error;
	unsigned int flags = LOOKUP_DIRECTORY;

retry:
	dent = kern_path_create(AT_FDCWD, req->path, &path, flags);
	if (err_ptr(dent)) {
		rsp->ret = QTFS_ERR;
		qtfs_info("handle mknod path:<%s>, mode:%o in kern_path_create with ret:%ld\n", req->path, req->mode, PTR_ERR(dent));
		return sizeof(struct qtrsp_mknod);
	}

	if (!IS_POSIXACL(path.dentry->d_inode))
		req->mode &= ~current_umask();
	error = security_path_mknod(&path, dent, req->mode, req->dev);
	if (!error)
		error = vfs_mknod(path.dentry->d_inode, dent, req->mode, req->dev);
	done_path_create(&path, dent);
	if (error == -ESTALE && !(flags & LOOKUP_REVAL)) {
		flags |= LOOKUP_REVAL;
		qtfs_debug("retry mknod.\n");
		rsp->errno = error;
		goto retry;
	}
	qtfs_inode_info_fill(&rsp->inode_info, dent->d_inode);
	rsp->ret = QTFS_OK;
	qtfs_info("handle mknod path:<%s>, mode:%o success\n", req->path, req->mode);
	rsp->errno = 0;
	return sizeof(struct qtrsp_mknod);
}

int handle_unlink(struct qtserver_arg *arg)
{
	struct qtreq_unlink *req = (struct qtreq_unlink *)REQ(arg);
	struct qtrsp_unlink *rsp = (struct qtrsp_unlink *)RSP(arg);

	rsp->errno = qtfs_kern_syms.do_unlinkat(AT_FDCWD, qtfs_kern_syms.getname_kernel(req->path));
	if (rsp->errno < 0) {
		qtfs_err("handle unlink failed, errno:%d\n", rsp->errno);
	} else {
		qtfs_info("handle unlink path:%s success\n", req->path);
	}
	return sizeof(struct qtrsp_unlink);
}

int handle_link(struct qtserver_arg *arg)
{
	char *oldname, *newname;
	struct qtreq_link *req = (struct qtreq_link *)REQ(arg);
	struct qtrsp_link *rsp = (struct qtrsp_link *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	oldname = req->path;
	newname = req->path + req->d.oldlen;
	if (copy_to_user(userp->userp, oldname, strlen(oldname) + 1) ||
		copy_to_user(userp->userp2, newname, strlen(newname) + 1)) {
		qtfs_err("handle link failed in copy to userp.\n");
		rsp->errno = -EFAULT;
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_link);
	}

	rsp->errno = qtfs_kern_syms.do_linkat(AT_FDCWD, userp->userp, AT_FDCWD, userp->userp2, 0);
	qtfs_info("handle link new:%s old:%s return %d\n", newname, oldname, rsp->errno);
	rsp->ret = rsp->errno == 0 ? QTFS_OK : QTFS_ERR;
	return sizeof(struct qtrsp_link);
}

int handle_symlink(struct qtserver_arg *arg)
{
	char *oldname, *newname;
	struct qtreq_symlink *req = (struct qtreq_symlink *)REQ(arg);
	struct qtrsp_symlink *rsp = (struct qtrsp_symlink *)RSP(arg);
	int error;
	struct dentry *dentry;
	struct path path;
	unsigned int lookup_flags = 0;

	newname = req->path;
	oldname = &req->path[req->d.newlen];
retry:
	dentry = kern_path_create(AT_FDCWD, newname, &path, lookup_flags);
	error = PTR_ERR(dentry);
	if (err_ptr(dentry)) {
		rsp->ret = QTFS_ERR;
		qtfs_err("handle_symlink: newname(%s), oldname(%s) in kern_path_create %d\n", newname, oldname, error);
		return sizeof(struct qtrsp_symlink);
	}

	rsp->errno = vfs_symlink(path.dentry->d_inode, dentry, oldname);
	done_path_create(&path, dentry);
	if (rsp->errno == -ESTALE && !(lookup_flags & LOOKUP_REVAL)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	rsp->ret = QTFS_OK;
	qtfs_info("handle_symlink: newname(%s), oldname(%s) success\n", newname, oldname);
	qtfs_inode_info_fill(&rsp->inode_info, dentry->d_inode);
	return sizeof(struct qtrsp_symlink);
}

int handle_getlink(struct qtserver_arg *arg)
{
	struct qtreq_getlink *req = (struct qtreq_getlink *)REQ(arg);
	struct qtrsp_getlink *rsp = (struct qtrsp_getlink *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	if (copy_to_user(userp->userp, req->path, strlen(req->path) + 1) ||
		copy_to_user(userp->userp2, rsp->path, (userp->size < MAX_PATH_LEN) ? userp->size : MAX_PATH_LEN)) {
		qtfs_err("handle getlink<%s> copy to userp failed.\n", req->path);
		rsp->errno = -EFAULT;
		goto err_handle;
	}
	rsp->errno = qtfs_kern_syms.do_readlinkat(AT_FDCWD, userp->userp, userp->userp2, userp->size);
	if (rsp->errno < 0) {
		qtfs_err("handle getlink<%s> do readlinkat failed, errno:%d\n", req->path, rsp->errno);
		goto err_handle;
	}
	if (copy_from_user(rsp->path, userp->userp2, rsp->errno)) {
		qtfs_err("handle getlink<%s> copy from user failed, len:%d.", req->path, rsp->errno);
		rsp->errno = -EFAULT;
		goto err_handle;
	}
	rsp->ret = QTFS_OK;
	qtfs_info("handle getlink<%s> ok, len:%d link:%s.", req->path, rsp->errno, rsp->path);
	return sizeof(struct qtrsp_getlink) - sizeof(rsp->path) + strlen(rsp->path) + 1;

err_handle:
	rsp->ret = QTFS_ERR;
	return sizeof(struct qtrsp_getlink) - sizeof(rsp->path);
}

int handle_rename(struct qtserver_arg *arg)
{
	struct qtreq_rename *req = (struct qtreq_rename *)REQ(arg);
	struct qtrsp_rename *rsp = (struct qtrsp_rename *)RSP(arg);
	struct qtfs_server_userp_s *userp = (struct qtfs_server_userp_s *)USERP(arg);

	if (copy_to_user(userp->userp, req->path, strlen(req->path) + 1) ||
		copy_to_user(userp->userp2, &req->path[req->d.oldlen], strlen(&req->path[req->d.oldlen]) + 1)) {
		qtfs_err("handle rename copy to userp failed.\n");
		rsp->errno = -EFAULT;
		goto err_handle;
	}
	rsp->errno = qtfs_kern_syms.do_renameat2(AT_FDCWD, userp->userp, AT_FDCWD, userp->userp2, 0);

err_handle:
	rsp->ret = (rsp->errno < 0) ? QTFS_ERR : QTFS_OK;
	qtfs_info("handle rename oldname:%s newname:%s ret:%d %s", req->path, &req->path[req->d.oldlen], rsp->errno,
			(rsp->errno < 0) ? "failed" : "successed");
	return sizeof(struct qtrsp_rename);
}

int handle_xattrlist(struct qtserver_arg *arg)
{
	struct qtreq_xattrlist *req = (struct qtreq_xattrlist *)REQ(arg);
	struct qtrsp_xattrlist *rsp = (struct qtrsp_xattrlist *)RSP(arg);
	struct path path;
	int ret;
	ssize_t size;
	int i;

	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle xattr list path error.\n");
		rsp->d.errno = -ENOENT;
		goto err_handle;
	}
	size = generic_listxattr(path.dentry, rsp->name, sizeof(rsp->name));
	path_put(&path);
	if (size < 0) {
		qtfs_err("handle list xattr failed, errno:%ld.\n", size);
		rsp->d.errno = size;
		goto err_handle;
	}
	if (size == 0)
		goto err_handle;
	rsp->d.ret = QTFS_OK;
	rsp->d.result = true;
	while (i < size) {
		qtfs_info("handle list xattr result:%s\n", &rsp->name[i]);
		i += strlen(&rsp->name[i]) + 1;
	}
	return sizeof(struct qtrsp_xattrlist);

err_handle:
	rsp->d.ret = QTFS_ERR;
	rsp->d.result = false;
	return sizeof(struct qtrsp_xattrlist);
}

int handle_xattrget(struct qtserver_arg *arg)
{
	struct qtreq_xattrget *req = (struct qtreq_xattrget *)REQ(arg);
	struct qtrsp_xattrget *rsp = (struct qtrsp_xattrget *)RSP(arg);
	struct path path;
	int ret = 0;
	ssize_t error = 0;
	int len = 0;
	char *kvalue = NULL;

	ret = kern_path(req->path, 0, &path);
	if (ret) {
		qtfs_err("handle xattrget path error.\n");
		rsp->d.errno = -ENOENT;
		goto err_handle;
	}

	if (req->d.size > XATTR_SIZE_MAX)
		req->d.size = XATTR_SIZE_MAX;
	kvalue = (char *)kvzalloc(req->d.size, GFP_KERNEL);
	if (!kvalue) {
		qtfs_err("handle xattrget kvzalloc failed, size:%d.\n", req->d.size);
		rsp->d.ret = QTFS_ERR;
		rsp->d.errno = -ENOMEM;
		path_put(&path);
		goto err_handle;
	}

	error = vfs_getxattr(path.dentry, req->d.prefix_name, kvalue, req->d.size);
	path_put(&path);
	if (error > 0) {
		if (req->d.pos >= error) {
			rsp->d.size = 0;
			rsp->d.pos = req->d.pos;
			goto end;
		}
		qtfs_info("handle getxattr: path:%s prefix name:%s : (%s - 0x%llx), size:%ld, reqpos:%d\n", req->path, req->d.prefix_name, kvalue, (__u64)kvalue, error, req->d.pos);
		len = (error - req->d.pos)>sizeof(rsp->buf)? sizeof(rsp->buf):(error - req->d.pos);
		memcpy(rsp->buf, &kvalue[req->d.pos], len);
		rsp->d.pos = req->d.pos + len;
		rsp->d.size = len;
	} else {
		rsp->d.ret = QTFS_ERR;
		rsp->d.errno = error;
		kvfree(kvalue);
		goto err_handle;
	}
end:
	kvfree(kvalue);
	rsp->d.ret = QTFS_OK;
	return sizeof(struct qtrsp_xattrget) - sizeof(rsp->buf) + len;

err_handle:
	return sizeof(struct qtrsp_xattrget) - sizeof(rsp->buf);
}

int handle_xattrset(struct qtserver_arg *arg)
{
	return 0;
}

long qtfs_do_mount(const char *dev_name, const char *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	struct path path;
	int ret;

	ret = kern_path(dir_name, LOOKUP_FOLLOW, &path);
	if (ret) {
		qtfs_err("qtfs do mount failed, ret:%d\n", ret);
		return ret;
	}
	qtfs_info("handle path mount: dev(%s), dir(%s), type(%s), flags(0x%lx), data(%s)", dev_name, dir_name, type_page, flags, (char *)data_page);
	ret = qtfs_kern_syms.path_mount(dev_name, &path, type_page, flags, data_page);
	path_put(&path);
	return ret;
}

int handle_syscall_mount(struct qtserver_arg *arg)
{
	struct qtreq_sysmount *req = (struct qtreq_sysmount *)REQ(arg);
	struct qtrsp_sysmount *rsp = (struct qtrsp_sysmount *)RSP(arg);
	char *dev_name, *dir_name, *type;
	void *data_page;

	dev_name = req->d.dev_len == 0 ? NULL : req->buf;
	dir_name = &req->buf[req->d.dev_len];
	type = req->d.type_len == 0 ? NULL : &req->buf[req->d.dev_len + req->d.dir_len];
	if (req->d.data_len != 0)
		data_page = &req->buf[req->d.dev_len + req->d.dir_len + req->d.type_len];
	else
		data_page = NULL;

	qtfs_info("handle syscall mount devname:%s dirname:%s type:%s data:%s\n", dev_name, dir_name, type,
			(data_page == NULL) ? "nil" : (char *)data_page);
	rsp->errno = qtfs_do_mount(dev_name, dir_name, type, req->d.flags, data_page);
	if (rsp->errno < 0)
		qtfs_err("handle syscall mount failed devname:%s dirname:%s type:%s data:%s, errno:%d\n",
				dev_name, dir_name, type, (char *)data_page, rsp->errno);

	return sizeof(struct qtrsp_sysmount);
}

int handle_syscall_umount(struct qtserver_arg *arg)
{
	struct qtreq_sysumount *req = (struct qtreq_sysumount *)REQ(arg);
	struct qtrsp_sysumount *rsp = (struct qtrsp_sysumount *)RSP(arg);
	int lookup_flags = LOOKUP_MOUNTPOINT;
	struct path path;
	int ret;

	qtfs_info("handle umount path:%s\n", req->buf);
	// basic validity checks done first
	if (req->flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW)) {
		qtfs_err("handle syscall umount flags error:%x", req->flags);
		rsp->errno = -EINVAL;
		return sizeof(struct qtrsp_sysumount);
	}

	if (!(req->flags & UMOUNT_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	ret = kern_path(req->buf, lookup_flags, &path);
	if (ret) {
		qtfs_err("umount(%s) failed, ret:%d\n", req->buf, ret);
		rsp->errno = ret;
		return sizeof(struct qtrsp_sysumount);
	}
	rsp->errno = qtfs_kern_syms.path_umount(&path, req->flags);
	if (rsp->errno)
		qtfs_err("umount(%s) failed, errno:%d\n", req->buf, rsp->errno);
	//dont need to path_put here.
	return sizeof(struct qtrsp_sysumount);
}

int handle_fifopoll(struct qtserver_arg *arg)
{
	struct qtreq_poll *req = (struct qtreq_poll *)REQ(arg);
	struct qtrsp_poll *rsp = (struct qtrsp_poll *)RSP(arg);
	struct file *filp = NULL;
	unsigned int head, tail;
	struct pipe_inode_info *pipe;
	__poll_t mask;

	filp = (struct file *)req->file;
	pipe = filp->private_data;
	if (pipe == NULL) {
		qtfs_err("file :%s pipe data is NULL.", filp->f_path.dentry->d_iname);
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_poll);
	}
	head = READ_ONCE(pipe->head);
	tail = READ_ONCE(pipe->tail);
	mask = 0;
	if (filp->f_mode & FMODE_READ) {
		if (!pipe_empty(head, tail))
			mask |= EPOLLIN | EPOLLRDNORM;
		if (!pipe->writers && filp->f_version != pipe->w_counter)
			mask |= EPOLLHUP;
	}

	if (filp->f_mode & FMODE_WRITE) {
		if (!pipe_full(head, tail, pipe->max_usage))
			mask |= EPOLLOUT | EPOLLWRNORM;
		if (!pipe->readers)
			mask |= EPOLLERR;
	}
	rsp->mask = mask;
	rsp->ret = QTFS_OK;

	qtfs_info("handle fifo poll f_mode:%o: %s get poll 0x%x\n", filp->f_mode, filp->f_path.dentry->d_iname, rsp->ret);
	return sizeof(struct qtrsp_poll);
}

int handle_epollctl(struct qtserver_arg *arg)
{
	struct qtreq_epollctl *req = (struct qtreq_epollctl *)REQ(arg);
	struct qtrsp_epollctl *rsp = (struct qtrsp_epollctl *)RSP(arg);
	int ret;
	struct epoll_event evt;

	evt.data = (__u64)req->event.data;
	evt.events = req->event.events;
	ret = qtfs_kern_syms.do_epoll_ctl(qtfs_epoll.epfd, req->op, req->fd, &evt, false);
	if (ret < 0) {
		qtfs_err("handle do epoll ctl failed, ret:%d.", ret);
		rsp->ret = QTFS_ERR;
		return sizeof(struct qtrsp_epollctl);
	}
	qtinfo_cntinc((req->op == EPOLL_CTL_ADD) ? QTINF_EPOLL_ADDFDS : QTINF_EPOLL_DELFDS);
	rsp->ret = QTFS_OK;
	qtfs_info("handle do epoll ctl success, fd:%d file:%lx op:%x data:%lx poll_t:%x.",
			req->fd, (unsigned long)req->file, req->op, req->event.data, (unsigned)req->event.events);

	return sizeof(struct qtrsp_epollctl);
}

int handle_exit(struct qtserver_arg *arg)
{
	return 4;
}

int handle_null(struct qtserver_arg *arg)
{
	qtfs_err("unknown events.");
	return 4;
}

static struct qtserver_ops qtfs_server_handles[] = {
	{QTFS_REQ_NULL,			handle_null,		"null"},
	{QTFS_REQ_MOUNT,		handle_mount,		"mount"},
	{QTFS_REQ_OPEN,			handle_open,		"open"},
	{QTFS_REQ_CLOSE,		handle_close,		"close"},
	{QTFS_REQ_READ,			handle_null,		"read"},
	{QTFS_REQ_READITER,		handle_readiter,	"readiter"},
	{QTFS_REQ_WRITE,		handle_write,		"write"},
	{QTFS_REQ_LOOKUP,		handle_lookup,		"lookup"},
	{QTFS_REQ_READDIR,		handle_readdir,		"readdir"},
	{QTFS_REQ_MKDIR,		handle_mkdir,		"mkdir"},
	{QTFS_REQ_RMDIR,		handle_rmdir,		"rmdir"},
	{QTFS_REQ_GETATTR,		handle_getattr,		"getattr"},
	{QTFS_REQ_SETATTR,		handle_setattr,		"setattr"},
	{QTFS_REQ_ICREATE,		handle_icreate,		"icreate"},
	{QTFS_REQ_MKNOD,		handle_mknod,		"mknod"},
	{QTFS_REQ_UNLINK,		handle_unlink,		"unlink"},
	{QTFS_REQ_SYMLINK,		handle_symlink,		"symlink"},
	{QTFS_REQ_LINK,			handle_link,		"link"},
	{QTFS_REQ_GETLINK,		handle_getlink,		"getlink"},
	{QTFS_REQ_READLINK,		handle_null,		"readlink"},
	{QTFS_REQ_RENAME,		handle_rename,		"rename"},

	{QTFS_REQ_XATTRLIST,	handle_xattrlist,	"xattrlist"},
	{QTFS_REQ_XATTRGET,		handle_xattrget,	"xattrget"},
	{QTFS_REQ_XATTRSET,		handle_xattrset,	"xattrset"},

	{QTFS_REQ_SYSMOUNT,		handle_syscall_mount,	"sysmount"},
	{QTFS_REQ_SYSUMOUNT,	handle_syscall_umount,	"sysumount"},
	{QTFS_REQ_FIFOPOLL,		handle_fifopoll,		"fifo_poll"},

	{QTFS_REQ_STATFS,		handle_statfs,		"statfs"},
	{QTFS_REQ_IOCTL,		handle_ioctl,		"ioctl"},

	{QTFS_REQ_EPOLL_CTL,	handle_epollctl,	"epollctl"},
	{QTFS_REQ_EPOLL_EVENT,	NULL,			"epollevent"},

	{QTFS_REQ_EXIT,			handle_exit,	"exit"}, // keep this handle at the end
};

int qtfs_sock_server_run(struct qtfs_sock_var_s *pvar)
{
	int ret;
	struct qtreq *req;
	struct qtreq *rsp;
	unsigned long totalproc = 0;

	req = pvar->vec_recv.iov_base;
	rsp = pvar->vec_send.iov_base;
	do {
		ret = qtfs_conn_recv_block(QTFS_CONN_SOCKET, pvar);
		if (ret == -EPIPE) {
			qtfs_err("qtfs server thread recv EPIPE, restart the connection.");
			qtfs_sm_reconnect(pvar);
			break;
		}
		if (ret < 0)
			break;
		pvar->recv_valid = ret + 1;
		if (req->type >= QTFS_REQ_INV) {
			qtfs_err("qtfs server recv unknown operate type:%d\n", req->type);
			rsp->type = req->type;
			rsp->len = 0;
			rsp->err = QTFS_ERR;
		} else {
			struct qtserver_arg arg;
			arg.data = req->data;
			arg.out = rsp->data;
			arg.userp = &qtfs_userps[pvar->cur_threadidx];
			if (arg.userp->userp == NULL || arg.userp->userp2 == NULL)
				qtfs_err("server run userp:%lx userp2:%lx", (unsigned long)arg.userp->userp, (unsigned long)arg.userp->userp2);
			rsp->len = qtfs_server_handles[req->type].handle(&arg);
			rsp->type = req->type;
			rsp->err = QTFS_OK;
			totalproc++;
			qtinfo_recvinc(req->type);
		}
		if (rsp->len > QTFS_REQ_MAX_LEN) {
			qtfs_err("handle rsp len error type:%d len:%lu", rsp->type, rsp->len);
			WARN_ON(1);
			continue;
		}
		rsp->seq_num = req->seq_num;
		pvar->vec_send.iov_len = QTFS_MSG_LEN - QTFS_REQ_MAX_LEN + rsp->len;
		pvar->send_valid = pvar->vec_send.iov_len + 1;
		qtfs_debug("Server thread:%d count:%lu recv len:%d type:%d(%s) seq_num:%lu, reqlen:%lu, resp len:%lu, rsp threadidx:%d.\n",
				pvar->cur_threadidx, totalproc, ret, req->type, qtfs_server_handles[req->type].str, req->seq_num,
				req->len, pvar->vec_send.iov_len, pvar->cur_threadidx);
		ret = qtfs_conn_send(QTFS_CONN_SOCKET, pvar);
		if (ret == -EPIPE) {
			qtfs_err("qtfs server send get EPIPE, just restart the connection\n");
			qtfs_sm_reconnect(pvar);
			break;
		}
		if (ret < 0) {
			qtfs_err("conn send failed, ret:%d\n", ret);
			WARN_ON(1);
		}
		qtinfo_sendinc(rsp->type);
	} while(0);

	qtfs_sock_msg_clear(pvar);
	return (ret < 0) ? QTERROR : QTOK;
}
