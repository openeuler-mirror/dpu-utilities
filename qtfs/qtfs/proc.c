#include <linux/time.h>
#include <linux/fs_struct.h>

#include "conn.h"
#include "qtfs-mod.h"
#include "req.h"
#include "log.h"
#include "ops.h"

struct dentry *qtfs_proc_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags);
const char *qtfs_proc_getlink(struct dentry *dentry, struct inode *inode, struct delayed_call *done);
int qtfs_proc_getattr(const struct path *path, struct kstat *stat, u32 req_mask, unsigned int flags);

enum qtfs_type qtfs_get_type(char *str)
{
	if (str && !strcmp(str, "proc"))
		return QTFS_PROC;
	return QTFS_NORMAL;
}

bool is_sb_proc(struct super_block *sb)
{
	struct qtfs_fs_info *qfi = sb->s_fs_info;

	return qfi->type == QTFS_PROC;
}

const char *match_str[] = {
	"bash",
	"isula",
	"isulad",
	"isulad-real",
	"kubelet",
	"kubelet-real",
	"dockerd",
	"dockerd-real",
	"containerd",
	"containerd-real"
};

int is_local_process(const char *path)
{
	int pid = -1;
	char cmdline[TASK_COMM_LEN];
	char *pos = NULL;
	struct task_struct *t = NULL;
	int i = 0;

	sscanf(path, "/proc/%d", &pid);
	if (pid <= 0)
		return -1;

	t = qtfs_kern_syms.find_get_task_by_vpid((pid_t)pid);
	if (!t) {
		qtfs_info("[is_local_process] Failed to get task_struct from pid(%d)", pid);
		return -1;
	}
	get_task_comm(cmdline, t);

	pos = strrchr(cmdline, '/');
	if (!pos) {
		pos = cmdline;
	} else {
		pos++;
	}

	for (i = 0; i < sizeof(match_str)/sizeof(char *); i++) {
		if (!strncmp(pos, match_str[i], NAME_MAX)) {
			qtfs_debug("[is_local_process] cmdline: %s is local process %d\n", cmdline, pid);
			return pid;
		}
	}

	qtfs_debug("[is_local_process] cmdline: %s is not local process", cmdline);
	return -1;
}

struct inode_operations qtfs_proc_inode_ops = {
	.lookup = qtfs_proc_lookup,
	.getattr = qtfs_proc_getattr,
};

struct inode_operations qtfs_proc_sym_ops = {
	.get_link = qtfs_proc_getlink,
	.getattr = qtfs_proc_getattr,
};

struct dentry *qtfs_proc_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
	char cpath[NAME_MAX] = {0};
	char local_path[NAME_MAX] = {0};
	char tmp[NAME_MAX] = {0};
	struct path spath;
	struct dentry *d = NULL;
	struct inode_info ii;
	struct inode *inode = NULL;
	int ret = 0;
	int pid = -1;

	if (qtfs_fullname(cpath, child_dentry) < 0) {
		qtfs_err("%s: failed to get fullname", __func__);
		goto remote;
	}

	pid = is_local_process(cpath);
	if (pid > 0) {
		sscanf(cpath, "/proc/%s", tmp);
		sprintf(local_path, "/test_proc/%s", tmp);
		qtfs_debug("[%s]: get path:%s from local: %s\n", __func__, cpath, local_path);
		ret = kern_path(local_path, 0, &spath);
		if(ret) {
			qtfs_err("[%s]: kern_path(%s) failed: %d\n", __func__, local_path, ret);
			goto remote;
		}

		ii.mode = spath.dentry->d_inode->i_mode;
		ii.mode = (ii.mode & ~(S_IFMT)) | S_IFLNK;
		ii.i_size = spath.dentry->d_inode->i_size;
		ii.i_ino = spath.dentry->d_inode->i_ino;
		ii.atime = spath.dentry->d_inode->i_atime;
		ii.mtime = spath.dentry->d_inode->i_mtime;
		ii.ctime = spath.dentry->d_inode->i_ctime;
		path_put(&spath);

		inode = qtfs_iget(parent_inode->i_sb, &ii);
		if (inode == NULL) {
			qtfs_err("%s: failed to get inode for %s:%s", __func__, cpath, local_path);
			return ERR_PTR(-ENOMEM);
		}
		d = d_splice_alias(inode, child_dentry);
		return d;
	}

remote:
	return qtfs_lookup(parent_inode, child_dentry, flags);
}

const char *qtfs_proc_getlink(struct dentry *dentry,
					struct inode *inode, struct delayed_call *done)
{
	char path[NAME_MAX] = {0};
	char tmp[NAME_MAX] = {0};
	char *link;
	int pid = -1;

	link = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
	if (!link) {
		qtfs_err("[%s]: failed to alloc memory", __func__);
		goto remote;
	}
	memset(link, 0, MAX_PATH_LEN);

	if (qtfs_fullname(path, dentry) < 0) {
		qtfs_info("[%s]: get path failed", __func__);
		goto link_remote;
	}

	if (!strncmp(path, "/proc/self", 11)) {
		sprintf(link, "/test_proc/%d", (int)current->pid);
		qtfs_info("[%s] success: %s getlink: %s", __func__, path, link);
		return link;
	}

	if (!strcmp(path, "/proc/mounts")) {
		sprintf(link, "/proc/1/mounts");
		qtfs_info("[%s] success: %s getlink /proc/1/mounts", __func__, path);
		return link;
	}

	pid = is_local_process(path);
	if (pid > 0) {
		sscanf(path, "/proc/%s", tmp);
		sprintf(link, "/test_proc/%s", tmp);
		qtfs_info("[%s] success: %s getlink: %s", __func__, path, link);
		return link;
	}

link_remote:
	kfree(link);
remote:
	return qtfs_getlink(dentry, inode, done);
}

int qtfs_proc_getattr(const struct path *path, struct kstat *stat, u32 req_mask, unsigned int flags)
{
	char cpath[NAME_MAX] = {0};
	char tmp[NAME_MAX] = {0};
	char local_path[NAME_MAX] = {0};
	struct path spath;
	int ret = 0;
	int pid = -1;

	if (qtfs_fullname(cpath, path->dentry) < 0) {
		qtfs_err("%s: failed to get fullname", __func__);
		goto remote;
	}

	pid = is_local_process(cpath);
	if (pid > 0) {
		sscanf(cpath, "/proc/%s", tmp);
		sprintf(local_path, "/test_proc/%s", tmp);
		ret = kern_path(local_path, 0, &spath);
		if (ret) {
			qtfs_err("[%s]: kern_path(%s) failed: %d", __func__, local_path, ret);
			goto remote;
		}

		ret = vfs_getattr(&spath, stat, req_mask, flags);
		path_put(&spath);
		if (ret) {
			qtfs_err("[%s]: vfs_getattr %s failed: %d", __func__, local_path, ret);
			goto remote;
		}
		qtfs_debug("[%s]: %s success", __func__, local_path);
		stat->mode = (stat->mode & ~(S_IFMT)) | S_IFLNK;
		return 0;
	}

remote:
	return qtfs_getattr(path, stat, req_mask, flags);
}
