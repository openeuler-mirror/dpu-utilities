#include <linux/compiler_types.h>
#include <asm/syscall_wrapper.h>
#include <linux/syscalls.h>
#include <linux/trace_events.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/eventpoll.h>

#include "conn.h"
#include "qtfs-mod.h"


static long qtfs_remote_mount(char __user *dev_name, char __user *dir_name, char __user *type,
		unsigned long flags, void __user *data);
static int qtfs_remote_umount(char __user *name, int flags);

#ifdef __aarch64__
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern unsigned long kallsyms_lookup_name(const char *name);
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata, end_rodata;
#define section_size  (end_rodata - start_rodata)
#endif

static char *qtfs_copy_mount_string(const void __user *data)
{
	return data ? strndup_user(data, PATH_MAX) : NULL;
}

static void *qtfs_copy_mount_options(const void __user *data)
{
	char *copy;
	unsigned left, offset;

	if (!data)
		return NULL;

	copy = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!copy)
		return ERR_PTR(-ENOMEM);
	left = copy_from_user(copy, data, PAGE_SIZE);
	/*
	 * Not all architectures have an exact copy_from_user, Resort to
	 * byte at a time.
	 */
	offset = PAGE_SIZE - left;
	while (left) {
		char c;
		if (get_user(c, (const char __user *)data + offset))
			break;
		copy[offset] = c;
		left--;
		offset++;
	}

	if (left == PAGE_SIZE) {
		kfree(copy);
		return ERR_PTR(-EFAULT);
	}
	return copy;
}

static inline int qtfs_fstype_judgment(char __user *dir)
{
	struct path path;
	int ret;

	ret = user_path_at(AT_FDCWD, dir, LOOKUP_FOLLOW, &path);
	if (ret)
		return 0;

	if (strcmp(path.mnt->mnt_sb->s_type->name, QTFS_FSTYPE_NAME) == 0) {
		qtfs_info("qtfs fstype judge <%s> is qtfs.\n", path.dentry->d_iname);
		path_put(&path);
		return 1;
	}
	path_put(&path);

	return 0;
}

/* if this dir is root node of qtfs */
static inline int qtfs_root_judgment(char __user *dir)
{
	struct dentry *dentry;
	struct path path;
	int ret = 0;

	ret = user_path_at(AT_FDCWD, dir, LOOKUP_FOLLOW, &path);
	if (ret)
		return 0;

	dentry = path.dentry;
	if (dentry->d_parent == dentry)
		ret = 1;
	path_put(&path);

	return ret;
}

static void do_epoll_ctl_remote(int op, struct epoll_event __user *event, struct file *file)
{
	struct qtreq_epollctl *req;
	struct qtrsp_epollctl *rsp;
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct private_data *priv = file->private_data;
	struct epoll_event tmp;

	if (pvar == NULL) {
		qtfs_err("qtfs do epoll ctl remote get pvar failed.");
		return;
	}
	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	req->fd = priv->fd;
	req->file = priv->file;
	req->op = op;
	if (ep_op_has_event(op) && copy_from_user(&tmp, event, sizeof(struct epoll_event))) {
		qtfs_err("qtfs do epoll ctl remote copy from user failed.");
		qtfs_conn_put_param(pvar);
		return;
	}
	req->event.events = tmp.events;
	req->event.data = (__u64)file;
	rsp = qtfs_remote_run(pvar, QTFS_REQ_EPOLL_CTL, sizeof(struct qtreq_epollctl));
	if (rsp == NULL || IS_ERR(rsp) || rsp->ret == QTFS_ERR) {
		qtfs_err("qtfs do epoll ctl remote failed.");
		qtfs_conn_put_param(pvar);
		qtinfo_cntinc(QTINF_EPOLL_FDERR);
		return;
	}
	if (op == EPOLL_CTL_ADD) {
		qtinfo_cntinc(QTINF_EPOLL_ADDFDS);
	} else {
		qtinfo_cntinc(QTINF_EPOLL_DELFDS);
	}
	qtfs_info("qtfs do epoll ctl remote success, fd:%d file:%lx.", req->fd, (unsigned long)req->file);
	qtfs_conn_put_param(pvar);
	return;
}

int qtfs_epoll_ctl_remote(int op, int fd, struct epoll_event __user * event)
{
	struct fd f;
	struct file *file;
	struct private_data *priv;
	int ret = 0;
	f = fdget(fd);
	if (!f.file) {
		// qtfs_err("epoll ctl remote fd:%d file error.", fd);
		return -1;
	}
	file = f.file;
	if (strcmp(file->f_path.mnt->mnt_sb->s_type->name, QTFS_FSTYPE_NAME) != 0) {
		ret = 0;
		goto end;
	}
	if (!S_ISFIFO(file->f_inode->i_mode)) {
		char *fullname = (char *)kmalloc(MAX_PATH_LEN, GFP_KERNEL);
		memset(fullname, 0, MAX_PATH_LEN);
		if (qtfs_fullname(fullname, file->f_path.dentry) < 0) {
			qtfs_err("qtfs fullname failed\n");
			kfree(fullname);
			ret = -1;
			goto end;
		}
		qtfs_info("qtfs remote epoll not support file:%s mode:%o.", fullname, file->f_inode->i_mode);
		kfree(fullname);
		ret = -1;
		goto end;
	}

	priv = file->private_data;
	if (priv == NULL) {
		qtfs_err("epoll ctl remote failed, private data invalid.");
		ret = -1;
		goto end;
	}

	qtfs_info("qtfs qtfs remote epoll file:%s mode:%x.", file->f_path.dentry->d_iname, file->f_inode->i_mode);
	do_epoll_ctl_remote(op, event, file);

end:
	fdput(f);
	return ret;
}

__SYSCALL_DEFINEx(4, _qtfs_epoll_ctl, int, epfd, int, op, int, fd,
	struct epoll_event __user *, event)
{
	struct epoll_event epds;
	int ret = -1;

	ret = qtfs_epoll_ctl_remote(op, fd, event);
	if (ep_op_has_event(op) &&
			copy_from_user(&epds, event, sizeof(struct epoll_event)))
		return -EFAULT;
	if (!ret) {
		return qtfs_kern_syms.do_epoll_ctl(epfd, op, fd, &epds, false);
	} else {
		return -1;
	}
}

__SYSCALL_DEFINEx(5, _qtfs_mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	char *kernel_dev;
	void *options = NULL;

	// if both dev_name and dir_name are qtfs, it is a remote mount operator.
	kernel_type = qtfs_copy_mount_string(type);
	ret = PTR_ERR(kernel_type);
	if (IS_ERR(kernel_type))
		goto out_type;

	kernel_dev = qtfs_copy_mount_string(dev_name);
	ret = PTR_ERR(kernel_dev);
	if (IS_ERR(kernel_dev))
		goto out_dev;

	options = qtfs_copy_mount_options(data);
	ret = PTR_ERR(options);
	if (IS_ERR(options))
		goto out_data;

	// if both dev_name and dir_name are qtfs, it is a remote mount operator,
	if (qtfs_fstype_judgment(dir_name) == 1) {
		ret = qtfs_remote_mount(kernel_dev, dir_name, kernel_type, flags, options);
		goto remote_mount;
	}

	ret = qtfs_kern_syms.do_mount(kernel_dev, dir_name, kernel_type, flags, options);

remote_mount:
	kfree(options);
out_data:
	kfree(kernel_dev);
out_dev:
	kfree(kernel_type);
out_type:
	return ret;
}

__SYSCALL_DEFINEx(2, _qtfs_umount, char __user *, name, int, flags)
{
	int lookup_flags = LOOKUP_MOUNTPOINT;
	struct path path;
	int ret;

	// basic validate checks done first
	if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
		return -EINVAL;

	/* if umount path is qtfs and not qtfs root, then do remote umount */
	if (qtfs_fstype_judgment(name) && !qtfs_root_judgment(name)) {
		return qtfs_remote_umount(name, flags);
	}

	if (!(flags & UMOUNT_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	ret = user_path_at(AT_FDCWD, name, lookup_flags, &path);
	if (ret)
		return ret;
	return qtfs_kern_syms.path_umount(&path, flags);
}

// make the page writable
int make_rw(unsigned long address)
{
#ifdef __x86_64__
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte |= _PAGE_RW;
#endif
#ifdef __aarch64__
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL);
#endif

	return 0;
}
// make the page write protected
int make_ro(unsigned long address)
{
#ifdef __x86_64__
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte &= ~_PAGE_RW;
#endif

#ifdef __aarch64__
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL_RO);
#endif
	return 0;
}

int qtfs_dir_to_qtdir(char *dir, char *qtdir)
{
	int ret;
	struct path path;
	ret = kern_path(dir, LOOKUP_FOLLOW, &path);
	if (ret) {
		qtfs_err("qtfs dir to qtdir failed, ret: %d\n", ret);
		return ret;
	}

	ret = qtfs_fullname(qtdir, path.dentry);
	path_put(&path);
	return ret;
}

int qtfs_parse_data(void *data, void *newc)
{
	char *options = data, *key;
	int ret = 0;
	char *newchar = (char *)newc;
	char *lowers;
	int firstkey = 0;

	if (!options)
		return 0;

	while ((key = strsep(&options, ",")) != NULL) {
		if (*key) {
			size_t v_len = 0;
			char *value = strchr(key, '=');

			if (value) {
				if (value == key)
					continue;
				*value++ = 0;
				v_len = strlen(value);
			}
			if (firstkey != 0)
				strcat(newchar, ",");
			firstkey++;

			qtfs_info("qtfs parse mount data: key:%s value:%s v_len:%ld\n", key, value, v_len);
			if (strcmp(key, "lowerdir") == 0) {
				int firstlower = 0;
				strcat(newchar, "lowerdir=");
				while ((lowers = strsep(&value, ":")) != NULL) {
					if (*lowers) {
						if (firstlower != 0)
							strcat(newchar, ":");
						firstlower++;
						qtfs_dir_to_qtdir(lowers, &newchar[strlen(newchar)]);
					}
				}
			} else {
				strcat(newchar, key);
				strcat(newchar, "=");
				qtfs_dir_to_qtdir(value, &newchar[strlen(newchar)]);
			}
		}
	}
	qtfs_info("qtfs parse mount data result:%s\n", newchar);

	return ret;
}

/*
 * overlay -o format: lowerdir=/xxx/overlay/lower:/xx/xx,upperdir=
 *			/xx/overlay/upper,workdir=/xxx/overlay/work
 */
static inline void *qtfs_mount_data_overlay(void *data)
{
	void *mod;
	int len;
	len = strlen((char *)data);
	mod = (void *)kmalloc(len + 1, GFP_KERNEL);
	if (mod == NULL) {
		qtfs_err("kmalloc failed.\n");
		return (void *)-ENOMEM;
	}
	memset(mod, 0, len+1);
	qtfs_parse_data(data, mod);
	memset(data, 0, len);
	strcpy(data, mod);

	kfree(mod);
	return data;
}

static inline void *qtfs_mount_datapage_modify(char *type, void *data)
{
	if (type != NULL && strcmp(type, "overlay") == 0) {
		return qtfs_mount_data_overlay(data);
	}
	return data;
}

static long qtfs_remote_mount(char *dev_name, char __user *dir_name, char *type,
		unsigned long flags, void *data)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_sysmount *req;
	struct qtrsp_sysmount *rsp;
	char *kernel_dir;
	int ret;
	int totallen;

	if (!pvar) {
		qtfs_err("Failed to get qtfs sock var\n");
		return -EINVAL;
	}
	kernel_dir = qtfs_copy_mount_string(dir_name);
	ret = PTR_ERR(kernel_dir);
	if (IS_ERR(kernel_dir)) {
		qtfs_err("qtfs remote mount %s, kernel dir dup failed ret:%d.\n", dev_name, ret);
		qtfs_conn_put_param(pvar);
		return ret;
	}

	// data = qtfs_mount_datapage_modify(type, data);
	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	if (dev_name != NULL) {
		qtfs_dir_to_qtdir(dev_name, req->buf);
		req->d.dev_len = strlen(dev_name) + 1;
	} else {
		req->d.dev_len = 0;
	}

	strcpy(&req->buf[req->d.dev_len], kernel_dir);
	qtfs_dir_to_qtdir(kernel_dir, &req->buf[req->d.dev_len]);
	req->d.dir_len = strlen(&req->buf[req->d.dev_len]) + 1;
	if (type != NULL) {
		strcpy(&req->buf[req->d.dev_len + req->d.dir_len], type);
		req->d.type_len = strlen(type) + 1;
	} else {
		req->d.type_len = 0;
	}

	if (data != NULL) {
		req->d.data_len = strlen(data) + 1;
		strcpy(&req->buf[req->d.dev_len + req->d.dir_len + req->d.type_len], data);
	} else {
		req->d.data_len = 0;
	}
	req->d.flags = flags;

	totallen = req->d.dev_len + req->d.dir_len + req->d.type_len + req->d.data_len;
	if (totallen >= sizeof(req->buf)) {
		qtfs_err("qtfs remote mount devname:%s, dir_name:%s failed, len:%d is too big.\n", dev_name, kernel_dir, totallen);
		rsp->errno = -EFAULT;
		goto out_free;
	}

	rsp = qtfs_remote_run(pvar, QTFS_REQ_SYSMOUNT, sizeof(struct qtreq_sysmount) - sizeof(req->buf) + totallen);
	if (IS_ERR(rsp) || rsp == NULL) {
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->errno < 0) {
		qtfs_err("qtfs remote mount failed, devname:%s dir_name:%s type:%s, data:%s, flags(0x%lx), errno:%d\n",
				dev_name, kernel_dir, type, (char *)data, flags, rsp->errno);
	} else {
		qtfs_info("qtfs remote mount success devname:%s dir_name:%s type:%s, data:%s, flags(0x%lx)\n",
				dev_name, kernel_dir, type, (char *)data, flags);
	}

out_free:
	kfree(kernel_dir);
	ret = rsp->errno;
	qtfs_conn_put_param(pvar);
	return ret;
}

static int qtfs_remote_umount(char __user *name, int flags)
{
	struct qtfs_sock_var_s *pvar = qtfs_conn_get_param();
	struct qtreq_sysumount *req;
	struct qtrsp_sysumount *rsp;
	char *kernel_name;
	int ret;

	if (pvar == NULL) {
		qtfs_err("qtfs remote umount get pvar failed.");
		return -EINVAL;
	}
	req = qtfs_sock_msg_buf(pvar, QTFS_SEND);
	kernel_name = qtfs_copy_mount_string(name);
	req->flags = flags;
	qtfs_dir_to_qtdir(kernel_name, req->buf);
	qtfs_info("qtfs remote umount string:%s reqbuf:%s", (kernel_name == NULL) ? "INVALID":kernel_name, req->buf);

	rsp = qtfs_remote_run(pvar, QTFS_REQ_SYSUMOUNT, sizeof(struct qtreq_sysumount) - sizeof(req->buf) + strlen(req->buf));
	if (IS_ERR(rsp) || rsp == NULL) {
		kfree(kernel_name);
		qtfs_conn_put_param(pvar);
		return PTR_ERR(rsp);
	}
	if (rsp->errno)
		qtfs_err("qtfs remote umount failed, errno:%d\n", rsp->errno);
	
	kfree(kernel_name);
	ret = rsp->errno;
	qtfs_conn_put_param(pvar);
	return ret;
}

static unsigned long *qtfs_oldsyscall_mount = NULL;
static unsigned long *qtfs_oldsyscall_umount = NULL;
static unsigned long *qtfs_oldsyscall_epoll_ctl = NULL;

int qtfs_syscall_init(void)
{
#ifdef __aarch64__
	kallsyms_lookup_name_t kallsyms_lookup_name;
#endif
	qtfs_debug("qtfs use my_mount instead of mount:0x%lx umount:0x%lx\n",
			(unsigned long)qtfs_kern_syms.sys_call_table[__NR_mount], (unsigned long)qtfs_kern_syms.sys_call_table[__NR_umount2]);
	qtfs_debug("qtfs use my_epoll_ctl instead of epoll_ctl:0x%lx\n",
			(unsigned long)qtfs_kern_syms.sys_call_table[__NR_epoll_ctl]);
	qtfs_oldsyscall_mount = qtfs_kern_syms.sys_call_table[__NR_mount];
	qtfs_oldsyscall_umount = qtfs_kern_syms.sys_call_table[__NR_umount2];
	qtfs_oldsyscall_epoll_ctl = qtfs_kern_syms.sys_call_table[__NR_epoll_ctl];
	make_rw((unsigned long)qtfs_kern_syms.sys_call_table);
#ifdef __x86_64__
	qtfs_kern_syms.sys_call_table[__NR_mount] = (unsigned long *)__x64_sys_qtfs_mount;
	qtfs_kern_syms.sys_call_table[__NR_umount2] = (unsigned long *)__x64_sys_qtfs_umount;
	qtfs_kern_syms.sys_call_table[__NR_epoll_ctl] = (unsigned long *)__x64_sys_qtfs_epoll_ctl;
#endif
#ifdef __aarch64__
        register_kprobe(&kp);
        kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
        start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	end_rodata= (unsigned long)kallsyms_lookup_name("__end_rodata");

	qtfs_kern_syms.sys_call_table[__NR_mount] = (unsigned long *)__arm64_sys_qtfs_mount;
	qtfs_kern_syms.sys_call_table[__NR_umount2] = (unsigned long *)__arm64_sys_qtfs_umount;
	qtfs_kern_syms.sys_call_table[__NR_epoll_ctl] = (unsigned long *)__arm64_sys_qtfs_epoll_ctl;
#endif
	make_ro((unsigned long)qtfs_kern_syms.sys_call_table);
	qtfs_debug("qtfs use my_mount:0x%lx, my_umount:0x%lx, my_epoll_ctl:0x%lx\n",
			(unsigned long)qtfs_kern_syms.sys_call_table[__NR_mount],
			(unsigned long)qtfs_kern_syms.sys_call_table[__NR_umount2],
			(unsigned long)qtfs_kern_syms.sys_call_table[__NR_epoll_ctl]);
	return 0;
}

int qtfs_syscall_fini(void)
{
	qtfs_info("qtfs mount resume to 0x%lx.\n", (unsigned long)qtfs_oldsyscall_mount);

	make_rw((unsigned long)qtfs_kern_syms.sys_call_table);
	qtfs_kern_syms.sys_call_table[__NR_mount] = (unsigned long *)qtfs_oldsyscall_mount;
	qtfs_kern_syms.sys_call_table[__NR_umount2] = (unsigned long *)qtfs_oldsyscall_umount;
	qtfs_kern_syms.sys_call_table[__NR_epoll_ctl] = (unsigned long *)qtfs_oldsyscall_epoll_ctl;
	/*set mkdir syscall to the original one */
	make_ro((unsigned long)qtfs_kern_syms.sys_call_table);
	return 0;
}
