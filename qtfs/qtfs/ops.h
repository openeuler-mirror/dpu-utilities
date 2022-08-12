#ifndef __QTFS_OPS_H__
#define __QTFS_OPS_H__

#include <linux/fs.h>

#include "qtfs-mod.h"

extern struct inode_operations qtfs_proc_inode_ops;
extern struct file_operations qtfs_proc_file_ops;
extern struct inode_operations qtfs_proc_sym_ops;

enum qtfs_type qtfs_get_type(char *str);
bool is_sb_proc(struct super_block *sb);

struct inode *qtfs_iget(struct super_block *sb, struct inode_info *ii);
const char *qtfs_getlink(struct dentry *dentry,
					struct inode *inode, struct delayed_call *done);
int qtfs_getattr(const struct path *, struct kstat *, u32, unsigned int);
struct dentry * qtfs_lookup(struct inode *, struct dentry *, unsigned int);

#endif
