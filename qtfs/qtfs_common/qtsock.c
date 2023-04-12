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

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/un.h>

#include "conn.h"
#include "log.h"
#include "comm.h"
#include "qtfs/syscall.h"

#define MAX_SOCK_PATH_LEN 108

static struct socket *qtfs_sock = NULL;
static struct mutex qtfs_sock_mutex;
static char qtfs_sock_path[] = "/var/run/qtfs/remote_uds.sock";

struct qtsock_wl_stru qtsock_wl;

static struct sock *(*origin_unix_find_other)(struct net *net,
		struct sockaddr_un *sunname, int len,
		int type, unsigned int hash, int *error);

struct ftrace_hook {
	const char *name;
	void *func;
	void *origin;

	unsigned long addr;
	struct ftrace_ops ops;
};

struct ftrace_hook unix_find_other_hook;

static int resolve_hook_address(struct ftrace_hook *hook)
{
	hook->addr = qtfs_kallsyms_lookup_name(hook->name);
	if (!hook->addr) {
		qtfs_warn("unresolved symbol during resolving hook address:%s\n", hook->name);
		return -ENOENT;
	}
	*((unsigned long *)hook->origin) = hook->addr;

	return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->func;
}

int install_hook(struct ftrace_hook *hook)
{
	int err;

	err = resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
	if (err) {
		qtfs_err("ftrace_set_filter_ip failed:%d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		qtfs_err("register_ftrace_function failed with :%d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
		return err;
	}
	qtfs_info("install hook(%s) done\n", hook->name);

	return 0;
}

void remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err)
		qtfs_err("unregister_ftrace_function failed:%d\n", err);

	err = ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
	if (err)
		qtfs_err("ftrace_set_filter_ip failed:%d\n", err);
	qtfs_info("remove hook(%s) done", hook->name);
}

struct qtfs_sock_req {
	int magic;
	int type;
	char sunname[MAX_SOCK_PATH_LEN];
};

struct qtfs_sock_rsp {
	int found;
};

static int qtsock_conn(void)
{
	int ret;
	struct sockaddr_un saddr;

	ret = mutex_lock_interruptible(&qtfs_sock_mutex);
	if (ret <0) {
		qtfs_err("Failed to get qtfs sock mutex lock:%d\n", ret);
		return false;
	}
	// calling this function means qtfs_sock isn't working properly.
	// so it's ok to release and clean old qtfs_sock
	if (qtfs_sock) {
		sock_release(qtfs_sock);
		qtfs_sock = NULL;
	}
	// connect to userspace unix socket server
	ret = __sock_create(&init_net, AF_UNIX, SOCK_STREAM, 0, &qtfs_sock, 1);
	if (ret) {
		qtfs_err("qtfs sock client init create sock failed:%d\n", ret);
		mutex_unlock(&qtfs_sock_mutex);
		return ret;
	}
	saddr.sun_family = PF_UNIX;
	strcpy(saddr.sun_path, qtfs_sock_path);
	ret = qtfs_sock->ops->connect(qtfs_sock, (struct sockaddr *)&saddr,
			sizeof(struct sockaddr_un) - 1, 0);
	if (ret) {
		qtfs_err("qtfs sock client sock connect failed:%d\n", ret);
		sock_release(qtfs_sock);
		qtfs_sock = NULL;
		mutex_unlock(&qtfs_sock_mutex);
		return ret;
	}

	mutex_unlock(&qtfs_sock_mutex);
	return ret;
}

bool qtfs_udsfind(char *sunname, int len, int type)
{
	struct qtfs_sock_req qs_req;
	struct qtfs_sock_rsp qs_rsp;
	struct kvec send_vec, recv_vec;
	struct msghdr send_msg, recv_msg;
	int ret;
	int retry = 0, penalty = 100, i = 0;

	// qtfs_sock still not initialized, try to connect to server
	if (!qtfs_sock && (qtsock_conn() < 0)) {
		qtfs_err("failed to connect to qtfs socket\n");
		return false;
	}
	if (len > MAX_SOCK_PATH_LEN) {
		qtfs_err("Invalid socket path name len(%d)\n", len);
		return false;
	}
	memset(&qs_req, 0, sizeof(qs_req));
	memset(&qs_rsp, 0, sizeof(qs_rsp));
	strncpy(qs_req.sunname, sunname, len);
	qs_req.type = type;
	qs_req.magic = 0xDEADBEEF;

	memset(&send_msg, 0, sizeof(send_msg));
	memset(&send_vec, 0, sizeof(send_vec));
	memset(&recv_msg, 0, sizeof(recv_msg));
	memset(&recv_vec, 0, sizeof(recv_vec));

	send_vec.iov_base = &qs_req;
	send_vec.iov_len = sizeof(qs_req);
	qtfs_info("qtfs uds find socket(%s), type(%d)\n", sunname, type);

reconn:
	if (retry) {
		for (i = 0; i < retry; i++) {
			if (qtsock_conn() == 0)
				break;
			qtfs_err("qtfs socket reconnect failed for %d trial", i+1);
			penalty *= 2;
			msleep(penalty);
		}
	}
	ret = mutex_lock_interruptible(&qtfs_sock_mutex);
	if (ret < 0) {
		qtfs_err("Failed to get qtfs sock mutex lock:%d\n", ret);
		return false;
	}
	if (!qtfs_sock) {
		qtfs_err("qtfs_sock is NULL, please check\n");
		mutex_unlock(&qtfs_sock_mutex);
		return false;
	}
	send_msg.msg_flags |= MSG_NOSIGNAL;
	ret = kernel_sendmsg(qtfs_sock, &send_msg, &send_vec, 1, sizeof(qs_req));
	if (ret == -EPIPE && retry == 0) {
		qtfs_err("uds find connection has broken, try to reconnect\n");
		retry = 3;
		mutex_unlock(&qtfs_sock_mutex);
		goto reconn;
	} else if (ret < 0) {
		qtfs_err("Failed to send uds find message:%d\n", ret);
		mutex_unlock(&qtfs_sock_mutex);
		return false;
	}

	// waiting for response
	recv_vec.iov_base = &qs_rsp;
	recv_vec.iov_len = sizeof(qs_rsp);
retry:
	recv_msg.msg_flags |= MSG_NOSIGNAL;
	ret = kernel_recvmsg(qtfs_sock, &recv_msg, &recv_vec, 1, sizeof(qs_rsp), 0);
	if (ret == -ERESTARTSYS || ret == -EINTR) {
		qtfs_err("uds remote find get interrupted, just retry");
		msleep(1);
		goto retry;
	}
	mutex_unlock(&qtfs_sock_mutex);
	if (ret < 0) {
		qtfs_err("Failed to receive uds find response:%d\n", ret);
		return false;
	}
	qtfs_info("uds remote find socket(%s), type(%d), result:%s\n", sunname, type, qs_rsp.found ? "found" : "not found");
	return qs_rsp.found;
}

static int uds_find_whitelist(const char *path)
{
	int i;
	int ret = 1;
	read_lock(&qtsock_wl.rwlock);
	for (i = 0; i< qtsock_wl.nums; i++) {
		if (strncmp(path, qtsock_wl.wl[i], strlen(qtsock_wl.wl[i])) == 0) {
			ret = 0;
			break;
		}
	}
	read_unlock(&qtsock_wl.rwlock);
	return ret;
}

static inline bool uds_is_proxy(void)
{
	return (current->tgid == qtfs_uds_proxy_pid);
}

static struct sock *qtfs_unix_find_other(struct net *net,
		struct sockaddr_un *sunname, int len,
		int type, unsigned int hash, int *error)
{
	struct sock *other = NULL;
	bool found = false;

	qtfs_debug("in qtfs_unix_find_other (%s)\n", sunname->sun_path);
	other = origin_unix_find_other(net, sunname, len, type, hash, error);
	if (other) {
		qtfs_debug("find unix other sock(%s) locally", sunname->sun_path);
		return other;
	}

	// do not call remote find if sunname is annomous or sunpath not in whitelist
	if (!sunname->sun_path[0] || uds_find_whitelist(sunname->sun_path) ||
			uds_is_proxy() == true) {
		*error = -ECONNREFUSED;
		return NULL;
	}

	qtfs_info("Failed to find unix other sock(%s) locally, try to find remotely\n", sunname->sun_path);
	// refer userspace service to get remote socket status
	// if found, which means userspace service has create this unix socket server, just go to origin_unix_find_other, it will be found
	// if not found, return NULL
	found = qtfs_udsfind(sunname->sun_path, len, type);
	if (!found) {
		qtfs_info("failed to find unix other sock(%s) remotely", sunname->sun_path);
		*error = -ECONNREFUSED;
		return NULL;
	}
	qtfs_info("find unix other sock(%s) remotely\n", sunname->sun_path);

	// found it remotely, so we will inform userspace engine to create specfic unix socket and connect to qtfs server
	// and call unix_find_other locally
	// xxx: will this be called recursively? Hope not
	return origin_unix_find_other(net, sunname, len, type, hash, error);
}

int qtfs_sock_init(void)
{
	qtfs_kallsyms_hack_init();

	qtfs_info("in qtfs ftrace hook unix_find_other\n");
	unix_find_other_hook.name = "unix_find_other";
	unix_find_other_hook.func = qtfs_unix_find_other;
	unix_find_other_hook.origin = &origin_unix_find_other;

	install_hook(&unix_find_other_hook);
	mutex_init(&qtfs_sock_mutex);
	rwlock_init(&qtsock_wl.rwlock);
	qtsock_wl.nums = 0;
	qtsock_wl.wl = (char **)kmalloc(sizeof(char *) * QTSOCK_WL_MAX_NUM, GFP_KERNEL);
	if (qtsock_wl.wl == NULL) {

		qtfs_err("failed to kmalloc wl, max num:%d", QTSOCK_WL_MAX_NUM);
	}

	return 0;
}

void qtfs_sock_exit(void)
{
	int ret;
	qtfs_info("exit qtfs ftrace, remove unix_find_other_hook\n");
	remove_hook(&unix_find_other_hook);

	ret = mutex_lock_interruptible(&qtfs_sock_mutex);
	if (ret < 0)
		qtfs_err("Failed to get qtfs sock mutex lock:%d\n", ret);
	// close unix socket connected to userspace
	if (qtfs_sock) {
		sock_release(qtfs_sock);
		qtfs_sock = NULL;
	}
	mutex_unlock(&qtfs_sock_mutex);
}
