/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * qtfs licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Liqiang
 * Create: 2023-03-20
 * Description: 
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "qtinfo.h"
#include "comm.h"
#include "ipc/uds_module.h"

#ifdef client
#define QTFS_DEV_NAME "/dev/qtfs_client"
#else
#define QTFS_DEV_NAME "/dev/qtfs_server"
#endif

#define qtinfo_out(info, ...) \
	do {\
		printf(info"\n", ##__VA_ARGS__);\
	} while (0);

#define qtinfo_out2(info, ...) \
	do {\
		printf(info, ##__VA_ARGS__);\
	} while (0);

#define qtinfo_err(info, ...) \
	do {\
		printf("ERROR: "info"\n", ##__VA_ARGS__);\
	} while (0);

#define RECV_BUFF_LEN	256

struct qtinfo_type_str qtinfo_all_events[] = {
	{QTFS_REQ_NULL,				"null"},
	{QTFS_REQ_MOUNT,			"mount"},
	{QTFS_REQ_OPEN,				"open"},
	{QTFS_REQ_CLOSE,			"close"},
	{QTFS_REQ_READ,				"read"},
	{QTFS_REQ_READITER,			"readiter"}, //5
	{QTFS_REQ_WRITE,			"write"},
	{QTFS_REQ_LOOKUP,			"lookup"},
	{QTFS_REQ_READDIR,			"readdir"},
	{QTFS_REQ_MKDIR,			"mkdir"},
	{QTFS_REQ_RMDIR,			"rmdir"}, //10
	{QTFS_REQ_GETATTR,			"getattr"},
	{QTFS_REQ_SETATTR,			"setattr"},
	{QTFS_REQ_ICREATE,			"icreate"},
	{QTFS_REQ_MKNOD,			"mknod"},
	{QTFS_REQ_UNLINK,			"unlink"}, //15
	{QTFS_REQ_SYMLINK,			"symlink"},
	{QTFS_REQ_LINK,				"link"},
	{QTFS_REQ_GETLINK,			"getlink"},
	{QTFS_REQ_READLINK,			"readlink"},
	{QTFS_REQ_RENAME,			"rename"}, //20

	{QTFS_REQ_XATTRLIST,		"xattrlist"},
	{QTFS_REQ_XATTRGET,			"xattrget"},
	{QTFS_REQ_XATTRSET,			"xattrset"},

	{QTFS_REQ_SYSMOUNT,			"sysmount"},
	{QTFS_REQ_SYSUMOUNT,		"sysumount"}, //25
	{QTFS_REQ_FIFOPOLL,			"fifo_poll"},

	{QTFS_REQ_STATFS,			"statfs"},
	{QTFS_REQ_IOCTL,			"ioctl"},
	{QTFS_REQ_EPOLL_CTL,		"epollctl"},

	{QTFS_REQ_EPOLL_EVENT,		"epollevent"}, // 30
	{QTFS_REQ_LLSEEK,			"llseek"},
	{QTFS_SC_KILL,				"sc_kill"},
	{QTFS_SC_SCHED_GETAFFINITY,	"sc_getaffi"},
	{QTFS_SC_SCHED_SETAFFINITY,	"sc_setaffi"},
};

static void qtinfo_events_count(struct qtinfo *evts)
{
	unsigned long total = 0;
	int i;
#ifdef client
	qtinfo_out("++++++++++++++++++++++++++send events count++++++++++++++++++++++++++");
	for (i = 0; i < (sizeof(qtinfo_all_events) / sizeof(struct qtinfo_type_str)) - 3; i += 3) {
		qtinfo_out("%-10s: %-10lu %-10s: %-10lu %-10s: %-10lu",
						qtinfo_all_events[i].str, evts->c.o_events[i],
						qtinfo_all_events[i+1].str, evts->c.o_events[i+1],
						qtinfo_all_events[i+2].str, evts->c.o_events[i+2]);
		total += evts->c.o_events[i] + evts->c.o_events[i+1] + evts->c.o_events[i+2];
	}
	for (; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		qtinfo_out2("%-10s: %-10lu ", qtinfo_all_events[i].str, evts->c.o_events[i]);
		total += evts->c.o_events[i];
	}
	qtinfo_out2("\n");
	qtinfo_out("Send events total: %lu", total);
	total = 0;

	qtinfo_out("++++++++++++++++++++++++++recv events count++++++++++++++++++++++++++");
	for (i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {
		qtinfo_out("%-10s: %-10lu %-10s: %-10lu %-10s: %-10lu",
						qtinfo_all_events[i].str, evts->c.i_events[i],
						qtinfo_all_events[i+1].str, evts->c.i_events[i+1],
						qtinfo_all_events[i+2].str, evts->c.i_events[i+2]);
		total += evts->c.i_events[i] + evts->c.i_events[i+1] + evts->c.i_events[i+2];
	}
	for(; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		 qtinfo_out2("%-10s: %-10lu ", qtinfo_all_events[i].str, evts->c.i_events[i]);
		 total += evts->c.i_events[i];
	}
	qtinfo_out2("\n");
	qtinfo_out("Recv events total: %lu", total);
	total = 0;
	qtinfo_out("++++++++++++++++++++++++++send error count+++++++++++++++++++++++++++");
	for(i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {
		qtinfo_out("%-10s: %-10lu %-10s: %-10lu %-10s: %-10lu",
					    qtinfo_all_events[i].str, evts->c.send_err[i],
						qtinfo_all_events[i+1].str, evts->c.send_err[i+1],
						qtinfo_all_events[i+2].str, evts->c.send_err[i+2]);
		total += evts->c.send_err[i] + evts->c.send_err[i+1] + evts->c.send_err[i+2];
    }
	for(; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		qtinfo_out2("%-10s: %-10lu ", qtinfo_all_events[i].str, evts->c.send_err[i]);
		total += evts->c.send_err[i];
	}
	qtinfo_out2("\n");
	qtinfo_out("Send events error total: %lu", total);
	total = 0;

	qtinfo_out("++++++++++++++++++++++++++recv error count+++++++++++++++++++++++++++");
	for(i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {
		qtinfo_out("%-10s: %-10lu %-10s: %-10lu %-10s: %-10lu",
				qtinfo_all_events[i].str, evts->c.recv_err[i],
				qtinfo_all_events[i+1].str, evts->c.recv_err[i+1],
				qtinfo_all_events[i+2].str, evts->c.recv_err[i+2]);
		total += evts->c.recv_err[i] + evts->c.recv_err[i+1] + evts->c.recv_err[i+2];
	}
	for(; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		qtinfo_out2("%-10s: %-10lu ", qtinfo_all_events[i].str, evts->c.recv_err[i]);
		total += evts->c.recv_err[i];
	}
	qtinfo_out2("\n");
	qtinfo_out("Recv events error total: %lu", total);
	total = 0;
#endif
#ifdef server
	qtinfo_out("++++++++++++++++++++++++++send events count++++++++++++++++++++++++++");
	for (i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {	
		qtinfo_out("%-10s: %-10lu %-10s: %-10lu %-10s: %-10lu",
				qtinfo_all_events[i].str, evts->s.o_events[i],
				qtinfo_all_events[i+1].str, evts->s.o_events[i+1],
				qtinfo_all_events[i+2].str, evts->s.o_events[i+2]);
		total += evts->s.o_events[i] + evts->s.o_events[i+1] + evts->s.o_events[i+2];
	}
	for (; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		qtinfo_out2("%-10s: %-10lu ", qtinfo_all_events[i].str, evts->s.o_events[i]);
		total += evts->s.o_events[i];
	}
	qtinfo_out2("\n");
	qtinfo_out("Send events total: %lu", total);
	total = 0;

	qtinfo_out("++++++++++++++++++++++++++recv events count++++++++++++++++++++++++++");
	for (i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {
		qtinfo_out("%-10s: %-10lu %-10s: %-10lu %-10s: %-10lu",
				qtinfo_all_events[i].str, evts->s.i_events[i],
				qtinfo_all_events[i+1].str, evts->s.i_events[i+1],
				qtinfo_all_events[i+2].str, evts->s.i_events[i+2]);
		total += evts->s.i_events[i] + evts->s.i_events[i+1] + evts->s.i_events[i+2];
	}
	for(; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		qtinfo_out2("%-10s: %-10lu ", qtinfo_all_events[i].str, evts->s.i_events[i]);
		total += evts->s.i_events[i];
	}
	qtinfo_out2("\n");
	qtinfo_out("Recv events total: %lu", total);

	qtinfo_out("++++++++++++++++++++++++++req check err+++++++++++++++++++++++++++++++");
	for (i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {
		qtinfo_out("%-10s: %-10lu %-10s: %-10lu %-10s: %-10lu",
				qtinfo_all_events[i].str, evts->s.req_check[i],
				qtinfo_all_events[i+1].str, evts->s.req_check[i+1],
				qtinfo_all_events[i+2].str, evts->s.req_check[i+2]);
	}
	for(; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		qtinfo_out2("%-10s: %-10lu ", qtinfo_all_events[i].str, evts->s.req_check[i]);
	}
	qtinfo_out("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
#endif
}

static void qtinfo_misc_count(struct qtinfo *info)
{
	qtinfo_out("++++++++++++++++++++++++++++++Misc count+++++++++++++++++++++++++++++");
#ifdef client
	qtinfo_out("Active connects: %-8lu Seq err count   : %-8lu Restartsys   : %-8lu",
					info->c.cnts[QTINF_ACTIV_CONN], info->c.cnts[QTINF_SEQ_ERR], info->c.cnts[QTINF_RESTART_SYS]);
	qtinfo_out("Type mismatch  : %-8lu Epoll add fds   : %-8lu Epoll del fds: %-8lu",
					info->c.cnts[QTINF_TYPE_MISMATCH], info->c.cnts[QTINF_EPOLL_ADDFDS], info->c.cnts[QTINF_EPOLL_DELFDS]);
	qtinfo_out("Epoll err fds  : %-8lu",
					info->c.cnts[QTINF_EPOLL_FDERR]);
#else
	qtinfo_out("Active connects: %-8lu Epoll add fds: %-8lu Epoll del fds: %-8lu",
					info->s.cnts[QTINF_ACTIV_CONN], info->s.cnts[QTINF_EPOLL_ADDFDS], info->s.cnts[QTINF_EPOLL_DELFDS]);
#endif
}

static void qtinfo_thread_state(struct qtinfo *info)
{
	int i = 0;

	qtinfo_out("+++++++++++++++++++++++++++Connection state++++++++++++++++++++++++++");
	for (i = 0; i < QTFS_MAX_THREADS - 3; i+=3) {
		qtinfo_out("Conn%-2d: %-10s Conn%-2d: %-10s Conn%-2d: %-10s",
				i+1, QTINFO_STATE(info->thread_state[i]),
				i+2, QTINFO_STATE(info->thread_state[i+1]),
				i+3, QTINFO_STATE(info->thread_state[i+2]));
	}
	for (; i < QTFS_MAX_THREADS; i++) {
		qtinfo_out2("Conn%-2d: %-10s ", i+1, QTINFO_STATE(info->thread_state[i]));
	}
	qtinfo_out("Epoll state: %-10s", QTINFO_STATE(info->epoll_state));
	return;
}

static void qtinfo_pvar_count(struct qtinfo *info)
{
	int i = 0;
	qtinfo_out("+++++++++++++++++++++++++++++Param count+++++++++++++++++++++++++++++");
	qtinfo_out("Parameter valid count: %-2d Parameter busy count: %-2d",
							info->pvar_vld, info->pvar_busy);
	for (i = 0; i < QTFS_MAX_THREADS; i++) {
		qtinfo_out("Conn%-2d holder: [%-20s]", i+1, (info->who_using[i][0] == '\0') ? "No one" : info->who_using[i]);
	}
}

static void qtinfo_log_level(struct qtinfo *info)
{
	qtinfo_out("Log level: %d", info->log_level);
}

static int qtinfo_opt_a(int fd)
{
	struct qtinfo *diag = (struct qtinfo *)malloc(sizeof(struct qtinfo));
	if (diag == NULL) {
		qtinfo_err("malloc failed.");
		return -1;
	}
	memset(diag, 0, sizeof(struct qtinfo));
	int ret = ioctl(fd, QTFS_IOCTL_ALLINFO, diag);
	if (ret != QTOK) {
		qtinfo_err("ioctl failed, ret:%d.", ret);
		free(diag);
		return -1;
	}
	qtinfo_events_count(diag);
	qtinfo_misc_count(diag);
	qtinfo_log_level(diag);
	qtinfo_thread_state(diag);
	qtinfo_pvar_count(diag);
	free(diag);
	return 0;
}

static int qtinfo_opt_c(int fd)
{
	int ret = ioctl(fd, QTFS_IOCTL_CLEARALL, NULL);
	return ret;
}

static int qtinfo_opt_l(int fd, char *level)
{
	int ret;

	ret = ioctl(fd, QTFS_IOCTL_LOGLEVEL, level);
	if (ret != QTOK) {
		qtinfo_err("Set qtfs log level:%s failed.", level);
		return ret;
	}
	qtinfo_out("Set qtfs log level to %s success.", level);
	return ret;
}

static int qtinfo_opt_t(int fd)
{
	int i;
	struct qtinfo *diag = (struct qtinfo *)malloc(sizeof(struct qtinfo));
	if (diag == NULL) {
		qtinfo_err("malloc failed.");
		return -1;
	}
	int ret = ioctl(fd, QTFS_IOCTL_ALLINFO, (unsigned long)diag);
	qtinfo_out("++++++++++++++++++++++++++qtreq_xxx size++++++++++++++++++++++++++");
	for (i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {
		qtinfo_out("%-10s req: %-10lu %-10s req: %-10lu %-10s req: %-10lu",
						qtinfo_all_events[i].str, diag->req_size[i],
						qtinfo_all_events[i+1].str, diag->req_size[i+1],
						qtinfo_all_events[i+2].str, diag->req_size[i+2]);
	}
	for (; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		qtinfo_out2("%-10s req: %-10lu ", qtinfo_all_events[i].str, diag->req_size[i]);
	}
	qtinfo_out2("\n");
	qtinfo_out("++++++++++++++++++++++++++qtrsp_xxx size++++++++++++++++++++++++++");
	for (i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {
		qtinfo_out("%-10s rsp: %-10lu %-10s rsp: %-10lu %-10s rsp: %-10lu",
				        qtinfo_all_events[i].str, diag->rsp_size[i],
						qtinfo_all_events[i+1].str, diag->rsp_size[i+1],
						qtinfo_all_events[i+2].str, diag->rsp_size[i+2]);
	}
	for (; i < sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str); i++) {
		qtinfo_out2("%-10s rsp: %-10lu ", qtinfo_all_events[i].str, diag->rsp_size[i]);
	}
	qtinfo_out2("\n");

	free(diag);
	return ret;
}

static int qtinfo_opt_p(int fd, char *support)
{
	int ret;
	int sup = atoi(support);

	ret = ioctl(fd, QTFS_IOCTL_EPOLL_SUPPORT, sup);
	if (ret != QTOK) {
		qtinfo_out("Set qtfs epoll support to:%s failed.", (sup == 1) ? "any file" : "fifo file");
		return ret;
	}
	qtinfo_out("Set qtfs epoll support to %s success.", (sup == 1) ? "any file" : "fifo file");
	return ret;
}

#define PATH_MAX 4096
static int qtinfo_opt_u()
{
	int ret = -1;
	int len;
	struct sockaddr_un svr;
	char buf[RECV_BUFF_LEN];
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		qtinfo_err("Create socket fd failed.");
		return -1;
	}

	memset(&svr, 0, sizeof(svr));
	svr.sun_family = AF_UNIX;
	strcpy(svr.sun_path, UDS_DIAG_ADDR);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(svr.sun_path);
	if (connect(sockfd, (struct sockaddr *)&svr, len) < 0) {
		qtinfo_err("connect to %s failed.", UDS_DIAG_ADDR);
		close(sockfd);
		return -1;
	}
	while (1) {
		memset(buf, 0, RECV_BUFF_LEN);
		ret = recv(sockfd, buf, RECV_BUFF_LEN, 0);
		if (ret <= 0)
			break;
		qtinfo_out2("%s", buf);
	}
	qtinfo_out2("\n");
	close(sockfd);
	return ret;
}

static int qtinfo_opt_s()
{
	int ret = -1;
	int len;
	struct sockaddr_un svr;
	char buf[RECV_BUFF_LEN];
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		qtinfo_err("Create socket fd failed.");
		return -1;
	}

	memset(&svr, 0, sizeof(svr));
	svr.sun_family = AF_UNIX;
	strcpy(svr.sun_path, UDS_LOGLEVEL_UPD);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(svr.sun_path);
	if (connect(sockfd, (struct sockaddr *)&svr, len) < 0) {
		qtinfo_err("connect to %s failed.", UDS_LOGLEVEL_UPD);
		close(sockfd);
		return -1;
	}
	while (1) {
		memset(buf, 0, RECV_BUFF_LEN);
		ret = recv(sockfd, buf, RECV_BUFF_LEN, 0);
		if (ret <= 0)
			break;
		qtinfo_out2("%s", buf);
	}
	qtinfo_out2("\n");
	close(sockfd);
	return ret;

}

char wl_type_str[QTFS_WHITELIST_MAX][16] = {
#ifdef server
	"Open",
	"Write",
	"Read",
	"Readdir",
	"Mkdir",
	"Rmdir",
	"Create",
	"Unlink",
	"Rename",
	"Setattr",
	"Setxattr",
	"Mount",
	"Kill",
#endif
	"Udsconnect"
};

int qtinfo_match_cap(char *cap)
{
	if (cap == NULL)
		return -1;
	for (int type = 0; type < QTFS_WHITELIST_MAX; type++) {
		if (strcasecmp(wl_type_str[type], cap) == 0)
			return type;
	}
	return -1;
}

#define PATH_MAX 4096
static int qtinfo_opt_x(int fd, char *path, char *cap)
{
	int ret = -1;
	int index = 0;
	struct qtfs_wl_item head;
	ret = qtinfo_match_cap(cap);
	if (ret < 0) {
		qtinfo_err("White list add type:%s unknown.", cap);
		return -1;
	}
	head.type = ret;
	head.len = strlen(path);
	if (head.len >= PATH_MAX || head.len == 0) {
		qtinfo_err("White list add len:%u invalid", head.len);
		return -1;
	}
	head.path = path;
	ret = ioctl(fd, QTFS_IOCTL_WL_ADD, &head);
	if (ret != QTOK) {
		qtinfo_err("ioctl add white list failed");
		ret = -1;
	} else {
		qtinfo_out("successed to add white list item:%s successed", path);
		ret = 0;
	}
	return ret;
}

static int qtinfo_opt_y(int fd, char *index, char *cap)
{
	struct qtfs_wl_item head;
	int ret = qtinfo_match_cap(cap);
	if (ret < 0) {
		qtinfo_err("White list delete type:%s unknown.", cap);
		return -1;
	}
	head.index = atoi(index);
	head.type = ret;
	head.path = NULL;
	head.len = 0;
	ret = ioctl(fd, QTFS_IOCTL_WL_DEL, &head);
	if (ret != QTOK) {
		qtinfo_err("failed to delete white list index:%d", head.index);
		return -1;
	} else {
		qtinfo_out("successed to delete white list index:%d", head.index);
	}
	return 0;
}

static void qtinfo_opt_z_bytype(int fd, unsigned int type)
{
	int ret;
	char query[PATH_MAX];
	struct qtfs_wl_item head;
	head.path = query;
	head.type = type;
	qtinfo_out("Get qtfs <%s> white list:", wl_type_str[type]);
	for (unsigned int index = 0; index < QTFS_WL_MAX_NUM; index++) {
		memset(head.path, 0, PATH_MAX);
		head.index = index;
		ret = ioctl(fd, QTFS_IOCTL_WL_GET, &head);
		if (ret != QTOK)
			break;
		qtinfo_out("  [index:%d][path:%s]", index, head.path);
	}
	return;
}

static int qtinfo_opt_z(int fd, char *cap)
{
	int ret = -1;
	int index = 0;
	ret = qtinfo_match_cap(cap);

	if (ret >= 0 && ret < QTFS_WHITELIST_MAX) {
		qtinfo_opt_z_bytype(fd, ret);
		return 0;
	}
	for (int i = 0; i < QTFS_WHITELIST_MAX; i++) {
		qtinfo_opt_z_bytype(fd, i);
	}
	return 0;
}

static void qtinfo_help(char *exec)
{
	qtinfo_out("Usage: %s [OPTION].", exec);
	qtinfo_out("Display qtfs client/server diagnostic information.");
#ifndef QTINFO_RELEASE
	qtinfo_out("  -a, All diag info.");
	qtinfo_out("  -c, Clear all diag info.");
	qtinfo_out("  -l, Set log level(valid param: \"NONE\", \"ERROR\", \"WARN\", \"INFO\", \"DEBUG\").");
	qtinfo_out("  -t, For test informations.");
	qtinfo_out("  -p, Epoll support file mode(1: any files; 0: only fifo).");
	qtinfo_out("  -u, Display unix socket proxy diagnostic info");
	qtinfo_out("  -s, Set unix socket proxy log level(Increase by 1 each time)");
#endif
#ifdef server
	qtinfo_out("  -w, White list type(open/write/read/readdir/mkdir/rmdir/create/\n"
				"      unlink/rename/setattr/setxattr/mount/kill/udsconnect)");
#endif
#ifdef client
	qtinfo_out("  -w, White list type(udsconnect)");
#endif
	qtinfo_out("  -x, Add a qtfs white list path(example: -x /home/, must use with -w)");
	qtinfo_out("  -y, Delete a qtfs white list with index(example: -y 1, must use with -w)");
	qtinfo_out("  -z, Get all qtfs white list(just use -z, or with white list type)");
}

int main(int argc, char *argv[])
{
#define MAX_CAP_LEN 16
	int ret = -1;
	int ch;
	char wl_cap[MAX_CAP_LEN] = {0};
	if ((argc == 1) || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
		qtinfo_help(argv[0]);
		return -1;
	}
	int fd = open(QTFS_DEV_NAME, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		qtinfo_err("open file %s failed.", QTFS_DEV_NAME);
#ifdef QTINFO_RELEASE
		return -1;
#endif
	}
#ifndef QTINFO_RELEASE
	while ((ch = getopt(argc, argv, "acl:tp:usw:x:y:z::")) != -1) {
#else
	while ((ch = getopt(argc, argv, "w:x:y:z::")) != -1) {
#endif
		switch (ch) {
#ifndef QTINFO_RELEASE
			case 'a':
				ret = qtinfo_opt_a(fd);
				break;
			case 'c':
				ret = qtinfo_opt_c(fd);
				break;
			case 'l':
				ret = qtinfo_opt_l(fd, optarg);
				break;
			case 't':
				ret = qtinfo_opt_t(fd);
				break;
			case 'p':
				ret = qtinfo_opt_p(fd, optarg);
				break;
			case 'u':
				ret = qtinfo_opt_u();
				break;
			case 's':
				ret = qtinfo_opt_s();
				break;
#endif
			case 'w':
				strncpy(wl_cap, optarg, MAX_CAP_LEN - 1);
				break;
			case 'x':
				ret = qtinfo_opt_x(fd, optarg, wl_cap);
				break;
			case 'y':
				ret = qtinfo_opt_y(fd, optarg, wl_cap);
				break;
			case 'z':
				ret = qtinfo_opt_z(fd, optarg);
				break;
			default:
				ret = 0;
				qtinfo_help(argv[0]);
				break;
		}
	}

	close(fd);
	return ret;
}
