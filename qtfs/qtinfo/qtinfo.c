#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

#include "qtinfo.h"
#include "comm.h"

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

	{QTFS_REQ_EPOLL_EVENT,		"epollevent"},
};

static void qtinfo_events_count(struct qtinfo *evts)
{
	unsigned long total = 0;
	int i;
#ifdef client
	qtinfo_out("++++++++++++++++++++++++++send events count++++++++++++++++++++++++++");
	for (i = 0; i < (sizeof(qtinfo_all_events)/sizeof(struct qtinfo_type_str)) - 3; i+=3) {
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
	total=0;
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

static void qtinfo_opt_a(int fd)
{
	struct qtinfo *diag = (struct qtinfo *)malloc(sizeof(struct qtinfo));
	if (diag == NULL) {
		qtinfo_err("malloc failed.");
		return;
	}
	memset(diag, 0, sizeof(struct qtinfo));
	int ret = ioctl(fd, QTFS_IOCTL_ALLINFO, diag);
	if (ret < 0) {
		qtinfo_err("ioctl failed, ret:%d.", ret);
		goto end;
	}
	qtinfo_events_count(diag);
	qtinfo_misc_count(diag);
	qtinfo_log_level(diag);
	qtinfo_thread_state(diag);
	qtinfo_pvar_count(diag);
end:
	free(diag);
	return;
}

void qtinfo_opt_c(int fd)
{
	int ret = ioctl(fd, QTFS_IOCTL_CLEARALL, NULL);
	return;
}

void qtinfo_opt_l(int fd, char *level)
{
	int ret;

	ret = ioctl(fd, QTFS_IOCTL_LOGLEVEL, level);
	if (ret != 0) {
		qtinfo_out("Set qtfs log level:%s failed.", level);
		return;
	}
	qtinfo_out("Set qtfs log level to %s success.", level);
	return;
}

void qtinfo_opt_t(int fd)
{
	int i;
	struct qtinfo *diag = (struct qtinfo *)malloc(sizeof(struct qtinfo));
	if (diag == NULL) {
		qtinfo_err("malloc failed.");
		return;
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
	return;
}

static void qtinfo_help(char *exec)
{
	qtinfo_out("Usage: %s [OPTION].", exec);
	qtinfo_out("Display qtfs client/server diagnostic information.");
	qtinfo_out("  -a, All diag info.");
	qtinfo_out("  -c, Clear all diag info.");
	qtinfo_out("  -l, Set log level(valid param: \"NONE\", \"ERROR\", \"WARN\", \"INFO\", \"DEBUG\").");
	qtinfo_out("  -t, For test informations.");
}

int main(int argc, char *argv[])
{
	int ch;
	if ((argc == 1) || (argc == 2 && strcmp(argv[1], "--help") == 0))
		qtinfo_help(argv[0]);
	int fd = open(QTFS_DEV_NAME, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		qtinfo_err("open file %s failed.", QTFS_DEV_NAME);
		return 0;
	}
	while ((ch = getopt(argc, argv, "acl:t")) != -1) {
		switch (ch) {
			case 'a':
				qtinfo_opt_a(fd);
				break;
			case 'c':
				qtinfo_opt_c(fd);
				break;
			case 'l':
				qtinfo_opt_l(fd, optarg);
				break;
			case 't':
				qtinfo_opt_t(fd);
				break;
			default:
				qtinfo_help(argv[0]);
				break;
		}
	}

	close(fd);
	return 0;
}
