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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <json-c/json_object.h>

#include "dirent.h"

#include "rexec_sock.h"
#include "rexec.h"

#define REXEC_MSG_LEN 1024
FILE *rexec_logfile = NULL;

struct rexec_global_var {
	int rexec_hs_fd[2];
};

struct rexec_thread_arg {
	int efd;
	int connfd;
	char **argv;
};

struct rexec_global_var g_rexec;


struct rexec_client_event {
	int fd;
	int outfd; // for stdin out err and other pipe
	int (*handler)(struct rexec_client_event *);
	int *exit_status;
	int *pidfd;
};

#define REXEC_PIDMAP_PATH "/var/run/rexec/pids"
#define REXEC_PIDMAP_PATH_LEN 64
#define REXEC_PID_LEN   16
static int rexec_conn_to_server()
{
	struct rexec_conn_arg arg;
	char *ret = strncpy(arg.sun_path, REXEC_UDS_CONN, sizeof(arg.sun_path));
	if (ret == NULL) {
		rexec_err("strncpy sun path failed");
		return -1;
	}
	arg.cs = REXEC_SOCK_CLIENT;
	arg.udstype = SOCK_STREAM;
	if (rexec_build_unix_connection(&arg) != 0)
		return -1;
	return arg.connfd;
}

static int rexec_calc_argv_len(int argc, char *argv[])
{
	int len = 0;
	for (int i = 0; i < argc; i++) {
		if (argv[i] == NULL) {
			rexec_err("Invalid argv index:%d", i);
			return -1;
		}
		len += strlen(argv[i]);
		len++;
	}
	return len;
}

static int rexec_msg_fill_argv(int argc, char *argv[], char *msg)
{
	int offset = 0;
	for (int i = 0; i < argc; i++) {
		strcpy(&msg[offset], argv[i]); //此处msg已经在前面通过计算出的len预先分配内存，保证这里不会越界
		offset += (strlen(argv[i]) + 1);
	}
	return offset;
}

static int rexec_io(struct rexec_client_event *evt)
{
#define MAX_MSG_LEN 256
	char buf[MAX_MSG_LEN];
	int len;
	int ret;
	while ((len = read(evt->fd, buf, MAX_MSG_LEN)) > 0) {
		ret = write(evt->outfd, buf, len);
		if (ret <= 0) {
			rexec_err("Read from fd:%d len:%d write to fd:%d failed ret:%d", evt->fd, len, evt->outfd, ret);
			return REXEC_EVENT_DEL;
		}
		if (ret != len) {
			rexec_err("Read from fd:%d len:%d but write to fd:%d ret:%d", evt->fd, len, evt->outfd, ret);
		}
	}
	return REXEC_EVENT_OK;
}

// return -1 means process exit.
static int rexec_conn_msg(struct rexec_client_event *evt)
{
	struct rexec_msg head;
	int ret = recv(evt->fd, &head, sizeof(struct rexec_msg), MSG_WAITALL);
	if (ret <= 0) {
		rexec_err("Rexec conn recv err:%d errno:%d", ret, errno);
		return REXEC_EVENT_EXIT;
	}
	switch (head.msgtype) {
		case REXEC_KILL:
			*evt->exit_status = head.exit_status;
			rexec_err("Rexec conn recv kill msg, exit:%d now.", head.exit_status);
			return REXEC_EVENT_EXIT;
		case REXEC_PIDMAP: {
			int mypid = getpid();
			int peerpid = head.pid;
			char path[REXEC_PIDMAP_PATH_LEN] = {0};
			char buf[REXEC_PID_LEN] = {0};
			int fd;
			int err;
			if (*evt->pidfd > 0) {
				rexec_err("Rexec pidmap msg > 1 error.");
				return REXEC_EVENT_OK;
			}
			sprintf(path, "%s/%d", REXEC_PIDMAP_PATH, mypid);
			fd = open(path, O_CREAT|O_WRONLY, 0600);
			if (fd < 0) {
				rexec_err("Rexec create pidmap:%d-%d failed, path:%s open failed:%d",
							mypid, peerpid, path, fd);
				break;
			}
			*evt->pidfd = fd;
			if ((err = flock(fd, LOCK_EX)) != 0) {
				rexec_err("Rexec flock file:%s failed, errno:%d rexec exit.", path, err);
				return REXEC_EVENT_EXIT;
			}
			if ((err = ftruncate(fd, 0)) != 0) {
				rexec_err("Rexec pidmap file:%s clear failed errno:%d rexec exit.", path, err);
				return REXEC_EVENT_EXIT;
			}
			if ((err = lseek(fd, 0, SEEK_SET)) < 0) {
				rexec_err("Rexec pidmap file:%s lseek 0 failed errno:%d rexec exit", path, err);
				return REXEC_EVENT_EXIT;
			}
			sprintf(buf, "%d", peerpid);
			if ((err = write(fd, buf, strlen(buf))) <= 0) {
				rexec_err("Rexec pidmap file:%s write pid:%d failed errno:%d rexec exit.", path, peerpid, err);
				return REXEC_EVENT_EXIT;
			}
			if (g_rexec.rexec_hs_fd[PIPE_WRITE] != -1 && g_rexec.rexec_hs_fd[PIPE_READ] != -1) {
				err = write(g_rexec.rexec_hs_fd[PIPE_WRITE], "1", 1);
				if (err <= 0) {
					rexec_err("rexec handshake write 1 failed, hs write:%d.", g_rexec.rexec_hs_fd[PIPE_WRITE]);
					return REXEC_EVENT_ERR;
				}
			} else {
				char msg[sizeof(struct rexec_msg) + 1];
				struct rexec_msg *hs = msg;
				char *ok = hs->msg;
				hs->msgtype = REXEC_HANDSHAKE;
				hs->msglen = 1;
				*ok = '1';
				if (write(evt->fd, hs, sizeof(struct rexec_msg) + 1) <= 0) {
					rexec_err("send handshake failed, remote process will die");
					return REXEC_EVENT_EXIT;
				}
			}
			break;
		}
		default:
			break;
	}

	rexec_log("Rexec conn recv msgtype:%d argc:%d pipefd:%d msglen:%d",
					head.msgtype, head.argc, head.pipefd, head.msglen);
	return REXEC_EVENT_OK;
}

static struct rexec_client_event *rexec_add_event(int efd, int fd, int outfd, int (*handler)(struct rexec_client_event *))
{
	struct rexec_client_event *event = (struct rexec_client_event *)malloc(sizeof(struct rexec_client_event));
	if (event == NULL) {
		rexec_err("malloc failed.");
		return NULL;
	}
	event->fd = fd;
	event->outfd = outfd;
	event->handler = handler;
	struct epoll_event evt;
	evt.data.ptr = (void *)event;
	evt.events = EPOLLIN;
	if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, event->fd, &evt)) {
		rexec_err("epoll ctl add fd:%d event failed.", event->fd);
		free(event);
		return NULL;
	}
	return event;
}

static int rexec_del_event(struct rexec_client_event *event)
{
	// close will del fd in epoll list
	close(event->fd);
	free(event);
	return 0;
}

enum {
	REPOL_IN_INDEX = 0,
	REPOL_OUT_INDEX,
	REPOL_ERR_INDEX,
	REPOL_INV_INDEX,
};
static int rexec_std_event(int efd, int rstdin, int rstdout, int rstderr)
{
	#define REXEC_MAX_EVENTS 4
	int infds[REPOL_INV_INDEX] = {STDIN_FILENO, rstdout, rstderr};
	int outfds[REPOL_INV_INDEX] = {rstdin, STDOUT_FILENO, STDERR_FILENO};

	for (int i = 0; i < REPOL_INV_INDEX; i++) {
		if (NULL == rexec_add_event(efd, infds[i], outfds[i], rexec_io)) {
			rexec_err("epoll ctl add fd:%d event failed and ignore this mistake.", infds[i]);
			continue;
		} else {
			if (rexec_set_nonblock(infds[i], 1) != 0) {
				rexec_err("rexec set fd:%d i:%d non block failed.", infds[i], i);
				return -1;
			}
		}
	}
	return 0;
}

static void rexec_event_run(int efd)
{
	struct epoll_event *evts = calloc(REXEC_MAX_EVENTS, sizeof(struct epoll_event));
	if (evts == NULL) {
		rexec_err("init calloc evts failed.");
		return;
	}
	while (1) {
		int n = epoll_wait(efd, evts, REXEC_MAX_EVENTS, 1000);
		int process_exit = 0;
		if (n == 0)
			continue;
		if (n < 0) {
			rexec_err("epoll wait return errcode:%d", n);
			continue;
		}
		for (int i = 0; i < n; i++) {
			struct rexec_client_event *evt = (struct rexec_client_event *)evts[i].data.ptr;
			int ret = evt->handler(evt);
			if (ret == REXEC_EVENT_EXIT) {
				process_exit = 1;
			}
			if (ret == REXEC_EVENT_DEL) {
				rexec_del_event(evt);
			}
		}
		// process will exit, and free all resource and exit
		if (process_exit) {
			break;
		}
	}
	free(evts);
	return;
}

static int rexec_run(int efd, int connfd, char *argv[])
{
	int pidfd = -1;
	int exit_status = EXIT_FAILURE;

	struct rexec_client_event *connevt = rexec_add_event(efd, connfd, -1, rexec_conn_msg);
	if (NULL == connevt || rexec_set_nonblock(connfd, 1) != 0) {
		// process will exit, fd or mem resource will free by kernel soon
		rexec_err("rexec add connfd event failed");
		return exit_status;
	}
	// 这两个指针只能在当前函数上下文使用，是当前函数栈指针
	connevt->exit_status = &exit_status;
	connevt->pidfd = &pidfd;

	rexec_log("Rexec process start run, as proxy of remote %s", argv[1]);
	rexec_event_run(efd);
	rexec_log("Rexec process %s exit.", argv[1]);

	// clear pidmap file
	if (pidfd > 0) {
		char path[32] = {0};
		sprintf(path, "%s/%d", REXEC_PIDMAP_PATH, getpid());
		close(pidfd);
		remove(path);
	}

end:
	close(efd);
	return exit_status;
}

void rexec_create_pidmap_path()
{
	if (access(REXEC_RUN_PATH, F_OK) != 0) {
		mkdir(REXEC_RUN_PATH, 0700);
	}
	mkdir(REXEC_PIDMAP_PATH, 0700);
	return;
}

void rexec_clear_pids()
{
	char path[REXEC_PIDMAP_PATH_LEN] = {0};
	DIR *dir = NULL;
	struct dirent *entry;
	if (access(REXEC_PIDMAP_PATH, F_OK) != 0) {
		rexec_create_pidmap_path();
		return;
	}
	dir = opendir(REXEC_PIDMAP_PATH);
	if (dir == NULL) {
		rexec_err("open path:%s failed", REXEC_PIDMAP_PATH);
		return;
	}
	while (entry = readdir(dir)) {
		int fd;

		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
			strlen(entry->d_name) >= REXEC_PID_LEN)
			continue;

		memset(path, 0, sizeof(path));
		sprintf(path, "%s/%s", REXEC_PIDMAP_PATH, entry->d_name);
		fd = open(path, O_RDONLY);
		if (fd <= 0) {
			rexec_err("open pid file:%s failed", path);
			continue;
		}
		if (flock(fd, LOCK_EX|LOCK_NB) != 0) {
			close(fd);
			continue;
		}
		close(fd);
		if (remove(path) != 0) {
			rexec_err("remove unuse pidmap file:%s failed", path);
		}
	}

	closedir(dir);
	return;
}

#define REXEC_PATH_MAX 4096
struct rexec_fdinfo {
	int fd;
	char path[REXEC_PATH_MAX];
	unsigned int perm;
	int offset;
};

static inline int rexec_is_reg_file(int fd)
{
	if (S_ISREG(rexec_fd_mode(fd)))
		return 1;
	return 0;
}

static int rexec_get_fdinfo(struct dirent *fdentry, struct rexec_fdinfo *fdinfo)
{
	char path[32] = {0};
	int ret;
	int fd = atoi(fdentry->d_name);
	if (fd <= STDERR_FILENO || fd == fileno(rexec_logfile))
		return -1;
	if (!rexec_is_reg_file(fd))
		return -1;
	sprintf(path, "/proc/self/fd/%s", fdentry->d_name);
	ret = readlink(path, fdinfo->path, REXEC_PATH_MAX);
	if (ret < 0) {
		rexec_err("Get fd:%d link failed.", fd);
		return -1;
	}
	fdinfo->fd = fd;
	fdinfo->offset = lseek(fd, 0, SEEK_CUR);

	fdinfo->perm = fcntl(fd, F_GETFL, NULL);
	if (fdinfo->perm == -1) {
		rexec_err("Get fd:%d flags failed", fd);
		return -1;
	}
	return 0;
}
// 返回一个拼装好的json格式字符串，内存在内部申请好
// 由调用者释放
// 内容是本进程所有REG类型文件的信息
static char *rexec_get_fds_jsonstr()
{
	struct json_object *root = json_object_new_object();
	char *json_str;
	int len;
	DIR *fddir = NULL;
	struct dirent *fdentry;
	struct rexec_fdinfo *fdinfo;
	if (root == NULL) {
		rexec_err("create json-c root failed.");
		return NULL;
	}
	fdinfo = (struct rexec_fdinfo *)malloc(sizeof(struct rexec_fdinfo));
	if (fdinfo == NULL) {
		rexec_err("malloc failed.");
		goto err_end;
	}

	fddir = opendir("/proc/self/fd");
	if (fddir == NULL) {
		free(fdinfo);
		rexec_err("open path:/proc/self/fd failed");
		goto err_end;
	}

	struct json_object *files_arr = json_object_new_array();

	while (fdentry = readdir(fddir)) {
		struct json_object *fd_obj = json_object_new_object();
		struct json_object *item = NULL;

		if (fd_obj == NULL) {
			rexec_err("json c new object failed.");
			goto json_err;
		}
		memset(fdinfo, 0, sizeof(struct rexec_fdinfo));
		if (rexec_get_fdinfo(fdentry, fdinfo) != 0) {
			json_object_put(fd_obj);
			continue;
		}
		item = json_object_new_int(fdinfo->fd);
		json_object_object_add(fd_obj, "Fd", item);
		item = json_object_new_string(fdinfo->path);
		json_object_object_add(fd_obj, "Path", item);
		item = json_object_new_int(fdinfo->perm);
		json_object_object_add(fd_obj, "Perm", item);
		item = json_object_new_int(fdinfo->offset);
		json_object_object_add(fd_obj, "Offset", item);

		json_object_array_add(files_arr, fd_obj);
	}
	closedir(fddir);
	free(fdinfo);

	json_object_object_add(root, "Files", files_arr);
	json_str = strdup(json_object_get_string(root));
	json_object_put(root);

	return json_str;

json_err:
	closedir(fddir);
	free(fdinfo);
err_end:
	json_object_put(root);
	return NULL;
}

// 将rexec进程从parent继承到的匿名pipe继承给远端进程
static int rexec_pipe_remote_inherit(int efd, int connfd)
{
#define SELF_FD_PATH "/proc/self/fd"
	DIR *fddir = NULL;
	struct dirent *fdentry;
	struct rexec_msg msg;
	mode_t mode;
	int pfd[2];

	fddir = opendir(SELF_FD_PATH);
	if (fddir == NULL) {
		rexec_err("open path:%s failed", SELF_FD_PATH);
		return -1;
	}
	memset(&msg, 0, sizeof(struct rexec_msg));
	msg.msglen = 0;
	msg.pipefd = -1;
	msg.msgtype = REXEC_PIPE;
	while (fdentry = readdir(fddir)) {
		int fd = atoi(fdentry->d_name);
		if (fd <= STDERR_FILENO)
			continue;
		mode = rexec_fd_mode(fd);
		if (!S_ISFIFO(mode))
			continue;
		rexec_log("inherit pipe fd:%d mode:%o is %s pipe", fd, mode, (!!(mode & S_IRUSR)) ? "read" : "write");
		if (pipe(pfd) == -1) {
			rexec_err("failed to create pipe for:%d", fd);
			goto err_end;
		}
		msg.pipefd = fd;
		if (!!(mode & S_IRUSR)) {
			// inherit read pipe
			if (rexec_sendmsg(connfd, (char *)&msg, sizeof(struct rexec_msg), pfd[PIPE_READ]) < 0) {
				rexec_err("send read pipe failed, inherit fd:%d", fd);
				goto pipe_end;
			}
			if (rexec_add_event(efd, fd, pfd[PIPE_WRITE], rexec_io) == NULL) {
				rexec_err("add read pipe event failed:%d", fd);
				goto pipe_end;
			}
			close(pfd[PIPE_READ]);
		} else if (!!(mode & S_IWUSR)) {
			if (rexec_sendmsg(connfd, (char *)&msg, sizeof(struct rexec_msg), pfd[PIPE_WRITE]) < 0) {
				rexec_err("send write pipe failed, inherit fd:%d", fd);
				goto pipe_end;
			}
			if (rexec_add_event(efd, pfd[PIPE_READ], fd, rexec_io) == NULL) {
				rexec_err("add write pipe event failed:%d", fd);
				goto pipe_end;
			}
			close(pfd[PIPE_WRITE]);
		}
		rexec_log("successed to add pipe fd:%d to remote inherit", fd);
	}
	closedir(fddir);
	return 0;

pipe_end:
	close(pfd[0]);
	close(pfd[1]);
err_end:
	closedir(fddir);
	return -1;
}

static int rexec_handshake_proc(struct rexec_client_event *evt)
{
	char msg[sizeof(struct rexec_msg) + 1];
	struct rexec_msg *hs = msg;
	int ret = read(evt->fd, hs->msg, 1);
	if (ret <= 0) {
		rexec_err("read from handshake pipe failed, ret:%d err:%d", ret, errno);
		return REXEC_EVENT_DEL;
	}
	hs->msgtype = REXEC_HANDSHAKE;
	hs->msglen = 1;
	ret = write(evt->outfd, hs, sizeof(struct rexec_msg) + 1);
	if (ret < 0) {
		rexec_err("send handshake failed, connfd:%d.", evt->outfd);
	}
	return REXEC_EVENT_OK;
}

static int rexec_handshake_init(int efd, int connfd)
{
	char *hs_read = getenv("REXEC_HANDSHAKE_RD");
	if (hs_read == NULL) {
		rexec_log("handshake not in effect, read:%lx", hs_read);
		return 0;
	}
	g_rexec.rexec_hs_fd[PIPE_READ] = atoi(hs_read);

	char *hs_write = getenv("REXEC_HANDSHAKE_WR");
	if (hs_write == NULL) {
		rexec_log("handshake not in effect, wirte:%lx", hs_write);
		g_rexec.rexec_hs_fd[PIPE_READ] = -1;
		return 0;
	}
	g_rexec.rexec_hs_fd[PIPE_WRITE] = atoi(hs_write);

	if (g_rexec.rexec_hs_fd[PIPE_READ] <= STDERR_FILENO || g_rexec.rexec_hs_fd[PIPE_WRITE] <= STDERR_FILENO) {
		rexec_log("handshake invalid fd read:%d write:%d", g_rexec.rexec_hs_fd[PIPE_READ], g_rexec.rexec_hs_fd[PIPE_WRITE]);
		goto err_end;
	}
	if (!S_ISFIFO(rexec_fd_mode(g_rexec.rexec_hs_fd[PIPE_READ])) || !S_ISFIFO(rexec_fd_mode(g_rexec.rexec_hs_fd[PIPE_WRITE]))) {
		rexec_err("handshake fd mode not fifo:%d %d", g_rexec.rexec_hs_fd[PIPE_READ], g_rexec.rexec_hs_fd[PIPE_WRITE]);
		goto err_end;
	}
	if (rexec_add_event(efd, g_rexec.rexec_hs_fd[PIPE_READ], connfd, rexec_handshake_proc) == NULL) {
		rexec_err("add handshake pipe read fd:%d to epoll failed", g_rexec.rexec_hs_fd[PIPE_READ]);
		goto err_end;
	}
	rexec_log("handshake effect read:%d write:%d", g_rexec.rexec_hs_fd[PIPE_READ], g_rexec.rexec_hs_fd[PIPE_WRITE]);
	return 0;
err_end:
	g_rexec.rexec_hs_fd[PIPE_READ] = -1;
	g_rexec.rexec_hs_fd[PIPE_WRITE] = -1;
	return -1;
}

static int rexec_send_binary_msg(int efd, int argc, char *argv[], int arglen, char *fds_json, int connfd)
{
	struct rexec_msg *pmsg = (struct rexec_msg *)malloc(arglen);
	if (pmsg == NULL) {
		rexec_err("malloc failed");
		free(fds_json);
		return -1;
	}
	char *bufmsg = pmsg->msg;
	memset(pmsg, 0, arglen);
	pmsg->msgtype = REXEC_EXEC;
	pmsg->argc = argc - 1; // for remote binary's argc is argc-1
	// pmsg->msg is like: "binary"\0"argv[1]"\0"argv[2]"\0"..."
	pmsg->msglen = rexec_msg_fill_argv(pmsg->argc, &argv[1], bufmsg);
	strcpy(&bufmsg[pmsg->msglen], fds_json);
	pmsg->msglen += strlen(fds_json);
	free(fds_json);

	// pipefd[0] -- for read; pipefd[1] -- for write.
	// rexec stdin -->  rstdin[1]  ------> rstdin[0] as stdin
	// rexec stdout <-- rstdout[0] <------ rstdout[1] as stdout
	// rexec stderr <-- rstderr[0] <------ rstderr[1] as stderr
	int rstdin[2];
	int rstdout[2];
	int rstderr[2];

	if (pipe(rstdin) == -1 || pipe(rstdout) == -1 || pipe(rstderr) == -1) {
		rexec_err("Rexec create pipe failed.");
		goto err_end;
	}
	pmsg->pipefd = REXEC_STDIN;
	if (rexec_sendmsg(connfd, (char *)pmsg, sizeof(struct rexec_msg) + pmsg->msglen, rstdin[0]) < 0) {
		rexec_err("Rexec send exec msg failed, errno:%d", errno);
		goto err_end;
	}
	rexec_log("Normal msg send len:%d head:%d", sizeof(struct rexec_msg) + pmsg->msglen, sizeof(struct rexec_msg));
	pmsg->msgtype = REXEC_PIPE;
	pmsg->argc = 0;
	pmsg->msglen = 0;
	pmsg->pipefd = REXEC_STDOUT;
	if (rexec_sendmsg(connfd, (char *)pmsg, sizeof(struct rexec_msg), rstdout[1]) < 0) {
		rexec_err("Rexec send exec msg failed, errno:%d", errno);
		goto err_end;
	}
	pmsg->pipefd = REXEC_STDERR;
	if (rexec_sendmsg(connfd, (char *)pmsg, sizeof(struct rexec_msg), rstderr[1]) < 0) {
		rexec_err("Rexec send exec msg failed, errno:%d", errno);
		goto err_end;
	}

	if (rexec_std_event(efd, rstdin[1], rstdout[0], rstderr[0]) != 0) {
		rexec_err("add std event failed");
		goto err_end;
	}
	free(pmsg);
	close(rstdin[0]);
	close(rstdout[1]);
	close(rstderr[1]);
	return 0;
err_end:
	free(pmsg);
	return -1;
}

static void *rexec_pipe_proxy_thread(void *arg)
{
	struct rexec_thread_arg *parg = (struct rexec_thread_arg *)arg;
	rexec_log("pipe proxy thread run.");
	rexec_event_run(parg->efd);
	rexec_log("pipe proxy thread run over");
	return NULL;
}

static void *rexec_conn_thread(void *arg)
{
	struct rexec_thread_arg *parg = (struct rexec_thread_arg *)arg;

	return (void *)rexec_run(parg->efd, parg->connfd, parg->argv);
}

static void rexec_global_var_init()
{
	memset(&g_rexec, 0, sizeof(g_rexec));
	g_rexec.rexec_hs_fd[PIPE_READ] = -1;
	g_rexec.rexec_hs_fd[PIPE_WRITE] = -1;
	return;
}

int main(int argc, char *argv[])
{
	rexec_log_init();
	rexec_clear_pids();

	int pipeefd = epoll_create1(0);
	int efd = epoll_create1(0);
	if (efd == -1 || pipeefd == -1) {
		rexec_err("epoll create1 failed, errno:%d.", errno);
		return -1;
	}
	rexec_global_var_init();

	int connfd = rexec_conn_to_server();
	if (connfd < 0) {
		rexec_err("Rexec connect to server failed, errno:%d", errno);
		return -1;
	}

	if (rexec_handshake_init(efd, connfd) != 0) {
		rexec_err("Rexec handshake environment set but get error.");
		return -1;
	}
	rexec_log("Remote exec binary:%s", argv[1]);
	/*if (rexec_pipe_remote_inherit(pipeefd, connfd) != 0) {
		rexec_err("Rexec pipe remote inherit failed.");
		goto err_end;
	}*/

	int arglen = rexec_calc_argv_len(argc - 1, &argv[1]);
	if (arglen <= 0) {
		rexec_err("argv is invalid.");
		return -1;
	}
	char *fds_json = rexec_get_fds_jsonstr();
	if (fds_json == NULL) {
		rexec_err("Get fds info json string failed.");
		return -1;
	}
	arglen += sizeof(struct rexec_msg);
	arglen += strlen(fds_json);
	arglen = ((arglen / REXEC_MSG_LEN) + 1) * REXEC_MSG_LEN;
	if (arglen <= 0) {
		rexec_err("invalid arguments length:%d.", arglen);
		free(fds_json);
		return -1;
	}

	if (rexec_send_binary_msg(efd, argc, argv, arglen, fds_json, connfd) != 0) {
		rexec_err("send binary information message failed.");
		goto err_end;
	}

	pthread_t thrd;
	pthread_t thrd_conn;
	struct rexec_thread_arg targ;
	struct rexec_thread_arg connarg;
	void *exit_status;
	targ.efd = pipeefd;
	(void)pthread_create(&thrd, NULL, rexec_pipe_proxy_thread, &targ);

	connarg.efd = efd;
	connarg.connfd = connfd;
	connarg.argv = argv;
	(void)pthread_create(&thrd_conn, NULL, rexec_conn_thread, &connarg);
	pthread_join(thrd_conn, (void *)&exit_status);
	fclose(rexec_logfile);
	exit((int)exit_status);
err_end:
	fclose(rexec_logfile);
	rexec_logfile = NULL;
	return -1;
}
