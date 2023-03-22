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

#define REXEC_PIDMAP_PATH "/var/run/rexec/pids"

static int rexec_conn_to_server()
{
    struct rexec_conn_arg arg;
    arg.cs = REXEC_SOCK_CLIENT;
    strncpy(arg.sun_path, REXEC_UDS_CONN, sizeof(arg.sun_path));
    arg.udstype = SOCK_STREAM;
    if (0 != rexec_build_unix_connection(&arg))
        return -1;
    return arg.connfd;
}

static int rexec_calc_argv_len(int argc, char *argv[])
{
    int len = 0;
    for (int i = 0; i < argc; i++) {
        if (argv[i] == NULL) {
            rexec_err("Invalid argv index:%d", i);
            return len;
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
        strcpy(&msg[offset], argv[i]);
        offset += (strlen(argv[i]) + 1);
    }
    return offset;
}

static int rexec_io(int infd, int outfd, char *buf, int buflen)
{
    int len;
    int ret;
    while ((len = read(infd, buf, buflen)) > 0) {
        ret = write(outfd, buf, len);
        if (ret <= 0) {
            rexec_err("Read from fd:%d len:%d write to fd:%d failed ret:%d", infd, len, outfd, ret);
            return -1;
        }
        if (ret != len) {
            rexec_err("Read from fd:%d len:%d but write to fd:%d ret:%d", infd, len, outfd, ret);
        }
    }
    return 0;
}

// return -1 means process exit.
static int rexec_conn_msg(int connfd, int *exit_status, int *pidfd)
{
    struct rexec_msg head;
    int ret = recv(connfd, &head, sizeof(struct rexec_msg), MSG_WAITALL);
    if (ret <= 0) {
        rexec_err("Rexec conn recv err:%d errstr:%s", ret, strerror(errno));
        return -1;
    }
    switch (head.msgtype) {
        case REXEC_KILL:
            *exit_status = head.exit_status;
            rexec_err("Rexec conn recv kill msg, exit:%d now.", head.exit_status);
            return -1;
        case REXEC_PIDMAP: {
            int mypid = getpid();
            int peerpid = head.pid;
            char path[32] = {0};
            char buf[16] = {0};
            int fd;
            if (*pidfd > 0) {
                rexec_err("Rexec pidmap msg > 1 error.");
                return 0;
            }
            sprintf(path, "%s/%d", REXEC_PIDMAP_PATH, mypid);
            fd = open(path, O_CREAT|O_WRONLY, 0600);
            if (fd < 0) {
                rexec_err("Rexec create pidmap:%d-%d failed, path:%s open failed:%d",
                            mypid, peerpid, path, fd);
                break;
            }
            *pidfd = fd;
            if (0 != flock(fd, LOCK_EX)) {
                rexec_err("Rexec flock file:%s failed.", path);
            }
            ftruncate(fd, 0);
            lseek(fd, 0, SEEK_SET);
            sprintf(buf, "%d", peerpid);
            write(fd, buf, strlen(buf));
            break;
        }
        default:
            break;
    }

    rexec_log("Rexec conn recv msgtype:%d argc:%d stdno:%d msglen:%d",
                    head.msgtype, head.argc, head.stdno, head.msglen);
    return 0;
}

enum {
    REPOL_IN_INDEX = 0,
    REPOL_OUT_INDEX,
    REPOL_ERR_INDEX,
    REPOL_CONN_INDEX,
    REPOL_INV_INDEX,
};
static int rexec_run(int rstdin, int rstdout, int rstderr, int connfd, char *argv[])
{
    int exit_status = EXIT_FAILURE;
#define REXEC_MAX_EVENTS 4
    int infds[4] = {STDIN_FILENO, rstdout, rstderr, connfd};
    int outfds[4] = {rstdin, STDOUT_FILENO, STDERR_FILENO, connfd};

    int efd = epoll_create1(0);
    if (efd == -1) {
        rexec_err("epoll create1 failed, err:%s.", strerror(errno));
        return exit_status;
    }
    struct epoll_event evt;
    for (int i = 0; i < REPOL_INV_INDEX; i++) {
        evt.data.u32 = i;
        evt.events = EPOLLIN;
        if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, infds[i], &evt)) {
            rexec_err("epoll ctl add fd:%d event failed and ignore this mistake.", infds[i]);
            continue;
        } else {
            if (rexec_set_nonblock(infds[i], 1) != 0) {
                rexec_err("rexec set fd:%d i:%d non block failed.", infds[i], i)
            }
        }
    }

    struct epoll_event *evts = calloc(REXEC_MAX_EVENTS, sizeof(struct epoll_event));
        if (evts == NULL) {
        rexec_err("init calloc evts failed.");
        goto end;
    }
    int buflen = REXEC_MSG_LEN;
    char *buf = (char *)malloc(buflen);
    int pidfd = -1;
    if (buf == NULL) {
        rexec_err("Rexec malloc failed.");
        goto free_end;
    }
    rexec_log("Rexec process start run, as proxy of remote %s", argv[1]);
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
            int infd = -1;
            int outfd = -1;
            if (evts[i].data.u32 >= REPOL_INV_INDEX) {
                rexec_err("invalid epoll events index data:%d", evts[i].data.u32);
                continue;
            }
            infd = infds[evts[i].data.u32];
            outfd = outfds[evts[i].data.u32];
            if (infd == connfd) {
                if (evts[i].events & EPOLLHUP || rexec_conn_msg(connfd, &exit_status, &pidfd) == -1)
                    process_exit = 1;
            } else {
                if (rexec_io(infd, outfd, buf, buflen) == -1) {
                    close(infd);
                }
            }
        }
        if (process_exit) {
            rexec_log("Rexec process %s exit.", argv[1]);
            break;
        }
    }

    // clear pidmap file
    if (pidfd > 0) {
        char path[32] = {0};
        sprintf(path, "%s/%d", REXEC_PIDMAP_PATH, getpid());
        close(pidfd);
        remove(path);
    }

    free(buf);

free_end:
    free(evts);

end:
    close(efd);
    return exit_status;
}

void rexec_create_pidmap_path()
{
    if (access(REXEC_RUN_PATH, F_OK) != 0) {
        mkdir(REXEC_RUN_PATH, 0755);
    }
    mkdir(REXEC_PIDMAP_PATH, 0755);
    return;
}

void rexec_clear_pids()
{
    char path[32] = {0};
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

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
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
    struct stat st;
    char path[32] = {0};
    if (fstat(fd, &st) != 0) {
        rexec_err("get fd:%d fstat failed, errstr:%s", fd, strerror(errno));
        return 0;
    }
    if (S_ISREG(st.st_mode)) {
        return 1;
    }
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
        return NULL;
    }

    fddir = opendir("/proc/self/fd");
    if (fddir == NULL) {
        free(fdinfo);
        rexec_err("open path:%s failed", REXEC_PIDMAP_PATH);
        return NULL;
    }

    struct json_object *files_arr = json_object_new_array();

    while (fdentry = readdir(fddir)) {
        struct json_object *fd_obj = json_object_new_object();
        struct json_object *item = NULL;

        memset(fdinfo, 0, sizeof(struct rexec_fdinfo));
        if (rexec_get_fdinfo(fdentry, fdinfo) != 0)
            continue;
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
}

int main(int argc, char *argv[])
{
    rexec_log_init();
    rexec_clear_pids();

    int connfd = rexec_conn_to_server();
    if (connfd < 0) {
        rexec_err("Rexec connect to server failed, err:%s", strerror(errno));
        return -1;
    }
    rexec_log("Remote exec binary:%s", argv[1]);
    int arglen = rexec_calc_argv_len(argc - 1, &argv[1]);
    char *fds_json = rexec_get_fds_jsonstr();
    if (fds_json == NULL) {
        rexec_err("Get fds info json string failed.");
        return -1;
    }
    arglen += sizeof(struct rexec_msg);
    arglen += strlen(fds_json);
    arglen = ((arglen / REXEC_MSG_LEN) + 1) * REXEC_MSG_LEN;

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
    pmsg->stdno = REXEC_STDIN;
    if (rexec_sendmsg(connfd, (char *)pmsg, sizeof(struct rexec_msg) + pmsg->msglen, rstdin[0]) < 0) {
        rexec_err("Rexec send exec msg failed, err:%s", strerror(errno));
        goto err_end;
    }
    rexec_log("Normal msg send len:%d head:%d", sizeof(struct rexec_msg) + pmsg->msglen, sizeof(struct rexec_msg));
    pmsg->msgtype = REXEC_PIPE;
    pmsg->argc = 0;
    pmsg->msglen = 0;
    pmsg->stdno = REXEC_STDOUT;
    if (rexec_sendmsg(connfd, (char *)pmsg, sizeof(struct rexec_msg), rstdout[1]) < 0) {
        rexec_err("Rexec send exec msg failed, err:%s", strerror(errno));
        goto err_end;
    }
    pmsg->stdno = REXEC_STDERR;
    if (rexec_sendmsg(connfd, (char *)pmsg, sizeof(struct rexec_msg), rstderr[1]) < 0) {
        rexec_err("Rexec send exec msg failed, err:%s", strerror(errno));
        goto err_end;
    }
    free(pmsg);

    int exit_status;
    close(rstdin[0]);
    close(rstdout[1]);
    close(rstderr[1]);
    exit_status = rexec_run(rstdin[1], rstdout[0], rstderr[0], connfd, argv);
    close(rstdin[1]);
    close(rstdout[0]);
    close(rstderr[0]);
    fclose(rexec_logfile);

    exit(exit_status);
err_end:
    fclose(rexec_logfile);
    free(pmsg);
    return -1;
}
