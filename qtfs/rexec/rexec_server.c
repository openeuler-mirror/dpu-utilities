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
#include <sys/wait.h>
#include <stdbool.h>
#include <glib.h>

#include "rexec_sock.h"
#include "rexec.h"

static int main_epoll_fd = -1;
FILE *rexec_logfile = NULL;
static GHashTable *child_hash = NULL;

#define REXEC_WHITELIST_MAX_ITEMS 256
struct rexec_white_list_str {
    int wl_nums;
    char *wl[REXEC_WHITELIST_MAX_ITEMS];
};
static struct rexec_white_list_str rexec_wl;

extern int rexec_shim_entry(int argc, char *argv[]);

int rexec_hash_insert_direct(GHashTable *table, int key, int value);
int rexec_hash_lookup_direct(GHashTable *table, int key);
void rexec_hash_remove_direct(GHashTable *table, int key);

struct rexec_event {
    int fd;
    union {
        int pid;
        int connfd;
    };
    int (*handler)(struct rexec_event *);
};

enum {
    REXEC_EVENT_OK,
    REXEC_EVENT_ERR,
    REXEC_EVENT_DEL,
};

static int rexec_add_event(int efd, int fd, int pid, int (*handler)(struct rexec_event *))
{
    struct rexec_event *event = (struct rexec_event *)malloc(sizeof(struct rexec_event));
    if (event == NULL) {
        rexec_err("malloc failed.");
        return -1;
    }
    event->fd = fd;
    event->pid = pid;
    event->handler = handler;
    struct epoll_event evt;
    evt.data.ptr = (void *)event;
    evt.events = EPOLLIN;
    if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, event->fd, &evt)) {
        rexec_err("epoll ctl add fd:%d event failed.", event->fd);
        return -1;
    }
    return 0;
}

static int rexec_del_event(int efd, struct rexec_event *event)
{
    int ret = epoll_ctl(efd, EPOLL_CTL_DEL, event->fd, NULL);
    if (ret != 0) {
        rexec_err("failed to delete event fd:%d.", event->fd);
    } else {
        rexec_log("event fd:%d deleted.", event->fd);
    }
    close(event->fd);
    free(event);
    return 0;
}

static int rexec_event_process_manage(struct rexec_event *event)
{
    struct rexec_msg head;
    int ret = recv(event->fd, &head, sizeof(struct rexec_msg), MSG_WAITALL);
    if (ret <= 0) {
        rexec_log("Event fd:%d recv ret:%d str:%s, peer rexec closed, kill the associated process:%d.",
                    event->fd, ret, strerror(errno), event->pid);
        kill(event->pid, SIGKILL);
        return REXEC_EVENT_DEL;
    }
    rexec_err("Recv msg from client, msgtype:%d msglen:%d argc:%d stdno:%d",
                head.msgtype, head.msglen, head.argc, head.stdno);
    return REXEC_EVENT_OK;
}

static int rexec_event_handshake(struct rexec_event *event)
{
    int sonpid = 0;
    int ret = read(event->fd, &sonpid, sizeof(int));
    if (ret <= 0) {
        rexec_err("Rexec read from pipe ret:%d err:%s", ret, strerror(errno));
        return REXEC_EVENT_DEL;
    }
    int connfd = event->connfd;
    if (sonpid == -1) {
        rexec_err("Handshake recv -1, dont add to process manage");
        close(connfd);
        return REXEC_EVENT_DEL;
    }
    rexec_log("Rexec recv son pid:%d, connfd:%d", sonpid, connfd);

    rexec_hash_insert_direct(child_hash, sonpid, connfd);
    
    struct rexec_msg head;
    head.msgtype = REXEC_PIDMAP;
    head.msglen = 0;
    head.pid = sonpid;
    ret = write(connfd, &head, sizeof(struct rexec_msg));
    if (ret <= 0) {
        rexec_err("Rexec send son pid:%d to client failed, ret:%d err:%s", sonpid, ret, strerror(errno));
    }
    rexec_add_event(main_epoll_fd, connfd, sonpid, rexec_event_process_manage);

    // 成功后同样要删除这个pipe监听事件，删除时会close掉fd
    return REXEC_EVENT_DEL;
}

static void rexec_dup_std(int fd, int stdno)
{
    if (stdno < REXEC_STDIN || stdno > REXEC_STDERR) {
        return;
    }
    dup2(fd, stdno - REXEC_STDIN);
    close(fd);
    return;
}

// argv list: [0]binary,[1]-f,[2]*json_str,[3]arg1,[4]arg2,...
static int rexec_parse_argv(int argc, char *argv_str, char *argv[])
{
    int offset = 0;
    for (int i = 0; i < argc; i++) {
        argv[i] = &argv_str[offset];
        offset += strlen(argv[i]) + 1;
    }
    argv[argc] = NULL;
    return offset;
}

static inline void rexec_clear_string_tail(char *str, int len)
{
    while (str[len] < 0x20) {
        str[len] = '\0';
        len--;
    }
    return;
}

#define REXEC_WHITELIST_FILE "/etc/rexec/whitelist"
static int rexec_whitelist_build(struct rexec_white_list_str *wl)
{
    if (access(REXEC_WHITELIST_FILE, F_OK) != 0)
        return 0;

    wl->wl_nums = 0;
    memset(wl->wl, 0, sizeof(uintptr_t) * REXEC_WHITELIST_MAX_ITEMS);
#define MAX_CMD_LEN 256
    char cmd[MAX_CMD_LEN];
    FILE *fwl = fopen(REXEC_WHITELIST_FILE, "r");
    if (fwl == NULL) {
        rexec_err("open white list file:%s failed.", REXEC_WHITELIST_FILE);
        return -1;
    }
    struct stat stats;
    int ret = fstat(fileno(fwl), &stats);
    if (ret != 0) {
        rexec_err("fstat white list file:%s failed.", REXEC_WHITELIST_FILE);
        goto err_end;
    }
    if (stats.st_mode & 0777 != 0400) {
        rexec_err("white list file:%s permissions(%o) error, must be read-only(0400)", stats.st_mode, REXEC_WHITELIST_FILE);
        goto err_end;
    }
    while (!feof(fwl) && wl->wl_nums < REXEC_WHITELIST_MAX_ITEMS) {
        int len;
        char *fstr;
        memset(cmd, 0, MAX_CMD_LEN);
        fstr = fgets(cmd, MAX_CMD_LEN, fwl);
        if (fstr == NULL)
            continue;
        rexec_clear_string_tail(cmd, strlen(cmd));
        len = strlen(cmd);
        fstr = (char *)malloc(len + 1);
        if (fstr == NULL) {
            rexec_err("Malloc failed");
            goto err_end;
        }
        memset(fstr, 0, len + 1);
        memcpy(fstr, cmd, len);
        wl->wl[wl->wl_nums] = fstr;
        wl->wl_nums++;
        rexec_log("Cmd:<%s> added to white list.", cmd);
    }
    fclose(fwl);
    return 0;

err_end:
    for (int i = 0; i < wl->wl_nums; i++) {
        free(wl->wl[i]);
    }
    fclose(fwl);
    return -1;
}

static void rexec_white_list_free(struct rexec_white_list_str *wl)
{
    for (int i = 0; i < wl->wl_nums; i++) {
        free(wl->wl[i]);
    }
    return;
}

static int rexec_whitelist_check(char *binary)
{
    // white list file not exist, always ok
    if (access(REXEC_WHITELIST_FILE, F_OK) != 0)
        return 0;
    for (int i = 0; i < rexec_wl.wl_nums; i++) {
        if (strncmp(binary, rexec_wl.wl[i], strlen(rexec_wl.wl[i])) == 0)
            return 0;
    }
    return -1;
}

#define IS_VALID_FD(fd) (fd > STDERR_FILENO)
static void rexec_server_sig_chld(int num)
{
    int status;
    pid_t pid;
    while ((pid = waitpid(0, &status, WNOHANG)) > 0) {
        int exit_status = status;
        if (WIFEXITED(status)) {
            exit_status = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            exit_status = WTERMSIG(status) + 128;
        }
        int connfd = rexec_hash_lookup_direct(child_hash, pid);
        if (IS_VALID_FD(connfd)) {
            struct rexec_msg head;
            head.msgtype = REXEC_KILL;
            head.msglen = 0;
            head.exit_status = exit_status;
            rexec_sendmsg(connfd, (char *)&head, sizeof(struct rexec_msg), -1);
            rexec_hash_remove_direct(child_hash, pid);
            // don't close connfd
        }
    }
    return;
}

static void rexec_server_sig_pipe(int signum)
{
    return;
}

#define REXEC_MSG_NORMAL (1 << 3)
#define REXEC_MSG_OVER 0xf
static int rexec_start_new_process(int newconnfd)
{
    int ret;
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        rexec_err("pipe syscall error, strerr:%s", strerror(errno));
        return -1;
    }
    // handshake阶段，联合体里面记录newconnfd
    // 等到handshake成功后，新的事件监听这个newconnfd，联合体改为记录son pid
    rexec_add_event(main_epoll_fd, pipefd[PIPE_READ], newconnfd, rexec_event_handshake);

    int pid = fork();
    // parent
    if (pid != 0) {
        close(pipefd[PIPE_WRITE]);
        return 0;
    }
    // son
    close(pipefd[PIPE_READ]);

    struct rexec_msg head;
    int argc;
    char *msgbuf = NULL;
    char msg_bit = 0;
    while (msg_bit != REXEC_MSG_OVER) {
        int scmfd = -1;
        int len = sizeof(struct rexec_msg);
        memset(&head, 0, sizeof(struct rexec_msg));
        int ret = rexec_recvmsg(newconnfd, (char *)&head, len, &scmfd, MSG_WAITALL);
        if (ret <= 0) {
            rexec_log("recvmsg ret:%d, err:%s", ret, strerror(errno));
            goto err_to_parent;
        }
        // 将管道与自己的标准输入输出关联
        rexec_dup_std(scmfd, head.stdno);
        if (head.stdno >= REXEC_STDIN && head.stdno <= REXEC_STDERR) {
            msg_bit |= (1 << (head.stdno - REXEC_STDIN));
        }
        if (head.msglen == 0)
            continue;
        // 普通消息，代码暂时没考虑多个普通消息的，先直接过滤
        if (msgbuf != NULL || head.msgtype != REXEC_EXEC) {
            rexec_err("not support multi normal msg or msgtype:%d msglen:%d invalid", head.msgtype, head.msglen);
            continue;
        }
        msg_bit |= REXEC_MSG_NORMAL;
        // exec msg
        rexec_log("Exec msgtype:0x%x msglen:%d argc:%d stdno:%d",
                    head.msgtype, head.msglen, head.argc, head.stdno);
        argc = head.argc;
        if (head.msglen > REXEC_MSG_MAX || argc > REXEC_MSG_MAX / sizeof(uintptr_t) ||
            head.msglen <= 0 || argc < 0) {
            rexec_err("msg len:%d or argc:%d is too large", head.msglen, argc);
            goto err_to_parent;
        }
        msgbuf = (char *)malloc(head.msglen + 1);
        if (msgbuf == NULL) {
            rexec_err("malloc failed");
            goto err_to_parent;
        }
        memset(msgbuf, 0, head.msglen + 1);
        ret = recv(newconnfd, msgbuf, head.msglen, MSG_WAITALL);
        if (ret <= 0) {
            rexec_err("recv failed, ret:%d err:%s", ret, strerror(errno));
            goto err_free;
        }
        rexec_log("recv normal msg len:%d headlen:%d real recv:%d msg:%s",
                    head.msglen, sizeof(struct rexec_msg), ret, msgbuf);
    }

    // msg is like: "binary"\0"argv[1]"\0"argv[2]"\0"..."
    char *binary = msgbuf;
    if (rexec_whitelist_check(binary) != 0) {
        rexec_err("Cmd:<%s> not in white list.", binary);
        goto err_free;
    }

    int mypid = getpid();
    // 写会PID必须放在基于newconnfd接收完所有消息之后，
    // 后面newconnfd的控制权交回父进程rexec server服务进程
    write(pipefd[PIPE_WRITE], &mypid, sizeof(int));
    // 子进程不再使用pipe write和connfd
    close(pipefd[PIPE_WRITE]);
    close(newconnfd);

    // rexec_shim_entry argv like:
    //      argv[0]: binary
    //      argv[1]: -f
    //      argv[2]: *json_str
    //      argv[3]: param list 1
    //      argv[4]: ...
    char **argv = (char **)malloc(sizeof(uintptr_t) * (argc + 3));
    if (argv == NULL) {
        rexec_err("malloc failed, argc:%d.", argc);
        goto err_free;
    }
    int offset = rexec_parse_argv(argc, msgbuf, &argv[2]);
    argv[0] = "-f";
    argv[1] = &msgbuf[offset];

    rexec_log("Parse argv result argc:%d", argc);
    for (int i = 2; i < argc + 2; i++) {
        rexec_log("  argv[%d]:%s", i - 2, argv[i]);
    }
    ret = rexec_shim_entry(argc + 2, argv);
    perror("rexec shim entry");

err_free:
    free(msgbuf);

err_to_parent:
    do {
        int errpid = -1;
        write(pipefd[PIPE_WRITE], &errpid, sizeof(int));
    } while (0);

    return ret;
}

// 道生一
static int rexec_event_new_process(struct rexec_event *event)
{
    int newconnfd = rexec_sock_step_accept(event->fd, AF_UNIX);
    if (newconnfd < 0) {
        rexec_err("Accept failed, ret:%d err:%s", newconnfd, strerror(errno));
        return REXEC_EVENT_OK;
    }
    //     主进程只负责接收新链接，基于newconnfd的新消息由子进程自己去接收，但是最
    // 后父进程要进入监听此链接的状态，是为了联动kill（对端杀死client进程则本端
    // 也杀死，或者本端杀死子进程后消息通知对端也杀死）
    //     这个fd不能同时被父子进程监听，所以先建立一个pipe，等子进程完全接收完
    // 初始消息后，通过pipe告知父进程再由父进程接管newconnfd，在这之前，父进程
    // 监听pipe的read端
    // 白名单也在子进程里做，在fork之后，rexec代码控制范围
    rexec_log("Start new process new conn fd:%d", newconnfd);
    rexec_start_new_process(newconnfd);
    return REXEC_EVENT_OK;
}

static void rexec_server_mainloop()
{
#define REXEC_MAX_EVENTS 16
    main_epoll_fd = epoll_create1(0);
    if (main_epoll_fd == -1) {
        rexec_err("epoll create1 failed, err:%s.", strerror(errno));
        return;
    }
    if (rexec_set_inherit(main_epoll_fd, false) < 0) {
        rexec_err("epoll fd set inherit to false failed.");
    }
    struct rexec_conn_arg ser = {
        .cs = REXEC_SOCK_SERVER,
        .udstype = SOCK_STREAM,
    };
    strncpy(ser.sun_path, REXEC_UDS_CONN, strlen(REXEC_UDS_CONN) + 1);
    int buildret = rexec_build_unix_connection(&ser);
    if (buildret != 0) {
        rexec_err("faild to build main sock:%d err:%s", buildret, strerror(errno));
        close(main_epoll_fd);
        return;
    }
    if (rexec_set_inherit(ser.sockfd, false) < 0) {
        rexec_err("cs conn fd fd set inherit to false failed.");
    }
    rexec_add_event(main_epoll_fd, ser.sockfd, 0, rexec_event_new_process);

    struct epoll_event *evts = calloc(REXEC_MAX_EVENTS, sizeof(struct epoll_event));
    if (evts == NULL) {
        rexec_err("init calloc evts failed.");
        goto end;
    }
    while (1) {
        int n = epoll_wait(main_epoll_fd, evts, REXEC_MAX_EVENTS, 1000);
        if (n == 0)
            continue;
        if (n < 0) {
            rexec_err("epoll wait return errcode:%d", n);
            continue;
        }
        rexec_log("epoll wait trigger %d events.", n);
        for (int i = 0; i < n; i++) {
            struct rexec_event *event = (struct rexec_event *)evts[i].data.ptr;
            int ret = event->handler(event);
            if (ret == REXEC_EVENT_DEL)
                rexec_del_event(main_epoll_fd, event);
        }
    }
    free(evts);

end:
    close(main_epoll_fd);
    close(ser.sockfd);
    return;
}

// hash map for child pid and conn fd
int rexec_pid_hashmap_init(GHashTable **table)
{
    *table = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (*table == NULL) {
        rexec_err("Init child pid hashmap failed.");
        return -1;
    }
    return 0;
}

void rexec_pid_hashmap_destroy(GHashTable *table)
{
    g_hash_table_destroy(table);
    return;
}

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
int rexec_hash_insert_direct(GHashTable *table, int key, int value)
{
    if (g_hash_table_insert(table, (gpointer)key, (gpointer)value) == 0) {
        rexec_err("Hash table key:%d value:%d is already exist, update it.", key, value);
    }
    return 0;
}

int rexec_hash_lookup_direct(GHashTable *table, int key)
{
    return (int)g_hash_table_lookup(table, (gpointer)key);
}

void rexec_hash_remove_direct(GHashTable *table, int key)
{
    g_hash_table_remove(table, (gpointer)key);
    return;
}
#pragma GCC diagnostic pop

int main(int argc, char *argv[])
{
    rexec_log_init();
    signal(SIGCHLD, rexec_server_sig_chld);
    signal(SIGPIPE, rexec_server_sig_pipe);
    if (rexec_whitelist_build(&rexec_wl) != 0) {
        return -1;
    }
    if (access(REXEC_RUN_PATH, F_OK) != 0) {
        mkdir(REXEC_RUN_PATH, 0755);
    }
    if (rexec_pid_hashmap_init(&child_hash) != 0) {
        rexec_white_list_free(&rexec_wl);
        return -1;
    }
    rexec_server_mainloop();
    rexec_pid_hashmap_destroy(child_hash);
    fclose(rexec_logfile);
    return 0;
}

