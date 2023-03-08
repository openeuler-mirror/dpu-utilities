#ifndef __REXEC_H__
#define __REXEC_H__

#include <time.h>
#include <stdbool.h>

enum {
    PIPE_READ = 0,
    PIPE_WRITE,
};

enum {
    REXEC_STDIN = 0x5a,
    REXEC_STDOUT,
    REXEC_STDERR,
    REXEC_NONE,
};

#define REXEC_MSG_1K 1024
#define REXEC_MSG_MAX REXEC_MSG_1K * 1024

// rexec client与server之间建联的sock文件路径
#define REXEC_UDS_CONN "/var/run/rexec/rexec_uds.sock"

enum rexec_msgtype {
    REXEC_EXEC = 0x5a5a,    // exec process
    REXEC_KILL,             // kill process
    REXEC_PIPE,             // client send a pipefd as stdin/out/err to server
    REXEC_PIDMAP,           // server send remote process's pid to client
};

struct rexec_msg {
    int msgtype;
    // client to server
    int argc;
    int stdno;
    int msglen;
    // server to client
    int exit_status;
    int pid; // for pidmap
    char msg[0];
};

#define REXEC_LOG_FILE "/var/run/rexec/rexec.log"
extern FILE *rexec_logfile;
static inline void rexec_log_init()
{
    char *logfile = getenv("REXEC_LOG_FILE");
    if (logfile == NULL) {
        logfile = "/dev/null";
    } else if (strcmp(logfile, "std") == 0) {
        rexec_logfile = stderr;
        return;
    }
retry:
    rexec_logfile = fopen(logfile, "a");
    if (rexec_logfile == NULL) {
        if (strcmp(logfile, "/dev/null") == 0) {
            return;
        }
        // 输入的文件打开失败则回退到无日志模式
        logfile = "/dev/null";
        goto retry;
    }
    return;
}

// flag: 1--nonblock; 0--block
static inline int rexec_set_nonblock(int fd, int block)
{
    int fflags;
    if ((fflags = fcntl(fd, F_GETFL)) < 0)
        return -1;
    if (block == 0)
        fflags &= ~O_NONBLOCK;
    else
        fflags |= O_NONBLOCK;
    if ((fcntl(fd, F_SETFL, fflags)) < 0)
        return -1;
    return 0;
}

static inline int rexec_set_inherit(int fd, bool inherit)
{
    int fflags;
    if ((fflags = fcntl(fd, F_GETFD)) < 0)
        return -1;
    if (inherit)
        fflags &= ~FD_CLOEXEC;
    else
        fflags |= FD_CLOEXEC;
    if ((fcntl(fd, F_SETFD, fflags)) < 0)
        return -1;
    return 0;
}

#define rexec_log(info, ...) \
	if (rexec_logfile != NULL) {\
		time_t t; \
		struct tm *p; \
		time(&t); \
		p = localtime(&t); \
		fprintf(rexec_logfile, "[%d/%02d/%02d %02d:%02d:%02d][LOG:%s:%3d]"info"\n", \
				p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
				p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
	}

#define rexec_log2(info, ...) \
	if (rexec_logfile != NULL) {\
		time_t t; \
		struct tm *p; \
		time(&t); \
		p = localtime(&t); \
		fprintf(rexec_logfile, "[%d/%02d/%02d %02d:%02d:%02d][LOG:%s:%3d]"info"\n", \
				p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
				p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
	}

#define rexec_err(info, ...) \
	if (rexec_logfile != NULL) {\
		time_t t; \
		struct tm *p; \
		time(&t); \
		p = localtime(&t); \
		fprintf(rexec_logfile, "[%d/%02d/%02d %02d:%02d:%02d][ERROR:%s:%3d]"info"\n", \
				p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
				p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
	}

#endif

