#ifndef __REXEC_SOCK_H__
#define __REXEC_SOCK_H__

enum {
    REXEC_SOCK_CLIENT = 1,
    REXEC_SOCK_SERVER,
};

#define UDS_SUN_PATH_LEN 108
struct rexec_conn_arg {
	int cs;		// client(1) or server(2)

	int udstype; 	// DGRAM or STREAM
	char sun_path[UDS_SUN_PATH_LEN];
	int sockfd;
	int connfd;
};

int rexec_sock_step_accept(int sock_fd, int family);
int rexec_build_unix_connection(struct rexec_conn_arg *arg);
int rexec_sendmsg(int sockfd, char *msgbuf, int msglen, int scmfd);
int rexec_recvmsg(int sockfd, char *msgbuf, int msglen, int *scmfd, int flags);

#endif

