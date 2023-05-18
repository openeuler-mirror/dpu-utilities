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

int rexec_sock_step_accept(int sock_fd);
int rexec_build_unix_connection(struct rexec_conn_arg *arg);
int rexec_sendmsg(int sockfd, char *msgbuf, int msglen, int scmfd);
int rexec_recvmsg(int sockfd, char *msgbuf, int msglen, int *scmfd, int flags);

#endif

