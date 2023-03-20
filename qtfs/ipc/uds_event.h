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

#ifndef __QTFS_UDS_EVENT_H__
#define __QTFS_UDS_EVENT_H__

#define UDS_EVENT_BUFLEN 	4096
#define UDS_PATH_MAX		1024

#define UDS_EVENT_WAIT_TMOUT 5 // 5s timeout

enum EVENT_RETCODE {
	EVENT_OK = 0,
	EVENT_ERR = -1,
	EVENT_DEL = -2, // del this event after return
};

enum TCP2TCP_TYPE {
	MSG_NORMAL = 0xa5a5,		// 消息类型从特殊数字开始，防止误识别消息
	MSG_SCM_RIGHTS,
	MSG_SCM_CREDENTIALS,	// unix domain 扩展消息，预留
	MSG_SCM_SECURITY,	// unix domain 扩展消息，预留
	MSG_GET_TARGET,		// 控制消息，用于获取对端的target fd
	MSG_SCM_PIPE,		// 使用SCM传递了一个pipe
	MSG_END,		// tcp消息的结束体
};

enum TCPCNTL_TYPE {
	MSGCNTL_UDS = 1,	// uds代理模式
	MSGCNTL_PIPE,		// pipe匿名管道代理模式
};

// 因为要区分SCM_RIGHTS和普通消息，TCP到TCP需要有一个协议头
struct uds_tcp2tcp {
	int msgtype;
	int msglen;	// len of data
	char data[0];
};

struct uds_msg_scmrights {
	int flags;	// open flags
	char path[UDS_PATH_MAX];
};

enum {
	SCM_PIPE_READ = 0,
	SCM_PIPE_WRITE,
	SCM_PIPE_NUM,
};

struct uds_stru_scm_pipe {
	int dir;	// 0: send read filedes; 1: send write filedes
	// proxy通过scm rights接收到员pipe fd，后面消息回来时事件
	// 会发生变化，所以需要回消息时带上，才能建立关联
	int srcfd;
};

int uds_event_uds_listener(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_tcp_listener(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_diag_info(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_debug_level(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_pre_handler(struct uds_event *evt);
int uds_event_pre_hook(struct uds_event_global_var *p_event_var);
int uds_event_post_hook(struct uds_event_global_var *p_event_var);
int uds_event_module_init(struct uds_event_global_var *p_event_var);
void uds_event_module_fini(struct uds_event_global_var *p);

#endif

