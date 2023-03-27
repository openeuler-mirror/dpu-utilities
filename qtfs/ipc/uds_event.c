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
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <glib.h>
#include "dirent.h"

#include "uds_main.h"
#include "uds_event.h"

int uds_event_build_step2(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_remote_build(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_build_step3(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_uds2tcp(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_tcp2uds(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_build_step4(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_tcp2pipe(void *arg, int epfd, struct uds_event_global_var *p_event_var);
int uds_event_pipe2tcp(void *arg, int epfd, struct uds_event_global_var *p_event_var);

int uds_event_module_init(struct uds_event_global_var *p)
{
	p->msg_controllen = UDS_EVENT_BUFLEN;
	p->iov_len = UDS_EVENT_BUFLEN;
	p->buflen = UDS_EVENT_BUFLEN;
	p->msg_controlsendlen = UDS_EVENT_BUFLEN;
	p->iov_sendlen = UDS_EVENT_BUFLEN;

	p->msg_control = (char *)malloc(p->msg_controllen);
	if (p->msg_control == NULL) {
		uds_err("malloc msg control buf failed.");
		p->msg_controllen = 0;
		return EVENT_ERR;
	}
	p->msg_control_send = (char *)malloc(p->msg_controlsendlen);
	if (p->msg_control_send == NULL) {
		goto free1;
	}
	p->iov_base = (char *)malloc(p->iov_len);
	if (p->iov_base == NULL) {
		uds_err("malloc iov base failed.");
		goto free2;
	}
	p->iov_base_send = (char *)malloc(p->iov_sendlen);
	if (p->iov_base_send == NULL) {
		goto free3;
	}
	p->buf = (char *)malloc(p->buflen);
	if (p->buf == NULL) {
		uds_err("malloc buf failed.");
		goto free4;
	}
	return EVENT_OK;

free4:
	free(p->iov_base_send);
	p->iov_base_send = NULL;

free3:
	free(p->iov_base);
	p->iov_base = NULL;

free2:
	free(p->msg_control_send);
	p->msg_control_send = NULL;

free1:
	free(p->msg_control);
	p->msg_control = NULL;
	return EVENT_ERR;
}

void uds_event_module_fini(struct uds_event_global_var *p)
{
	if (p->msg_control != NULL) {
		free(p->msg_control);
		p->msg_control = NULL;
		p->msg_controllen = 0;
	}
	if (p->msg_control_send != NULL) {
		free(p->msg_control_send);
		p->msg_control_send = NULL;
		p->msg_controlsendlen = 0;
	}
	if (p->iov_base != NULL) {
		free(p->iov_base);
		p->iov_base = NULL;
		p->iov_len = 0;
	}
	if (p->iov_base_send != NULL) {
		free(p->iov_base_send);
		p->iov_base_send = NULL;
		p->iov_sendlen = 0;
	}
	if (p->buf != NULL) {
		free(p->buf);
		p->buf = NULL;
		p->buflen = 0;
	}
	return;
}

int uds_event_pre_hook(struct uds_event_global_var *p_event_var)
{
	p_event_var->cur = 0;
	memset(p_event_var->tofree, 0, sizeof(struct uds_event *) * UDS_EPOLL_MAX_EVENTS);
	return 0;
}

int uds_event_post_hook(struct uds_event_global_var *p_event_var)
{
	for (int i = 0; i < p_event_var->cur; i++) {
		uds_log("event:%lx fd:%d free by its peer", p_event_var->tofree[i], p_event_var->tofree[i]->fd);
		uds_del_event(p_event_var->tofree[i]);
	}
	return 0;
}

int uds_event_add_to_free(struct uds_event_global_var *p_event_var, struct uds_event *evt)
{
	if (evt->pipe == 1) {
		uds_log("pipe event:%d no need to free peer", evt->fd);
		return 0;
	}

	struct uds_event *peerevt = evt->peer;
	if (peerevt == NULL) {
		uds_err("peer event add to free is NULL, my fd:%d", evt->fd);
		return -1;
	}
	peerevt->tofree = 1;
	uds_log("event fd:%d addr:%lx add to free", peerevt->fd, peerevt);
	p_event_var->tofree[p_event_var->cur] = peerevt;
	p_event_var->cur++;
	return 0;
}

int uds_event_pre_handler(struct uds_event *evt)
{
	if (evt->tofree == 1) {
		uds_log("event fd:%d marked by peer as pending deletion", evt->fd);
		return EVENT_ERR;
	}
	return EVENT_OK;
}

/*
 * 1. accept local uds connect request
 * 2. set new connection's event to build link step2
 * 3. add new connection event to epoll list
 */
int uds_event_uds_listener(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	int connfd;
	struct uds_event *evt = (struct uds_event *)arg;
	if (evt == NULL) {
		uds_err("param is invalid.");
		return EVENT_ERR;
	}
	connfd = uds_sock_step_accept(evt->fd, AF_UNIX);
	if (connfd <= 0) {
		uds_err("conn fd error:%d", connfd);
		return EVENT_ERR;
	}

	uds_log("accept an new connection, fd:%d", connfd);

	uds_add_event(connfd, NULL, uds_event_build_step2, NULL);
	return EVENT_OK;
}

int uds_event_build_step2(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	struct uds_event *evt = (struct uds_event *)arg;
	if (evt == NULL) {
		uds_err("param is invalid.");
		return EVENT_ERR;
	}
	char buf[sizeof(struct uds_tcp2tcp) + sizeof(struct uds_proxy_remote_conn_req)] = {0};
	struct uds_tcp2tcp *bdmsg = (struct uds_tcp2tcp *)buf;
	struct uds_proxy_remote_conn_req *msg = (struct uds_proxy_remote_conn_req *)bdmsg->data;
	int len;
	memset(buf, 0, sizeof(buf));
	len = recv(evt->fd, msg, sizeof(struct uds_proxy_remote_conn_req), MSG_WAITALL);
	if (len == 0) {
		uds_err("recv err msg:%d errno:%s", len, strerror(errno));
		return EVENT_DEL;
	}
	if (len < 0) {
		uds_err("read msg error:%d errno:%s", len, strerror(errno));
		goto end;
	}
	if (strlen(msg->sun_path) >= (UDS_SUN_PATH_LEN - strlen(UDS_PROXY_SUFFIX))) {
		uds_err("sun_path:<%s> len:%d is too large to add suffex:<%s>, so can't build uds proxy server.",
			msg->sun_path, strlen(msg->sun_path), UDS_PROXY_SUFFIX);
			goto end;
	}
	if (msg->type != SOCK_STREAM && msg->type != SOCK_DGRAM) {
		uds_err("uds type:%d invalid", msg->type);
		return EVENT_ERR;
	}

	struct uds_conn_arg tcp = {
		.cs = UDS_SOCKET_CLIENT,
	};
	int ret;
	if ((ret = uds_build_tcp_connection(&tcp)) < 0) {
		uds_err("step2 build tcp connection failed, return:%d", ret);
		goto end;
	}
	bdmsg->msgtype = MSGCNTL_UDS;
	bdmsg->msglen = sizeof(struct uds_proxy_remote_conn_req);
	if (write(tcp.connfd, bdmsg, sizeof(struct uds_tcp2tcp) + sizeof(struct uds_proxy_remote_conn_req)) < 0) {
		uds_err("send msg to tcp failed");
		goto end;
	}

	struct uds_proxy_remote_conn_req *priv = (void *)malloc(sizeof(struct uds_proxy_remote_conn_req));
	if (priv == NULL) {
		uds_err("malloc failed");
		goto end;
	}

	uds_log("step2 recv sun path:%s, add step3 event fd:%d", msg->sun_path, tcp.connfd);
	memcpy(priv, msg, sizeof(struct uds_proxy_remote_conn_req));
	uds_add_event(tcp.connfd, evt, uds_event_build_step3, priv);

end:
	return EVENT_OK;
}


int uds_event_build_step3(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	struct uds_event *evt = (struct uds_event *)arg;
	struct uds_proxy_remote_conn_rsp msg;
	int len;
	memset(&msg, 0, sizeof(struct uds_proxy_remote_conn_rsp));
	len = read(evt->fd, &msg, sizeof(struct uds_proxy_remote_conn_rsp));
	if (len <= 0) {
		uds_err("read error len:%d", len);
		if (len == 0)
			goto event_del;
		return EVENT_ERR;
	}
	if (msg.ret == EVENT_ERR) {
		uds_log("get build ack:%d, failed", msg.ret);
		goto event_del;
	}

	struct uds_proxy_remote_conn_req *udsmsg = (struct uds_proxy_remote_conn_req *)evt->priv;
	struct uds_conn_arg uds;

	memset(&uds, 0, sizeof(struct uds_conn_arg));
	uds.cs = UDS_SOCKET_SERVER;
	uds.udstype = udsmsg->type;
	strncpy(uds.sun_path, udsmsg->sun_path, sizeof(uds.sun_path));
	strcat(uds.sun_path, UDS_PROXY_SUFFIX);
	if (uds_build_unix_connection(&uds) < 0) {
		uds_err("failed to build uds server sunpath:%s", uds.sun_path);
		goto event_del;
	}
	uds_log("remote conn build success, build uds server type:%d sunpath:%s fd:%d OK this event suspend,",
			uds.udstype, uds.sun_path, uds.sockfd);
	uds_event_suspend(epfd, evt);
	
	struct uds_event *newevt = uds_add_event(uds.sockfd, evt, uds_event_build_step4, NULL);
	evt->tmout = UDS_EVENT_WAIT_TMOUT;
	newevt->tmout = UDS_EVENT_WAIT_TMOUT;
	uds_hash_insert_dirct(event_tmout_hash, evt->fd, evt);
	uds_hash_insert_dirct(event_tmout_hash, newevt->fd, newevt);
	uds_log("Add hash key:%d-->value:0x%lx and key:%d-->value:%lx", evt->fd, evt, newevt->fd, newevt);

	msg.ret = 1;
	write(evt->peer->fd, &msg, sizeof(struct uds_proxy_remote_conn_rsp));
	return EVENT_OK;

event_del:
	msg.ret = 0;
	write(evt->peer->fd, &msg, sizeof(struct uds_proxy_remote_conn_rsp));
	free(evt->priv);
	return EVENT_DEL;
}

int uds_event_build_step4(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	struct uds_event *evt = (struct uds_event *)arg;
	int connfd = uds_sock_step_accept(evt->fd, AF_UNIX);
	if (connfd < 0) {
		uds_err("accept connection failed fd:%d", connfd);
		return EVENT_ERR;
	}
	uds_hash_remove_dirct(event_tmout_hash, evt->fd);
	uds_hash_remove_dirct(event_tmout_hash, evt->peer->fd);
	evt->tmout = 0;
	evt->peer->tmout = 0;

	struct uds_event *peerevt = (struct uds_event *)evt->peer;
	peerevt->handler = uds_event_tcp2uds;
	peerevt->peer = uds_add_event(connfd, peerevt, uds_event_uds2tcp, NULL);

	uds_log("accept new connection fd:%d, peerfd:%d frontfd:%d peerfd:%d, peerevt(fd:%d) active now",
			connfd, evt->peer->fd, peerevt->fd, peerevt->peer->fd, peerevt->fd);
	uds_event_insert(epfd, peerevt);
	return EVENT_DEL;
}

int uds_event_tcp_listener(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	struct uds_event *evt = (struct uds_event *)arg;
	int connfd = uds_sock_step_accept(evt->fd, AF_INET);
	if (connfd <= 0) {
		uds_err("tcp conn fd error:%d", connfd);
		return EVENT_ERR;
	}
	uds_log("tcp listener event enter, new connection fd:%d.", connfd);

	uds_add_event(connfd, NULL, uds_event_remote_build, NULL);
	return 0;
}

int uds_build_connect2uds(struct uds_event *evt, struct uds_proxy_remote_conn_req *msg)
{
	struct uds_conn_arg targ;
	int len = recv(evt->fd, msg, sizeof(struct uds_proxy_remote_conn_req), MSG_WAITALL);
	if (len <= 0) {
		uds_err("recv failed, len:%d str:%s", len, strerror(errno));
		return EVENT_ERR;
	}

	targ.cs = UDS_SOCKET_CLIENT;
	targ.udstype = msg->type;
	memset(targ.sun_path, 0, sizeof(targ.sun_path));
	strncpy(targ.sun_path, msg->sun_path, sizeof(targ.sun_path));
	if (uds_build_unix_connection(&targ) < 0) {
		struct uds_proxy_remote_conn_rsp ack;
		uds_err("can't connect to sun_path:%s", targ.sun_path);
		ack.ret = EVENT_ERR;
		write(evt->fd, &ack, sizeof(struct uds_proxy_remote_conn_rsp));
		return EVENT_DEL;
	}

	evt->peer = uds_add_event(targ.connfd, evt, uds_event_uds2tcp, NULL);
	evt->handler = uds_event_tcp2uds;

	uds_log("build link req from tcp, sunpath:%s, type:%d, eventfd:%d peerfd:%d",
			msg->sun_path, msg->type, targ.connfd, evt->fd);

	struct uds_proxy_remote_conn_rsp ack;
	ack.ret = EVENT_OK;

	int ret = write(evt->fd, &ack, sizeof(struct uds_proxy_remote_conn_rsp));
	if (ret <= 0) {
		uds_err("apply ack failed, ret:%d", ret);
		return EVENT_DEL;
	}
	return EVENT_OK;
}

int uds_build_pipe_proxy(int efd, struct uds_event *evt, struct uds_stru_scm_pipe *msg)
{
	int len = recv(evt->fd, msg, sizeof(struct uds_stru_scm_pipe), MSG_WAITALL);
	if (len <= 0) {
		uds_err("recv failed, len:%d str:%s", len, strerror(errno));
		return EVENT_ERR;
	}
	if (msg->dir != SCM_PIPE_READ && msg->dir != SCM_PIPE_WRITE) {
		uds_err("invalid pipe dir:%d", msg->dir);
		return EVENT_ERR;
	}
	uds_log("pipe proxy event fd:%d pipe fd:%d dir:%d", evt->fd, msg->srcfd, msg->dir);

	if (msg->dir == SCM_PIPE_READ) {
		uds_add_pipe_event(msg->srcfd, evt->fd, uds_event_pipe2tcp, NULL);
		// 此处必须保留evt->fd，只删除对他的监听，以及释放evt内存即可
		uds_event_suspend(efd, evt);
		free(evt);
	} else {
		evt->pipe = 1;
		evt->peerfd = msg->srcfd;
		evt->handler = uds_event_tcp2pipe;
	}
	return EVENT_OK;
}

int uds_event_remote_build(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	struct uds_event *evt = (struct uds_event *)arg;
	struct uds_tcp2tcp *bdmsg = (struct uds_tcp2tcp *)p_event_var->iov_base;
	struct uds_proxy_remote_conn_req *msg = (struct uds_proxy_remote_conn_req *)bdmsg->data;
	int len;
	int ret = EVENT_OK;
	memset(p_event_var->iov_base, 0, p_event_var->iov_len);
	len = recv(evt->fd, bdmsg, sizeof(struct uds_tcp2tcp), MSG_WAITALL);
	if (len <= 0) {
		uds_err("read no msg from sock:%d, len:%d", evt->fd, len);
		return EVENT_ERR;
	}

	switch (bdmsg->msgtype) {
		case MSGCNTL_UDS:
			ret = uds_build_connect2uds(evt, msg);
			break;
		case MSGCNTL_PIPE:
			ret = uds_build_pipe_proxy(epfd, evt, (struct uds_stru_scm_pipe *)bdmsg->data);
			break;
		default:
			uds_err("remote build not support msgtype %d now", bdmsg->msgtype);
			break;
	}
	return ret;
}

static inline mode_t uds_msg_file_mode(int fd)
{
	struct stat st;
	char path[32] = {0};
	if (fstat(fd, &st) != 0) {
		uds_err("get fd:%d fstat failed, errstr:%s", fd, strerror(errno));
	}
	if (S_ISFIFO(st.st_mode)) {
		uds_log("fd:%d is fifo", fd);
	}

	return st.st_mode;
}

static int uds_msg_scm_regular_file(int scmfd, int tcpfd, struct uds_event_global_var *p_event_var)
{
	int ret;
	struct uds_tcp2tcp *p_msg = (struct uds_tcp2tcp *)p_event_var->buf;
	struct uds_msg_scmrights *p_scmr = (struct uds_msg_scmrights *)&p_msg->data;
	char *fdproc = calloc(1, UDS_PATH_MAX);
	if (fdproc == NULL) {
		uds_err("failed to calloc memory:%lx %lx", fdproc);
		return EVENT_ERR;
	}
	sprintf(fdproc, "/proc/self/fd/%d", scmfd);
	ret = readlink(fdproc, p_scmr->path, UDS_PATH_MAX);
	if (ret < 0) {
		uds_err("readlink:%s error, ret:%d, errstr:%s", fdproc, ret, strerror(errno));
		free(fdproc);
		close(scmfd);
		return EVENT_ERR;
	}
	free(fdproc);
	p_scmr->flags = fcntl(scmfd, F_GETFL, 0);
	if (p_scmr->flags < 0) {
		uds_err("fcntl get flags failed:%d error:%s", p_scmr->flags, strerror(errno));
		close(scmfd);
		return EVENT_ERR;
	}
	close(scmfd);
	p_msg->msgtype = MSG_SCM_RIGHTS;
	p_msg->msglen = sizeof(struct uds_msg_scmrights) - sizeof(p_scmr->path) + strlen(p_scmr->path) + 1;
	ret = write(tcpfd, p_msg, sizeof(struct uds_tcp2tcp) + p_msg->msglen);
	if (ret <= 0) {
		uds_err("send scm rights msg to tcp failed, ret:%d", ret);
		return EVENT_ERR;
	}
	uds_log("scm rights msg send to tcp, fd:%d path:%s flags:%d", scmfd, p_scmr->path, p_scmr->flags);
	return EVENT_OK;
}

static int uds_msg_scm_fifo_file(int scmfd, int tcpfd, struct uds_event_global_var *p_event_var)
{
#define FDPATH_LEN 32
	int ret;
	struct uds_tcp2tcp *p_get = (struct uds_tcp2tcp *)p_event_var->buf;
	struct uds_stru_scm_pipe *p_pipe = (struct uds_stru_scm_pipe *)p_get->data;
	char path[FDPATH_LEN] = {0};
	struct stat st;
	p_get->msgtype = MSG_SCM_PIPE;
	p_get->msglen = sizeof(struct uds_stru_scm_pipe);

	sprintf(path, "/proc/self/fd/%d", scmfd);
	lstat(path, &st);
	if (st.st_mode & S_IRUSR) {
		p_pipe->dir = SCM_PIPE_READ;
		uds_log("scm rights recv read pipe fd:%d, mode:%o", scmfd, st.st_mode);
	} else if (st.st_mode & S_IWUSR) {
		p_pipe->dir = SCM_PIPE_WRITE;
		uds_log("scm rights recv write pipe fd:%d, mode:%o", scmfd, st.st_mode);
	} else {
		uds_err("scm rights recv invalid pipe, mode:%o fd:%d", st.st_mode, scmfd);
		return EVENT_ERR;
	}
	p_pipe->srcfd = scmfd;
	ret = send(tcpfd, p_get, sizeof(struct uds_tcp2tcp) + sizeof(struct uds_stru_scm_pipe), 0);
	if (ret <= 0) {
		uds_err("send tar get msg failed, ret:%d errstr:%s", ret, strerror(errno));
		return EVENT_ERR;
	}
	return EVENT_OK;
}

static int uds_msg_scmrights2tcp(struct cmsghdr *cmsg, int tcpfd, struct uds_event_global_var *p_event_var)
{
	int scmfd;
	mode_t mode;

	memset(p_event_var->buf, 0, p_event_var->buflen);
	memcpy(&scmfd, CMSG_DATA(cmsg), sizeof(scmfd));
	if (scmfd <= 0) {
		uds_err("recv invalid scm fd:%d", scmfd);
		return EVENT_ERR;
	}

	mode = uds_msg_file_mode(scmfd);

	switch (mode & S_IFMT) {
		case S_IFREG:
			uds_log("recv scmfd:%d from uds, is regular file", scmfd);
			uds_msg_scm_regular_file(scmfd, tcpfd, p_event_var);
			break;
		case S_IFIFO:
			uds_log("recv scmfd:%d from uds, is fifo", scmfd);
			uds_msg_scm_fifo_file(scmfd, tcpfd, p_event_var);
			break;
		default:
			uds_err("scm rights not support file mode:%o", mode);
			break;
	}

	return EVENT_OK;
}

static int uds_msg_cmsg2tcp(struct msghdr *msg, struct uds_event *evt, struct uds_event_global_var *p_event_var)
{
	int cnt = 0;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
	while (cmsg != NULL) {
		cnt ++;
		uds_log("cmsg type:%d len:%d level:%d, tcpfd:%d", cmsg->cmsg_type,
				cmsg->cmsg_len, cmsg->cmsg_level, evt->peer->fd);
		switch (cmsg->cmsg_type) {
			case SCM_RIGHTS:
				uds_msg_scmrights2tcp(cmsg, evt->peer->fd, p_event_var);
				break;
			default:
				uds_err("cmsg type:%d not support now", cmsg->cmsg_type);
				break;
		}
		cmsg = CMSG_NXTHDR(msg, cmsg);
	}
	return cnt;
}

static int uds_msg_scmfd_combine_msg(struct msghdr *msg, struct cmsghdr **cmsg, int *controllen, int fd)
{
	struct cmsghdr *cnxt = NULL;
	if (*cmsg == NULL) {
		cnxt = CMSG_FIRSTHDR(msg);
	} else {
		cnxt = CMSG_NXTHDR(msg, *cmsg);
	}
	*cmsg = cnxt;
	cnxt->cmsg_level = SOL_SOCKET;
	cnxt->cmsg_type = SCM_RIGHTS;
	cnxt->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cnxt), &fd, sizeof(fd));
	*controllen = *controllen + cnxt->cmsg_len;
	return EVENT_OK;
}

static int uds_msg_scmright_send_fd(int sock, int fd)
{
	char byte = 0;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(fd))];

	// send at least one char
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;


	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	// Initialize the payload
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(sock, &msg, 0) != iov.iov_len)
		return -1;
	return 0;
}

static int uds_msg_cmsg2uds(struct uds_tcp2tcp *msg, struct uds_event *evt)
{
	int scmfd = -1;
	switch (msg->msgtype) {
		case MSG_SCM_RIGHTS: {
			struct uds_msg_scmrights *p_scmr = (struct uds_msg_scmrights *)&msg->data;
			int ret;
			scmfd = open(p_scmr->path, p_scmr->flags);
			if (scmfd < 0) {
				uds_err("scm rights send fd failed, scmfd:%d path:%s flags:%d", scmfd, p_scmr->path, p_scmr->flags);
				return -1;
			}
			uds_log("scm send fd:%d path:%s flags:%d", scmfd, p_scmr->path, p_scmr->flags);
			break;
		}
		default:
			uds_err("msg type:%d not support.", msg->msgtype);
			return -1;
	}
	return scmfd;
}

int uds_msg_tcp2uds_scm_pipe(struct uds_tcp2tcp *p_msg, struct uds_event *evt)
{
	int scmfd;
	int fd[SCM_PIPE_NUM];
	struct uds_stru_scm_pipe *p_pipe = (struct uds_stru_scm_pipe *)p_msg->data;
	int len = recv(evt->fd, p_pipe, p_msg->msglen, MSG_WAITALL);
	if (len <= 0) {
		uds_err("recv data failed, len:%d", len);
		return EVENT_DEL;
	}
	if (p_pipe->dir != SCM_PIPE_READ && p_pipe->dir != SCM_PIPE_WRITE) {
		uds_err("scm pipe recv invalid pipe dir:%d, srcfd:%d", p_pipe->dir, p_pipe->srcfd);
		return EVENT_ERR;
	}
	struct uds_conn_arg tcp = {
		.cs = UDS_SOCKET_CLIENT,
	};
	int ret;
	if ((ret = uds_build_tcp_connection(&tcp)) < 0) {
		uds_err("build tcp connection failed, return:%d", ret);
		return EVENT_ERR;
	}
	if (pipe(fd) == -1) {
		uds_err("pipe syscall error, strerr:%s", strerror(errno));
		return EVENT_ERR;
	}
	if (p_pipe->dir == SCM_PIPE_READ) {
		uds_log("send read pipe:%d to peer:%d", fd[SCM_PIPE_READ], evt->peer->fd);
		scmfd = fd[SCM_PIPE_READ];
		// read方向，proxy读取消息并转发，此代码处是远端，所以监听tcp换发给pipe write
		uds_add_pipe_event(tcp.connfd, fd[SCM_PIPE_WRITE], uds_event_tcp2pipe, NULL);
	} else {
		uds_log("send write pipe:%d to peer:%d", fd[SCM_PIPE_WRITE], evt->peer->fd);
		scmfd = fd[SCM_PIPE_WRITE];
		// write方向，proxy读取远端代理pipe消息并转发，此处是远端，所以监听pipe read并转发给tcp
		uds_add_pipe_event(fd[SCM_PIPE_READ], tcp.connfd, uds_event_pipe2tcp, NULL);
	}

	p_msg->msgtype = MSGCNTL_PIPE;
	p_msg->msglen = sizeof(struct uds_stru_scm_pipe);
	len = write(tcp.connfd, p_msg, sizeof(struct uds_tcp2tcp) + sizeof(struct uds_stru_scm_pipe));
	if (len <= 0) {
		uds_err("send pipe msg failed, len:%d", len);
		return EVENT_ERR;
	}
	uds_log("success to build pipe fd map, dir:%d srcfd:%d tcpfd:%d readfd:%d writefd:%d",
			p_pipe->dir, p_pipe->srcfd, tcp.connfd, fd[SCM_PIPE_READ], fd[SCM_PIPE_WRITE]);

	return scmfd;
}

int uds_event_tcp2pipe(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	struct uds_event *evt = (struct uds_event *)arg;
	memset(p_event_var->iov_base, 0, p_event_var->iov_len);
	int len = read(evt->fd, p_event_var->iov_base, p_event_var->iov_len);
	if (len <= 0) {
		uds_err("read from tcp failed, len:%d str:%s", len, strerror(errno));
		return EVENT_DEL;
	}

	uds_log("tcp:%d to pipe:%d len:%d, buf:\n>>>>>>>\n%.*s\n<<<<<<<\n", evt->fd, evt->peerfd, len, len, p_event_var->iov_base);
	int ret = write(evt->peerfd, p_event_var->iov_base, len);
	if (ret <= 0) {
		uds_err("write to pipe failed, fd:%d str:%s", evt->peerfd, strerror(errno));
		return EVENT_DEL;
	}
	return EVENT_OK;
}

int uds_event_pipe2tcp(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	struct uds_event *evt = (struct uds_event *)arg;
	memset(p_event_var->iov_base, 0, p_event_var->iov_len);
	int len = read(evt->fd, p_event_var->iov_base, p_event_var->iov_len);
	if (len <= 0) {
		uds_err("read from pipe failed, len:%d str:%s", len, strerror(errno));
		return EVENT_DEL;
	}

	uds_log("pipe:%d to tcp:%d len:%d, buf:\n>>>>>>>\n%.*s\n<<<<<<<\n", evt->fd, evt->peerfd, len, len, p_event_var->iov_base);
	int ret = write(evt->peerfd, p_event_var->iov_base, len);
	if (ret <= 0) {
		uds_err("write to tcp failed, fd:%d str:%s", evt->peerfd, strerror(errno));
		return EVENT_DEL;
	}
	return EVENT_OK;

}

int uds_msg_tcp_end_msg(int sock)
{
	struct uds_tcp2tcp end = {.msgtype = MSG_END, .msglen = 0,};
	int ret = write(sock, &end, sizeof(struct uds_tcp2tcp));
	if (ret <= 0) {
		uds_err("write end msg failed, ret:%d fd:%d", ret, sock);
		return EVENT_DEL;
	}
	return EVENT_OK;
}

void uds_msg_init_event_buf(struct uds_event_global_var *p)
{
	memset(p->iov_base, 0, p->iov_len);
	memset(p->iov_base_send, 0, p->iov_sendlen);
	memset(p->msg_control, 0, p->msg_controllen);
	memset(p->msg_control_send, 0, p->msg_controlsendlen);
	memset(p->buf, 0, p->buflen);
	return;
}

#define TEST_BUFLEN 256
int uds_event_uds2tcp(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	struct uds_event *evt = (struct uds_event *)arg;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int cmsgcnt = 0;
	int len;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = p_event_var->iov_base + sizeof(struct uds_tcp2tcp);
	iov.iov_len = p_event_var->iov_len - sizeof(struct uds_tcp2tcp);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	msg.msg_control = p_event_var->msg_control;
	msg.msg_controllen = p_event_var->msg_controllen;
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_len = p_event_var->msg_controllen;

	len = recvmsg(evt->fd, &msg, 0);
	if (len == 0) {
		uds_err("recvmsg error, return:%d", len);
		uds_event_add_to_free(p_event_var, evt);
		return EVENT_DEL;
	}
	if (len < 0) {
		uds_err("recvmsg error return val:%d", len);
		return EVENT_ERR;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg != NULL) {
		uds_log("recvmsg cmsg len:%d cmsglen:%d iovlen:%d iov:%s cmsglevel:%d cmsgtype:%d",
				len, cmsg->cmsg_len, iov.iov_len, iov.iov_base, cmsg->cmsg_level, cmsg->cmsg_type);
		cmsgcnt = uds_msg_cmsg2tcp(&msg, evt, p_event_var);
		if (len - cmsgcnt == 0)
			goto endmsg;
	}

	struct uds_tcp2tcp *p_msg = (struct uds_tcp2tcp *)p_event_var->iov_base;
	p_msg->msgtype = MSG_NORMAL;
	p_msg->msglen = len;
	int ret = write(evt->peer->fd, (void *)p_msg, p_msg->msglen + sizeof(struct uds_tcp2tcp));
	if (ret <= 0) {
		uds_err("write to peer:%d failed, retcode:%d len:%d", evt->peer->fd, ret, len);
		return EVENT_ERR;
	}

	uds_log("write iov msg to tcp success, msgtype:%d ret:%d iovlen:%d recvlen:%d udsheadlen:%d msglen:%d msg:\n>>>>>>>\n%.*s\n<<<<<<<\n",
			p_msg->msgtype, ret, iov.iov_len, len, sizeof(struct uds_tcp2tcp), p_msg->msglen, p_msg->msglen, p_msg->data);
endmsg:
	return uds_msg_tcp_end_msg(evt->peer->fd);
}

int uds_event_tcp2uds(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
#define MAX_FDS 64	
	int fds[MAX_FDS] = {0};
	int fdnum = 0;
	struct uds_event *evt = (struct uds_event *)arg;
	struct uds_tcp2tcp *p_msg = (struct uds_tcp2tcp *)p_event_var->iov_base;
	int ret;
	int normal_msg_len = 0;
	struct msghdr msg;
	struct cmsghdr *cmsg = NULL;
	struct iovec iov;
	int msg_controllen = 0;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = p_event_var->iov_base_send;
	iov.iov_len = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = p_event_var->msg_control_send;
	msg.msg_controllen = p_event_var->msg_controlsendlen;

	while (1) {
		int len = recv(evt->fd, p_msg, sizeof(struct uds_tcp2tcp), MSG_WAITALL);
		if (len <= 0) {
			uds_err("recv no msg maybe sock is closed, delete this tcp2uds event, len:%d.", len);
			goto close_event;
		}
		uds_log("pmsg:%lx type:%d len:%d iov_base:%lx len:%d", p_msg, p_msg->msgtype, p_msg->msglen, p_event_var->iov_base, len);
		if (p_msg->msgtype == MSG_END) {
			break;
		}
		if (p_msg->msglen > p_event_var->iov_len - sizeof(struct uds_tcp2tcp) || p_msg->msglen <= 0) {
			uds_err("pmsg len:%d is invalid, fd:%d peerfd:%d", p_msg->msglen, evt->fd, evt->peer->fd);
			continue;
		}
		switch(p_msg->msgtype) {
			case MSG_NORMAL:
				if (normal_msg_len != 0) {
					uds_err("normal msg repeat recv fd:%d", evt->fd);
					goto err;
				}
				normal_msg_len = recv(evt->fd, p_event_var->iov_base_send, p_msg->msglen, MSG_WAITALL);
				if (normal_msg_len <= 0) {
					uds_err("recv msg error:%d fd:%d", len, evt->fd);
					goto close_event;
				}
				iov.iov_len = normal_msg_len;
				uds_log("recv normal msg len:%d str: \n>>>>>>>\n%.*s\n<<<<<<<", iov.iov_len, iov.iov_len, iov.iov_base);
				break;
			case MSG_SCM_RIGHTS: {
				int len;
				int scmfd;
				struct uds_msg_scmrights *p_scm = (struct uds_msg_scmrights *) p_msg->data;
				memset(p_scm->path, 0, sizeof(p_scm->path));
				// SCM RIGHTS msg proc
				len = recv(evt->fd, p_msg->data, p_msg->msglen, MSG_WAITALL);
				if (len <= 0) {
					uds_err("recv data failed len:%d", p_msg->msglen);
					return EVENT_DEL;
				}
				scmfd = uds_msg_cmsg2uds(p_msg, evt);
				if (scmfd == -1) {
					goto err;
				}
				fds[fdnum++] = scmfd;
				uds_msg_scmfd_combine_msg(&msg, &cmsg, &msg_controllen, scmfd);
				break;
				}
			case MSG_SCM_PIPE: {
				int scmfd;
				scmfd = uds_msg_tcp2uds_scm_pipe(p_msg, evt);
				if (scmfd == EVENT_DEL)
					goto close_event;
				if (scmfd < 0)
					goto err;
				fds[fdnum++] = scmfd;
				uds_msg_scmfd_combine_msg(&msg, &cmsg, &msg_controllen, scmfd);
				break;
				}
			default:
				uds_err("recv unsupport msg type:%d event fd:%d", p_msg->msgtype, evt->fd);
				break;
		}
	}
	if (msg_controllen == 0 && iov.iov_len == 0)
		goto err;
	msg.msg_controllen = msg_controllen;
	if (iov.iov_len == 0) iov.iov_len = 1;
	ret = sendmsg(evt->peer->fd, &msg, 0);
	uds_log("evt:%d sendmsg len:%d, controllen:%d errno:%s", evt->fd, ret, msg_controllen, strerror(errno));
	for (int i = 0; i < fdnum; i++) {
		close(fds[i]);
	}
	return EVENT_OK;
err:
	return EVENT_ERR;

close_event:
	uds_event_add_to_free(p_event_var, evt);
	return EVENT_DEL;
}

int uds_diag_is_epoll_fd(int fd)
{
	for (int i = 0; i < p_uds_var->work_thread_num; i++) {
		if (fd == p_uds_var->efd[i])
			return 1;
	}
	return 0;
}

void uds_diag_list_fd(char *buf, int len)
{
#define FDPATH_LEN 32
	int pos = 0;
	char path[32] = {0};
	DIR *dir = NULL;
	struct dirent *entry;
	dir = opendir("/proc/self/fd/");
	if (dir == NULL) {
		uds_err("open path:/proc/self/fd/ failed");
		return;
	}
	while (entry = readdir(dir)) {
		int fd = atoi(entry->d_name);
		char fdpath[FDPATH_LEN];
		char link[FDPATH_LEN];
		int ret;
		if (fd <= 2 || uds_diag_is_epoll_fd(fd))
			continue;
		memset(fdpath, 0, FDPATH_LEN);
		memset(link, 0, FDPATH_LEN);
		sprintf(fdpath, "/proc/self/fd/%d", fd);
		ret = readlink(fdpath, link, FDPATH_LEN);
		pos += sprintf(&buf[pos], "+ fd:%s type:%u link:%s\n", entry->d_name, entry->d_type, link);
	}
	closedir(dir);
	return;
}

int uds_diag_string(char *buf, int len)
{
	int pos = 0;
	memset(buf, 0, len);
	pos = sprintf(buf,		"+-----------------------------Unix Proxy Diagnostic information-------------------------+\n");
	pos += sprintf(&buf[pos],	"+ Thread nums:%d\n", p_uds_var->work_thread_num);
	for (int i = 0; i < p_uds_var->work_thread_num; i++) {
		pos += sprintf(&buf[pos], "+	Thread %d events count:%d\n", i+1, p_uds_var->work_thread[i].info.events);
	}
	pos += sprintf(&buf[pos],	"+	Log level:%s\n", p_uds_var->logstr[p_uds_var->loglevel]);
	strcat(buf,			"+---------------------------------------------------------------------------------------+\n");
	return strlen(buf);
}

// DIAG INFO
int uds_event_diag_info(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	int connfd;
	int len;
	int ret;
	struct uds_event *evt = (struct uds_event *)arg;
	if (evt == NULL) {
		uds_err("param is invalid.");
		return EVENT_ERR;
	}
	connfd = uds_sock_step_accept(evt->fd, AF_UNIX);
	if (connfd <= 0) {
		uds_err("conn fd error:%d", connfd);
		return EVENT_ERR;
	}

	uds_log("diag accept an new connection to send diag info, fd:%d", connfd);
	len = uds_diag_string(p_event_var->iov_base, p_event_var->iov_len);
	ret = send(connfd, p_event_var->iov_base, len, 0);
	if (ret <= 0) {
		uds_err("send diag info error, ret:%d len:%d", ret, len);
	}
	close(connfd);
	return EVENT_OK;
}

#define UDS_LOG_STR(level) (level < 0 || level >= UDS_LOG_MAX) ? p_uds_var->logstr[UDS_LOG_MAX] : p_uds_var->logstr[level]
int uds_event_debug_level(void *arg, int epfd, struct uds_event_global_var *p_event_var)
{
	int connfd;
	int len;
	int ret;
	int cur;
	struct uds_event *evt = (struct uds_event *)arg;
	if (evt == NULL) {
		uds_err("param is invalid.");
		return EVENT_ERR;
	}
	connfd = uds_sock_step_accept(evt->fd, AF_UNIX);
	if (connfd <= 0) {
		uds_err("conn fd error:%d", connfd);
		return EVENT_ERR;
	}

	cur = p_uds_var->loglevel;
	if (cur + 1 < UDS_LOG_MAX) {
		p_uds_var->loglevel += 1;
	} else {
		p_uds_var->loglevel = UDS_LOG_NONE;
	}

	uds_log("debug level accept a new connection, current level:%s change to:%s", UDS_LOG_STR(cur), UDS_LOG_STR(p_uds_var->loglevel));

	len = sprintf(p_event_var->iov_base,	"+---------------UDS LOG LEVEL UPDATE--------------+\n"
						"+ Log level is:%s before, now change to :%s.\n"
						"+-------------------------------------------------+\n", UDS_LOG_STR(cur), UDS_LOG_STR(p_uds_var->loglevel));

	ret = send(connfd, p_event_var->iov_base, len, 0);
	if (ret <= 0) {
		uds_err("send debug level info error, ret:%d len:%d", ret, len);
	}
	close(connfd);
	return EVENT_OK;
}
