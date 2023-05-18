/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/un.h>

#include "comm.h"
#include "conn.h"
#include "log.h"
#include "req.h"
#include "symbol_wrapper.h"

char qtfs_server_ip[20] = "127.0.0.1";
int qtfs_server_port = 12345;
#ifdef QTFS_SERVER
struct socket *qtfs_server_main_sock = NULL;
#endif

#ifdef KVER_4_19
static inline void sock_valbool_flag(struct sock *sk, enum sock_flags bit,
				     int valbool)
{
	if (valbool)
		sock_set_flag(sk, bit);
	else
		sock_reset_flag(sk, bit);
}

void sock_set_keepalive(struct sock *sk)
{
	lock_sock(sk);
	if (sk->sk_prot->keepalive)
		sk->sk_prot->keepalive(sk, true);
	sock_valbool_flag(sk, SOCK_KEEPOPEN, true);
	release_sock(sk);
}

int tcp_sock_set_keepidle_locked(struct sock *sk, int val)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (val < 1 || val > MAX_TCP_KEEPIDLE)
		return -EINVAL;

	tp->keepalive_time = val * HZ;
	if (sock_flag(sk, SOCK_KEEPOPEN) &&
		!((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))) {
		u32 elapsed = keepalive_time_elapsed(tp);

		if (tp->keepalive_time > elapsed)
			elapsed = tp->keepalive_time - elapsed;
		else
			elapsed = 0;
		inet_csk_reset_keepalive_timer(sk, elapsed);
	}

	return 0;
}

int tcp_sock_set_keepidle(struct sock *sk, int val)
{
	int err;

	lock_sock(sk);
	err = tcp_sock_set_keepidle_locked(sk, val);
	release_sock(sk);
	return err;
}

int tcp_sock_set_keepintvl(struct sock *sk, int val)
{
	if (val < 1 || val > MAX_TCP_KEEPINTVL)
		return -EINVAL;

	lock_sock(sk);
	tcp_sk(sk)->keepalive_intvl = val * HZ;
	release_sock(sk);
	return 0;
}

int tcp_sock_set_keepcnt(struct sock *sk, int val)
{
	if (val < 1 || val > MAX_TCP_KEEPCNT)
		return -EINVAL;

	lock_sock(sk);
	tcp_sk(sk)->keepalive_probes = val;
	release_sock(sk);
	return 0;
}

void sock_set_reuseaddr(struct sock *sk)
{
	lock_sock(sk);
	sk->sk_reuse = SK_CAN_REUSE;
	release_sock(sk);
}
#endif

#define QTSOCK_SET_KEEPX(sock, val) sock_set_keepalive(sock->sk); tcp_sock_set_keepcnt(sock->sk, val);\
		tcp_sock_set_keepidle(sock->sk, val); tcp_sock_set_keepintvl(sock->sk, val);

static int qtfs_conn_sock_recv(struct qtfs_conn_var_s *pvar, bool block);
static int qtfs_conn_sock_send(struct qtfs_conn_var_s *pvar);
static void qtfs_conn_sock_fini(struct qtfs_conn_var_s *pvar);

void qtfs_sock_recvtimeo_set(struct socket *sock, __s64 sec, __s64 usec)
{
	int error;
#ifdef KVER_4_19
	struct timeval tv;
#else
	struct __kernel_sock_timeval tv;
	sockptr_t optval = KERNEL_SOCKPTR((void *)&tv);
#endif
	tv.tv_sec = sec;
	tv.tv_usec = usec;

	if (sock == NULL) {
		qtfs_err("qtfs sock recvtimeo set failed, sock is invalid.");
		return;
	}

#ifdef KVER_4_19
	error = sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
			(char *)&tv, sizeof(tv));
#else
	error = sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_OLD,
			optval, sizeof(struct __kernel_sock_timeval));
#endif
	if (error) {
		qtfs_err("qtfs param setsockopt error, ret:%d.\n", error);
	}
}

#ifdef QTFS_SERVER
static int qtfs_conn_sock_server_accept(struct qtfs_conn_var_s *pvar)
{
	struct socket *sock = NULL;
	int ret;

	if (!QTCONN_IS_EPOLL_CONN(pvar)) {
		sock = qtfs_server_main_sock;
	} else {
		sock = pvar->conn_var.sock_var.sock;
	}

	if (sock == NULL) {
		WARN_ON(1);
		qtfs_err("qtfs server accept failed, main sock is NULL, threadidx:%d.", pvar->cur_threadidx);
		return -EINVAL;
	}
	ret = kernel_accept(sock, &pvar->conn_var.sock_var.client_sock, SOCK_NONBLOCK);
	if (ret < 0) {
		return ret;
	}
	QTSOCK_SET_KEEPX(sock, 5);

	qtfs_info("qtfs accept a client connection.\n");
	qtfs_sock_recvtimeo_set(pvar->conn_var.sock_var.client_sock, QTFS_SOCK_RCVTIMEO, 0);
	return 0;
}

static int qtfs_conn_sockserver_init(struct qtfs_conn_var_s *pvar)
{
	struct socket *sock;
	int ret;
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(pvar->conn_var.sock_var.port);
	saddr.sin_addr.s_addr = in_aton(pvar->conn_var.sock_var.addr);

	if (!QTCONN_IS_EPOLL_CONN(pvar) && qtfs_server_main_sock != NULL) {
		qtfs_info("qtfs server main sock is set, valid or out-of-date?");
		return 0;
	}
	if (QTCONN_IS_EPOLL_CONN(pvar) && pvar->conn_var.sock_var.sock != NULL) {
		qtfs_info("qtfs server epoll sock is set, valid or out-of-date?");
		return 0;
	}
	qtfs_info("qtfs sock server init enter threadidx:%d", pvar->cur_threadidx);

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &sock);
	if (ret) {
		qtfs_err("qtfs sock server init create sock failed.\n");
		goto err_end;
	}

	sock_set_reuseaddr(sock->sk);
	QTSOCK_SET_KEEPX(sock, 5);

	ret = sock->ops->bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		qtfs_err("qtfs sock server bind error: %d.\n", ret);
		goto err_end;
	}

	ret = sock->ops->listen(sock, QTFS_SERVER_MAXCONN);
	if (ret < 0) {
		qtfs_err("qtfs sock server listen failed.\n");
		goto err_end;
	}

	if (!QTCONN_IS_EPOLL_CONN(pvar)) {
		qtfs_server_main_sock = sock;
		qtfs_info("qtfs thread main sock get, threadidx:%d.", pvar->cur_threadidx);
	} else {
		pvar->conn_var.sock_var.sock = sock;
		qtfs_info("qtfs epoll main sock get, threadidx:%d.", pvar->cur_threadidx);
	}

	return 0;

err_end:
	sock_release(sock);
	return ret;
}
#endif
#ifdef QTFS_CLIENT
static int qtfs_conn_sock_client_connect(struct qtfs_conn_var_s *pvar)
{
	struct socket *sock = pvar->conn_var.sock_var.client_sock;
	int ret;
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(pvar->conn_var.sock_var.port);
	saddr.sin_addr.s_addr = in_aton(pvar->conn_var.sock_var.addr);

	ret = sock->ops->connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), SOCK_NONBLOCK);
	if (ret < 0) {
		qtfs_err("sock addr(%s): connect get ret: %d\n", pvar->conn_var.sock_var.addr, ret);
		return ret;
	}
	QTSOCK_SET_KEEPX(sock, 5);

	qtfs_sock_recvtimeo_set(pvar->conn_var.sock_var.client_sock, QTFS_SOCK_RCVTIMEO, 0);
	return 0;
}
static int qtfs_conn_sockclient_init(struct qtfs_conn_var_s *pvar)
{
	struct socket *sock;
	int ret;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &sock);
	if (ret) {
		qtfs_err("qtfs sock client init create sock failed.\n");
		return -EFAULT;
	}
	QTSOCK_SET_KEEPX(sock, 5);
	pvar->conn_var.sock_var.client_sock = sock;

	return 0;
}
#endif

int qtfs_conn_sock_init(struct qtfs_conn_var_s *pvar)
{
	int ret = -EINVAL;

	if (pvar->conn_var.sock_var.client_sock != NULL) {
		WARN_ON(1);
		qtfs_err("qtfs connection socket init client_sock not NULL!");
	}
#ifdef QTFS_SERVER
	ret = qtfs_conn_sockserver_init(pvar);
#endif
#ifdef QTFS_CLIENT
	ret = qtfs_conn_sockclient_init(pvar);
#endif
	return ret;
}

static int qtfs_conn_sock_recv(struct qtfs_conn_var_s *pvar, bool block)
{
	int ret;
	int headlen = 0;
	int total = 0;
	struct qtreq *rsp = NULL;
	struct kvec load;
	unsigned long retrytimes = 0;

	memset(&pvar->msg_recv, 0, sizeof(pvar->msg_recv));

	headlen = kernel_recvmsg(pvar->conn_var.sock_var.client_sock, &pvar->msg_recv, &pvar->vec_recv, 1,
							QTFS_MSG_HEAD_LEN, (block == true) ? 0 : MSG_DONTWAIT);
	if (headlen <= 0) {
		return headlen;
	}

	load.iov_base = pvar->vec_recv.iov_base + QTFS_MSG_HEAD_LEN;
	load.iov_len = pvar->vec_recv.iov_len - QTFS_MSG_HEAD_LEN;
	total = 0;
	rsp = pvar->vec_recv.iov_base;
	if (rsp->len > load.iov_len) {
		qtfs_err("qtfs recv head invalid len is:%lu", rsp->len);
		return -EINVAL;
	}
	while (total < rsp->len) {
retry:
		ret = kernel_recvmsg(pvar->conn_var.sock_var.client_sock, &pvar->msg_recv, &load, 1,
						rsp->len - total, (block == true) ? 0 : MSG_DONTWAIT);
		if (ret == 0) break;
		if (ret == -EAGAIN)
			goto retry;
		if (ret == -ERESTARTSYS || ret == -EINTR) {
#ifdef QTFS_CLIENT
			if (retrytimes == 0) {
				qtinfo_cntinc(QTINF_RESTART_SYS);
				qtinfo_recverrinc(rsp->type);
			}
#endif
			retrytimes++;
			msleep(1);
			goto retry;
		}
		if (ret < 0) {
			qtfs_err("qtfs recv get invalidelen is:%lu", ret);
			return ret;
		}
		total += ret;
		load.iov_base += ret;
		load.iov_len -= ret;
		if (load.iov_base > (pvar->vec_recv.iov_base + pvar->vec_recv.iov_len)) {
			qtfs_err("qtfs recv error, total:%d iovlen:%lu ret:%d rsplen:%lu", total,
							pvar->vec_recv.iov_len, ret, rsp->len);
			WARN_ON(1);
			break;
		}
	}
	if (total > rsp->len) {
		qtfs_crit("recv total:%d msg len:%lu\n", total, rsp->len);
		WARN_ON(1);
	}

	return total + headlen;
}

static int qtfs_conn_sock_send(struct qtfs_conn_var_s *pvar)
{
	int ret = kernel_sendmsg(pvar->conn_var.sock_var.client_sock, &pvar->msg_send, &pvar->vec_send, 1,
							pvar->vec_send.iov_len);
	if (ret < 0) {
		qtfs_err("qtfs sock send error, ret:%d.\n", ret);
	}
	return ret;
}

static void qtfs_conn_sock_fini(struct qtfs_conn_var_s *pvar)
{
	if (pvar->conn_var.sock_var.client_sock == NULL) {
		qtfs_err("qtfs client sock is NULL during sock_fini");
	}

	if (pvar->conn_var.sock_var.client_sock != NULL) {
		qtfs_err("qtfs conn sock finish threadidx:%d.", pvar->cur_threadidx);
		sock_release(pvar->conn_var.sock_var.client_sock);
		pvar->conn_var.sock_var.client_sock = NULL;
	}

	if (pvar->conn_var.sock_var.sock != NULL) {
		sock_release(pvar->conn_var.sock_var.sock);
		pvar->conn_var.sock_var.sock = NULL;
	}
	return;
}

static bool qtfs_conn_sock_connected(struct qtfs_conn_var_s *pvar)
{
	struct socket *sock = pvar->conn_var.sock_var.client_sock;
	__u8 tcpi_state;
	if (sock == NULL)
		return false;
	tcpi_state = inet_sk_state_load(sock->sk);
	if (tcpi_state == TCP_ESTABLISHED)
		return true;
	qtfs_warn("qtfs threadidx:%d tcpi state:%u(define:TCP_ESTABLISHED=1 is connected) disconnect!", pvar->cur_threadidx, tcpi_state);

	return false;
}
#ifdef QTFS_CLIENT
void qtfs_sock_drop_recv_buf(struct qtfs_conn_var_s *pvar)
{
#define TMP_STACK_LEN 64
	int ret = 0;
	char buf[TMP_STACK_LEN];
	struct kvec vec_recv;
	struct msghdr msg_recv;
	vec_recv.iov_base = buf;
	vec_recv.iov_len = TMP_STACK_LEN;
	do {
		ret = kernel_recvmsg(pvar->conn_var.sock_var.client_sock, &msg_recv, &vec_recv, 1,
					vec_recv.iov_len, MSG_DONTWAIT);
		if (ret > 0) {
			qtfs_err("drop invalid data len:%d", ret);
		}
	} while (ret > 0);
	return;
}
#endif

#ifdef QTFS_SERVER
static bool qtfs_conn_sock_inited(struct qtfs_conn_var_s *pvar)
{
	return qtfs_server_main_sock != NULL;
}
#endif

int qtfs_sock_param_init(void)
{
	return 0;
}

int qtfs_sock_param_fini(void)
{
#ifdef QTFS_SERVER
	if (qtfs_server_main_sock != NULL) {
		sock_release(qtfs_server_main_sock);
		qtfs_server_main_sock = NULL;
	}
#endif
	return 0;
}

struct qtfs_conn_ops_s qtfs_conn_sock_ops = {
	.conn_var_init = qtfs_conn_var_init,
	.conn_var_fini = qtfs_conn_var_fini,
	.conn_msg_clear = qtfs_conn_msg_clear,
	.get_conn_msg_buf = qtfs_conn_msg_buf,
	.conn_init = qtfs_conn_sock_init,
	.conn_fini = qtfs_conn_sock_fini,
	.conn_send = qtfs_conn_sock_send,
	.conn_recv = qtfs_conn_sock_recv,
#ifdef QTFS_SERVER
	.conn_server_accept = qtfs_conn_sock_server_accept,
	.conn_inited = qtfs_conn_sock_inited,
#endif
#ifdef QTFS_CLIENT
	.conn_client_connect = qtfs_conn_sock_client_connect,
	.conn_recv_buff_drop = qtfs_sock_drop_recv_buf,
#endif
	.conn_connected = qtfs_conn_sock_connected,
};

int qtfs_sock_pvar_init(struct qtfs_conn_var_s *pvar)
{
	// fill conn_pvar struct here
	strlcpy(pvar->conn_var.sock_var.addr, qtfs_server_ip, sizeof(pvar->conn_var.sock_var.addr));
	if (QTCONN_IS_EPOLL_CONN(pvar)) {
		pvar->conn_var.sock_var.port = qtfs_server_port + 1;
	} else {
		pvar->conn_var.sock_var.port = qtfs_server_port;
	}

	pvar->conn_ops = &qtfs_conn_sock_ops;
	return 0;
}

static int qtfs_sock_parse_param(void)
{
	// parse conn specific params here
	return 0;
}

struct qtfs_pvar_ops_s qtfs_conn_sock_pvar_ops = {
	.parse_param = qtfs_sock_parse_param,
	.param_init = qtfs_sock_param_init,
	.param_fini = qtfs_sock_param_fini,
	.pvar_init = qtfs_sock_pvar_init
};
