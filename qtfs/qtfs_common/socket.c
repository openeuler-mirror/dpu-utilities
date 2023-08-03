/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/un.h>
#include <linux/vm_sockets.h>

#include "comm.h"
#include "conn.h"
#include "log.h"
#include "req.h"
#include "symbol_wrapper.h"

#ifdef QTFS_TEST_MODE
char qtfs_server_ip[20] = "127.0.0.1";
int qtfs_server_port = 12345;
#else
unsigned int qtfs_server_vsock_port = 12345;
unsigned int qtfs_server_vsock_cid = 2; // host cid in vm is always 2
#endif

#ifdef QTFS_SERVER
struct socket *qtfs_server_main_sock[QTFS_CONN_TYPE_INV] = {NULL};
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

static int qtfs_conn_sock_recv(void *connvar, void *buf, size_t len, bool block);
static int qtfs_conn_sock_send(void *connvar, void *buf, size_t len);
static void qtfs_conn_sock_fini(void *connvar, qtfs_conn_type_e type);

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
static int qtfs_conn_sock_server_accept(void *connvar, qtfs_conn_type_e type)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	int ret;
	struct socket *sock = NULL;
	if (type >= QTFS_CONN_TYPE_INV || qtfs_server_main_sock[type] == NULL) {
		qtfs_err("invalid type:%u or main sock is invalid.", type);
		return -EFAULT;
	}
	sock = qtfs_server_main_sock[type];

	if (sock == NULL) {
		WARN_ON(1);
		qtfs_err("qtfs server accept failed, main sock is NULL.");
		return -EINVAL;
	}
	ret = kernel_accept(sock, &sockvar->client_sock, SOCK_NONBLOCK);
	if (ret < 0) {
		return ret;
	}
#ifdef QTFS_TEST_MODE
	QTSOCK_SET_KEEPX(sock, 5);
#else
	sock_set_keepalive(sock->sk);
#endif

	qtfs_info("qtfs accept a client connection.\n");
	qtfs_sock_recvtimeo_set(sockvar->client_sock, QTFS_SOCK_RCVTIMEO, 0);
	return 0;
}

static int qtfs_conn_sock_init(void *connvar, qtfs_conn_type_e type)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	struct socket *sock;
	int ret;
	int sock_family = AF_VSOCK;
#ifdef QTFS_TEST_MODE
	struct sockaddr_in saddr;
	sock_family = AF_INET;
	saddr.sin_family = sock_family;
	saddr.sin_port = htons(sockvar->port);
	saddr.sin_addr.s_addr = in_aton(sockvar->addr);
#else
	struct sockaddr_vm saddr;
	sock_family = AF_VSOCK;
	saddr.svm_family = sock_family;
	saddr.svm_port = sockvar->vm_port;
	saddr.svm_cid = sockvar->vm_cid;
#endif
	if (type >= QTFS_CONN_TYPE_INV || qtfs_server_main_sock[type] != NULL) {
		qtfs_info("qtfs conn type:%u main sock is set, valid or out-of-date?", type);
		return 0;
	}

	qtfs_info("qtfs sock server init enter");

	ret = sock_create_kern(&init_net, sock_family, SOCK_STREAM, 0, &sock);
	if (ret) {
		qtfs_err("qtfs sock server init create sock failed.\n");
		goto err_end;
	}

	sock_set_reuseaddr(sock->sk);
#ifdef QTFS_TEST_MODE
	QTSOCK_SET_KEEPX(sock, 5);
#else
	sock_set_keepalive(sock->sk);
#endif

	ret = sock->ops->bind(sock, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		qtfs_err("qtfs sock server bind error: %d.\n", ret);
		goto err_end;
	}

	ret = sock->ops->listen(sock, QTFS_SERVER_MAXCONN);
	if (ret < 0) {
		qtfs_err("qtfs sock server listen failed.\n");
		goto err_end;
	}

	qtfs_info("qtfs socket init sock OK!");
	qtfs_server_main_sock[type] = sock;
	return 0;

err_end:
	sock_release(sock);
	return ret;
}
#endif
#ifdef QTFS_CLIENT
static int qtfs_conn_sock_client_connect(void *connvar, qtfs_conn_type_e type)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	struct socket *sock = sockvar->client_sock;
	int ret;
#ifdef QTFS_TEST_MODE
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(sockvar->port);
	saddr.sin_addr.s_addr = in_aton(sockvar->addr);
#else
	struct sockaddr_vm saddr;
	saddr.svm_family = AF_VSOCK;
	saddr.svm_port = sockvar->vm_port;
	saddr.svm_cid = sockvar->vm_cid;
#endif
	if (!sock) {
		qtfs_err("Invalid client sock, which is null\n");
		return -EINVAL;
	}

	ret = sock->ops->connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
	if (ret < 0) {
#ifdef QTFS_TEST_MODE
		qtfs_err("sock addr(%s): connect get ret: %d\n", sockvar->addr, ret);
#else
		qtfs_err("vsock cid:%u: connect get ret: %d\n", sockvar->vm_cid, ret);
#endif
		return ret;
	}
#ifdef QTFS_TEST_MODE
	QTSOCK_SET_KEEPX(sock, 5);
#else
	sock_set_keepalive(sock->sk);
#endif

	qtfs_sock_recvtimeo_set(sockvar->client_sock, QTFS_SOCK_RCVTIMEO, 0);
	return 0;
}
//client侧type用不上
static int qtfs_conn_sock_init(void *connvar, qtfs_conn_type_e type)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	struct socket *sock;
	int ret;

#ifdef QTFS_TEST_MODE
	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &sock);
#else
	ret = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &sock);
#endif
	if (ret) {
		qtfs_err("qtfs sock client init create sock failed.\n");
		return -EFAULT;
	}
#ifdef QTFS_TEST_MODE
	QTSOCK_SET_KEEPX(sock, 5);
#else
	sock_set_keepalive(sock->sk);
#endif
	sockvar->client_sock = sock;

	return 0;
}
#endif

static int qtfs_conn_sock_recv(void *connvar, void *buf, size_t len, bool block)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	struct kvec v;
	memset(&sockvar->msg_recv, 0, sizeof(sockvar->msg_recv));
	v.iov_base = buf;
	v.iov_len = len;

	return kernel_recvmsg(sockvar->client_sock, &sockvar->msg_recv, &v, 1,
							len, (block == true) ? 0 : MSG_DONTWAIT);
}

static int qtfs_conn_sock_send(void *connvar, void *buf, size_t len)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	struct kvec v;
	int ret;
	
	v.iov_base = buf;
	v.iov_len = len;

	ret = kernel_sendmsg(sockvar->client_sock, &sockvar->msg_send, &v, 1, len);
	if (ret < 0) {
		qtfs_err("qtfs sock send error, ret:%d.\n", ret);
	}
	return ret;
}

static void qtfs_conn_sock_fini(void *connvar, qtfs_conn_type_e type)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	if (sockvar->client_sock == NULL) {
		qtfs_err("qtfs client sock is NULL during sock_fini");
	}

	if (sockvar->client_sock != NULL) {
		qtfs_err("qtfs conn sock finish.");
		sock_release(sockvar->client_sock);
		sockvar->client_sock = NULL;
	}

#ifdef QTFS_SERVER
	if (type < QTFS_CONN_TYPE_INV && qtfs_server_main_sock[type] != NULL) {
		sock_release(qtfs_server_main_sock[type]);
		qtfs_server_main_sock[type] = NULL;
	}
#endif
	return;
}

static bool qtfs_conn_sock_connected(void *connvar)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	struct socket *sock = sockvar->client_sock;
	__u8 tcpi_state;
	if (sock == NULL)
		return false;
	tcpi_state = inet_sk_state_load(sock->sk);
	if (tcpi_state == TCP_ESTABLISHED)
		return true;
	qtfs_warn("qtfs tcpi state:%u(define:TCP_ESTABLISHED=1 is connected) disconnect!", tcpi_state);

	return false;
}
#ifdef QTFS_CLIENT
void qtfs_sock_drop_recv_buf(void *connvar)
{
#define TMP_STACK_LEN 64
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	int ret = 0;
	char buf[TMP_STACK_LEN];
	struct kvec vec_recv;
	struct msghdr msg_recv;
	vec_recv.iov_base = buf;
	vec_recv.iov_len = TMP_STACK_LEN;
	do {
		ret = kernel_recvmsg(sockvar->client_sock, &msg_recv, &vec_recv, 1,
					vec_recv.iov_len, MSG_DONTWAIT);
		if (ret > 0) {
			qtfs_err("drop invalid data len:%d", ret);
		}
	} while (ret > 0);
	return;
}
#endif

#ifdef QTFS_SERVER
static bool qtfs_conn_sock_inited(void *connvar, qtfs_conn_type_e type)
{
	if (type >= QTFS_CONN_TYPE_INV) {
		qtfs_err("invalid type:%u", type);
		return false;
	}
	return qtfs_server_main_sock[type] != NULL;
}
#endif

int qtfs_sock_param_init(void)
{
	return 0;
}

int qtfs_sock_param_fini(void)
{
#ifdef QTFS_SERVER
	if (qtfs_server_main_sock[QTFS_CONN_TYPE_QTFS] != NULL) {
		sock_release(qtfs_server_main_sock[QTFS_CONN_TYPE_QTFS]);
		qtfs_server_main_sock[QTFS_CONN_TYPE_QTFS] = NULL;
	}
	if (qtfs_server_main_sock[QTFS_CONN_TYPE_FIFO] != NULL) {
		sock_release(qtfs_server_main_sock[QTFS_CONN_TYPE_FIFO]);
		qtfs_server_main_sock[QTFS_CONN_TYPE_FIFO] = NULL;
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
	.conn_new_connection = qtfs_conn_sock_server_accept,
	.conn_inited = qtfs_conn_sock_inited,
#endif
#ifdef QTFS_CLIENT
	.conn_new_connection = qtfs_conn_sock_client_connect,
	.conn_recv_buff_drop = qtfs_sock_drop_recv_buf,
#endif
	.conn_connected = qtfs_conn_sock_connected,
};

int qtfs_sock_pvar_init(void *connvar, struct qtfs_conn_ops_s **conn_ops, qtfs_conn_type_e type)
{
	struct qtfs_sock_var_s *sockvar = (struct qtfs_sock_var_s *)connvar;
	
	if (type >= QTFS_CONN_TYPE_INV) {
		qtfs_err("invalid type:%u", type);
		return -1;
	}

#ifdef QTFS_TEST_MODE
	// fill conn_pvar struct here
	strlcpy(sockvar->addr, qtfs_server_ip, sizeof(sockvar->addr));
	sockvar->port = qtfs_server_port + type;
#else
	// vsock
	sockvar->vm_cid = qtfs_server_vsock_cid;
	sockvar->vm_port = qtfs_server_vsock_port + type;
#endif
	*conn_ops = &qtfs_conn_sock_ops;
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

#ifdef QTFS_TEST_MODE
module_param_string(qtfs_server_ip, qtfs_server_ip, sizeof(qtfs_server_ip), 0600);
MODULE_PARM_DESC(qtfs_server_ip, "qtfs server ip");
module_param(qtfs_server_port, int, 0600);
#else
module_param(qtfs_server_vsock_port, uint, 0600);
module_param(qtfs_server_vsock_cid, uint, 0600);
#endif