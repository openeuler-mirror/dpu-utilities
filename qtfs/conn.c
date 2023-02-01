
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/tcp.h>

#include "comm.h"
#include "conn.h"
#include "log.h"
#include "req.h"

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

char qtfs_log_level[QTFS_LOGLEVEL_STRLEN] = {0};
char qtfs_server_ip[20] = "127.0.0.1";
int log_level = LOG_ERROR;
int qtfs_server_port = 12345;
int qtfs_sock_max_conn = QTFS_MAX_THREADS;
struct qtinfo *qtfs_diag_info = NULL;
bool qtfs_epoll_mode = false; // true: support any mode; false: only support fifo

static atomic_t g_qtfs_conn_num;
static struct list_head g_vld_lst;
static struct list_head g_busy_lst;
static struct llist_head g_lazy_put_llst;
static struct mutex g_param_mutex;
int qtfs_mod_exiting = false;
struct qtfs_sock_var_s *qtfs_thread_var[QTFS_MAX_THREADS] = {NULL};
struct qtfs_sock_var_s *qtfs_epoll_var = NULL;
#ifdef QTFS_SERVER
struct socket *qtfs_server_main_sock = NULL;
struct qtfs_server_userp_s *qtfs_userps = NULL;
#endif
int qtfs_uds_proxy_pid = -1;
#define QTFS_EPOLL_THREADIDX (QTFS_MAX_THREADS + 4)


#define QTCONN_IS_EPOLL_CONN(pvar) (pvar->cur_threadidx == QTFS_EPOLL_THREADIDX)
#define QTSOCK_SET_KEEPX(sock, val) sock_set_keepalive(sock->sk); tcp_sock_set_keepcnt(sock->sk, val);\
		tcp_sock_set_keepidle(sock->sk, val); tcp_sock_set_keepintvl(sock->sk, val);

#define QTFS_SERVER_MAXCONN 2

static int qtfs_conn_sock_recv(struct qtfs_sock_var_s *pvar, bool block);
static int qtfs_conn_sock_send(struct qtfs_sock_var_s *pvar);
static void qtfs_conn_sock_fini(struct qtfs_sock_var_s *pvar);

#ifdef QTFS_SERVER
static int qtfs_conn_server_accept(struct qtfs_sock_var_s *pvar)
{
	struct socket *sock = NULL;
	int ret;

	if (!QTCONN_IS_EPOLL_CONN(pvar)) {
		sock = qtfs_server_main_sock;
	} else {
		sock = pvar->sock;
	}

	if (sock == NULL) {
		WARN_ON(1);
		qtfs_err("qtfs server accept failed, main sock is NULL, threadidx:%d.", pvar->cur_threadidx);
		return -EINVAL;
	}
	ret = kernel_accept(sock, &pvar->client_sock, SOCK_NONBLOCK);
	if (ret < 0) {
		return ret;
	}
	QTSOCK_SET_KEEPX(sock, 5);

	qtfs_info("qtfs accept a client connection.\n");
	return 0;
}

static int qtfs_conn_sockserver_init(struct qtfs_sock_var_s *pvar)
{
	struct socket *sock;
	int ret;
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(pvar->port);
	saddr.sin_addr.s_addr = in_aton(pvar->addr);
	
	if (!QTCONN_IS_EPOLL_CONN(pvar) && qtfs_server_main_sock != NULL) {
		qtfs_info("qtfs server main sock is %lx, valid or out-of-date?", (unsigned long)qtfs_server_main_sock);
		return 0;
	}
	if (QTCONN_IS_EPOLL_CONN(pvar) && pvar->sock != NULL) {
		qtfs_info("qtfs server epoll sock is %lx, valid or out-of-date?", (unsigned long)pvar->sock);
		return 0;
	}
	qtfs_info("qtfs sock server init enter pvar:%lx, threadidx:%d mainsock:%lx pvarsock:%lx", (unsigned long)pvar, pvar->cur_threadidx,
							(unsigned long)qtfs_server_main_sock, (unsigned long)pvar->sock);

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
		qtfs_info("qtfs thread main sock get:%lx, threadidx:%d.", (unsigned long)qtfs_server_main_sock, pvar->cur_threadidx);
	} else {
		pvar->sock = sock;
		qtfs_info("qtfs epoll main sock get:%lx, threadidx:%d.", (unsigned long)pvar->sock, pvar->cur_threadidx);
	}

	return 0;

err_end:
	sock_release(sock);
	return ret;
}
#endif
#ifdef QTFS_CLIENT
static int qtfs_conn_client_conn(struct qtfs_sock_var_s *pvar)
{
	struct socket *sock = pvar->client_sock;
	int ret;
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(pvar->port);
	saddr.sin_addr.s_addr = in_aton(pvar->addr);

	ret = sock->ops->connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), SOCK_NONBLOCK);
	if (ret < 0) {
		qtfs_err("%s: sock(%llx) addr(%s): connect get ret: %d\n", __func__, (__u64)sock, pvar->addr, ret);
		return ret;
	}
	QTSOCK_SET_KEEPX(sock, 5);

	return 0;
}
static int qtfs_conn_sockclient_init(struct qtfs_sock_var_s *pvar)
{
	struct socket *sock;
	int ret;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &sock);
	if (ret) {
		qtfs_err("qtfs sock client init create sock failed.\n");
		goto err_end;
	}
	QTSOCK_SET_KEEPX(sock, 5);
	pvar->client_sock = sock;

	return 0;
err_end:
	sock_release(sock);
	return ret;
}
#endif

int qtfs_conn_init(int msg_mode, struct qtfs_sock_var_s *pvar)
{
	int ret;

	switch (msg_mode) {
		case QTFS_CONN_SOCKET:
#ifdef QTFS_SERVER
			ret = qtfs_conn_sockserver_init(pvar);
#endif
#ifdef QTFS_CLIENT
			ret = qtfs_conn_sockclient_init(pvar);
#endif
			break;

		default:
			qtfs_err("qtfs connection init failed, unknown mode:%d.\n", msg_mode);
			break;
	}

	return ret;
}

void qtfs_conn_fini(int msg_mode, struct qtfs_sock_var_s *pvar)
{
	switch (msg_mode) {
		case QTFS_CONN_SOCKET:
			qtfs_conn_sock_fini(pvar);
			break;

		default:
			qtfs_err("qtfs connection fini failed, unknown mode:%d.\n", msg_mode);
			break;
	}
	return;
}

int qtfs_conn_send(int msg_mode, struct qtfs_sock_var_s *pvar)
{
	int ret;
	switch (msg_mode) {
		case QTFS_CONN_SOCKET:
			ret = qtfs_conn_sock_send(pvar);
			break;
		default:
			qtfs_err("qtfs connection send failed, unknown mode:%d.\n", msg_mode);
			break;
	}
	return ret;
}

int do_qtfs_conn_recv(int msg_mode, struct qtfs_sock_var_s *pvar, bool block)
{
	int ret;
	switch (msg_mode) {
		case QTFS_CONN_SOCKET:
			ret = qtfs_conn_sock_recv(pvar, block);
			break;

		default:
			qtfs_err("qtfs connection recv failed, unknown mode:%d.\n", msg_mode);
			break;
	}
	return ret;
}

int qtfs_conn_recv_block(int msg_mode, struct qtfs_sock_var_s *pvar)
{
	return do_qtfs_conn_recv(msg_mode, pvar, true);
}

int qtfs_conn_recv(int msg_mode, struct qtfs_sock_var_s *pvar)
{
	int ret = do_qtfs_conn_recv(msg_mode, pvar, false);
	if (ret <= 0) {
		msleep(1);
	}
	return ret;
}

void qtfs_sock_recvtimeo_set(struct socket *sock, __s64 sec, __s64 usec)
{
	int error;
	struct __kernel_sock_timeval tv;
	sockptr_t optval = KERNEL_SOCKPTR((void *)&tv);
	tv.tv_sec = sec;
	tv.tv_usec = usec;

	if (sock == NULL) {
		qtfs_err("qtfs sock recvtimeo set failed, sock is invalid.");
		return;
	}
	error = sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_OLD,
													optval, sizeof(struct __kernel_sock_timeval));
	if (error) {
		qtfs_err("qtfs param setsockopt error, ret:%d.\n", error);
	}
}

static int qtfs_conn_sock_recv(struct qtfs_sock_var_s *pvar, bool block)
{
	int ret;
	int headlen = 0;
	int total = 0;
	struct qtreq *rsp = NULL;
	struct kvec load;

	memset(&pvar->msg_recv, 0, sizeof(pvar->msg_recv));

	headlen = kernel_recvmsg(pvar->client_sock, &pvar->msg_recv, &pvar->vec_recv, 1,
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
		ret = kernel_recvmsg(pvar->client_sock, &pvar->msg_recv, &load, 1,
						rsp->len - total, (block == true) ? 0 : MSG_DONTWAIT);
		if (ret <= 0) break;
		total += ret;
		load.iov_base += ret;
		load.iov_len -= ret;
		if (load.iov_base > (pvar->vec_recv.iov_base + pvar->vec_recv.iov_len)) {
			qtfs_err("qtfs recv error, total:%d iov_base:%lx iovlen:%lu ret:%d rsplen:%lu", total,
							(unsigned long)pvar->vec_recv.iov_base, pvar->vec_recv.iov_len, ret, rsp->len);
			WARN_ON(1);
			dump_stack();
			break;
		}
	}
	if (total > rsp->len) {
		qtfs_err("recv total:%d msg len:%lu\n", total, rsp->len);
		BUG();
	}
	
	return total + headlen;
}

static int qtfs_conn_sock_send(struct qtfs_sock_var_s *pvar)
{
	int ret = kernel_sendmsg(pvar->client_sock, &pvar->msg_send, &pvar->vec_send, 1,
							pvar->vec_send.iov_len);
	if (ret < 0) {
		qtfs_err("qtfs sock send error, ret:%d.\n", ret);
	}
	return ret;
}

static void qtfs_conn_sock_fini(struct qtfs_sock_var_s *pvar)
{
	if (pvar->client_sock != NULL) {
		qtfs_err("qtfs conn sock finish threadidx:%d, client:%lx.", pvar->cur_threadidx, (unsigned long)pvar->client_sock);
		sock_release(pvar->client_sock);
		pvar->client_sock = NULL;
	}

	return;
}

int qtfs_sock_var_init(struct qtfs_sock_var_s *pvar)
{
	memset(pvar, 0, sizeof(struct qtfs_sock_var_s));
	pvar->vec_recv.iov_base = kmalloc(QTFS_MSG_LEN, GFP_KERNEL);
	if (pvar->vec_recv.iov_base == NULL) {
		qtfs_err("qtfs recv kmalloc failed, len:%lu.\n", QTFS_MSG_LEN);
		return QTFS_ERR;
	}
	pvar->vec_send.iov_base = kmalloc(QTFS_MSG_LEN, GFP_KERNEL);
	if (pvar->vec_send.iov_base == NULL) {
		qtfs_err("qtfs send kmalloc failed, len:%lu.\n", QTFS_MSG_LEN);
		kfree(pvar->vec_recv.iov_base);
		pvar->vec_recv.iov_base = NULL;
		return QTFS_ERR;
	}
	pvar->vec_recv.iov_len = QTFS_MSG_LEN;
	pvar->vec_send.iov_len = 0;
	memset(pvar->vec_recv.iov_base, 0, QTFS_MSG_LEN);
	memset(pvar->vec_send.iov_base, 0, QTFS_MSG_LEN);
	INIT_LIST_HEAD(&pvar->lst);
	return QTFS_OK;
}

void qtfs_sock_var_fini(struct qtfs_sock_var_s *pvar)
{
	if (pvar->vec_recv.iov_base != NULL) {
		kfree(pvar->vec_recv.iov_base);
		pvar->vec_recv.iov_base = NULL;
	}
	if (pvar->vec_send.iov_base != NULL) {
		kfree(pvar->vec_send.iov_base);
		pvar->vec_send.iov_base = NULL;
	}

	return ;
}

void qtfs_sock_msg_clear(struct qtfs_sock_var_s *pvar)
{
	memset(pvar->vec_recv.iov_base, 0, QTFS_MSG_LEN);
	memset(pvar->vec_send.iov_base, 0, QTFS_MSG_LEN);
	pvar->recv_valid = QTFS_MSG_LEN;
	pvar->send_valid = QTFS_MSG_LEN;
#ifdef QTFS_CLIENT
	memset(pvar->who_using, 0, QTFS_FUNCTION_LEN);
#endif
	return;
}

void *qtfs_sock_msg_buf(struct qtfs_sock_var_s *pvar, int dir)
{
	struct qtreq *req = (dir == QTFS_SEND) ? pvar->vec_send.iov_base : pvar->vec_recv.iov_base;
	if (!req) {
		WARN_ON(1);
		return NULL;
	}
	return req->data;
}

// state machine
#define QTCONN_CUR_STATE(pvar) ((pvar->state == QTCONN_INIT) ? "INIT" : \
														((pvar->state == QTCONN_CONNECTING) ? "CONNECTING" : \
														((pvar->state == QTCONN_ACTIVE) ? "ACTIVE" : "UNKNOWN")))

static int qtfs_sm_connecting(struct qtfs_sock_var_s *pvar)
{
	int ret = QTERROR;

#ifdef QTFS_SERVER
	ret = qtfs_conn_server_accept(pvar);
	if (ret == 0) {
		qtfs_info("qtfs sm connecting accept a new connection, addr:%s port:%u.",
								pvar->addr, pvar->port);
		qtfs_sock_recvtimeo_set(pvar->client_sock, QTFS_SOCK_RCVTIMEO, 0);
	} else {
		msleep(500);
	}
#endif
#ifdef QTFS_CLIENT
	int retry;
	qtfs_info("qtfs sm connecting wait for server thread:%d, addr:%s port:%u",
									pvar->cur_threadidx, pvar->addr, pvar->port);
	retry = 3;
	while (qtfs_mod_exiting == false && retry-- > 0) {
		ret = qtfs_conn_client_conn(pvar);
		if (ret == 0) {
			qtfs_info("qtfs sm connecting connect to a new connection, addr:%s port:%u.",
									pvar->addr, pvar->port);
			qtfs_sock_recvtimeo_set(pvar->client_sock, QTFS_SOCK_RCVTIMEO, 0);
			break;
		}
		msleep(1);
	}
#endif

	return ret;
}

int qtfs_sm_active(struct qtfs_sock_var_s *pvar)
{
	int ret = 0;

	switch (pvar->state) {
		case QTCONN_ACTIVE:
			// do nothing
			break;
		case QTCONN_INIT:
			// create sock (server:bind listen)
			if (pvar->client_sock != NULL) {
				WARN_ON(1);
				qtfs_err("qtfs sm active client sock not NULL!");
			}
			ret = qtfs_conn_init(QTFS_CONN_SOCKET, pvar);
			if (ret < 0) {
				qtfs_err("qtfs sm active init failed, ret:%d.", ret);
				break;
			}
			// dont break, just enter connecting state to process
			pvar->state = QTCONN_CONNECTING;
			qtfs_info("qtfs sm active connecting, threadidx:%d sock:%lx client_sock:%lx",
							pvar->cur_threadidx, (unsigned long)pvar->sock, (unsigned long)pvar->client_sock);
			// fall-through

		case QTCONN_CONNECTING:
			// accept(server) or connect(client)
			ret = qtfs_sm_connecting(pvar);
			if (ret == 0)
				pvar->state = QTCONN_ACTIVE;
			break;
		default:
			qtfs_err("qtfs sm active unknown state:%s.", QTCONN_CUR_STATE(pvar));
			ret = -EINVAL;
			break;
	}
	return ret;
}

int qtfs_sm_reconnect(struct qtfs_sock_var_s *pvar)
{
	int ret = QTOK;
	switch (pvar->state) {
		case QTCONN_INIT:
			WARN_ON(1);
			qtfs_err("qtfs sm reconnect state error!");
			ret = QTERROR;
			break;
		case QTCONN_ACTIVE:
			// release current socket and reconnect
			if (pvar->client_sock == NULL) {
				qtfs_err("qtfs sm reconnect client sock invalid?");
				WARN_ON(1);
			}
			sock_release(pvar->client_sock);
			pvar->client_sock = NULL;

			ret = qtfs_conn_init(QTFS_CONN_SOCKET, pvar);
			if (ret < 0) {
				qtfs_err("qtfs sm active init failed, ret:%d.", ret);
				break;
			}

			pvar->state = QTCONN_CONNECTING;
			qtfs_warn("qtfs sm reconnect thread:%d, state:%s.", pvar->cur_threadidx, QTCONN_CUR_STATE(pvar));
			// fall-through
		case QTCONN_CONNECTING:
			ret = qtfs_sm_connecting(pvar);
			if (ret == 0)
				pvar->state = QTCONN_ACTIVE;
			break;
		default:
			qtfs_err("qtfs sm reconnect unknown state:%s.", QTCONN_CUR_STATE(pvar));
			ret = QTERROR;
			break;
	}
	return ret;
}

int qtfs_sm_exit(struct qtfs_sock_var_s *pvar)
{
	int ret = QTOK;
	switch (pvar->state) {
		case QTCONN_INIT:
			// do nothing
			break;
		case QTCONN_ACTIVE:
		case QTCONN_CONNECTING:
			if (pvar->client_sock == NULL) {
				qtfs_err("qtfs sm exit client sock invalid.");
				break;
			}
			sock_release(pvar->client_sock);
			pvar->client_sock = NULL;
#ifdef QTFS_SERVER
			pvar->state = QTCONN_CONNECTING;
#endif
#ifdef QTFS_CLIENT
			pvar->state = QTCONN_INIT;
#endif
			qtfs_warn("qtfs sm exit thread:%d state:%s.", pvar->cur_threadidx, QTCONN_CUR_STATE(pvar));
			break;

		default:
			qtfs_err("qtfs sm exit unknown state:%s.", QTCONN_CUR_STATE(pvar));
			ret = QTERROR;
			break;
	}
	return ret;
}

int qtfs_mutex_lock_interruptible(struct mutex *lock)
{
	int ret;
	ret = mutex_lock_interruptible(lock);
	if (ret == 0) {
		// mutex lock successed, proc lazy put
		while (1) {
			struct llist_node *toput = llist_del_first(&g_lazy_put_llst);
			struct qtfs_sock_var_s *pvar;
			if (toput == NULL)
				break;
			pvar = llist_entry(toput, struct qtfs_sock_var_s, lazy_put);
			qtfs_sock_msg_clear(pvar);
			list_move_tail(&pvar->lst, &g_vld_lst);
			qtfs_warn("qtfs pvar lazy put idx:%d.", pvar->cur_threadidx);
		}
	}
	return ret;
}

void qtfs_conn_param_init(void)
{
	INIT_LIST_HEAD(&g_vld_lst);
	INIT_LIST_HEAD(&g_busy_lst);
	init_llist_head(&g_lazy_put_llst);
	atomic_set(&g_qtfs_conn_num, 0);

	mutex_init(&g_param_mutex);
	return;
}

void qtfs_conn_param_fini(void)
{
	struct list_head *plst;
	struct list_head *n;
	int ret;
	int conn_num;
	int i;

	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret < 0) {
		qtfs_err("qtfs conn param finish mutex lock interrup failed, ret:%d.", ret);
		WARN_ON(1);
		return;
	}

	list_for_each_safe(plst, n, &g_vld_lst) {
		struct qtfs_sock_var_s *pvar = (struct qtfs_sock_var_s *)plst;
		qtfs_sock_var_fini((struct qtfs_sock_var_s *)plst);
		qtfs_sm_exit((struct qtfs_sock_var_s *)plst);
		kfree(plst);
		if (pvar->cur_threadidx < 0 || pvar->cur_threadidx >= QTFS_MAX_THREADS) {
			qtfs_err("qtfs free unknown threadidx %d", pvar->cur_threadidx);
		} else {
			qtfs_thread_var[pvar->cur_threadidx] = NULL;
			qtfs_info("qtfs free pvar idx:%d successed.", pvar->cur_threadidx);
		}
	}
	conn_num = atomic_read(&g_qtfs_conn_num);
	for (i = 0; i < conn_num; i++) {
		if (qtfs_thread_var[i] != NULL) {
			qtfs_err("qtfs param not free idx:%d holder:%s",
							qtfs_thread_var[i]->cur_threadidx,
							qtfs_thread_var[i]->who_using);
		}
	}
	mutex_unlock(&g_param_mutex);
#ifdef QTFS_SERVER
	if (qtfs_server_main_sock != NULL) {
		sock_release(qtfs_server_main_sock);
		qtfs_server_main_sock = NULL;
	}
#endif
}

struct qtfs_sock_var_s *_qtfs_conn_get_param(const char *func)
{
	struct qtfs_sock_var_s *pvar = NULL;
	int ret;
	int cnt = 0;

	if (qtfs_mod_exiting == true) {
		qtfs_warn("qtfs module is exiting, good bye!");
		return NULL;
	}

retry:
	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret < 0) {
		qtfs_err("qtfs conn get param mutex lock interrup failed, ret:%d.", ret);
		return NULL;
	}
	if (!list_empty(&g_vld_lst))
		pvar = list_last_entry(&g_vld_lst, struct qtfs_sock_var_s, lst);
	if (pvar != NULL) {
		list_move_tail(&pvar->lst, &g_busy_lst);
	}
	mutex_unlock(&g_param_mutex);

	if (pvar != NULL) {
		int ret;
		if (pvar->state == QTCONN_ACTIVE && qtfs_sock_connected(pvar) == false) {
			qtfs_warn("qtfs get param thread:%d disconnected, try to reconnect.", pvar->cur_threadidx);
			ret = qtfs_sm_reconnect(pvar);
		} else {
			ret = qtfs_sm_active(pvar);
		}
		if (ret != 0) {
			qtfs_conn_put_param(pvar);
			return NULL;
		}
		memcpy(pvar->who_using, func, (strlen(func) >= QTFS_FUNCTION_LEN - 1) ? (QTFS_FUNCTION_LEN - 1) : strlen(func));
		return pvar;
	}

	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret < 0) {
		qtfs_err("qtfs conn get param mutex lock interrup failed, ret:%d.", ret);
		return NULL;
	}
	if (atomic_read(&g_qtfs_conn_num) >= qtfs_sock_max_conn) {
		mutex_unlock(&g_param_mutex);
		cnt++;
		msleep(1);
		if (cnt < 100000)
			goto retry;
		qtfs_err("qtfs get param failed, the concurrency specification has reached the upper limit");
		return NULL;
	}
	pvar = kmalloc(sizeof(struct qtfs_sock_var_s), GFP_KERNEL);
	if (pvar == NULL) {
		qtfs_err("qtfs get param kmalloc failed.\n");
		mutex_unlock(&g_param_mutex);
		return NULL;
	}
	if (QTFS_OK != qtfs_sock_var_init(pvar)) {
		qtfs_err("qtfs sock var init failed.\n");
		kfree(pvar);
		mutex_unlock(&g_param_mutex);
		return NULL;
	}

	memcpy(pvar->who_using, func, (strlen(func) >= QTFS_FUNCTION_LEN - 1) ? (QTFS_FUNCTION_LEN - 1) : strlen(func));
	pvar->cur_threadidx = atomic_read(&g_qtfs_conn_num);
	qtfs_info("qtfs create new param, cur conn num:%d\n", atomic_read(&g_qtfs_conn_num));

	qtfs_thread_var[pvar->cur_threadidx] = pvar;
	// add to busy list
	atomic_inc(&g_qtfs_conn_num);
	list_add(&pvar->lst, &g_busy_lst);

	strcpy(pvar->addr, qtfs_server_ip);
	pvar->port = qtfs_server_port;
	pvar->state = QTCONN_INIT;
	pvar->seq_num = 0;

#ifdef QTFS_CLIENT
	mutex_unlock(&g_param_mutex);
	pvar->cs = QTFS_CONN_SOCK_CLIENT;
	ret = qtfs_sm_active(pvar);
	if (ret < 0) {
		qtfs_err("qtfs get param active connection failed, ret:%d, curstate:%s", ret, QTCONN_CUR_STATE(pvar));
		// put to vld list
		qtfs_conn_put_param(pvar);
		return NULL;
	}
	qtfs_thread_var[pvar->cur_threadidx] = pvar;
#else
	pvar->cs = QTFS_CONN_SOCK_SERVER;
	if (qtfs_server_main_sock == NULL) {
		if (qtfs_sm_active(pvar)) {
			qtfs_err("qtfs get param active connection failed, ret:%d, curstate:%s", ret, QTCONN_CUR_STATE(pvar));
			// put to vld list
			mutex_unlock(&g_param_mutex);
			qtfs_conn_put_param(pvar);
			return NULL;
		}
		mutex_unlock(&g_param_mutex);
	} else {
		mutex_unlock(&g_param_mutex);
		pvar->state = QTCONN_CONNECTING;
		ret = qtfs_sm_active(pvar);
		if (ret < 0) {
			qtfs_err("qtfs get param active connection failed, ret:%d curstate:%s", ret, QTCONN_CUR_STATE(pvar));
			qtfs_conn_put_param(pvar);
			return NULL;
		}
	}
#endif
	qtinfo_cntinc(QTINF_ACTIV_CONN);

	return pvar;
}

struct qtfs_sock_var_s *qtfs_epoll_establish_conn(void)
{
	struct qtfs_sock_var_s *pvar = NULL;
	int ret;

	pvar = qtfs_epoll_var;
	if (pvar) {
		if (pvar->state == QTCONN_ACTIVE && qtfs_sock_connected(pvar) == false) {
			qtfs_warn("qtfs epoll get param thread:%d disconnected, try to reconnect.", pvar->cur_threadidx);
			ret = qtfs_sm_reconnect(pvar);
		} else {
			ret = qtfs_sm_active(pvar);
		}
		if (ret < 0) {
			return NULL;
		}
		return pvar;
	}

	pvar = kmalloc(sizeof(struct qtfs_sock_var_s), GFP_KERNEL);
	if (pvar == NULL) {
		qtfs_err("qtfs get param kmalloc failed.\n");
		return NULL;
	}
	if (QTFS_OK != qtfs_sock_var_init(pvar)) {
		qtfs_err("qtfs sock var init failed.\n");
		kfree(pvar);
		return NULL;
	}
	qtfs_epoll_var = pvar;
	pvar->cur_threadidx = QTFS_EPOLL_THREADIDX;
	strcpy(pvar->addr, qtfs_server_ip);
	pvar->port = qtfs_server_port + 1;
	pvar->state = QTCONN_INIT;

#ifdef QTFS_CLIENT
	pvar->cs = QTFS_CONN_SOCK_CLIENT;
#else
	pvar->cs = QTFS_CONN_SOCK_SERVER;
#endif
	ret = qtfs_sm_active(pvar);
	if (ret < 0) {
		qtfs_err("qtfs epoll get param active new param failed, ret:%d state:%s", ret, QTCONN_CUR_STATE(pvar));
		return NULL;
	}

	qtfs_info("qtfs create new epoll param state:%s", QTCONN_CUR_STATE(pvar));
	return pvar;
}

void qtfs_conn_put_param(struct qtfs_sock_var_s *pvar)
{
	int ret;
	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret < 0) {
		llist_add(&pvar->lazy_put, &g_lazy_put_llst);
		qtfs_warn("qtfs conn put param add to lazy list idx:%d, ret:%d.", pvar->cur_threadidx, ret);
		return;
	}
	qtfs_sock_msg_clear(pvar);
	list_move_tail(&pvar->lst, &g_vld_lst);
	mutex_unlock(&g_param_mutex);
	return;
}

void qtfs_epoll_cut_conn(struct qtfs_sock_var_s *pvar)
{
	int ret = qtfs_sm_exit(pvar);
	if (ret < 0) {
		qtfs_err("qtfs epoll put param exit failed, ret:%d state:%s", ret, QTCONN_CUR_STATE(pvar));
	}
	return;
}

void qtfs_conn_list_cnt(void)
{
	struct list_head *entry;
	struct qtfs_sock_var_s *pvar;
#ifdef QTFS_CLIENT
	int ret = 0;
	ret = qtfs_mutex_lock_interruptible(&g_param_mutex);
	if (ret < 0) {
		qtfs_err("qtfs conn put param mutex lock interrup failed, ret:%d.", ret);
		return;
	}
#endif
	qtfs_diag_info->pvar_busy = 0;
	qtfs_diag_info->pvar_vld = 0;
	memset(qtfs_diag_info->who_using, 0, sizeof(qtfs_diag_info->who_using));
	list_for_each(entry, &g_busy_lst) {
		qtfs_diag_info->pvar_busy++;
		pvar = (struct qtfs_sock_var_s *)entry;
		if (pvar->cur_threadidx < 0 || pvar->cur_threadidx >= QTFS_MAX_THREADS)
			continue;
		strncpy(qtfs_diag_info->who_using[pvar->cur_threadidx],
								qtfs_thread_var[pvar->cur_threadidx]->who_using, QTFS_FUNCTION_LEN);
	}
	list_for_each(entry, &g_vld_lst)
		qtfs_diag_info->pvar_vld++;
#ifdef QTFS_CLIENT
	mutex_unlock(&g_param_mutex);
#endif
	return;
}

#define KSYMS(sym, type) \
				qtfs_kern_syms.sym = (type) qtfs_kallsyms_lookup_name(#sym);\
				qtfs_info("qtfs kallsyms get %s:0x%lx.", #sym, (unsigned long)qtfs_kern_syms.sym);

struct qtfs_kallsyms qtfs_kern_syms;
kallsyms_lookup_name_t qtfs_kallsyms_lookup_name;
void qtfs_kallsyms_hack_init(void)
{
	register_kprobe(&kp);
	qtfs_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	KSYMS(sys_call_table, unsigned long **);
	KSYMS(d_absolute_path, char * (*)(const struct path *, char *, int));
	KSYMS(do_unlinkat, long (*)(int, struct filename *));
	KSYMS(getname_kernel, struct filename * (*)(const char *));
	KSYMS(filename_parentat, struct filename * (*)(int, struct filename *, unsigned int,
									struct path *, struct qstr *, int *));
	KSYMS(__lookup_hash, struct dentry * (*)(const struct qstr *, struct dentry *,
									unsigned int));
	KSYMS(do_mount, long (*)(const char *, const char __user *, const char *,
									unsigned long, void *));
	KSYMS(path_mount, int (*)(const char *, struct path *, const char *, unsigned long, void *));
	KSYMS(path_umount, int (*)(struct path *, int));
	KSYMS(find_get_task_by_vpid, struct task_struct *(*)(pid_t nr));
	KSYMS(do_readlinkat, int (*)(int, const char __user *, char __user *, int));
	KSYMS(do_renameat2, int (*)(int, const char __user *, int, const char __user *, unsigned int));
	KSYMS(do_mkdirat, long (*)(int, const char __user *, umode_t));
	KSYMS(do_rmdir, long (*)(int, struct filename *));
	KSYMS(getname, struct filename * (*)(const char __user *));
	KSYMS(ep_ptable_queue_proc, void (*)(struct file *, wait_queue_head_t *, struct poll_table_struct *));
	KSYMS(user_statfs, int (*)(const char __user *, struct kstatfs *));
	
	KSYMS(__close_fd, int (*)(struct files_struct *, int));
	KSYMS(do_sys_open, int (*)(int, const char __user *, int ,umode_t));
	KSYMS(do_epoll_ctl, int (*)(int, int, int, struct epoll_event *, bool));
	KSYMS(do_epoll_wait, int (*)(int, struct epoll_event __user *, int, int));
	KSYMS(do_linkat, int (*)(int, const char __user *, int, const char __user *, int));
	KSYMS(mnt_get_count, int (*)(void *));
	KSYMS(do_mknodat, long (*)(int, const char __user *, umode_t, unsigned int));
	KSYMS(ksys_lseek, off_t (*)(unsigned int, off_t, unsigned int));
	return;
}


















