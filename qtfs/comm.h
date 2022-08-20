#ifndef __QTFS_SERVER_COMM_H__
#define __QTFS_SERVER_COMM_H__

extern struct qtinfo *qtfs_diag_info;

#define QTFS_IOCTL_MAGIC 'Q'
enum {
    _QTFS_IOCTL_EXEC,
    _QTFS_IOCTL_THREAD_RUN,
	_QTFS_IOCTL_EPFDSET,
	_QTFS_IOCTL_EPOLLT,
	_QTFS_IOCTL_EPOLL_THREAD_RUN,
	_QTFS_IOCTL_EXIT,

	_QTFS_IOCTL_ALLINFO,
	_QTFS_IOCTL_CLEARALL,

	_QTFS_IOCTL_LOG_LEVEL,
	_QTFS_IOCTL_EPOLL_SUPPORT,
};

#define QTFS_IOCTL_THREAD_INIT			_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EXEC)
#define QTFS_IOCTL_THREAD_RUN			_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_THREAD_RUN)
#define QTFS_IOCTL_EPFDSET				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EPFDSET)
#define QTFS_IOCTL_EPOLL_THREAD_INIT	_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EPOLLT)
#define QTFS_IOCTL_EPOLL_THREAD_RUN		_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EPOLL_THREAD_RUN)
#define QTFS_IOCTL_EXIT					_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EXIT)
#define QTFS_IOCTL_ALLINFO				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_ALLINFO)
#define QTFS_IOCTL_CLEARALL				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_CLEARALL)
#define QTFS_IOCTL_LOGLEVEL				_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_LOG_LEVEL)
#define QTFS_IOCTL_EPOLL_SUPPORT		_IO(QTFS_IOCTL_MAGIC, _QTFS_IOCTL_EPOLL_SUPPORT)

#define QTINFO_MAX_EVENT_TYPE 36 // look qtreq_type at req.h
#define QTFS_FUNCTION_LEN 64

#define QTFS_MAX_THREADS 16
#define QTFS_LOGLEVEL_STRLEN 6

struct qtfs_server_userp_s {
	size_t size;
	void *userp;
	void *userp2;
};

struct qtfs_thread_init_s {
	int thread_nums;
	struct qtfs_server_userp_s *userp;
};

struct qtreq_epoll_event {
	unsigned int events;
	unsigned long data;
};

struct qtfs_server_epoll_s {
	int epfd;
	int event_nums;
	struct epoll_event *events;
	struct epoll_event *kevents;
};

enum qtfs_errcode {
	QTOK = 0,
	QTERROR = 1,
	QTEXIT = 2,
};

// qtinfo start
#if (defined(QTFS_CLIENT) || defined(client))
enum qtinfo_cnts {
	QTINF_ACTIV_CONN,
	QTINF_EPOLL_ADDFDS,
	QTINF_EPOLL_DELFDS,
	QTINF_EPOLL_FDERR,
	QTINF_SEQ_ERR,
	QTINF_RESTART_SYS,
	QTINF_TYPE_MISMATCH,
	QTINF_NUM,
};
#endif

#if defined(QTFS_SERVER) || defined(server)
enum qtinfo_cnts {
	QTINF_ACTIV_CONN,
	QTINF_EPOLL_ADDFDS,
	QTINF_EPOLL_DELFDS,
	QTINF_NUM,
};
#endif

// for connection state machine
typedef enum {
	QTCONN_INIT,
	QTCONN_CONNECTING,
	QTCONN_ACTIVE,
} qtfs_conn_type_e;

struct qtinfo_client {
	unsigned long cnts[QTINF_NUM];
	unsigned long recv_err[QTINFO_MAX_EVENT_TYPE];
	unsigned long send_err[QTINFO_MAX_EVENT_TYPE];
	unsigned long i_events[QTINFO_MAX_EVENT_TYPE];
	unsigned long o_events[QTINFO_MAX_EVENT_TYPE];
};

struct qtinfo_server {
	unsigned long cnts[QTINF_NUM];
	unsigned long i_events[QTINFO_MAX_EVENT_TYPE];
	unsigned long o_events[QTINFO_MAX_EVENT_TYPE];
};

struct qtinfo {
	union {
		struct qtinfo_client c;
		struct qtinfo_server s;
	};
	// all struct qtreq_xxx's size
	unsigned int req_size[QTINFO_MAX_EVENT_TYPE];
	unsigned int rsp_size[QTINFO_MAX_EVENT_TYPE];
	int log_level;
	int thread_state[QTFS_MAX_THREADS];
	char who_using[QTFS_MAX_THREADS][QTFS_FUNCTION_LEN];
	int epoll_state;
	int pvar_vld; // valid param's number
	int pvar_busy; // busy param's number
};

#define QTINFO_STATE(state) ((state == QTCONN_INIT) ? "INIT" : \
							((state == QTCONN_CONNECTING) ? "CONNECTING" : \
							((state == QTCONN_ACTIVE) ? "ACTIVE" : "UNKNOWN")))

//ko compile
#if (defined(QTFS_CLIENT) || defined(client))
static inline void qtinfo_clear(void)
{
	int i;
	for (i = QTINF_SEQ_ERR; i < QTINF_NUM; i++)
		qtfs_diag_info->c.cnts[i] = 0;
	memset(qtfs_diag_info->c.recv_err, 0, sizeof(qtfs_diag_info->c.recv_err));
	memset(qtfs_diag_info->c.send_err, 0, sizeof(qtfs_diag_info->c.send_err));
	memset(qtfs_diag_info->c.i_events, 0, sizeof(qtfs_diag_info->c.i_events));
	memset(qtfs_diag_info->c.o_events, 0, sizeof(qtfs_diag_info->c.o_events));
	return;
}
static inline void qtinfo_cntinc(enum qtinfo_cnts idx)
{
	if (idx >= QTINF_NUM)
		return;
	qtfs_diag_info->c.cnts[idx]++;
	return;
}
static inline void qtinfo_cntdec(enum qtinfo_cnts idx)
{
	if (idx >= QTINF_NUM || qtfs_diag_info->c.cnts[idx] == 0)
		return;
	qtfs_diag_info->c.cnts[idx]--;
	return;
}
static inline void qtinfo_recvinc(int idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.i_events[idx]++;
	return;
}
static inline void qtinfo_sendinc(int idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.o_events[idx]++;
	return;
}
static inline void qtinfo_recverrinc(int idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.recv_err[idx]++;
	return;
}
static inline void qtinfo_senderrinc(int idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->c.send_err[idx]++;
	return;
}
#endif

// ko compile
#if defined(QTFS_SERVER) || defined(server)
static inline void qtinfo_clear(void)
{
	memset(qtfs_diag_info->s.i_events, 0, sizeof(qtfs_diag_info->s.i_events));
	memset(qtfs_diag_info->s.o_events, 0, sizeof(qtfs_diag_info->s.o_events));
	return;
}
static inline void qtinfo_cntinc(enum qtinfo_cnts idx)
{
	if (idx >= QTINF_NUM)
		return;
	qtfs_diag_info->s.cnts[idx]++;
	return;
}
static inline void qtinfo_cntdec(enum qtinfo_cnts idx)
{
	if (idx >= QTINF_NUM || qtfs_diag_info->s.cnts[idx] == 0)
		return;
	qtfs_diag_info->s.cnts[idx]--;
	return;
}
static inline void qtinfo_recvinc(int idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->s.i_events[idx]++;
	return;
}
static inline void qtinfo_sendinc(int idx)
{
	if (idx >= QTINFO_MAX_EVENT_TYPE)
		return;
	qtfs_diag_info->s.o_events[idx]++;
	return;
}
#endif
// QTINFO END

#endif

