#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include <sys/epoll.h>

#include "comm.h"

#define engine_out(info, ...) \
	do {\
		printf("[Engine::%s:%3d]"info"\n", __func__, __LINE__, ##__VA_ARGS__);\
	} while (0);

#define engine_out2(info, ...) \
		do {\
			printf("[Engine::%s:%3d]"info, __func__, __LINE__, ##__VA_ARGS__);\
		} while (0);

#define engine_err(info, ...) \
	do {\
		printf("[ERROR:Engine::%s:%3d]"info"\n", __func__, __LINE__, ##__VA_ARGS__);\
	} while (0);

struct engine_arg {
	int psize;
	int fd;
	int thread_idx;
};

#define QTFS_USERP_MAXSIZE 65536
#define QTFS_USERP_SIZE 4096
#define QTFS_SERVER_FILE "/dev/qtfs_server"

int qtfs_fd;
int engine_run = 1;
static void qtfs_engine_userp_free(struct qtfs_server_userp_s *userp, int thread_nums)
{
	for (int i = 0; i < thread_nums; i++) {
		if (userp[i].userp != NULL) 
			free(userp[i].userp);
		if (userp[i].userp2 != NULL) 
			free(userp[i].userp2);
	}
	free(userp);
	return;
}

static struct qtfs_server_userp_s *qtfs_engine_thread_init(int fd, int thread_nums, int psize)
{
	struct qtfs_server_userp_s *userp;
	userp = (struct qtfs_server_userp_s *)malloc(thread_nums * sizeof(struct qtfs_server_userp_s));
	if (userp == NULL) {
		engine_out("engine thread init malloc failed.");
		return NULL;
	}
	for (int i = 0; i < thread_nums; i++) {
		userp[i].size = psize;
		userp[i].userp = (void *)malloc(psize);
		if (userp[i].userp == NULL) {
			engine_out("engine userp malloc failed.");
			goto rollback;
		}
		userp[i].userp2 = (void *)malloc(psize);
		if (userp[i].userp2 == NULL) {
			engine_out("engine userp2 malloc failed.");
			goto rollback;
		}
	}
	struct qtfs_thread_init_s init_userp;
	init_userp.thread_nums = thread_nums;
	init_userp.userp = userp;
	(void)ioctl(fd, QTFS_IOCTL_THREAD_INIT, (unsigned long)&init_userp);
	return userp;
rollback:
	qtfs_engine_userp_free(userp, thread_nums);
	return NULL;
}

static void *qtfs_engine_kthread(void *arg)
{
	struct engine_arg *parg = (struct engine_arg *)arg;
	int psize = parg->psize;
	long ret;

	while (engine_run) {
		ret = ioctl(parg->fd, QTFS_IOCTL_THREAD_RUN, 0);
		if (ret == QTEXIT) {
			engine_out("qtfs server thread:%d exit.", parg->thread_idx);
			break;
		}
	}

end:
	engine_out("qtfs user engine over.");
	return NULL;
}

static void qtfs_signal_int(int signum)
{
	engine_out("qtfs engine recv signal number:%d.", signum);

	if (qtfs_fd < 0) {
		engine_err("qtfs engine signal int file:%s open failed, fd:%d.", QTFS_SERVER_FILE, qtfs_fd);
		return;
	}
	long ret = ioctl(qtfs_fd, QTFS_IOCTL_EXIT, 0);
	engine_run = 0;

	return;
}

static void *qtfs_engine_epoll_thread(void *data)
{
	struct engine_arg *arg = (struct engine_arg *)data;
	int fd = arg->fd;
	long ret;

	engine_out("qtfs server epoll thread run.");

	do {
		ret = ioctl(fd, QTFS_IOCTL_EPOLL_THREAD_INIT, NULL);
		if (ret == QTEXIT) {
			engine_out("qtfs server epoll thread init exit.");
			goto end;
		}
	} while (ret != 0 && engine_run);
	while (engine_run) {
		ret = ioctl(fd, QTFS_IOCTL_EPOLL_THREAD_RUN, NULL);
		if (ret == QTEXIT) {
			engine_out("qtfs server epoll thread exit.");
			break;
		}
	}
end:
	engine_out("qtfs server epoll thread exit, ret:%d.", ret);

	return NULL;
}

int qtfs_epoll_init(int fd)
{
#define MAX_EVENTS 64
	int epfd = epoll_create1(0);
	if (epfd < 0) {
		engine_err("epoll create error, ret:%d.", epfd);
		return -1;
	}

	struct qtfs_server_epoll_s ep;
	struct epoll_event *evts;
	evts = calloc(MAX_EVENTS, sizeof(struct epoll_event));
	if (evts == NULL) {
		engine_err("calloc events failed.");
		close(epfd);
		return -1;
	}
	engine_out("qtfs engine set epoll arg, fd:%d event nums:%d events:%lx.", epfd, MAX_EVENTS, evts);
	ep.epfd = epfd;
	ep.event_nums = MAX_EVENTS;
	ep.events = evts;
	int ret = ioctl(fd, QTFS_IOCTL_EPFDSET, &ep);

	return epfd;
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		engine_out("Usage: %s <buf size> <number of threads>.", argv[0]);
		engine_out("     Example: %s 4096 16.", argv[0]);
		return -1;
	}
	int psize = atoi(argv[1]);
	int thread_nums = atoi(argv[2]);
	int fd = open(QTFS_SERVER_FILE, O_RDONLY);
	if (fd < 0) {
		engine_err("qtfs server file:%s open failed, fd:%d.", QTFS_SERVER_FILE, fd);
		return 0;
	}
	qtfs_fd = fd;
	// init epoll
	int epfd = qtfs_epoll_init(fd);
	if (epfd < 0) {
		close(fd);
		return -1;
	}

	umask(0);

	pthread_t texec[QTFS_MAX_THREADS];
	pthread_t tepoll;
	if (psize > QTFS_USERP_MAXSIZE || thread_nums > QTFS_MAX_THREADS) {
		engine_err("qtfs engine param invalid, size:%d(must <= %d) thread_nums:%d(must <= %d).",
				psize, QTFS_USERP_MAXSIZE, thread_nums, QTFS_MAX_THREADS);
		goto end;
	}
	(void)ioctl(fd, QTFS_IOCTL_EXIT, 1);
	signal(SIGINT, qtfs_signal_int);
	signal(SIGKILL, qtfs_signal_int);
	signal(SIGTERM, qtfs_signal_int);

	struct qtfs_server_userp_s *userp = qtfs_engine_thread_init(fd, thread_nums, psize);
	if (userp == NULL) {
		engine_out("qtfs engine userp init failed.");
		goto end;
	}

	struct engine_arg arg[QTFS_MAX_THREADS];
	for (int i = 0; i < thread_nums; i++) {
		arg[i].psize = psize;
		arg[i].fd = fd;
		arg[i].thread_idx = i;
		(void)pthread_create(&texec[i], NULL, qtfs_engine_kthread, &arg[i]);
	}
	(void)pthread_create(&tepoll, NULL, qtfs_engine_epoll_thread, &arg[0]);
	for (int i = 0; i < thread_nums; i++) {
		pthread_join(texec[i], NULL);
		engine_out("qtfs engine join thread %d.", i);
	}
	pthread_join(tepoll, NULL);
	qtfs_engine_userp_free(userp, thread_nums);
	engine_out("qtfs engine join epoll thread.");
end:
	close(epfd);
	close(fd);
	engine_out("qtfs engine over.");
	return 0;
}
