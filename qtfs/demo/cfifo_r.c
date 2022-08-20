#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#define BUF_MAX 256
int single_read(int argc, char *argv[])
{
	char buf[BUF_MAX];
	char *fifo = argv[1];
	int rfd = open(fifo, O_RDONLY);
	if (rfd < 0) {
		printf("open file %s failed.\n", fifo);
		return 0;
	}

	do {
		memset(buf, 0, BUF_MAX);
		int ret = read(rfd, buf, BUF_MAX);
		if (ret == -1) {
			printf("read failed.\n");
			break;
		}
		printf("%s", buf);
	} while (strcmp(buf, "exit") != 0);
	close(rfd);
	return 0;
}

int my_epoll_read(int argc, char *argv[])
{
	int *fd = (int *)malloc((argc - 1) * sizeof(int));
	char *buf = (char *)malloc(65536);

	for (int i = 1; i < argc; i++) {
		fd[i-1] = open(argv[i], O_RDONLY|O_NONBLOCK);
		if (fd[i-1] < 0){
			printf("open file %s failed.\n", argv[i]);
			return 0;
		}
		printf("my epoll read open file:%s success, fd:%d.\n", argv[i], fd[i-1]);
	}

	struct epoll_event evt;
	struct epoll_event *evts;
	int epfd = epoll_create1(0);
	if (epfd == -1) {
		printf("epoll create failed.\n");
		abort();
	}
	for (int i = 0; i < argc - 1; i++) {
		evt.data.fd = fd[i];
		evt.events = EPOLLIN;
		int s = epoll_ctl(epfd, EPOLL_CTL_ADD, fd[i], &evt);
		if (s == -1) {
			printf("epoll ctl failed, fd:%d\n", fd[i]);
			abort();
		}
		printf("my epoll read epoll ctl fd:%d events:%x success.\n", fd[i], evt.events);
	}
	evts = calloc(64, sizeof(evt));
	while (1) {
		int n = epoll_wait(epfd, evts, 64, -1);
		printf("epoll wait get new %d events.\n", n);
		for (int i = 0; i < n; i++) {
			int ret;
			FILE *fp;
			printf(" > epoll wait new events, cur:%d key:%x data:%lx n:%d.\n", i, evts[i].events, evts[i].data, n);
			memset(buf, 0, 65536);
			if (evts[i].events & EPOLLHUP) {
				epoll_ctl(epfd, EPOLL_CTL_DEL, evts[i].data.fd, NULL);
				continue;
			}
			fp = fdopen(evts[i].data.fd, "r");
			fseek(fp, 0, SEEK_SET);
			ret = read(evts[i].data.fd, buf, 65536);
			if (ret <= 0) {
				printf(" >read fd:%d ret:%d data error.\n", evts[i].data.fd, ret);
				goto end;
			} else {
				printf(" >read fd:%d ret:%d data:%s.\n", evts[i].data.fd, ret, buf);
			}
		}
	}
end:
	close(epfd);
	for (int i = 0; i < argc-1; i++) {
		close(fd[i]);
	}
	return 1;
}

int main(int argc, char *argv[])
{
	return my_epoll_read(argc, argv);
}

