#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

#define BUF_MAX 256
int main(int argc, char *argv[])
{
	char buf[BUF_MAX];
	char *fifo = argv[1];
	int wfd = open(fifo, O_WRONLY);
	if (wfd < 0) {
		printf("open file %s failed.\n", fifo);
		return 0;
	}

	do {
		int ret;
		int len;
		memset(buf, 0, BUF_MAX);
		fgets(buf, BUF_MAX, stdin);
		len = strlen(buf);
		ret = write(wfd, buf, BUF_MAX);
		if (ret == -1) {
			break;
		}
	} while (strcmp(buf, "exit") != 0);

	close(wfd);
	return 0;
}
