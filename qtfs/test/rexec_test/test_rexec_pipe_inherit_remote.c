#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	char buf[16] = {0};
	int fd = atoi(argv[1]);
	int ret = read(fd, buf, 16);
	printf("read from pipe fd:%d string:%s ret:%d errno:%d\n", fd, buf, ret, errno);
	return 0;
}

