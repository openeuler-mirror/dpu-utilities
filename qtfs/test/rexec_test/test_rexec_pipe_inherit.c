#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int fd[2];
	pipe(fd);
	int pid = fork();
	if (pid == 0) {
		// child
		char fdstr[16] = {0};
		sprintf(fdstr, "%d", fd[0]);
		char *argvchild[] = {"rexec", argv[1], fdstr, NULL};
		close(fd[1]);
		execv("/usr/bin/rexec", argvchild);
		perror("execv");
	}
	close(fd[0]);
	sleep(1);
	write(fd[1], "hello", 5);
	return 0;
}

