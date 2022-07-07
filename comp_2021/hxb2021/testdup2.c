#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
	int fds[2];
	printf("%d",1);
	if (-1 == pipe(fds)){
		perror("pipe");
		return 1;
	}
	dup2(fds[0],STDIN_FILENO);
	dup2(fds[1],STDOUT_FILENO);
	printf("fds[0]=>%d",fds[0]);
	printf("fds[1]=>%d",fds[1]);
	int c;
	write(fds[1],"a",1);
	while((c = getchar()) != EOF) {
		putchar('a');
		fflush(stdout);
	}
	return 0;
}

