#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/magic.h>
#define IOCTL_MAGIC_NUMBER 912
#define NUM 5
#define IOCTL_PURGE _IO(IOCTL_MAGIC_NUMBER, NUM)
int main(int argc, char *const *argv)
{
	int error, fd;
	char response;

	error = 0;
	printf("Are you sure you want to permanently erase the items in the Trash? You can’t undo this action.\nY/N?\n");
	scanf("%c", &response);
	if (response == 'y' || response == 'Y') {
		fd = open(".tappu", O_CREAT|O_RDWR, 0644);
		if (fd == -1) {
			perror("fopen");
			printf("Error opening trashbin\n");
			exit(-1);
		}
		error = ioctl(fd, IOCTL_PURGE);
		printf("ioctl returned: %d\n", error);
		close(fd);
	} else {
		printf("action canceled\n");
	}
	if (error != 0)
		printf("%s\n", strerror(error));
	exit(error);
}
