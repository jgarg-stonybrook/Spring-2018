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
#define IOCTL_MAGIC_NUMBER 913
#define NUM 6
#define IOCTL_CIPHER _IO(IOCTL_MAGIC_NUMBER, NUM)
int main(int argc, char *const *argv)
{
	int error, fd;
	char *key;

	error = 0;

	if (argc != 2) {
		error = EINVAL;
		printf("%s\n", strerror(error));
		exit(error);
	}

	key = (char *)argv[1];
	if (strlen(key) != 16) {
		error = EINVAL;
		printf("key lenght should be 16\n");
		exit(error);
	}

	fd = open("/.keys", O_CREAT | O_RDWR, 0777);
	if (fd == -1) {
		perror("fopen");
		printf("Error opening key store\n");
		exit(-1);
	}
	error = ioctl(fd, IOCTL_CIPHER, key);
	printf("ioctl returned: %d\n", error);
	close(fd);
	if (error != 0)
		printf("%s\n", strerror(error));
	exit(error);
}
