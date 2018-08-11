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
#define IOCTL_MAGIC_NUMBER 911
#define NUM 4
#define IOCTL_UNDELETE _IO(IOCTL_MAGIC_NUMBER, NUM)

int main(int argc, char *const *argv)
{
	int u_flag, opt, error, fd;
	char *file_name;

	u_flag = 0;
	error = 0;
	while ((opt = getopt(argc, argv, "u")) != -1) {
		switch (opt) {
		case 'u':
			u_flag = 1;
			break;
		default:
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (u_flag == 0 || argc != 3) {
		error = EINVAL;
		goto OUT;
	}

	file_name = argv[optind];
	fd = open(file_name, O_RDWR);
	if (fd == -1) {
		printf("Error opening %s\n", file_name);
		exit(-1);
	}

	error = ioctl(fd, IOCTL_UNDELETE);
	printf("ioctl returned: %d\n", error);
	close(fd);

OUT:
	if (error != 0)
		printf("%s\n", strerror(error));
	else
		printf("success!\n");
	exit(error);
}
