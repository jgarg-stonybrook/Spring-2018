#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <error.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/magic.h>
#include "common_ioctl.h"

/* HW-2 */

int main (int argc, char* const argv[])
{
	long rc;
	int index;
	int option;
	int uFlag = 0;
	char* fileName = NULL;
	int file;
	int ret = 0;

	while ((option = getopt(argc, argv, "u")) != -1) {
		switch (option) {
			case 'u':
					uFlag = 1;
					break;
			case '?':
					printf("Unknown option: '-%c'\n", optopt);
			default:
					exit(EXIT_FAILURE);
					break;
		}
	}

	index = optind;

	if (uFlag == 1 && index < argc) {
		fileName = argv[index];
		index += 1;
	} 

	index += 1;

	if (uFlag == 1) {
		file = open(fileName, O_RDWR);

		if (file == -1)
	    {
	        printf("No such file or error\n");
	        exit(-1);
	    } 
	  
	 	ret = ioctl(file, IOCTL_UNDELETE);
	    close(file);
	}

	rc = 0;

  	if (ret != 0) {
  		printf("Error = %s\n", strerror(ret));
  	} else {
  		printf("%s\n", "Success");
  	}

	exit(rc);
}
