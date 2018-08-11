#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "common.h"

#ifndef __NR_xdedup
#error xdedup system call not defined
#endif

int main (int argc, char* const argv[])
{
	long rc;
	int index;
	int option;
	struct argStructure args;

	args.flags = 0;
	args.outfile = NULL;

	while ((option = getopt(argc, argv, "snpd")) != -1) {
		switch (option) {
			case 's':
					args.flags |= S_OPTION;
					break;
			case 'n':
					args.flags |= N_OPTION;
					break;
			case 'p':
					args.flags |= P_OPTION;
					break;
			case 'd':
					args.flags |= D_OPTION;
					break;
			case '?':
					printf("Unknown option: '-%c'\n", optopt);
			default:
					exit(EXIT_FAILURE);
					break;
		}
	}

	index = optind;

	// If 2 input files are not given
	if ((argc - index) < 2) {
		printf("%s\n", strerror(EINVAL));
		exit(0);
	}

	if (((args.flags & 8) == 8) && ((argc - index) < 3)) {
		printf("%s\n", strerror(EINVAL));
		exit(0);
	}

	if (((args.flags & 8) == 8) && (((args.flags & (4 | 2)) > 0))) {
		// printf("2");
		printf("%s\n", strerror(EINVAL));
		exit(0);
	}

	if ((args.flags & 8) != 8) {
		// In P flag if outfile not given
		if ((args.flags == 2 || args.flags == 3) && ((argc - index) < 3)) {
			printf("%s\n", strerror(EINVAL));
			exit(0);
		}

		// If not p flag and outfile is given
    	if (((args.flags & 2) == 0) && (argc - index) > 2) {
			printf("%s\n", strerror(E2BIG));
			exit(0);
    	}
	}


	if (index < argc) {
		args.infile1 = argv[index];
		index += 1;
	} 

	if (index < argc) {
		args.infile2 = argv[index];
		index += 1;
	} 

	if (index < argc) {
		args.outfile = argv[index];
	} 

	index += 1;

  	rc = syscall(__NR_xdedup, (void*) &args);

  	if (rc >= 0) {
  		printf("Identical Bytes = %ld\n", rc);
  	} else {
  		printf("%s\n", strerror(errno));
  	}

	exit(rc);
}
