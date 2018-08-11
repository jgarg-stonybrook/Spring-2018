#define _GNU_SOURCE
#include <sched.h>
#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/wait.h>

#define CLONE_PROT_MV	0x00000020	/* Files deleted just moves to trashbin */
#define CLONE_PROT_ZIP	0x00000040	/* Files deleted moves to trashbin with compression */
#define CLONE_PROT_ENC	0x00000080	/* Files deleted moves to trashbin with encryption */
#define CLONE_CHK_CSIGNAL  0x00001000	/* flag that need to be passed if user is passing C_SIGNAL flag */
#define STACK_SIZE		4096

static int deleteFile(void *fileName)
{
	printf("%s\n", (char *)fileName);
	if (remove(fileName) == 0)
		printf("Deleted successfully\n");
	fflush(stdout);

	return 0;
}

int main(int argc, char *const argv[])
{
	int index;
	int option;
	void *fileName = NULL;
	unsigned long flags = 0x00000000;
	char *stack;
	char *stackTop;
	pid_t pid;

	while ((option = getopt(argc, argv, "mze")) != -1) {
		switch (option) {
		case 'm':
			flags |= CLONE_PROT_MV;
			break;
		case 'z':
			flags |= CLONE_PROT_ZIP;
			break;
		case 'e':
			flags |= CLONE_PROT_ENC;
			break;
		case '?':
			printf("Unknown option: '-%c'\n", optopt);
		default:
			exit(EXIT_FAILURE);
			break;
		}
	}

	index = optind;

	if (index < argc) {
		fileName = argv[index];
		index += 1;
	}

	index += 1;

	printf("Flags = %lx %s\n", flags, (char *)fileName);

	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		printf("%s\n", "Error in stack allocation.");
		exit(0);
	}

	stackTop = stack + STACK_SIZE;	/* Assume stack grows downward */

	printf("parent --- %d parent pid %d\n", getpid(), getppid());
	pid =
	    clone(&deleteFile, stackTop, CLONE_VFORK | flags | SIGCHLD,
		  fileName);
	printf("new pid --- %d\n", pid);
	if (pid < 0)
		printf("%s\n", "Error in process creation.");

	return 0;
}
