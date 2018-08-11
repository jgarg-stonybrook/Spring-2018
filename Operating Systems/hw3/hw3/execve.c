#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

int main(int argc, char *const argv[])
{
	char *temp[] = { NULL, "hello", "world", NULL };
	execve(argv[1], temp, NULL);
	printf("world");
	return 0;
}
