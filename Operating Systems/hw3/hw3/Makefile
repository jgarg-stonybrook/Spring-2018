obj-m += proc_create_bin.o
INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: make1 cp

make1:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

cp: create_process.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi create_process.c -o create_process
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi execve.c -o execve
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi undo_ioctl.c -o undo_ioctl
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi purge_ioctl.c -o purge_ioctl
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi cipher_key_ioctl.c -o cipher_key
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f create_process
	rm -f execve
	rm -f undo_ioctl
	rm -f purge_ioctl
	rm -f cipher_key

