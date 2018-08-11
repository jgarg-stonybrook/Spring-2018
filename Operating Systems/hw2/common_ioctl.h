#include <linux/ioctl.h>
#include <linux/magic.h>
#ifndef _CMN_FLAGS_
#define _CMN_FLAGS_

/* HW-2 */
#define IOCTL_MAGIC_NUMBER 901
#define IOCTL_UNDELETE _IO(IOCTL_MAGIC_NUMBER,0) 

#endif