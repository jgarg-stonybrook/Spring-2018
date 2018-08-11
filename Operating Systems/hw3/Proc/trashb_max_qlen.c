
/**
 *  trashb_max_qlen.c -  To set max async queue len of trashbin
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <asm/uaccess.h>

#define PROCFS_MAX_SIZE		32
#define PROCFS_NAME 		"trashb_max_qlen"
/**
 * The buffer used to store character for this module
 *
 */
static char procfs_buffer[PROCFS_MAX_SIZE];

/**
 * The size of the buffer
 *
 */
static unsigned long procfs_buffer_size = 0;

/**
 * This function is called then the /proc file is read
 *
 */
static ssize_t
procfile_qlen_read(struct file *file, char *buffer, size_t count, loff_t *loff)
{
	int ret;

	printk(KERN_INFO "read of (/proc/%s) called.\n", PROCFS_NAME);

	if (*loff > 0) {
		/* EOF, return 0 */
		ret = 0;
	} else {
		/* fill the buffer */
		if (copy_to_user(buffer, procfs_buffer, procfs_buffer_size)) {
			return -EFAULT;
		}
		ret = procfs_buffer_size;
		*loff = procfs_buffer_size;
	}

	printk(KERN_INFO "procfile_read in user buffer %s\n", buffer);

	return ret;
}

/**
 * This function is called with the /proc file is written
 *
 */
static ssize_t procfile_qlen_write(struct file *file, const char *buffer,
				   size_t count, loff_t *loff)
{
	/* get buffer size */
	procfs_buffer_size = count;
	if (procfs_buffer_size > PROCFS_MAX_SIZE) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}

	printk(KERN_INFO "procfile_write (/proc/%s) called, size = %ld\n",
	       PROCFS_NAME, procfs_buffer_size);

	/* write data to the buffer */
	if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
		return -EFAULT;
	}

	sscanf(procfs_buffer, "%d", &trashb_max_qlen);
	printk(KERN_INFO "procfile_write in buffer %s\n", procfs_buffer);

	return procfs_buffer_size;
}

const struct file_operations proc_qlen_fops = {
	.read = procfile_qlen_read,
	.write = procfile_qlen_write,
};

/**
 *This function is called when the module is loaded
 *
 */
static int __init proc_qlen_module(void)
{
	/* create the /proc file */
	proc_create(PROCFS_NAME, 0644, NULL, &proc_qlen_fops);

	printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);

	trashb_max_qlen = 10;
	strcpy(procfs_buffer, "10");
	procfs_buffer_size = strlen(procfs_buffer);

	return 0;		/* everything is ok */
}

/**
 *This function is called when the module is unloaded
 *
 */

fs_initcall(proc_qlen_module);
