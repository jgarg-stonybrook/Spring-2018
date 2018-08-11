
/**
 *  trashb_max_size.c -  To set max size of trashbin and create Trashbin
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#define PROCFS_MAX_SIZE		32
#define PROCFS_NAME 		"trashb_max_size"
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
procfile_size_read(struct file *file, char *buffer, size_t count, loff_t *loff)
{
	int ret;

	printk(KERN_ALERT "read of (/proc/%s) called.\n", PROCFS_NAME);

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

	printk(KERN_ALERT "procfile_read in user buffer %s\n", buffer);

	return ret;
}

/**
 * This function is called with the /proc file is written
 *
 */
static ssize_t procfile_size_write(struct file *file, const char *buffer,
				   size_t count, loff_t *loff)
{
	/* get buffer size */
	procfs_buffer_size = count;
	if (procfs_buffer_size > PROCFS_MAX_SIZE) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}

	printk(KERN_ALERT "procfile_write (/proc/%s) called, size = %ld\n",
	       PROCFS_NAME, procfs_buffer_size);

	/* write data to the buffer */
	if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
		return -EFAULT;
	}

	sscanf(procfs_buffer, "%d", &trashb_max_size);
	printk(KERN_ALERT "procfile_write in buffer %s\n", procfs_buffer);
	return procfs_buffer_size;
}

const struct file_operations proc_size_fops = {
	.read = procfile_size_read,
	.write = procfile_size_write,
};

/**
 *This function is called when the module is loaded
 *
 */
static int __init proc_trash_size_module(void)
{
	proc_create(PROCFS_NAME, 0644, NULL, &proc_size_fops);

	printk(KERN_ALERT "/proc/%s created\n", PROCFS_NAME);

	trashb_max_size = 10;
	strcpy(procfs_buffer, "10");
	procfs_buffer_size = strlen(procfs_buffer);

	return 0;
}

fs_initcall(proc_trash_size_module);

