
/**
 *  queue_info.c -  To get the info about the enteries in the queue
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include "../trashlib.h"

#define PROCFS_MAX_SIZE		4096
#define PROCFS_NAME 		"workqueue_info"

/**
 * The buffer used to store character for this module
 *
 */
char *procfs_buffer;

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
procfile_workqueue_read(struct file *file, char *buffer, size_t count,
			loff_t *loff)
{
	int ret;

	printk(KERN_INFO "read of (/proc/%s) called.\n", PROCFS_NAME);
	procfs_buffer = kmalloc(4096, __GFP_REPEAT);

	if (*loff > 0) {
		/* EOF, return 0 */
		ret = 0;
	} else {
		/* get the buffer content */
		get_queue_info(procfs_buffer);
		procfs_buffer_size = strlen(procfs_buffer);

		/* fill the buffer */
		if (copy_to_user(buffer, procfs_buffer, procfs_buffer_size)) {
			return -EFAULT;
		}
		printk("%s procfs_buffer_size = %lu\n", __func__,
		       procfs_buffer_size);
		ret = procfs_buffer_size;
		*loff = procfs_buffer_size;
	}

	printk(KERN_INFO "procfile_read in user buffer %s\n", buffer);

	if (procfs_buffer != NULL) {
		kfree(procfs_buffer);
	}
	return ret;
}

const struct file_operations proc_fops = {
	.read = procfile_workqueue_read,
};

/**
 *This function is called when the module is loaded
 *
 */
int proc_workqueue_module(void)
{
	proc_create(PROCFS_NAME, 0644, NULL, &proc_fops);
	printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);

	return 0;		/* everything is ok */
}

fs_initcall(proc_workqueue_module);
