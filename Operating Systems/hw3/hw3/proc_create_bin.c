
/**
 *  trashb_clean.c -  to periodically clean the trashbin if trashbin has files more than max limit
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/namei.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#define PROCFS_NAME "create_bin"

static int create_sg_bin(void);
struct dentry *bin_dentry = NULL;

/**
 *This function is called when the module is loaded
 */
int proc_init_module(void)
{
	int err;

	err = 0;
	err = create_sg_bin();
	printk(KERN_ALERT " %s:%i, /proc/%s created\n", __FILE__, __LINE__,
	       PROCFS_NAME);
	return err;
}

/**
 *This function is called to create trashbin folder at top of mount point
 * as after we will set its max file limit.
 *
 */
static int create_sg_bin(void)
{
	mm_segment_t oldfs;
	struct path tb_path;
	struct path bin_path;
	int errorVal = 0;
	char *trash_path = "/.trashbin";

	oldfs = get_fs();
	set_fs(get_ds());
	printk(KERN_ALERT " %s:%i, Creating trashbin folder!\n", __FILE__,
	       __LINE__);

	errorVal = kern_path(trash_path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			     &bin_path);
	if (errorVal != -ENOENT) {
		if (S_ISDIR(bin_path.dentry->d_inode->i_mode)) {
			printk(KERN_ALERT " %s:%i, trashbin already present!\n",
			       __FILE__, __LINE__);
		}
	} else {
		bin_dentry = user_path_create(AT_FDCWD, trash_path,
					      &tb_path, 0);
		if (IS_ERR(bin_dentry)) {
			errorVal = PTR_ERR(bin_dentry);
			printk(KERN_ALERT
			       " %s:%i, error in trashbin dentry creation\n",
			       __FILE__, __LINE__);
			goto clear_out;
		}

		dget(bin_dentry);

		errorVal = vfs_mkdir(d_inode(tb_path.dentry), bin_dentry, 0755);

		done_path_create(&tb_path, bin_dentry);
		printk(KERN_ALERT " %s:%i, error in making trashbin: %d \n",
		       __FILE__, __LINE__, errorVal);
	}

 clear_out:
	set_fs(oldfs);
	return errorVal;
}

/**
 *This function is called when the module is unloaded
 */

MODULE_LICENSE("GPL");
module_init(proc_init_module);
