
/**
 *  trashb_clean.c -  to periodically clean the trashbin if trashbin has files more than max limit
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/namei.h>
#include <linux/kthread.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include "../trashlib.h"

static struct task_struct *thread_st = NULL;
/* global char buffer for path variable;
 * so that we dont need to create seperate buffer
 */
char *path_buf = NULL;
int listSize = 0;

struct custom_node {
	const char *data;
	struct custom_node *next;
};
struct custom_node *listHead = NULL;
void listInsert(struct custom_node *new_custom_node);
void deleteList(void);
void printList(struct custom_node *);
static int thread_fn(void *unused);
int performCleaning(void);
void cleanBin(void);
static int unlinkFile(struct file *filp);
int delete_fromBin(const char *file_name);
int is_olderFile(const char *first, const char *second);
int is_tempFile(const char *name);
int has_validFlag(const char *name);

/**
* local_fill: created to assign function pointer of dir_context
* @param: identical to original filldir function
*/
int local_fill(struct dir_context *ctx, const char *name, int namlen,
	       loff_t offset, u64 ino, unsigned int d_type)
{
	int err;
	err = 0;
	if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0
	    && !is_tempFile(name) && has_validFlag(name)) {
		struct custom_node *temp =
		    (struct custom_node *)kmalloc(sizeof(struct custom_node),
						  GFP_KERNEL);
		temp->data = name;
		temp->next = NULL;
		listInsert(temp);
	}
	return err;
}

/**
 * delete files incase trashbin contains more than max files
 * iterates on the lined list
 */
void cleanBin(void)
{
	int count = 0;
	struct custom_node *temp;
	printk(KERN_ALERT " %s:%i, Current max bin size is: %d\n", __FILE__,
	       __LINE__, trashb_max_size);

	if (listSize > trashb_max_size) {
		count = listSize - trashb_max_size;
		printk(KERN_ALERT " %d files to be deleted!\n", count);
		while (count > 0) {
			count--;
			temp = listHead->next;
			delete_fromBin(temp->data);
			listHead->next = listHead->next->next;
			if (temp != NULL) {
				kfree(temp);
			}
		}
	} else
		printk(KERN_ALERT " %s:%i, no need to clean!\n", __FILE__,
		       __LINE__);
}

/**
* is_tempFile: check if file is in the middle of processing
* return 1 if temporary file; 0 otherwise
*/
int is_tempFile(const char *name)
{
	int n, ret;
	char etc[80];

	ret = sscanf(name, "%d-%s", &n, etc);
	if (ret == 0)
		return 1;

	return 0;
}

/**
* performCleaning: fuction where actual cleaning happens
*/
int performCleaning()
{
	struct file *filp;
	struct dir_context local_dir_context = { &local_fill, 0 };
	int err;
	char *path;

	err = 0;
	path = "/.trashbin/";
	filp = filp_open(path, O_RDONLY, 0);
	if (!filp || IS_ERR(filp)) {
		err = (int)PTR_ERR(filp);
		printk(KERN_ALERT " %s:%i, error opening %s\n", __FILE__,
		       __LINE__, path);
		goto OUT;
	}
	err = iterate_dir(filp, &local_dir_context);
	filp_close(filp, NULL);
	cleanBin();
	deleteList();
 OUT:
	return err;
}

/**
*  method executed by cleaner kernel thread
*/
static int thread_fn(void *unused)
{
	int err;
	allow_signal(SIGKILL);	/* allow the SIGKILL signal */
	while (!kthread_should_stop()) {
		err = performCleaning();
		ssleep(20);
	}
	printk(KERN_ALERT " %s:%i, cleaner_thread stopping\n", __FILE__,
	       __LINE__);
	do_exit(0);
	return 0;
}

/*
 * unlinkFile - unlink a file from file system
 * @filp: file struct pointer
 */
static int unlinkFile(struct file *filp)
{
	mm_segment_t oldfs;
	int error;
	struct inode *delegated;
	struct dentry *file_dentry;
	struct path file_path;

	error = 0;
	delegated = NULL;

	oldfs = get_fs();
	set_fs(get_ds());

	file_path = filp->f_path;
	file_dentry = file_path.dentry;
	dget(file_dentry);

	mutex_lock_nested(&(file_dentry->d_parent->d_inode->i_mutex),
			  I_MUTEX_PARENT);
	if (!IS_ERR(file_dentry)) {
		error =
		    vfs_unlink(file_dentry->d_parent->d_inode, file_dentry,
			       &delegated);
	}
	mutex_unlock(&(file_dentry->d_parent->d_inode->i_mutex));

	dput(file_dentry);

	set_fs(oldfs);
	return error;
}

/**
* delete_fromBin: delete file from trashbin
* @file_name: name of the file
* return 0 on success error otherwise;
*/
int delete_fromBin(const char *file_name)
{
	struct file *filp;
	int err;

	err = 0;
	memset(path_buf, '\0', PAGE_SIZE);
	sprintf(path_buf, "/.trashbin/%s", file_name);
	printk("%s Filename to be deleted = %s \n", __func__, file_name);
	filp = filp_open(path_buf, O_WRONLY, 0);
	if (!filp || IS_ERR(filp)) {
		err = (int)PTR_ERR(filp);
		printk(KERN_ALERT " %s:%i, error opening %s\n", __FILE__,
		       __LINE__, path_buf);
		goto OUT;
	}
	err = unlinkFile(filp);
	if (filp != NULL)
		filp_close(filp, NULL);
 OUT:
	return err;
}

/**
* has_validFlag: check if file has valid i_private itrash_flags
* return 1 if file has valid i.e. itrash_flags = 0
* return 0 otherwise;
*/
int has_validFlag(const char *file_name)
{
	struct file *filp;
	int err;
	struct flag_path_info *file_metadata;

	err = 0;
	sprintf(path_buf, "/.trashbin/%s", file_name);
	filp = filp_open(path_buf, O_WRONLY, 0);
	if (!filp || IS_ERR(filp)) {
		err = 0;
		printk(KERN_ALERT " %s:%i, error opening %s\n", __FILE__,
		       __LINE__, path_buf);
		goto OUT;
	}
	file_metadata =
	    (struct flag_path_info *)(filp->f_path.dentry->d_inode->i_private);
	err = (file_metadata->itrash_flags == 0) ? 1 : 0;
	filp_close(filp, NULL);
 OUT:
	return err;
}

/**
 * function to insert a new_custom_node in list as per insertion sort
 */
void listInsert(struct custom_node *new_custom_node)
{
	struct custom_node *temp;
	listSize++;
	/* Special case for the head end */
	if (listHead->next == NULL
	    || is_olderFile(listHead->next->data, new_custom_node->data)) {
		new_custom_node->next = listHead->next;
		listHead->next = new_custom_node;
	} else {
		/* Locate the custom_node before the point of insertion */
		temp = listHead->next;
		while (temp->next != NULL
		       && !is_olderFile(temp->next->data,
					new_custom_node->data)) {
			temp = temp->next;
		}
		new_custom_node->next = temp->next;
		temp->next = new_custom_node;
	}
}

/**
 * is_olderFile: check if second file is older than first
 * return 1 if second file is older; 0 otherwise
 */
int is_olderFile(const char *first, const char *second)
{
	int fuid, fyear, fmonth, fday, fhour, fmin, fsec;
	int suid, syear, smonth, sday, shour, smin, ssec;
	char fname[40], sname[40];
	int ret;
	ret = 0;
	sscanf(first, "%d-%d-%d-%d-%d-%d-%d-%s", &fuid, &fyear, &fmonth, &fday,
	       &fhour, &fmin, &fsec, fname);
	sscanf(second, "%d-%d-%d-%d-%d-%d-%d-%s", &suid, &syear, &smonth, &sday,
	       &shour, &smin, &ssec, sname);

	if (syear < fyear)
		ret = 1;
	else if (syear > fyear)
		ret = 0;
	else if (smonth < fmonth)
		ret = 1;
	else if (smonth > fmonth)
		ret = 0;
	else if (sday < fday)
		ret = 1;
	else if (sday > fday)
		ret = 0;
	else if (shour < fhour)
		ret = 1;
	else if (shour > fhour)
		ret = 0;
	else if (smin < fmin)
		ret = 1;
	else if (smin > fmin)
		ret = 0;
	else if (ssec < fsec)
		ret = 1;
	else if (ssec > fsec)
		ret = 0;
	return ret;
}

/**
 * method to delete the entire linked list
 */
void deleteList(void)
{
	struct custom_node *temp = listHead->next;
	while (temp != NULL) {
		listHead->next = listHead->next->next;
		kfree(temp);
		temp = listHead->next;
	}
	listSize = 0;
}

/**
 * printk content of linked list
 */
void printList(struct custom_node *n)
{
	printk(KERN_ALERT " %s:%i, List size: %d, List content: ", __FILE__,
	       __LINE__, listSize);
	while (n != NULL) {
		printk(KERN_ALERT "%s, ", n->data);
		n = n->next;
	}
}

/**
 *This function is called when the module is loaded
 */
static int __init proc_trash_clean_module(void)
{
	int err;
	err = 0;

	/* initialize list attributes */
	listSize = 0;
	listHead = (struct custom_node *)
	    kmalloc(sizeof(struct custom_node), GFP_KERNEL);
	listHead->next = NULL;

	/* allocate path buff ahead of time */
	path_buf = (char *)kmalloc(PAGE_SIZE, __GFP_REPEAT);
	if (!path_buf) {
		printk(KERN_ALERT
		       " %s:%i, Couldn't allocate memory for path_buf\n",
		       __FILE__, __LINE__);
		err = -ENOMEM;
		goto OUT;
	}

	thread_st = kthread_create(thread_fn, NULL, "trash_cleaner");
	if (thread_st) {
		printk(KERN_ALERT
		       " %s:%i, trash_cleaner thread created successfully\n",
		       __FILE__, __LINE__);
		wake_up_process(thread_st);
	} else {
		printk(KERN_ALERT
		       " %s:%i, trash_cleaner thread creation failed\n",
		       __FILE__, __LINE__);
		err = (int)PTR_ERR(thread_st);
	}

 OUT:
	return err;
}

fs_initcall(proc_trash_clean_module);
