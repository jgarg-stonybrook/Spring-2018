
/**
 *  trashb_clean.c -  to periodically clean the trashbin if trashbin has files more than max limit
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

static struct task_struct *thread_st = NULL;
/* global char buffer for path variable;
 * so that we dont need to create seperate buffer
 */
char *path_buf = NULL;
int list_size = 0;
int max_bin_size = 2;

struct custom_node {
	const char *data;
	struct custom_node *next;
};
struct custom_node *list_head;
void list_insert(struct custom_node **head_ref,
		 struct custom_node *new_custom_node);
void delete_list(struct custom_node **);
void print_list(struct custom_node *);
static int thread_fn(void *unused);
int perform_cleaning(void);
void clean_bin(struct custom_node *n);
static int unlink_file(struct file *filp);
int delete_from_bin(const char *file_name);
int is_older_file(const char *first, const char *second);
/**
 * local_filldir: created to assign function pointer of dir_context
 * @param: identical to original filldir function
 * returns 0 if we dont want to list the file; call original filldir otherwise
 */
int local_filldir(struct dir_context *ctx, const char *name, int namlen,
		  loff_t offset, u64 ino, unsigned int d_type)
{
	int err;
	err = 0;
	if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
		struct custom_node *temp =
		    (struct custom_node *)kmalloc(sizeof(struct custom_node),
						  GFP_KERNEL);
		temp->data = name;
		temp->next = NULL;
		list_insert(&list_head, temp);
	}
	return err;
}

/**
 * delete files incase trashbin contains more than max files
 */
void clean_bin(struct custom_node *n)
{
	int count = 0;
	if (list_size > max_bin_size) {
		count = list_size - max_bin_size;
		printk(KERN_ALERT " %d files to be deleted!\n", count);
		while (count > 0 && n != NULL) {
			count--;
			delete_from_bin(n->data);
			n = n->next;
		}
	} else {
		printk(KERN_ALERT " %s:%i, no need to clean!\n", __FILE__,
		       __LINE__);
	}
}

/**
 * perform_cleaning: fuction where actual cleaning happens
 */
int perform_cleaning()
{
	struct file *filp;
	struct dir_context local_dir_context = { &local_filldir, 0 };
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
	clean_bin(list_head);
	delete_list(&list_head);
 OUT:
	return err;
}

/**
 *  method executed by cleaner kernel thread
 */
static int thread_fn(void *unused)
{
	int err;
	allow_signal(SIGKILL);
	while (!kthread_should_stop()) {
		printk(KERN_ALERT " %s:%i, cleaner_thread Running\n", __FILE__,
		       __LINE__);
		err = perform_cleaning();
		printk(KERN_ALERT " %s:%i, perform_cleaning() returned: %d\n",
		       __FILE__, __LINE__, err);
		ssleep(20);
	}
	printk(KERN_ALERT " %s:%i, cleaner_thread stopping\n", __FILE__,
	       __LINE__);
	do_exit(0);
	return 0;
}

/*
 * unlink_file - unlink a file from file system
 * @filp: file struct pointer
 */
static int unlink_file(struct file *filp)
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

	mutex_lock_nested(&(file_dentry->d_parent->d_inode->i_mutex),
			  I_MUTEX_PARENT);
	if (!IS_ERR(file_dentry)) {
		ihold(file_dentry->d_inode);
		error =
		    vfs_unlink(file_dentry->d_parent->d_inode, file_dentry,
			       &delegated);
	}
	mutex_unlock(&(file_dentry->d_parent->d_inode->i_mutex));

	if (file_dentry->d_inode) {
		iput(file_dentry->d_inode);
	}
	file_dentry->d_inode = NULL;

	set_fs(oldfs);
	printk(KERN_ALERT " %s:%i, returning:%d\n", __FILE__, __LINE__, error);
	return error;
}

/**
 * delete_from_bin: delete file from trashbin
 * @file_name: name of the file
 * return 0 on success error otherwise;
 */
int delete_from_bin(const char *file_name)
{
	struct file *filp;
	int err;

	err = 0;
	sprintf(path_buf, "/.trashbin/%s", file_name);

	filp = filp_open(path_buf, O_WRONLY, 0);
	if (!filp || IS_ERR(filp)) {
		err = (int)PTR_ERR(filp);
		printk(KERN_ALERT " %s:%i, error opening %s\n", __FILE__,
		       __LINE__, path_buf);
		goto OUT;
	}
	err = unlink_file(filp);
	filp_close(filp, NULL);
 OUT:
	return err;
}

/**
 * function to insert a new_custom_node in list as per insertion sort
 */
void list_insert(struct custom_node **head_ref,
		 struct custom_node *new_custom_node)
{
	struct custom_node *temp;
	list_size++;
	/* Special case for the head end */
	if (*head_ref == NULL
	    || is_older_file((*head_ref)->data, new_custom_node->data)) {
		new_custom_node->next = *head_ref;
		*head_ref = new_custom_node;
	} else {
		/* Locate the custom_node before the point of insertion */
		temp = *head_ref;
		while (temp->next != NULL
		       && !is_older_file(temp->next->data,
					 new_custom_node->data)) {
			temp = temp->next;
		}
		new_custom_node->next = temp->next;
		temp->next = new_custom_node;
	}
}

/**
 * is_older_file: check if second file is older than first
 * return 1 if second file is older; 0 otherwise
 */
int is_older_file(const char *first, const char *second)
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
void delete_list(struct custom_node **head_ref)
{
	struct custom_node *temp = *head_ref;
	struct custom_node *next;
	while (temp != NULL) {
		next = temp->next;
		kfree(temp);
		temp = next;
	}
	*head_ref = NULL;
	list_size = 0;
}

/**
 * printk content of linked list
 */
void print_list(struct custom_node *n)
{
	printk(KERN_ALERT " %s:%i, List size: %d, List content: ", __FILE__,
	       __LINE__, list_size);
	while (n != NULL) {
		printk(KERN_ALERT "%s, ", n->data);
		n = n->next;
	}
}

/**
 *This function is called when the module is loaded
 */
int proc_init_module(void)
{
	int err;
	err = 0;

	/* initialize list attributes */
	list_size = 0;
	list_head = NULL;

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

/**
 *This function is called when the module is unloaded
 */
void proc_cleanup_module(void)
{
	if (thread_st) {
		printk(KERN_ALERT " %s:%i, thread_st exist\n", __FILE__,
		       __LINE__);
		kthread_stop(thread_st);
		printk(KERN_ALERT " %s:%i, trash_cleaner thread stopped!\n",
		       __FILE__, __LINE__);
	}
	if (path_buf != NULL) {
		kfree(path_buf);
	}
	delete_list(&list_head);
}

MODULE_LICENSE("GPL");
module_init(proc_init_module);
module_exit(proc_cleanup_module);
