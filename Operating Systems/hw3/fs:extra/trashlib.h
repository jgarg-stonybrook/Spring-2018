#ifndef _TRASH_LIB_H_
#define _TRASH_LIB_H_

#define MY_PAGE_SIZE	4096
#define KEY_SIZE_AES	16

extern int compress_file(const char *infile, char *);
extern struct file *decompress_file(const char *infile, char *, int *);
extern int rename_to_trashbin(struct dentry *old_dentry,
			      unsigned long trash_flags);
extern int do_rename(struct dentry *old_dentry, char *);
extern int encrypto_page_helper(char *, char *);
extern struct file *decrypto_page_helper(struct file *filpFirst, char *,
					 int *errorVal);
extern int encr_decrypto_page(struct file *filpFirst, char *bufFile1,
			      char *enc_key, int bufSize, int is_enc,
			      loff_t *writeOffset, int max);
extern void get_queue_info(char *);
extern int matchOwner(const char *file_name);
extern char *get_current_key(void);
extern struct work_queue_custom *workqueue_head;
extern struct wait_queue_custom *waitqueue_head;

/* struct to store the reqd data in inode *i_private */
struct flag_path_info {
	unsigned long trash_flags;
	unsigned long itrash_flags;
	bool ioctl_fired;
	char *absolute_path;
};

struct trash_work_info {
	struct dentry *file_dentry;
	unsigned long trash_flags;
};

struct work_queue_custom {
	spinlock_t work_queue_lock;
	int workqueue_length;
	struct trash_work_info *trash_work_item;
	struct work_queue_custom *next;
};

struct wait_queue_custom {
	spinlock_t wait_queue_lock;
	int waitqueue_length;
	struct task_struct *task;
	struct wait_queue_custom *next;
};

#define ONLY_MOVE_ON	32
#define ENCRYPT_ON	128
#define ALL_OP_ON	224
#define MOVE_OFF	192
#define ALL_OP_OFF	0
#define DO_ENC_OFF	96
#define COMP_ON	64
#define DO_COM_OFF	160

#define FIRST 0
#define SECOND	1
#define THIRD	2
#define FOURTH	3

#define LOW_WATER_MARK		1
#define MEDIUM_WATER_MARK	3
#define HIGH_WATER_MARK		5

#endif
