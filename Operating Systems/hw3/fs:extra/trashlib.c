#include <linux/fs_stack.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/time.h>
#include <linux/namei.h>
#include <linux/rtc.h>
#include <linux/scatterlist.h>

#include "trashlib.h"
#define KEY_LEN 16

int compress_file(const char *infile, char *);
struct file *decompress_file(const char *infile, char *, int *);
int rename_to_trashbin(struct dentry *old_dentry, unsigned long trash_flags);
int do_unlink(struct file *filpFirst);
int encrypto_page_helper(char *, char *);
struct file *decrypto_page_helper(struct file *filpFirst, char *,
				  int *errorVal);
int encr_decrypto_page(struct file *filpFirst, char *bufFile1, char *enc_key,
		       int bufSize, int is_enc, loff_t *writeOffset, int max);
int my_readfs_file(struct file *filp, char *buf, size_t size, loff_t *offset);
int my_writefs_file(struct file *filp, char *buf, size_t size, loff_t *offset);
int matchOwner(const char *file_name);
char *get_current_key(void);
void get_queue_info(char *);
int do_rename(struct dentry *old_dentry, char *secondFileName);
void get_filename(bool, struct rtc_time, int, char *, char *);

/* method invoked on proc_read of module "queue_info" */
void get_queue_info(char *workqueue_buffer)
{
	char *ops_pending = NULL, *trash_item_buf = NULL;
	char *file_name = NULL;
	int i = 0;
	struct work_queue_custom *workqueue_traverse_head = NULL;
	struct trash_work_info *trash_work_item = NULL;
	int copy_workqueue_length;
	unsigned long trash_flags = 0;
	struct dentry *file_dentry = NULL;

	memset(workqueue_buffer, '\0', PAGE_SIZE);

	if (workqueue_head == NULL) {
		sprintf(workqueue_buffer, "%s\n",
			"Queue is not initialized yet");
		goto last_exit;
	}
	spin_lock(&workqueue_head->work_queue_lock);
	workqueue_traverse_head = workqueue_head->next;

	trash_item_buf = kmalloc(PAGE_SIZE, __GFP_REPEAT);
	ops_pending = kmalloc(PAGE_SIZE, __GFP_REPEAT);

	copy_workqueue_length = workqueue_head->workqueue_length;

	printk("%s workqueue_length = %d\n", __func__, copy_workqueue_length);

	if (workqueue_traverse_head == NULL) {
		sprintf(workqueue_buffer, "%s\n", "Queue is empty");
		goto exit;
	} else {
		for (i = 0; i < copy_workqueue_length; i++) {
			memset(trash_item_buf, '\0', PAGE_SIZE);
			memset(ops_pending, '\0', PAGE_SIZE);
			trash_work_item =
			    workqueue_traverse_head->trash_work_item;
			file_dentry = trash_work_item->file_dentry;
			trash_flags = trash_work_item->trash_flags;
			file_name = (char *)file_dentry->d_name.name;

			if (trash_flags & CLONE_PROT_MV) {
				strncat(ops_pending, "Move ", strlen("Move "));
			}
			if (trash_flags & CLONE_PROT_ZIP) {
				strncat(ops_pending, "Compress ",
					strlen("Compress "));
			}
			if (trash_flags & CLONE_PROT_ENC) {
				strncat(ops_pending, "Encrypt ",
					strlen("Encrypt "));
			}

			sprintf(trash_item_buf,
				"File name : %s Pending Ops : %s Waiting at No: = %d\n",
				file_name, ops_pending, i);
			printk("%s workqueue_item = %s\n", __func__,
			       trash_item_buf);
			strncat(workqueue_buffer, trash_item_buf,
				strlen(trash_item_buf));
			workqueue_traverse_head = workqueue_traverse_head->next;
		}
	}
 exit:
	spin_unlock(&workqueue_head->work_queue_lock);
 last_exit:
	if (trash_item_buf != NULL) {
		kfree(trash_item_buf);
	}
	if (ops_pending != NULL) {
		kfree(ops_pending);
	}
}

int rename_to_trashbin(struct dentry *old_dentry, unsigned long trash_flags)
{
	mm_segment_t oldfs;
	struct dentry *trapEntry;
	struct dentry *old_file_dentry;
	struct dentry *new_file_dentry;
	struct dentry *old_file_parent_dentry;
	struct dentry *new_file_parent_dentry;
	int errorVal = 0;
	struct path lower_path;
	struct timespec time;
	unsigned long local_time;
	struct rtc_time tm;
	char *secondFileName = NULL;
	struct flag_path_info *flag_path_private = NULL;
	bool compressionFlag = false;
	char *old_file_name = NULL;
	char *encrypt_infile_name = NULL;
	int user_id = 0;

	oldfs = get_fs();
	set_fs(get_ds());

	printk("Inside rename rename\n");

	old_file_dentry = old_dentry;
	user_id = old_dentry->d_inode->i_uid.val;

	old_file_name = kmalloc(PAGE_SIZE, GFP_KERNEL);
	snprintf(old_file_name, MY_PAGE_SIZE, "%s", old_dentry->d_name.name);

	secondFileName = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
	if (secondFileName == NULL) {
		errorVal = -ENOMEM;
		goto clear_out;
	}

	encrypt_infile_name = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
	if (encrypt_infile_name == NULL) {
		errorVal = -ENOMEM;
		goto clear_out;
	}

	getnstimeofday(&time);
	local_time = (u32) (time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);

	flag_path_private =
	    (struct flag_path_info *)old_file_dentry->d_inode->i_private;
	if ((flag_path_private->itrash_flags & ALL_OP_ON) != ONLY_MOVE_ON) {
		get_filename(true, tm, user_id, secondFileName, old_file_name);
	} else {
		get_filename(false, tm, user_id, secondFileName, old_file_name);
	}

	printk("%s\n", secondFileName);

	new_file_dentry = user_path_create(AT_FDCWD, secondFileName,
					   &lower_path, 0);
	if (IS_ERR(new_file_dentry)) {
		errorVal = PTR_ERR(new_file_dentry);
		printk("%s %s %d\n", __func__, "Unable to get new dentry",
		       errorVal);
		goto clear_out;
	}

	done_path_create(&lower_path, new_file_dentry);

	old_file_parent_dentry = old_file_dentry->d_parent;
	new_file_parent_dentry = new_file_dentry->d_parent;

	trapEntry = lock_rename(old_file_parent_dentry, new_file_parent_dentry);
	/* source should not be ancestor of target */
	if (trapEntry == old_file_dentry) {
		errorVal = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trapEntry == new_file_dentry) {
		errorVal = -ENOTEMPTY;
		goto out;
	}

	errorVal = vfs_rename(d_inode(old_file_parent_dentry), old_file_dentry,
			      d_inode(new_file_parent_dentry), new_file_dentry,
			      NULL, 0);

	if (errorVal)
		goto out;

	flag_path_private =
	    (struct flag_path_info *)old_file_dentry->d_inode->i_private;
	flag_path_private->itrash_flags &= MOVE_OFF;

 out:
	unlock_rename(old_file_parent_dentry, new_file_parent_dentry);

	printk("%s %s\n", __func__, "released lock in Renaming to trashbin");
	memset(encrypt_infile_name, '\0', PAGE_SIZE);
	memcpy(encrypt_infile_name, old_file_dentry->d_name.name,
	       strlen(old_file_dentry->d_name.name));
 clear_out:
	set_fs(oldfs);
	printk("dentry name %s %s\n", old_dentry->d_name.name, __func__);
	if (errorVal == 0) {
		if (trash_flags & CLONE_PROT_ZIP) {
			if ((flag_path_private->itrash_flags & ENCRYPT_ON) !=
			    ENCRYPT_ON) {
				get_filename(false, tm, user_id, secondFileName,
					     old_file_name);
			}
			errorVal =
			    compress_file(old_file_dentry->d_name.name,
					  secondFileName);
			while (errorVal != 0) {
				errorVal =
				    compress_file(old_file_dentry->d_name.name,
						  secondFileName);
			}
			printk("%s 1 = flag = %d\n", __func__,
			       (compressionFlag == true) ? 1 : 0);
			compressionFlag = true;
		}
		if (trash_flags & CLONE_PROT_ENC) {
			get_filename(false, tm, user_id, secondFileName,
				     old_file_name);
			printk("%s 2 = flag = %d\n", __func__,
			       (compressionFlag == true) ? 1 : 0);
			if (compressionFlag == true) {
				strcat(encrypt_infile_name, ".cmp");
				strcat(secondFileName, ".cmp");
				compressionFlag = false;
			}
			printk
			    ("%sencrypt_infile_name = %s secondFileName = %s\n",
			     __func__, encrypt_infile_name, secondFileName);
			errorVal =
			    encrypto_page_helper(encrypt_infile_name,
						 secondFileName);
			while (errorVal != 0) {
				errorVal =
				    encrypto_page_helper(encrypt_infile_name,
							 secondFileName);
			}
		}
	}

	if (secondFileName != NULL) {
		kfree(secondFileName);
	}
	if (old_file_name != NULL) {
		kfree(old_file_name);
	}
	if (encrypt_infile_name != NULL) {
		kfree(encrypt_infile_name);
	}

	return errorVal;
}

void get_filename(bool containstemp, struct rtc_time tm, int user_id,
		  char *secondFileName, char *old_file_name)
{
	memset(secondFileName, '\0', MY_PAGE_SIZE);
	printk("1...%s %s\n", secondFileName, __func__);
	memcpy(secondFileName, "/.trashbin/", strlen("/.trashbin/"));
	if (containstemp) {
		strcat(secondFileName, "temp-");
	}
	printk("2... %s %s\n", secondFileName, __func__);
	snprintf(secondFileName + strlen(secondFileName), MY_PAGE_SIZE,
		 "%d-%d-%02d-%02d-%02d-%02d-%02d-%s", user_id,
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		 tm.tm_min, tm.tm_sec, old_file_name);

	printk("3.. %s %s\n", secondFileName, __func__);

}

/**
 * encrypto_page_helper : This function read from un-encrypted file and
 * send that buffer to get encrypted.
 * @file_name: name of file to encrypt in .sg
 * Returns 0 on success; non-zero error otherwise
 * Also write no of padding bytes and ENC key to output file with which
 * the file is going to be encrypted. So that it can be matched while
 * decrypting.
 * Unlink old file if enc is successful.
 */
int encrypto_page_helper(char *file_name, char *outfile)
{
	mm_segment_t oldfs;
	loff_t offsetFirst = 0;
	loff_t write_offset = 0;
	struct file *filpFirst = NULL;
	struct file *filpSecond = NULL;
	int errorVal = 0;
	char *bufFile1 = NULL;
	char *filePath = NULL;
	long int fileSize = 0;
	struct flag_path_info *file_inode_info;
	int bytes_read_first;
	int padSize = 0;
	char padSizeChar[1];
	char *ENC_KEY = get_current_key();
	char topad_bytes[KEY_SIZE_AES];
	struct flag_path_info *flag_path_private = NULL;
	struct flag_path_info *flag_path_private_first = NULL;

	oldfs = get_fs();
	set_fs(get_ds());

	filePath = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
	memset(filePath, '\0', MY_PAGE_SIZE);
	memcpy(filePath, "/.trashbin/", strlen("/.trashbin/"));
	strcat(filePath, file_name);

	printk("%s %s\n", __func__, filePath);

	filpFirst = filp_open(filePath, O_RDONLY, 0644);
	if (!filpFirst || IS_ERR(filpFirst)) {
		printk("%s %s\n", __func__, "Error in file opening infile");
		errorVal = (int)PTR_ERR(filpFirst);
		goto first_exit;
	}

	file_inode_info =
	    (struct flag_path_info *)filpFirst->f_path.dentry->d_inode->
	    i_private;
	printk("%s Inode trash_flags= %lu\n", __func__,
	       file_inode_info->trash_flags);
	fileSize = filpFirst->f_inode->i_size;
	printk("%s fileSize = %d\n", __func__, (int)fileSize);

	bufFile1 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

	strcat(outfile, ".enc");
	printk("%s %s\n", __func__, outfile);
	filpSecond = filp_open(outfile, O_RDWR | O_CREAT, 0644);
	if (!filpSecond || IS_ERR(filpSecond)) {
		printk("%s %s\n", __func__, "Error in file opening outfile");
		errorVal = (int)PTR_ERR(filpSecond);
		goto clear_and_exit;
	}

	filpSecond->f_path.dentry->d_inode->i_private =
	    filpFirst->f_path.dentry->d_inode->i_private;
	flag_path_private =
	    (struct flag_path_info *)filpSecond->f_path.dentry->d_inode->
	    i_private;

	flag_path_private =
	    kmalloc(sizeof(struct flag_path_info), __GFP_REPEAT);
	flag_path_private_first =
	    (struct flag_path_info *)filpFirst->f_path.dentry->d_inode->
	    i_private;
	flag_path_private->trash_flags = flag_path_private_first->trash_flags;
	flag_path_private->itrash_flags = flag_path_private_first->itrash_flags;
	flag_path_private->absolute_path =
	    flag_path_private_first->absolute_path;
	flag_path_private->ioctl_fired = flag_path_private_first->ioctl_fired;

	filpSecond->f_path.dentry->d_inode->i_private =
	    (void *)flag_path_private;

	padSize = KEY_SIZE_AES - (fileSize % KEY_SIZE_AES);
	padSizeChar[0] = padSize;
	filpSecond->f_pos = 0;
	printk("%s Padsize = %d\n", __func__, (int)padSize);

	memset(topad_bytes, padSize, padSize);

	errorVal = my_writefs_file(filpSecond, padSizeChar, 1, &write_offset);
	if (errorVal == 0) {
		errorVal = -ENOENT;
		goto clear_and_exit;
	}

	errorVal = my_writefs_file(filpSecond, ENC_KEY,
				   KEY_SIZE_AES, &write_offset);
	if (errorVal == 0) {
		errorVal = -ENOENT;
		goto clear_and_exit;
	}

	while (1) {
		bytes_read_first = my_readfs_file(filpFirst, bufFile1,
						  MY_PAGE_SIZE, &offsetFirst);

		if (bytes_read_first < MY_PAGE_SIZE) {
			if (padSize > 0 && bytes_read_first >= 0) {
				memcpy(bufFile1 + bytes_read_first, topad_bytes,
				       padSize);
				bufFile1[bytes_read_first + padSize] = '\0';

				errorVal =
				    encr_decrypto_page(filpSecond, bufFile1,
						       ENC_KEY,
						       bytes_read_first +
						       padSize, 1,
						       &write_offset,
						       bytes_read_first +
						       padSize);
				if (errorVal != 0) {
					goto clear_and_exit;
				}
				break;
			}
			break;
		} else {
			errorVal = encr_decrypto_page(filpSecond, bufFile1,
						      ENC_KEY, bytes_read_first,
						      1, &write_offset,
						      bytes_read_first);
			if (errorVal != 0) {
				goto clear_and_exit;
			}
		}
	}

	printk("%s fileSize2 = %d\n", __func__,
	       (int)filpSecond->f_inode->i_size);

 clear_and_exit:
	if (bufFile1 != NULL) {
		kfree(bufFile1);
	}
	if (ENC_KEY != NULL) {
		kfree(ENC_KEY);
	}
	if (errorVal) {
		if (filpSecond != NULL) {
			do_unlink(filpSecond);
		}
	} else {
		if (filpFirst != NULL) {
			fsstack_copy_attr_all(filpSecond->f_path.dentry->
					      d_inode,
					      filpFirst->f_path.dentry->
					      d_inode);
			flag_path_private->itrash_flags &= ALL_OP_OFF;
			do_unlink(filpFirst);
		}
	}
	if (filpFirst != NULL) {
		filp_close(filpFirst, NULL);
	}
	if (filpSecond != NULL) {
		filp_close(filpSecond, NULL);
	}

 first_exit:
	if (filePath != NULL) {
		kfree(filePath);
	}
	set_fs(oldfs);
	return errorVal;

}

/**
 * decrypto_page_helper : This function read from encrypted file and
 * send that buffer to get decrypted.
 * @filpFirst: file pointer of file to decrypt
 * @errorVal: pointer received from caller to put error value
 * Returns file pointer of decrypted file.
 * Matches the key with which the file is encrypted and current user key
 * with which he is mounted. If no match , no decryption is possible.
 * Unlink old file if decryption is successful.
 */
struct file *decrypto_page_helper(struct file *filpFirst, char *decfilePath,
				  int *errorVal)
{
	mm_segment_t oldfs;
	loff_t offsetFirst = 0;
	loff_t write_offset = 0;
	struct file *filpSecond = NULL;
	char *bufFile1 = NULL;
	char *DEC_KEY = NULL;
	struct flag_path_info *flag_path_private = NULL;
	struct flag_path_info *flag_path_private_first = NULL;
	long int fileSize = 0;
	int bytes_read_first;
	int count = 0;
	int padSize = 0;

	oldfs = get_fs();
	set_fs(get_ds());

	printk("%s %s %d\n", __func__, decfilePath, (int)strlen(decfilePath));

	fileSize = filpFirst->f_inode->i_size - KEY_SIZE_AES - 1;
	count = fileSize;

	bufFile1 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
	DEC_KEY = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

	filpSecond = filp_open(decfilePath, O_RDWR | O_CREAT, 0644);
	if (!filpSecond || IS_ERR(filpSecond)) {
		printk("%s %s\n", __func__, "Error in file opening");
		*errorVal = (int)PTR_ERR(filpSecond);
		goto clear_and_exit;
	}

	filpFirst->f_pos = 0;
	filpSecond->f_pos = 0;
	padSize = my_readfs_file(filpFirst, bufFile1, 1, &offsetFirst);
	padSize = (int)bufFile1[0];

	printk("%s Padsize = %d\n", __func__, (int)padSize);

	my_readfs_file(filpFirst, DEC_KEY, KEY_SIZE_AES, &offsetFirst);

	while (count > MY_PAGE_SIZE) {
		bytes_read_first = my_readfs_file(filpFirst, bufFile1,
						  MY_PAGE_SIZE, &offsetFirst);
		count -= bytes_read_first;
		*errorVal = encr_decrypto_page(filpSecond, bufFile1, DEC_KEY,
					       bytes_read_first, 0,
					       &write_offset, bytes_read_first);
		if (*errorVal != 0) {
			goto clear_and_exit;
		}
	}

	bytes_read_first = my_readfs_file(filpFirst, bufFile1, MY_PAGE_SIZE,
					  &offsetFirst);

	*errorVal = encr_decrypto_page(filpSecond, bufFile1, DEC_KEY,
				       bytes_read_first, 0, &write_offset,
				       bytes_read_first - padSize);
	if (*errorVal != 0) {
		goto clear_and_exit;
	}

 clear_and_exit:
	set_fs(oldfs);
	if (bufFile1 != NULL) {
		kfree(bufFile1);
	}
	if (DEC_KEY != NULL) {
		kfree(DEC_KEY);
	}
	if (*errorVal) {
		if (filpSecond != NULL) {
			do_unlink(filpSecond);
		}
	} else {
		if (filpFirst != NULL) {
			fsstack_copy_attr_all(filpSecond->f_path.dentry->
					      d_inode,
					      filpFirst->f_path.dentry->
					      d_inode);

			flag_path_private =
			    kmalloc(sizeof(struct flag_path_info),
				    __GFP_REPEAT);
			flag_path_private_first =
			    (struct flag_path_info *)filpFirst->f_path.dentry->
			    d_inode->i_private;
			flag_path_private->trash_flags =
			    flag_path_private_first->trash_flags;
			flag_path_private->itrash_flags =
			    flag_path_private_first->itrash_flags;
			flag_path_private->absolute_path =
			    flag_path_private_first->absolute_path;
			flag_path_private->ioctl_fired =
			    flag_path_private_first->ioctl_fired;

			filpSecond->f_path.dentry->d_inode->i_private =
			    (void *)flag_path_private;

			flag_path_private->itrash_flags &= DO_ENC_OFF;
			do_unlink(filpFirst);
		}
	}
	if (filpFirst != NULL) {
		filp_close(filpFirst, NULL);
	}
	return filpSecond;
}

/**
 * encr_decrypto_page : This function do the main encryption and decryption
 * Initializes iv vectore, set key before enc/dec write buffer to out file
 * @filpFirst: file pointer of file to enc/dec
 * @bufFile1: buffer to enc/dec
 * @enc_key: key with which we do enc/dec
 * @bufSize: size of buffer to enc/dec
 * @is_enc: 1/0 for enc/dec
 * @writeOffset: offset of out file where to start writing in out file
 * @max : max bytes to write in out file
 * Returns 0 on success, error otherwise(Non-zero)
 */
int encr_decrypto_page(struct file *filpFirst, char *bufFile1,
		       char *enc_key, int bufSize, int is_enc,
		       loff_t *writeOffset, int max)
{
	int errorVal = 0;
	int bytes = 0;
	struct scatterlist sg;
	struct crypto_blkcipher *block_cipher = NULL;
	struct blkcipher_desc block_desc;

	char ini_vector[KEY_SIZE_AES] =
	    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";

	block_cipher = crypto_alloc_blkcipher("cbc(aes)", 0, 0);

	if (IS_ERR(block_cipher)) {
		printk("%s %s\n", __func__, "No memory alloacted");
		errorVal = PTR_ERR(block_cipher);
		goto clear_exit;
	}

	errorVal = crypto_blkcipher_setkey(block_cipher, enc_key, KEY_SIZE_AES);
	if (errorVal != 0) {
		printk("%s %s\n", __func__, "Unable to set key in cipher");
		goto clear_exit;
	}

	crypto_blkcipher_set_iv(block_cipher, ini_vector, KEY_SIZE_AES);

	block_desc.tfm = block_cipher;
	block_desc.flags = 0;

	sg_init_one(&sg, bufFile1, bufSize);

	if (is_enc == 0) {
		crypto_blkcipher_decrypt(&block_desc, &sg, &sg, bufSize);
	} else {
		crypto_blkcipher_encrypt(&block_desc, &sg, &sg, bufSize);
	}

	bytes = my_writefs_file(filpFirst, bufFile1, max, writeOffset);

	if (block_cipher)
		crypto_free_blkcipher(block_cipher);

 clear_exit:
	return errorVal;
}

/**
 * my_readfs_file : This function reads from a file into buf
 * @filp: file pointer of file to read
 * @buf: buffer to read into
 * @size: how much to read form file
 * @offset: from where to read file
 * Returns number of bytes read
 */
int my_readfs_file(struct file *filp, char *buf, size_t size, loff_t *offset)
{
	mm_segment_t oldfs;
	int bytes;

	/* now read len bytes from offset */
	oldfs = get_fs();
	set_fs(get_ds());

	bytes = vfs_read(filp, buf, size, offset);

	set_fs(oldfs);

	return bytes;
}

/**
 * my_writefs_file : This function write to a file from buf
 * @filp: file pointer of file to write
 * @buf: buffer to write in file
 * @size: how much to write into file
 * @offset: from where to write in file
 * Returns number of bytes written
 */
int my_writefs_file(struct file *filp, char *buf, size_t size, loff_t *offset)
{
	mm_segment_t oldfs;
	int bytes;

	/* now write size bytes from offset */
	oldfs = get_fs();
	set_fs(get_ds());

	bytes = vfs_write(filp, buf, size, offset);

	set_fs(oldfs);

	return bytes;

}

int compress_file(const char *infile, char *outfile)
{
	int err = 0;
	char *read_buf = NULL, *write_buf = NULL, *uint_buf = NULL, *ll_buf =
	    NULL, *filePath = NULL;
	struct file *rfilp = NULL, *wfilp = NULL;	/* file decrypting */
	u_int total_bytes = -1;
	u_int bytes_to_be_read, bytes_read, total_pages;
	struct crypto_comp *tfm;
	u_int write_len, uint_len;
	u_int outlen = PAGE_SIZE;
	char *algo = "deflate";
	struct flag_path_info *flag_path_private = NULL;
	struct flag_path_info *flag_path_private_rfilp = NULL;

	loff_t next_write_pos, next_uint_pos, total_size;

	filePath = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
	memset(filePath, '\0', MY_PAGE_SIZE);
	memcpy(filePath, "/.trashbin/", strlen("/.trashbin/"));
	strcat(filePath, infile);

	strcat(outfile, ".cmp");
	printk("infile %s %s\n", __func__, infile);
	printk("outfile %s %s\n", __func__, outfile);

	read_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	write_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	uint_buf = kmalloc(sizeof(u_int), GFP_KERNEL);
	ll_buf = kmalloc(sizeof(loff_t), GFP_KERNEL);

	if (read_buf == NULL || write_buf == NULL || uint_buf == NULL
	    || ll_buf == NULL) {
		printk("%s ERROR : kmalloc is unsuccessful \n", __func__);
		err = -ENOMEM;
		goto out_else_1;
	}

	rfilp = filp_open(filePath, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
		err = (int)PTR_ERR(rfilp);
		printk("%s ERROR : Opening of file is unsuccessful\n",
		       __func__);
		goto out_else_1;
	}

	wfilp =
	    filp_open(outfile, O_RDWR | O_CREAT | O_TRUNC,
		      0777 & ~current_umask());

	if (!wfilp || IS_ERR(wfilp)) {
		err = (int)PTR_ERR(wfilp);
		printk
		    ("ERROR : file.c : sgfs_unlocked_ioctl : Opening of file is unsuccessful\n");
		goto out_else_1;
	}

	flag_path_private =
	    kmalloc(sizeof(struct flag_path_info), __GFP_REPEAT);
	flag_path_private_rfilp =
	    (struct flag_path_info *)rfilp->f_path.dentry->d_inode->i_private;
	flag_path_private->trash_flags = flag_path_private_rfilp->trash_flags;
	flag_path_private->itrash_flags = flag_path_private_rfilp->itrash_flags;
	flag_path_private->absolute_path =
	    flag_path_private_rfilp->absolute_path;
	flag_path_private->ioctl_fired = flag_path_private_rfilp->ioctl_fired;

	wfilp->f_path.dentry->d_inode->i_private = (void *)flag_path_private;

	total_bytes = rfilp->f_path.dentry->d_inode->i_size;

	if (total_bytes == 0) {
		err = 0;
		goto out_else_1;
	}

	total_pages = total_bytes / PAGE_SIZE;

	if (total_bytes % PAGE_SIZE != 0) {
		total_pages += 1;
	}

	total_size = sizeof(loff_t) + (total_pages * sizeof(u_int));

	printk("total pages %u\n", total_pages);

	tfm = crypto_alloc_comp(algo, 0, 0);
	if (!tfm) {
		err = -EINVAL;
		printk(KERN_ALERT "\n Error: problem with tfm");
	}

	wfilp->f_pos = 0;
	rfilp->f_pos = 0;

	memset(write_buf, 0, PAGE_SIZE);
	memset(read_buf, 0, PAGE_SIZE);
	memset(uint_buf, 0, sizeof(u_int));
	memset(ll_buf, 0, sizeof(loff_t));

	sprintf(ll_buf, "%lli", total_size);

	uint_len =
	    my_writefs_file(wfilp, ll_buf, sizeof(loff_t), &wfilp->f_pos);

	next_uint_pos = wfilp->f_pos;

	wfilp->f_pos = total_size;

	while (true) {

		if (total_bytes < PAGE_SIZE) {
			bytes_to_be_read = total_bytes;
		} else {
			bytes_to_be_read = PAGE_SIZE;
		}

		bytes_read =
		    my_readfs_file(rfilp, read_buf, bytes_to_be_read,
				   &(rfilp->f_pos));

		if (bytes_read < 0) {
			printk
			    ("ERROR : file.c : sgfs_unlocked_ioctl : vfs_read has failed \n");
			err = bytes_read;
			goto out_else_1;
		} else if (bytes_read == 0) {
			break;
		} else {
			outlen = PAGE_SIZE;
			err =
			    crypto_comp_compress(tfm, read_buf, bytes_read,
						 write_buf, &outlen);

			if (err < 0) {
				printk(KERN_ALERT
				       "\n Error: Compression failed");
				goto out_else_1;
			}

			sprintf(uint_buf, "%u", outlen);
			next_write_pos = wfilp->f_pos;
			wfilp->f_pos = next_uint_pos;

			uint_len =
			    my_writefs_file(wfilp, uint_buf, sizeof(u_int),
					    &wfilp->f_pos);
			next_uint_pos = wfilp->f_pos;
			wfilp->f_pos = next_write_pos;

			write_len =
			    my_writefs_file(wfilp, write_buf, outlen,
					    &wfilp->f_pos);

			if (write_len < 0) {
				printk(KERN_ALERT "\n Error: writing O/P file");
				err = write_len;
				goto out_else_1;
			}
			total_bytes -= bytes_read;
		}
		memset(write_buf, 0, PAGE_SIZE);
		memset(read_buf, 0, PAGE_SIZE);
		memset(uint_buf, 0, sizeof(u_int));
	}

 out_else_1:
	if (read_buf != NULL)
		kfree(read_buf);
	if (write_buf != NULL)
		kfree(write_buf);
	if (uint_buf != NULL)
		kfree(uint_buf);
	if (ll_buf != NULL)
		kfree(ll_buf);

	if (err) {
		if (wfilp != NULL) {
			do_unlink(wfilp);
		}
	} else {
		if (rfilp != NULL) {
			fsstack_copy_attr_all(wfilp->f_path.dentry->d_inode,
					      rfilp->f_path.dentry->d_inode);
			flag_path_private->itrash_flags &= ENCRYPT_ON;
			do_unlink(rfilp);
		}
	}

	if (rfilp != NULL)
		filp_close(rfilp, NULL);
	if (wfilp != NULL)
		filp_close(wfilp, NULL);

	return err;
}

struct file *decompress_file(const char *infile, char *outfile, int *err)
{
	char *read_buf = NULL, *write_buf = NULL, *uint_buf = NULL, *ll_buf =
	    NULL;
	struct file *rfilp = NULL, *wfilp = NULL;	/* file decrypting */
	u_int total_bytes = -1;
	u_int bytes_to_be_read, bytes_read;
	struct crypto_comp *tfm;
	u_int write_len;
	u_int outlen = PAGE_SIZE;
	char *algo = "deflate";
	struct flag_path_info *flag_path_private = NULL;
	struct flag_path_info *flag_path_private_rfilp = NULL;
	char *infilenew = NULL;
	loff_t next_read_pos, next_uint_pos, total_size;

	*err = 0;

	infilenew = kmalloc(PAGE_SIZE, GFP_KERNEL);
	read_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	write_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	uint_buf = kmalloc(sizeof(u_int), GFP_KERNEL);
	ll_buf = kmalloc(sizeof(loff_t), GFP_KERNEL);
	if (read_buf == NULL || write_buf == NULL || uint_buf == NULL
	    || ll_buf == NULL || infilenew == NULL) {
		printk
		    ("ERROR : file.c : sgfs_unlocked_ioctl  : kmalloc is unsuccessful \n");
		*err = -ENOMEM;
		goto out_else_1;
	}

	memset(infilenew, '\0', PAGE_SIZE);
	memcpy(infilenew, "/.trashbin/", strlen("/.trashbin/"));
	strcat(infilenew, infile);

	rfilp = filp_open(infilenew, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
		*err = (int)PTR_ERR(rfilp);
		printk
		    ("ERROR : file.c : sgfs_unlocked_ioctl : Opening of infile is unsuccessful\n");
		goto out_else_1;
	}

	total_bytes = rfilp->f_path.dentry->d_inode->i_size;

	wfilp =
	    filp_open(outfile, O_RDWR | O_CREAT | O_TRUNC,
		      0777 & ~current_umask());

	if (!wfilp || IS_ERR(wfilp)) {
		*err = (int)PTR_ERR(wfilp);
		printk
		    ("ERROR : file.c : sgfs_unlocked_ioctl : Opening of outfile is unsuccessful\n");
		goto out_else_1;
	}

	if (total_bytes == 0) {
		*err = 0;
		goto out_else_1;
	}

	tfm = crypto_alloc_comp(algo, 0, 0);
	if (!tfm) {
		*err = -EINVAL;
		printk(KERN_ALERT "\n Error: problem with tfm");
	}

	wfilp->f_pos = 0;
	rfilp->f_pos = 0;

	memset(write_buf, 0, PAGE_SIZE);
	memset(read_buf, 0, PAGE_SIZE);
	memset(uint_buf, 0, sizeof(u_int));
	memset(ll_buf, 0, sizeof(loff_t));

	bytes_read =
	    my_readfs_file(rfilp, ll_buf, sizeof(loff_t), &(rfilp->f_pos));

	next_uint_pos = rfilp->f_pos;
	sscanf(ll_buf, "%lli", &total_size);
	rfilp->f_pos = total_size;

	total_bytes -= total_size;
	printk("uint pointer  %lli \n", next_uint_pos);
	printk("file poistion after cpnveriosn %lli \n", rfilp->f_pos);
	while (true) {
		if (total_bytes < PAGE_SIZE) {
			bytes_to_be_read = total_bytes;
		} else {
			bytes_to_be_read = PAGE_SIZE;
		}

		next_read_pos = rfilp->f_pos;
		rfilp->f_pos = next_uint_pos;
		bytes_read =
		    my_readfs_file(rfilp, uint_buf, sizeof(u_int),
				   &(rfilp->f_pos));
		next_uint_pos = rfilp->f_pos;
		rfilp->f_pos = next_read_pos;

		sscanf(uint_buf, "%u", &bytes_to_be_read);
		bytes_read =
		    my_readfs_file(rfilp, read_buf, bytes_to_be_read,
				   &(rfilp->f_pos));

		if (bytes_read < 0) {
			*err = bytes_read;
			goto out_else_1;
		} else if (bytes_read == 0) {
			break;
		} else {
			outlen = PAGE_SIZE;
			*err =
			    crypto_comp_decompress(tfm, read_buf, bytes_read,
						   write_buf, &outlen);

			if (*err < 0) {
				printk(KERN_ALERT
				       "\n Error: decompression failed");
				goto out_else_1;
			}

			write_len =
			    my_writefs_file(wfilp, write_buf, outlen,
					    &wfilp->f_pos);

			if (write_len < 0) {
				*err = write_len;
				goto out_else_1;
			}
			total_bytes -= bytes_read;
		}
		memset(write_buf, 0, PAGE_SIZE);
		memset(read_buf, 0, PAGE_SIZE);
		memset(uint_buf, 0, sizeof(u_int));
	}
 out_else_1:
	if (read_buf != NULL)
		kfree(read_buf);
	if (write_buf != NULL)
		kfree(write_buf);
	if (uint_buf != NULL)
		kfree(uint_buf);
	if (ll_buf != NULL)
		kfree(ll_buf);
	if (infilenew != NULL)
		kfree(infilenew);

	if (*err) {
		if (wfilp != NULL) {
			do_unlink(wfilp);
		}
	} else {
		if (rfilp != NULL) {
			fsstack_copy_attr_all(wfilp->f_path.dentry->d_inode,
					      rfilp->f_path.dentry->d_inode);
			flag_path_private =
			    kmalloc(sizeof(struct flag_path_info),
				    __GFP_REPEAT);
			flag_path_private_rfilp =
			    (struct flag_path_info *)rfilp->f_path.dentry->
			    d_inode->i_private;
			flag_path_private->trash_flags =
			    flag_path_private_rfilp->trash_flags;
			flag_path_private->itrash_flags =
			    flag_path_private_rfilp->itrash_flags;
			flag_path_private->absolute_path =
			    flag_path_private_rfilp->absolute_path;
			flag_path_private->ioctl_fired =
			    flag_path_private_rfilp->ioctl_fired;

			wfilp->f_path.dentry->d_inode->i_private =
			    (void *)flag_path_private;
			flag_path_private->itrash_flags &= DO_COM_OFF;
			do_unlink(rfilp);
		}
	}
	if (rfilp != NULL)
		filp_close(rfilp, NULL);

	return wfilp;

}

int matchOwner(const char *file_name)
{
	int count = 0;
	const struct cred *credentials = current_cred();
	char *currentUid = NULL;
	int remove = 0;
	char *findstart = NULL;
	char temp[5];

	if (strlen(file_name) < 21) {
		return 1;
	}

	memset(temp, '\0', sizeof(char) * 5);
	strncpy(temp, file_name, 5);
	if (strstr(temp, "temp-") != NULL) {
		printk("%s temp- \n", __func__);
		return 1;
	}

	if (credentials->uid.val == 0) {
		return 0;
	}

	findstart = strstr(file_name, "-");

	if (findstart != NULL) {
		currentUid = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
		snprintf(currentUid, MY_PAGE_SIZE, "%d", credentials->uid.val);
		while (file_name[count] != '\0' && currentUid[count] != '\0') {
			if (file_name[count] != currentUid[count]) {
				remove = 1;
				break;
			}
			count += 1;
		}
		if (file_name[count] != '-' || currentUid[count] != '\0') {
			remove = 1;
		}
	}

	if (currentUid != NULL) {
		kfree(currentUid);
	}
	return remove;
}

/**
 * do_unlink : This function unlink a lower level file
 * @filpFirst: file pointer of file to unlink(lower file)
 * Returns 0 on success, error otherwise(Non - zero)
 */
int do_unlink(struct file *filpFirst)
{
	int err;
	struct dentry *file_dentry;
	struct inode *dir_inode;

	file_dentry = filpFirst->f_path.dentry;
	dir_inode = file_dentry->d_parent->d_inode;

	inode_lock_nested(dir_inode, I_MUTEX_PARENT);

	err = vfs_unlink(dir_inode, file_dentry, NULL);

	inode_unlock(dir_inode);
	printk("%s File deleted = %s errorVal = %d\n", __func__,
	       filpFirst->f_path.dentry->d_name.name, err);
	return err;
}

int do_rename(struct dentry *old_dentry, char *secondFileName)
{
	mm_segment_t oldfs;
	struct dentry *trapEntry;
	struct dentry *old_file_dentry;
	struct dentry *new_file_dentry;
	struct dentry *old_file_parent_dentry;
	struct dentry *new_file_parent_dentry;
	int errorVal = 0;
	struct path lower_path;

	oldfs = get_fs();
	set_fs(get_ds());

	old_file_dentry = old_dentry;

	printk("%s\n", secondFileName);

	new_file_dentry = user_path_create(AT_FDCWD, secondFileName,
					   &lower_path, 0);
	if (IS_ERR(new_file_dentry)) {
		errorVal = PTR_ERR(new_file_dentry);
		printk("%s %s %d\n", __func__, "Unable to get new dentry",
		       errorVal);
		goto clear_out;
	}

	done_path_create(&lower_path, new_file_dentry);

	old_file_parent_dentry = old_file_dentry->d_parent;
	new_file_parent_dentry = new_file_dentry->d_parent;

	trapEntry = lock_rename(old_file_parent_dentry, new_file_parent_dentry);
	/* source should not be ancestor of target */
	if (trapEntry == old_file_dentry) {
		errorVal = -EINVAL;
		goto out;
	}

	/* target should not be ancestor of source */
	if (trapEntry == new_file_dentry) {
		errorVal = -ENOTEMPTY;
		goto out;
	}

	errorVal = vfs_rename(d_inode(old_file_parent_dentry), old_file_dentry,
			      d_inode(new_file_parent_dentry), new_file_dentry,
			      NULL, 0);
	if (errorVal)
		goto out;
 out:
	unlock_rename(old_file_parent_dentry, new_file_parent_dentry);

	printk("%s %s\n", __func__, "released lock in Renaming to trashbin");
 clear_out:
	if (errorVal == 0) {
		if (old_file_dentry != NULL) {
			if (old_file_dentry->d_inode != NULL) {
				if (old_file_dentry->d_inode->i_private != NULL) {
					kfree(old_file_dentry->d_inode->
					      i_private);
					old_file_dentry->d_inode->i_private =
					    NULL;
				}
			}
		}

	}

	set_fs(oldfs);

	return errorVal;
}

/**
 * get_current_key: return current cipher key if set by user;
 * default enc_key otherwise;
 */
char *get_current_key(void)
{
	struct file *filp;
	int read_length;
	loff_t offset;
	char *path, *buf;
	char ENC_KEY[16] = "1234123412341234";

	buf = (char *)kzalloc(PAGE_SIZE, __GFP_REPEAT);

	path = "/.keys";
	filp = filp_open(path, O_RDONLY, 0);
	if (!filp || IS_ERR(filp)) {
		printk(KERN_ALERT " %s:%i, key file doesn't exist.\n", __FILE__,
		       __LINE__);
		strcpy(buf, ENC_KEY);
		goto OUT;
	}
	offset = (get_current_user()->uid.val == 0) ? 0 : KEY_LEN + 1;

	read_length = my_readfs_file(filp, buf, KEY_LEN, &offset);
	printk(KERN_ALERT " %s:%i, read_length: %d, buf:%s\n",
	       __FILE__, __LINE__, read_length, buf);
	if (read_length != 16) {
		memset(buf, '\0', PAGE_SIZE);
		strcpy(buf, ENC_KEY);
	}

	filp_close(filp, NULL);
 OUT:
	return buf;
}
