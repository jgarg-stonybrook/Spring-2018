/*
 *  linux/fs/ioctl.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <linux/falloc.h>
#include <linux/delay.h>
#include "internal.h"
#include "trashlib.h"

#include <asm/ioctls.h>

/* So that the fiemap access checks can't overflow on 32 bit machines. */
#define FIEMAP_MAX_EXTENTS  (UINT_MAX / sizeof(struct fiemap_extent))
int is_in_bin(struct dentry *dentry);
int is_valid_user(const char *file_name);
int is_valid_user_byID(struct dentry *dentry);
int perform_undelete(struct file *filp_in);
static int unlink_file(struct file *filp);
int set_cipher_key(struct file *filp, char *arg);
void get_file_name(const char *infile, bool temp, char *middleName,
		   char *reducedPath);
int local_filldir(struct dir_context *ctx, const char *name, int namlen,
		  loff_t offset, u64 ino, unsigned int d_type);
int file_read(struct file *filp_in, char *buf, int len);
int file_write(struct file *filp_out, char *buf, int len);

int list_size;
struct custom_node {
	const char *data;
	struct custom_node *next;
};
struct custom_node *list_head;
int purge_bin(char *bin_path);
void iterate_and_delete(void);
int delete_from_bin(const char *file_name, char *path_buf);
void delete_list(void);
int is_temp_file(const char *name);
int has_valid_flag(const char *name);
/**
 * vfs_ioctl - call filesystem specific ioctl methods
 * @filp:   open file to invoke ioctl method on
 * @cmd:    ioctl command to execute
 * @arg:    command-specific argument for ioctl
 *
 * Invokes filesystem specific ->unlocked_ioctl, if one exists; otherwise
 * returns -ENOTTY.
 *
 * Returns 0 on success, -errno on error.
 */
long vfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int error = -ENOTTY;
	struct flag_path_info *flag_path_private = NULL;

	/* NUM = 4, makeing sure it's our ioctl call */
	if (cmd % 256 == 4) {
		printk(KERN_ALERT " %s:%i, Inside undo ioctl\n", __FILE__,
		       __LINE__);
		/* if not a valid user or not in .trash return error */
		if (!is_valid_user_byID(filp->f_path.dentry)) {
			error = -EPERM;
			goto out;
		}
		flag_path_private =
		    (struct flag_path_info *)filp->f_path.dentry->
		    d_inode->i_private;
		flag_path_private->ioctl_fired = true;
		if (!is_in_bin(filp->f_path.dentry)) {
			while (flag_path_private->ioctl_fired != false) {
				ssleep(2);
			}
			return 0;
		}

		/**now we have the name of new file which will be created in CWD
		go ahead and decrypt the content and unlink file from .sg after decryption
		*/
		printk(KERN_ALERT " %s:%i, Inside undo ioctl\n", __FILE__,
		       __LINE__);
		error = perform_undelete(filp);
		printk(KERN_ALERT "%s:%i, perform_undelete returned: %d \n",
		       __FILE__, __LINE__, error);
		return 0;
	} else if (cmd % 256 == 5) {
		printk(KERN_ALERT " %s:%i, Inside purge ioctl\n", __FILE__,
		       __LINE__);
		list_head = kmalloc(sizeof(struct custom_node), GFP_KERNEL);
		list_head->next = NULL;
		error = purge_bin("/.trashbin");
		if (list_head != NULL)
			kfree(list_head);
		return error;
	} else if (cmd % 256 == 6) {
		printk(KERN_ALERT
		       " %s:%i, Inside cipher key ioctl, name: %s, arg: %s\n",
		       __FILE__, __LINE__, filp->f_path.dentry->d_name.name,
		       (char *)arg);
		error = set_cipher_key(filp, (char *)arg);
		return 0;
	}
	if (!filp->f_op->unlocked_ioctl)
		goto out;

	error = filp->f_op->unlocked_ioctl(filp, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = -ENOTTY;
 out:
	return error;
}

/**
* set_cipher_key
*/
int set_cipher_key(struct file *filp, char *arg)
{
	int err, file_size, write_length;
	char *buf, *key_buf;
	char ENC_KEY[16] = "1234123412341234";

	err = 0;
	buf = (char *)kzalloc(PAGE_SIZE, __GFP_REPEAT);
	if (buf == NULL) {
		printk(KERN_ALERT " %s:%i, buffer allocation failed\n",
		       __FILE__, __LINE__);
		err = -ENOMEM;
		goto OUT;
	}

	file_size = (int)filp->f_path.dentry->d_inode->i_size;
	printk(KERN_ALERT " %s:%i,arg length: %d, file_size: %d\n",
	       __FILE__, __LINE__, (int)strlen(arg), file_size);

	if (copy_from_user(buf, arg, strlen(arg))) {
		printk(KERN_ALERT " %s:%i, error in copy_from_user!\n",
		       __FILE__, __LINE__);
		err = -EFAULT;
		goto OUT_1;
	}
	printk(KERN_ALERT " %s:%i, buf is: %s\n", __FILE__, __LINE__, buf);

	key_buf = (char *)kzalloc(PAGE_SIZE, __GFP_REPEAT);
	if (key_buf == NULL) {
		printk(KERN_ALERT " %s:%i, key buffer allocation failed\n",
		       __FILE__, __LINE__);
		err = -ENOMEM;
		goto OUT_1;
	}

	if (file_size == 0) {
		if (get_current_user()->uid.val == 0) {
			sprintf(key_buf, "%s-%s", buf, ENC_KEY);
		} else {
			sprintf(key_buf, "%s-%s", ENC_KEY, buf);
		}
		filp->f_pos = 0;
		write_length = file_write(filp, key_buf, 33);
		printk(KERN_ALERT
		       " %s:%i, zero size, key_buf: %s, write_length:%d\n",
		       __FILE__, __LINE__, key_buf, write_length);
		if (write_length == 33)
			err = 0;
	} else {
		if (get_current_user()->uid.val == 0) {
			filp->f_pos = 0;
		} else {
			filp->f_pos = 17;
		}
		write_length = file_write(filp, buf, 16);
		printk(KERN_ALERT
		       " %s:%i, NON zero size, buf: %s, write_length:%d\n",
		       __FILE__, __LINE__, buf, write_length);
		if (write_length == 16)
			err = 0;
	}

	kfree(key_buf);
 OUT_1:
	kfree(buf);
 OUT:
	return err;
}

int file_read(struct file *filp_in, char *buf, int len)
{
	int bytes_read;
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	bytes_read = vfs_read(filp_in, buf, len, &(filp_in->f_pos));
	set_fs(old_fs);
	return bytes_read;
}

int file_write(struct file *filp_out, char *buf, int len)
{
	int bytes_written;
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	bytes_written = vfs_write(filp_out, buf, len, &(filp_out->f_pos));
	set_fs(old_fs);
	return bytes_written;
}

/**
* purge_bin(): delete all the files from the trashbin, which belongs to the user
* @bin_path : trashbin path
* return 0 on success;
*/
int purge_bin(char *bin_path)
{
	struct file *filp;
	struct dir_context local_dir_context = { &local_filldir, 0 };
	int err;

	err = 0;
	list_size = 0;
	filp = filp_open(bin_path, O_RDONLY, 0);
	if (!filp || IS_ERR(filp)) {
		err = (int)PTR_ERR(filp);
		printk(KERN_ALERT " %s:%i, error opening %s\n", __FILE__,
		       __LINE__, bin_path);
		goto OUT;
	}
	err = iterate_dir(filp, &local_dir_context);
	filp_close(filp, NULL);
	iterate_and_delete();
	delete_list();
 OUT:
	return err;
}

/**
 * delete files from linked list
 */
void iterate_and_delete(void)
{
	char *path_buf = NULL;
	struct custom_node *temp = NULL;
	path_buf = kmalloc(PAGE_SIZE, __GFP_REPEAT);
	if (!path_buf) {
		printk(KERN_ALERT
		       " %s:%i, Couldn't allocate memory for path_buf, purge operation failed!\n",
		       __FILE__, __LINE__);
		return;
	}
	memset(path_buf, '\0', PAGE_SIZE);
	if (list_head != NULL) {
		printk("%s List head not null\n", __func__);
		temp = list_head->next;
	}
	
	while (temp != NULL) {
		delete_from_bin(temp->data, path_buf);
		temp = temp->next;
	}
	if (path_buf != NULL)
		kfree(path_buf);
}

/**
* delete_from_bin: delete file from trashbin
* @file_name: name of the file
* return 0 on success error otherwise;
*/
int delete_from_bin(const char *file_name, char *path_buf)
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
	if (err == 0) {
		printk(KERN_ALERT " %s:%i, %s deleted successfully!\n",
		       __FILE__, __LINE__, file_name);
	}
	if (filp != NULL)
		filp_close(filp, NULL);
 OUT:
	return err;
}

void get_file_name(const char *infile, bool temp, char *middleName,
		   char *reducedPath)
{
	memset(middleName, '\0', PAGE_SIZE);
	memset(reducedPath, '\0', PAGE_SIZE);
	memcpy(middleName, "/.trashbin/", strlen("/.trashbin/"));
	if (temp == true) {
		strcat(middleName, "temp-");
	}
	strcat(middleName, infile);
	strncpy(reducedPath, middleName, strlen(middleName) - 4);
	reducedPath[strlen(middleName) - 4] = 0;
	printk("%s middleName = %s\n", __func__, middleName);
	printk("%s reducedPath = %s\n", __func__, reducedPath);

}

/**
 * function to insert a new_custom_node in list
 */
void list_insert(struct custom_node *new_custom_node)
{
	list_size++;
	new_custom_node->next = list_head->next;
	list_head->next = new_custom_node;
}

/**
 * method to delete the entire linked list
 */
void delete_list(void)
{
	struct custom_node *temp = list_head->next;
	while (temp != NULL) {
		list_head->next = list_head->next->next;
		if (temp != NULL)
			kfree(temp);
		temp = list_head->next;
	}
	list_size = 0;
}

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
	if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0
	    && is_valid_user(name)
	    && !is_temp_file(name) && has_valid_flag(name)) {
		struct custom_node *temp =
		    (struct custom_node *)kmalloc(sizeof(struct custom_node),
						  GFP_KERNEL);
		temp->data = name;
		temp->next = NULL;
		list_insert(temp);
	}
	return err;
}

/**
* has_valid_flag: check if file has valid i_private itrash_flags
* return 1 if file has valid i.e. itrash_flags = 0
* return 0 otherwise;
*/
int has_valid_flag(const char *file_name)
{
	struct file *filp;
	int err;
	char *path_buf;
	struct flag_path_info *file_metadata;
	err = 0;
	path_buf = (char *)kmalloc(PAGE_SIZE, __GFP_REPEAT);
	memset(path_buf, '\0', PAGE_SIZE);
	sprintf(path_buf, "/.trashbin/%s", file_name);
	printk("%s File Name = %s\n", __func__, path_buf);
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

	if (filp != NULL)
		filp_close(filp, NULL);
 OUT:
 	if(path_buf != NULL)
		kfree(path_buf);
	return err;
}

int is_valid_user_byID(struct dentry *dentry)
{
	unsigned int user_id;
	user_id = dentry->d_inode->i_uid.val;
	if (get_current_user()->uid.val == 0
	    || user_id == get_current_user()->uid.val)
		return 1;
	return 0;
}

/**
* is_temp_file: check if file is in the middle of processing
* return 1 if temporary file; 0 otherwise
*/
int is_temp_file(const char *name)
{
	int n, ret;
	char etc[80];

	ret = sscanf(name, "%d-%s", &n, etc);
	if (ret == 0)
		return 1;

	return 0;
}

/**
* is_valid_user(): check if user is same for given file
* @file_name : name of the file
* return 1 if valid user; 0 otherwise
*/
int is_valid_user(const char *file_name)
{
	int user_id;
	char etc[100];
	sscanf(file_name, "%d-%s", &user_id, etc);
	if (get_current_user()->uid.val == 0
	    || user_id == get_current_user()->uid.val)
		return 1;
	return 0;
}

/**
* perform_undelete: perform undo delte operation
* @filp_in: input file file pointer
* @out_name: file name after undo delete in CWD
* @is_encrypted: 1 if in file is encrypted; 0 otherwise
*/
int perform_undelete(struct file *filp)
{
	char *out_name;
	struct flag_path_info *flag_path_private = NULL;
	char *middleName = NULL;
	char *reducedPath = NULL;
	int errorVal = 0;
	struct file *temp_decFile = NULL;
	struct file *temp_uncFile = NULL;
	bool enc_on = false;
	bool com_on = false;

	printk("%s \n", __func__);
	flag_path_private =
	    (struct flag_path_info *)filp->f_path.dentry->d_inode->i_private;
	if (flag_path_private != NULL) {
		while (flag_path_private->itrash_flags != 0) {
			ssleep(1);
		}
		middleName = kmalloc(PAGE_SIZE, GFP_KERNEL);
		reducedPath = kmalloc(PAGE_SIZE, GFP_KERNEL);
		out_name = flag_path_private->absolute_path;
		flag_path_private->itrash_flags =
		    flag_path_private->trash_flags;
		if ((flag_path_private->itrash_flags & ENCRYPT_ON) > 0) {
			enc_on = true;
			get_file_name(filp->f_path.dentry->d_name.name, true,
				      middleName, reducedPath);
			temp_decFile =
			    decrypto_page_helper(filp, reducedPath, &errorVal);
			while (errorVal != 0) {
				temp_decFile =
				    decrypto_page_helper(filp, reducedPath,
							 &errorVal);
			}
		}
		if ((flag_path_private->itrash_flags & COMP_ON) > 0) {
			com_on = true;
			if (enc_on == true) {
				get_file_name(temp_decFile->f_path.
					      dentry->d_name.name, false,
					      middleName, reducedPath);
				temp_uncFile =
				    decompress_file(temp_decFile->
						    f_path.dentry->d_name.name,
						    reducedPath, &errorVal);
				while (errorVal != 0) {
					temp_uncFile =
					    decompress_file
					    (temp_decFile->f_path.
					     dentry->d_name.name, reducedPath,
					     &errorVal);
				}
			} else {
				get_file_name(filp->f_path.dentry->d_name.name,
					      true, middleName, reducedPath);
				temp_uncFile =
				    decompress_file(filp->f_path.dentry->
						    d_name.name, reducedPath,
						    &errorVal);
				while (errorVal != 0) {
					temp_uncFile =
					    decompress_file(filp->
							    f_path.dentry->
							    d_name.name,
							    reducedPath,
							    &errorVal);
				}
			}

		}
		flag_path_private->itrash_flags = 0;
		if (com_on)
			errorVal =
			    do_rename(temp_uncFile->f_path.dentry, out_name);
		else if (enc_on)
			errorVal =
			    do_rename(temp_decFile->f_path.dentry, out_name);
		else
			errorVal = do_rename(filp->f_path.dentry, out_name);

	}
	if (middleName != NULL)
		kfree(middleName);
	if (reducedPath != NULL)
		kfree(reducedPath);
	return errorVal;
}

/* check if dentry is from secure garbage bin folder */
int is_in_bin(struct dentry *dentry)
{
	if ((strcmp(dentry->d_parent->d_name.name, ".trashbin") == 0)
	    && (strcmp(dentry->d_parent->d_parent->d_name.name, "/") == 0)) {
		return 1;
	}
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

static int ioctl_fibmap(struct file *filp, int __user * p)
{
	struct address_space *mapping = filp->f_mapping;
	int res, block;

	/* do we support this mess? */
	if (!mapping->a_ops->bmap)
		return -EINVAL;
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;
	res = get_user(block, p);
	if (res)
		return res;
	res = mapping->a_ops->bmap(mapping, block);
	return put_user(res, p);
}

/**
 * fiemap_fill_next_extent - Fiemap helper function
 * @fieinfo:    Fiemap context passed into ->fiemap
 * @logical:    Extent logical start offset, in bytes
 * @phys:   Extent physical start offset, in bytes
 * @len:    Extent length, in bytes
 * @flags:  FIEMAP_EXTENT flags that describe this extent
 *
 * Called from file system ->fiemap callback. Will populate extent
 * info as passed in via arguments and copy to user memory. On
 * success, extent count on fieinfo is incremented.
 *
 * Returns 0 on success, -errno on error, 1 if this was the last
 * extent that will fit in user array.
 */
#define SET_UNKNOWN_FLAGS   (FIEMAP_EXTENT_DELALLOC)
#define SET_NO_UNMOUNTED_IO_FLAGS   (FIEMAP_EXTENT_DATA_ENCRYPTED)
#define SET_NOT_ALIGNED_FLAGS   (FIEMAP_EXTENT_DATA_TAIL|FIEMAP_EXTENT_DATA_INLINE)
int fiemap_fill_next_extent(struct fiemap_extent_info *fieinfo, u64 logical,
			    u64 phys, u64 len, u32 flags)
{
	struct fiemap_extent extent;
	struct fiemap_extent __user *dest = fieinfo->fi_extents_start;

	/* only count the extents */
	if (fieinfo->fi_extents_max == 0) {
		fieinfo->fi_extents_mapped++;
		return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
	}

	if (fieinfo->fi_extents_mapped >= fieinfo->fi_extents_max)
		return 1;

	if (flags & SET_UNKNOWN_FLAGS)
		flags |= FIEMAP_EXTENT_UNKNOWN;
	if (flags & SET_NO_UNMOUNTED_IO_FLAGS)
		flags |= FIEMAP_EXTENT_ENCODED;
	if (flags & SET_NOT_ALIGNED_FLAGS)
		flags |= FIEMAP_EXTENT_NOT_ALIGNED;

	memset(&extent, 0, sizeof(extent));
	extent.fe_logical = logical;
	extent.fe_physical = phys;
	extent.fe_length = len;
	extent.fe_flags = flags;

	dest += fieinfo->fi_extents_mapped;
	if (copy_to_user(dest, &extent, sizeof(extent)))
		return -EFAULT;

	fieinfo->fi_extents_mapped++;
	if (fieinfo->fi_extents_mapped == fieinfo->fi_extents_max)
		return 1;
	return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
}

EXPORT_SYMBOL(fiemap_fill_next_extent);

/**
 * fiemap_check_flags - check validity of requested flags for fiemap
 * @fieinfo:    Fiemap context passed into ->fiemap
 * @fs_flags:   Set of fiemap flags that the file system understands
 *
 * Called from file system ->fiemap callback. This will compute the
 * intersection of valid fiemap flags and those that the fs supports. That
 * value is then compared against the user supplied flags. In case of bad user
 * flags, the invalid values will be written into the fieinfo structure, and
 * -EBADR is returned, which tells ioctl_fiemap() to return those values to
 * userspace. For this reason, a return code of -EBADR should be preserved.
 *
 * Returns 0 on success, -EBADR on bad flags.
 */
int fiemap_check_flags(struct fiemap_extent_info *fieinfo, u32 fs_flags)
{
	u32 incompat_flags;

	incompat_flags = fieinfo->fi_flags & ~(FIEMAP_FLAGS_COMPAT & fs_flags);
	if (incompat_flags) {
		fieinfo->fi_flags = incompat_flags;
		return -EBADR;
	}
	return 0;
}

EXPORT_SYMBOL(fiemap_check_flags);

static int fiemap_check_ranges(struct super_block *sb,
			       u64 start, u64 len, u64 * new_len)
{
	u64 maxbytes = (u64) sb->s_maxbytes;

	*new_len = len;

	if (len == 0)
		return -EINVAL;

	if (start > maxbytes)
		return -EFBIG;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (len > maxbytes || (maxbytes - len) < start)
		*new_len = maxbytes - start;

	return 0;
}

static int ioctl_fiemap(struct file *filp, unsigned long arg)
{
	struct fiemap fiemap;
	struct fiemap __user *ufiemap = (struct fiemap __user *)arg;
	struct fiemap_extent_info fieinfo = { 0, };
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	u64 len;
	int error;

	if (!inode->i_op->fiemap)
		return -EOPNOTSUPP;

	if (copy_from_user(&fiemap, ufiemap, sizeof(fiemap)))
		return -EFAULT;

	if (fiemap.fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	error = fiemap_check_ranges(sb, fiemap.fm_start, fiemap.fm_length,
				    &len);
	if (error)
		return error;

	fieinfo.fi_flags = fiemap.fm_flags;
	fieinfo.fi_extents_max = fiemap.fm_extent_count;
	fieinfo.fi_extents_start = ufiemap->fm_extents;

	if (fiemap.fm_extent_count != 0 &&
	    !access_ok(VERIFY_WRITE, fieinfo.fi_extents_start,
		       fieinfo.fi_extents_max * sizeof(struct fiemap_extent)))
		return -EFAULT;

	if (fieinfo.fi_flags & FIEMAP_FLAG_SYNC)
		filemap_write_and_wait(inode->i_mapping);

	error = inode->i_op->fiemap(inode, &fieinfo, fiemap.fm_start, len);
	fiemap.fm_flags = fieinfo.fi_flags;
	fiemap.fm_mapped_extents = fieinfo.fi_extents_mapped;
	if (copy_to_user(ufiemap, &fiemap, sizeof(fiemap)))
		error = -EFAULT;

	return error;
}

static long ioctl_file_clone(struct file *dst_file, unsigned long srcfd,
			     u64 off, u64 olen, u64 destoff)
{
	struct fd src_file = fdget(srcfd);
	int ret;

	if (!src_file.file)
		return -EBADF;
	ret = vfs_clone_file_range(src_file.file, off, dst_file, destoff, olen);
	fdput(src_file);
	return ret;
}

static long ioctl_file_clone_range(struct file *file, void __user * argp)
{
	struct file_clone_range args;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	return ioctl_file_clone(file, args.src_fd, args.src_offset,
				args.src_length, args.dest_offset);
}

#ifdef CONFIG_BLOCK

static inline sector_t logical_to_blk(struct inode *inode, loff_t offset)
{
	return (offset >> inode->i_blkbits);
}

static inline loff_t blk_to_logical(struct inode *inode, sector_t blk)
{
	return (blk << inode->i_blkbits);
}

/**
 * __generic_block_fiemap - FIEMAP for block based inodes (no locking)
 * @inode: the inode to map
 * @fieinfo: the fiemap info struct that will be passed back to userspace
 * @start: where to start mapping in the inode
 * @len: how much space to map
 * @get_block: the fs's get_block function
 *
 * This does FIEMAP for block based inodes.  Basically it will just loop
 * through get_block until we hit the number of extents we want to map, or we
 * go past the end of the file and hit a hole.
 *
 * If it is possible to have data blocks beyond a hole past @inode->i_size, then
 * please do not use this function, it will stop at the first unmapped block
 * beyond i_size.
 *
 * If you use this function directly, you need to do your own locking. Use
 * generic_block_fiemap if you want the locking done for you.
 */

int __generic_block_fiemap(struct inode *inode,
			   struct fiemap_extent_info *fieinfo, loff_t start,
			   loff_t len, get_block_t * get_block)
{
	struct buffer_head map_bh;
	sector_t start_blk, last_blk;
	loff_t isize = i_size_read(inode);
	u64 logical = 0, phys = 0, size = 0;
	u32 flags = FIEMAP_EXTENT_MERGED;
	bool past_eof = false, whole_file = false;
	int ret = 0;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	/*
	 * Either the i_mutex or other appropriate locking needs to be held
	 * since we expect isize to not change at all through the duration of
	 * this call.
	 */
	if (len >= isize) {
		whole_file = true;
		len = isize;
	}

	/*
	 * Some filesystems can't deal with being asked to map less than
	 * blocksize, so make sure our len is at least block length.
	 */
	if (logical_to_blk(inode, len) == 0)
		len = blk_to_logical(inode, 1);

	start_blk = logical_to_blk(inode, start);
	last_blk = logical_to_blk(inode, start + len - 1);

	do {
		/*
		 * we set b_size to the total size we want so it will map as
		 * many contiguous blocks as possible at once
		 */
		memset(&map_bh, 0, sizeof(struct buffer_head));
		map_bh.b_size = len;

		ret = get_block(inode, start_blk, &map_bh, 0);
		if (ret)
			break;

		/* HOLE */
		if (!buffer_mapped(&map_bh)) {
			start_blk++;

			/*
			 * We want to handle the case where there is an
			 * allocated block at the front of the file, and then
			 * nothing but holes up to the end of the file properly,
			 * to make sure that extent at the front gets properly
			 * marked with FIEMAP_EXTENT_LAST
			 */
			if (!past_eof &&
			    blk_to_logical(inode, start_blk) >= isize)
				past_eof = 1;

			/*
			 * First hole after going past the EOF, this is our
			 * last extent
			 */
			if (past_eof && size) {
				flags =
				    FIEMAP_EXTENT_MERGED | FIEMAP_EXTENT_LAST;
				ret =
				    fiemap_fill_next_extent(fieinfo, logical,
							    phys, size, flags);
			} else if (size) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
				size = 0;
			}

			/* if we have holes up to/past EOF then we're done */
			if (start_blk > last_blk || past_eof || ret)
				break;
		} else {
			/*
			 * We have gone over the length of what we wanted to
			 * map, and it wasn't the entire file, so add the extent
			 * we got last time and exit.
			 *
			 * This is for the case where say we want to map all the
			 * way up to the second to the last block in a file, but
			 * the last block is a hole, making the second to last
			 * block FIEMAP_EXTENT_LAST.  In this case we want to
			 * see if there is a hole after the second to last block
			 * so we can mark it properly.  If we found data after
			 * we exceeded the length we were requesting, then we
			 * are good to go, just add the extent to the fieinfo
			 * and break
			 */
			if (start_blk > last_blk && !whole_file) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
				break;
			}

			/*
			 * if size != 0 then we know we already have an extent
			 * to add, so add it.
			 */
			if (size) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
				if (ret)
					break;
			}

			logical = blk_to_logical(inode, start_blk);
			phys = blk_to_logical(inode, map_bh.b_blocknr);
			size = map_bh.b_size;
			flags = FIEMAP_EXTENT_MERGED;

			start_blk += logical_to_blk(inode, size);

			/*
			 * If we are past the EOF, then we need to make sure as
			 * soon as we find a hole that the last extent we found
			 * is marked with FIEMAP_EXTENT_LAST
			 */
			if (!past_eof && logical + size >= isize)
				past_eof = true;
		}
		cond_resched();
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

	}
	while (1);

	/* If ret is 1 then we just hit the end of the extent array */
	if (ret == 1)
		ret = 0;

	return ret;
}

EXPORT_SYMBOL(__generic_block_fiemap);

/**
 * generic_block_fiemap - FIEMAP for block based inodes
 * @inode: The inode to map
 * @fieinfo: The mapping information
 * @start: The initial block to map
 * @len: The length of the extect to attempt to map
 * @get_block: The block mapping function for the fs
 *
 * Calls __generic_block_fiemap to map the inode, after taking
 * the inode's mutex lock.
 */

int generic_block_fiemap(struct inode *inode,
			 struct fiemap_extent_info *fieinfo, u64 start,
			 u64 len, get_block_t * get_block)
{
	int ret;
	inode_lock(inode);
	ret = __generic_block_fiemap(inode, fieinfo, start, len, get_block);
	inode_unlock(inode);
	return ret;
}

EXPORT_SYMBOL(generic_block_fiemap);

#endif				/*  CONFIG_BLOCK  */

/*
 * This provides compatibility with legacy XFS pre-allocation ioctls
 * which predate the fallocate syscall.
 *
 * Only the l_start, l_len and l_whence fields of the 'struct space_resv'
 * are used here, rest are ignored.
 */
int ioctl_preallocate(struct file *filp, void __user * argp)
{
	struct inode *inode = file_inode(filp);
	struct space_resv sr;

	if (copy_from_user(&sr, argp, sizeof(sr)))
		return -EFAULT;

	switch (sr.l_whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		sr.l_start += filp->f_pos;
		break;
	case SEEK_END:
		sr.l_start += i_size_read(inode);
		break;
	default:
		return -EINVAL;
	}

	return vfs_fallocate(filp, FALLOC_FL_KEEP_SIZE, sr.l_start, sr.l_len);
}

static int file_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	int __user *p = (int __user *)arg;

	switch (cmd) {
	case FIBMAP:
		return ioctl_fibmap(filp, p);
	case FIONREAD:
		return put_user(i_size_read(inode) - filp->f_pos, p);
	case FS_IOC_RESVSP:
	case FS_IOC_RESVSP64:
		return ioctl_preallocate(filp, p);
	}

	return vfs_ioctl(filp, cmd, arg);
}

static int ioctl_fionbio(struct file *filp, int __user * argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = O_NONBLOCK;
#ifdef __sparc__
	/* SunOS compatibility item. */
	if (O_NONBLOCK != O_NDELAY)
		flag |= O_NDELAY;
#endif
	spin_lock(&filp->f_lock);
	if (on)
		filp->f_flags |= flag;
	else
		filp->f_flags &= ~flag;
	spin_unlock(&filp->f_lock);
	return error;
}

static int ioctl_fioasync(unsigned int fd, struct file *filp, int __user * argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = on ? FASYNC : 0;

	/* Did FASYNC state change ? */
	if ((flag ^ filp->f_flags) & FASYNC) {
		if (filp->f_op->fasync)
			/* fasync() adjusts filp->f_flags */
			error = filp->f_op->fasync(fd, filp, on);
		else
			error = -ENOTTY;
	}
	return error < 0 ? error : 0;
}

static int ioctl_fsfreeze(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* If filesystem doesn't support freeze feature, return. */
	if (sb->s_op->freeze_fs == NULL && sb->s_op->freeze_super == NULL)
		return -EOPNOTSUPP;

	/* Freeze */
	if (sb->s_op->freeze_super)
		return sb->s_op->freeze_super(sb);
	return freeze_super(sb);
}

static int ioctl_fsthaw(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* Thaw */
	if (sb->s_op->thaw_super)
		return sb->s_op->thaw_super(sb);
	return thaw_super(sb);
}

static long ioctl_file_dedupe_range(struct file *file, void __user * arg)
{
	struct file_dedupe_range __user *argp = arg;
	struct file_dedupe_range *same = NULL;
	int ret;
	unsigned long size;
	u16 count;

	if (get_user(count, &argp->dest_count)) {
		ret = -EFAULT;
		goto out;
	}

	size = offsetof(struct file_dedupe_range __user, info[count]);

	same = memdup_user(argp, size);
	if (IS_ERR(same)) {
		ret = PTR_ERR(same);
		same = NULL;
		goto out;
	}

	ret = vfs_dedupe_file_range(file, same);
	if (ret)
		goto out;

	ret = copy_to_user(argp, same, size);
	if (ret)
		ret = -EFAULT;

 out:
	kfree(same);
	return ret;
}

/*
 * When you add any new common ioctls to the switches above and below
 * please update compat_sys_ioctl() too.
 *
 * do_vfs_ioctl() is not for drivers and not intended to be EXPORT_SYMBOL()'d.
 * It's just a simple helper for sys_ioctl and compat_sys_ioctl.
 */
int do_vfs_ioctl(struct file *filp, unsigned int fd, unsigned int cmd,
		 unsigned long arg)
{
	int error = 0;
	int __user *argp = (int __user *)arg;
	struct inode *inode = file_inode(filp);

	switch (cmd) {
	case FIOCLEX:
		set_close_on_exec(fd, 1);
		break;

	case FIONCLEX:
		set_close_on_exec(fd, 0);
		break;

	case FIONBIO:
		error = ioctl_fionbio(filp, argp);
		break;

	case FIOASYNC:
		error = ioctl_fioasync(fd, filp, argp);
		break;

	case FIOQSIZE:
		if (S_ISDIR(inode->i_mode) || S_ISREG(inode->i_mode) ||
		    S_ISLNK(inode->i_mode)) {
			loff_t res = inode_get_bytes(inode);
			error = copy_to_user(argp, &res, sizeof(res)) ?
			    -EFAULT : 0;
		} else
			error = -ENOTTY;
		break;

	case FIFREEZE:
		error = ioctl_fsfreeze(filp);
		break;

	case FITHAW:
		error = ioctl_fsthaw(filp);
		break;

	case FS_IOC_FIEMAP:
		return ioctl_fiemap(filp, arg);

	case FIGETBSZ:
		return put_user(inode->i_sb->s_blocksize, argp);

	case FICLONE:
		return ioctl_file_clone(filp, arg, 0, 0, 0);

	case FICLONERANGE:
		return ioctl_file_clone_range(filp, argp);

	case FIDEDUPERANGE:
		return ioctl_file_dedupe_range(filp, argp);

	default:
		if (S_ISREG(inode->i_mode))
			error = file_ioctl(filp, cmd, arg);
		else
			error = vfs_ioctl(filp, cmd, arg);
		break;
	}
	return error;
}

SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	int error;
	struct fd f = fdget(fd);

	if (!f.file)
		return -EBADF;
	error = security_file_ioctl(f.file, cmd, arg);
	if (!error)
		error = do_vfs_ioctl(f.file, fd, cmd, arg);
	fdput(f);
	return error;
}
