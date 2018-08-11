/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
/* HW-2 */
#include "sgfs.h"
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

static int sgfs_renamemove_tosg(struct dentry *dentry);
static int do_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry);
static int do_unlink(struct file*);
int my_readfs_file(struct file *, char *, size_t, loff_t *);
int my_writefs_file(struct file *, char *, size_t, loff_t *);
int encr_decrypto_page(struct file*, char *, char*, int, int, loff_t*, int);
int encrypto_page_helper(char*);
struct file* decrypto_page_helper(struct file*, int *);

static int sgfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);
	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = sgfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  sgfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;
	int remove = 0;

	if (is_inside_sg_directory(dentry) == 0) {
			printk("%s %s\n", __func__, "Move file to .sg folder");
			err = sgfs_renamemove_tosg(dentry);
			return err;
	} else {
		remove = matchOwner(dentry->d_name.name);
		if (remove) {
			err = -ENOENT;
			return err;
		}
	}

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
		  sgfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/**
 * sgfs_renamemove_tosg : This function creates a new file in .sg and move
 * file to .sg with encryption if key is given else just rename to .sg   
 * @dentry: dentry of file that we want to move .sg
 * call other functions to rename and encryption
 * Returns 0 on success; non-zero error otherwise
 */
static int sgfs_renamemove_tosg(struct dentry *dentry) 
{
	mm_segment_t oldfs;
    char *secondFileName = NULL;
    struct dentry* sgDentry = NULL;
    struct dentry* old_file_dentry = NULL;
    struct dentry* new_file_dentry = NULL;
    int errorVal = 0;
    struct path lower_path;
	struct timespec time;
	unsigned long local_time;
	struct rtc_time tm;

	oldfs = get_fs();
    set_fs(get_ds());

    old_file_dentry = dentry;
	secondFileName = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
	if (secondFileName == NULL) {
        errorVal = -ENOMEM;
        printk("%s %s\n", __func__, "Buffer not alloacted for name");
        goto clear_out;
    }

    memset(secondFileName, '\0', MY_PAGE_SIZE);
    memcpy(secondFileName, mount_struct.sgbinPath, 
    			strlen(mount_struct.sgbinPath));
    strcat(secondFileName, "/");

	getnstimeofday(&time);
	local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);

	snprintf(secondFileName + strlen(secondFileName), MY_PAGE_SIZE, 
		"%d-%d-%02d-%02d-%02d:%02d-%s", dentry->d_inode->i_uid.val, 
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, 
				tm.tm_min, dentry->d_name.name);

	printk("%s\n", secondFileName);

	sgDentry = mount_struct.sgbinDentry;

	printk("%s %s\n", __func__, sgDentry->d_name.name);

	new_file_dentry = user_path_create(AT_FDCWD, secondFileName, 
				&lower_path, 0);
    if (IS_ERR(new_file_dentry)) {
        errorVal = PTR_ERR(new_file_dentry);
        printk("%s %s %d\n", __func__, "Unable to get both the Dentries", 
        		errorVal);
        goto clear_out;
    }

    printk("%s Dentry Debugging %d\n", __func__, new_file_dentry->d_lockref.count);

    done_path_create(&lower_path, new_file_dentry);

    printk("%s %s\n", __func__, new_file_dentry->d_parent->d_name.name);

    printk("%s %s\n", __func__, "Call do_rename for reanme");

	errorVal = do_rename(old_file_dentry->d_parent->d_inode, old_file_dentry, 
			new_file_dentry->d_parent->d_inode, new_file_dentry);

	printk("%s %s %d\n", __func__, "Renamed errorVal = ", errorVal);

	dput(old_file_dentry);

	if (mount_struct.iskeyGiven == 1) {
		errorVal = encrypto_page_helper(secondFileName);
	}

clear_out:
	set_fs(oldfs);

	if (secondFileName != NULL)
	{
		kfree(secondFileName);
	}
	return errorVal;
}

/**
 * do_rename : This function rename upper fs old file to lower fs new file 
 * @old_dir: inode of file parent that we want to move .sg (Upper)
 * @old_dentry: dentry of file that we want to move .sg (Upper)
 * @new_dir: inode of file parent in which we want to move file (Lower)
 * @new_dentry: dentry of file created in .sg (Lower)
 * Returns 0 on success; non-zero error otherwise
 */
static int do_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path;

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = new_dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = new_dentry->d_parent;

	printk("%s %s\n", __func__, lower_old_dentry->d_name.name);
	printk("%s %s\n", __func__, lower_new_dentry->d_name.name);
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);

	return err;
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
int encrypto_page_helper(char* file_name)
{
	mm_segment_t oldfs;
	loff_t offsetFirst = 0;
    loff_t write_offset = 0;
    struct file *filpFirst = NULL;
    struct file *filpSecond = NULL;
    int errorVal = 0;
    struct dentry* sgDentry;
    char *bufFile1 = NULL;
    char* filePath = NULL;
    long int fileSize = 0;
    int bytes_read_first;
    int padSize = 0;
    char padSizeChar[1];
    char topad_bytes[KEY_SIZE_AES];

	oldfs = get_fs();
    set_fs(get_ds());

    sgDentry = mount_struct.sgbinDentry;

    filePath = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
    memset(filePath, '\0', MY_PAGE_SIZE);
    printk("%s %s\n", __func__, mount_struct.sgbinPath);
  
    memcpy(filePath, file_name, strlen(file_name));

    printk("%s %s\n", __func__, filePath);

    filpFirst = filp_open(filePath, O_RDONLY, 0644);
    if (!filpFirst || IS_ERR(filpFirst)) {
        printk("%s %s\n", __func__, "Error in file opening");
        errorVal = (int) PTR_ERR(filpFirst);
        goto first_exit;
    }

    fileSize = filpFirst->f_inode->i_size;
    printk("%s fileSize = %d\n", __func__, (int)fileSize);

    bufFile1 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

    strcat(filePath, ".enc");
    filpSecond = filp_open(filePath, O_RDWR | O_CREAT, 0644);
    if (!filpSecond || IS_ERR(filpSecond)) {
        printk("%s %s\n", __func__, "Error in file opening");
        errorVal = (int) PTR_ERR(filpSecond);
        goto clear_and_exit;
    }

    duplicate_attr(filpFirst, filpSecond);

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

    errorVal = my_writefs_file(filpSecond, mount_struct.ENC_KEY, 
    			KEY_SIZE_AES, &write_offset);
    if (errorVal == 0) {
    	errorVal = -ENOENT;
    	goto clear_and_exit;
    }
    
    while (1) {
		bytes_read_first = my_readfs_file(filpFirst, bufFile1 , 
				MY_PAGE_SIZE, &offsetFirst);

		if (bytes_read_first < MY_PAGE_SIZE) {
			if (padSize > 0 && bytes_read_first >= 0) {
				memcpy(bufFile1 + bytes_read_first, topad_bytes, padSize);
				bufFile1[bytes_read_first + padSize] = '\0';

				errorVal = encr_decrypto_page(filpSecond, bufFile1, 
    				mount_struct.ENC_KEY, bytes_read_first + padSize, 1, 
    					&write_offset, bytes_read_first + padSize);
				if (errorVal != 0) {
					goto clear_and_exit;
				}
				break;
			}
			break;
		} else {
			errorVal = encr_decrypto_page(filpSecond, bufFile1, 
				mount_struct.ENC_KEY, bytes_read_first, 1, &write_offset, 
					bytes_read_first);
			if (errorVal != 0) {
				goto clear_and_exit;
			}
		}
    }

    printk("%s fileSize2 = %d\n", __func__, (int)filpSecond->f_inode->i_size);

clear_and_exit:
	if (bufFile1 != NULL) {
		kfree(bufFile1);
	}
	if (errorVal) {
		if (filpSecond != NULL) {
			do_unlink(filpSecond);
		}
	} else {
		if (filpFirst != NULL) {
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
struct file* decrypto_page_helper(struct file* filpFirst, int* errorVal)
{
	mm_segment_t oldfs;
	loff_t offsetFirst = 0;
    loff_t write_offset = 0;
    struct file* filpSecond = NULL;
    const char* firstFileName = filpFirst->f_path.dentry->d_name.name;
    char *bufFile1 = NULL;
    char* filePath = NULL;
    char* decfilePath = NULL;
    long int fileSize = 0;
    int bytes_read_first;
    int count = 0;
    int padSize = 0;

	oldfs = get_fs();
    set_fs(get_ds());

    filePath = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
    decfilePath = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
  
    memcpy(filePath, mount_struct.sgbinPath, MY_PAGE_SIZE);
    strcat(filePath, "/");
    strcat(filePath, firstFileName);
    strncpy(decfilePath, filePath, strlen(filePath) - 4);
    decfilePath[strlen(filePath) - 4] = 0; 

    printk("%s %s %d\n", __func__, decfilePath, (int)strlen(decfilePath));

    fileSize = filpFirst->f_inode->i_size - KEY_SIZE_AES - 1;
    count = fileSize;

    bufFile1 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

    filpSecond = filp_open(decfilePath, O_RDWR | O_CREAT, 0644);
    if (!filpSecond || IS_ERR(filpSecond)) {
        printk("%s %s\n", __func__, "Error in file opening");
        *errorVal = (int) PTR_ERR(filpSecond);
        goto clear_and_exit;
    }

    duplicate_attr(filpFirst, filpSecond);

    filpFirst->f_pos = 0;
    filpSecond->f_pos = 0;
    padSize = my_readfs_file(filpFirst, bufFile1 , 1, &offsetFirst);
    padSize = (int) bufFile1[0];

    printk("%s Padsize = %d\n", __func__, (int)padSize);

    my_readfs_file(filpFirst, bufFile1 , KEY_SIZE_AES, &offsetFirst);
    if (strcmp(bufFile1, mount_struct.ENC_KEY) != 0) {
    	printk("%s %s\n", __func__, "Mount Key did not match");
    	*errorVal = -EPERM;
    	goto clear_and_exit;
    }

    while (count > MY_PAGE_SIZE) {
		bytes_read_first = my_readfs_file(filpFirst, bufFile1 , 
						MY_PAGE_SIZE, &offsetFirst);
		count -= bytes_read_first;
		*errorVal = encr_decrypto_page(filpSecond, bufFile1, mount_struct.ENC_KEY, 
				bytes_read_first, 0, &write_offset, bytes_read_first);
		if (*errorVal != 0) {
			goto clear_and_exit;
		}
    }

	bytes_read_first = my_readfs_file(filpFirst, bufFile1 , MY_PAGE_SIZE, 
						&offsetFirst);

	*errorVal = encr_decrypto_page(filpSecond, bufFile1, mount_struct.ENC_KEY, 
			bytes_read_first, 0, &write_offset, bytes_read_first - padSize);
	if (*errorVal != 0) {
		goto clear_and_exit;
	}
    
clear_and_exit:
	set_fs(oldfs);
	if (bufFile1 != NULL) {
		kfree(bufFile1);
	}
	if (filePath != NULL) {
		kfree(filePath);
	}
	if (decfilePath != NULL) {
		kfree(decfilePath);
	}
	if (*errorVal) {
		if (filpSecond != NULL) {
			do_unlink(filpSecond);
		}
	} else {
		if (filpFirst != NULL) {
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
int encr_decrypto_page(struct file* filpFirst, char * bufFile1, 
	char* enc_key, int bufSize, int is_enc, loff_t* writeOffset, int max)
{
	int errorVal = 0;
	int bytes = 0;
	struct scatterlist sg;
	struct crypto_blkcipher *block_cipher = NULL;
	struct blkcipher_desc block_desc;

	char ini_vector[KEY_SIZE_AES] = 
		"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";

	block_cipher = crypto_alloc_blkcipher("cbc(aes)",  0, 0);

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

    /* now write size bytes from offset*/
    oldfs = get_fs();
    set_fs(get_ds());

    bytes = vfs_write(filp, buf, size, offset);

    set_fs(oldfs);

    return bytes;

}

/**
 * do_unlink : This function unlink a lower level file
 * @filpFirst: file pointer of file to unlink(lower file)
 * Returns 0 on success, error otherwise(Non - zero)
 */
static int do_unlink(struct file* filpFirst)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode;
	struct dentry *lower_dir_dentry;

	lower_dentry = filpFirst->f_path.dentry;;
	dget(lower_dentry);
	lower_dir_inode = lower_dentry->d_parent->d_inode;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	printk("%s File deleted = %s\n", __func__, 
			filpFirst->f_path.dentry->d_name.name);
	return err;
}

static int sgfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	printk("%s %s\n", __func__, dentry->d_name.name);

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	lower_parent_dentry = lock_parent(lower_dentry);

	printk("%s %s\n", "parent name", lower_parent_dentry->d_name.name);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sgfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	if (is_sg_directory(dentry)) {
		return -EPERM;
	}

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in sgfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	printk("%s %s\n", __func__, lower_old_dentry->d_name.name);
	printk("%s %s\n", __func__, lower_new_dentry->d_name.name);
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	printk("%s\n", __func__);
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sgfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}
	printk("%s\n", __func__);
	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sgfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int sgfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	// printk("%s %d\n", __func__, inode->i_ino);
	lower_inode = sgfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int sgfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);
	printk("%s\n", __func__);

	if (is_sg_directory(dentry) && (matchOwner(dentry->d_name.name) != 0)) {
		return -EPERM;
	}

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sgfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sgfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;
	int remove = 0;

	if (is_inside_sg_directory(dentry)) {
		remove = matchOwner(dentry->d_name.name);
		if (remove) {
			err = -ENOENT;
			return err;
		}
	}

	sgfs_get_lower_path(dentry, &lower_path);
	printk("%s\n", __func__);

	err = vfs_getattr(&lower_path, &lower_stat);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	printk("%s\n", __func__);
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	printk("%s\n", __func__);
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	printk("%s\n", __func__);
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	printk("%s\n", __func__);
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}
const struct inode_operations sgfs_symlink_iops = {
	.readlink	= sgfs_readlink,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.get_link	= sgfs_get_link,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_dir_iops = {
	.create		= sgfs_create,
	.lookup		= sgfs_lookup,
	.link		= sgfs_link,
	.unlink		= sgfs_unlink,
	.symlink	= sgfs_symlink,
	.mkdir		= sgfs_mkdir,
	.rmdir		= sgfs_rmdir,
	.mknod		= sgfs_mknod,
	.rename		= sgfs_rename,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_main_iops = {
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};
