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
#ifndef _SGFS_H_
#define _SGFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/string.h>
#include <linux/exportfs.h>

/* the file system name */
#define SGFS_NAME "sgfs"

/* sgfs root inode number */
#define SGFS_ROOT_INO     1

#define MY_PAGE_SIZE	4096

#define FS_TYPE	"sgfs"

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#define KEY_SIZE_AES 16

/* operations vectors defined in specific files */
extern const struct file_operations sgfs_main_fops;
extern const struct file_operations sgfs_dir_fops;
extern const struct inode_operations sgfs_main_iops;
extern const struct inode_operations sgfs_dir_iops;
extern const struct inode_operations sgfs_symlink_iops;
extern const struct super_operations sgfs_sops;
extern const struct dentry_operations sgfs_dops;
extern const struct address_space_operations sgfs_aops, sgfs_dummy_aops;
extern const struct vm_operations_struct sgfs_vm_ops;
extern const struct export_operations sgfs_export_ops;

extern int sgfs_init_inode_cache(void);
extern void sgfs_destroy_inode_cache(void);
extern int sgfs_init_dentry_cache(void);
extern void sgfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *sgfs_lookup(struct inode *dir, struct dentry *dentry,
				    unsigned int flags);
extern struct inode *sgfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int sgfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);

extern int my_readfs_file(struct file *, char *, size_t, loff_t *);
extern int my_writefs_file(struct file *, char *, size_t, loff_t *);
extern int encr_decrypto_page(struct file*, char *, char*, int, int, loff_t*, int);
extern int encrypto_page_helper(char*);
extern struct file* decrypto_page_helper(struct file*, int *);

struct mount_struct {
	char* mountPath;
	char* sgbinPath;
	struct dentry* sgbinDentry;
	int isbinNew;
	char* ENC_KEY;
	int iskeyGiven;
};

struct file_enc_info {
	char* ENC_KEY;
	char padSize[1];
};

extern struct mount_struct mount_struct; 
/* file private data */
struct sgfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* sgfs inode data in memory */
struct sgfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* sgfs dentry data in memory */
struct sgfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};

/* sgfs super-block data in memory */
struct sgfs_sb_info {
	struct super_block *lower_sb;
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * sgfs_inode_info structure, SGFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct sgfs_inode_info *SGFS_I(const struct inode *inode)
{
	return container_of(inode, struct sgfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define SGFS_D(dent) ((struct sgfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define SGFS_SB(super) ((struct sgfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define SGFS_F(file) ((struct sgfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *sgfs_lower_file(const struct file *f)
{
	return SGFS_F(f)->lower_file;
}

static inline void sgfs_set_lower_file(struct file *f, struct file *val)
{
	SGFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *sgfs_lower_inode(const struct inode *i)
{
	return SGFS_I(i)->lower_inode;
}

static inline void sgfs_set_lower_inode(struct inode *i, struct inode *val)
{
	SGFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *sgfs_lower_super(
	const struct super_block *sb)
{
	return SGFS_SB(sb)->lower_sb;
}

static inline void sgfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	SGFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void sgfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(lower_path, &SGFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void sgfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(&SGFS_D(dent)->lower_path, lower_path);
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&SGFS_D(dent)->lock);
	SGFS_D(dent)->lower_path.dentry = NULL;
	SGFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(&lower_path, &SGFS_D(dent)->lower_path);
	SGFS_D(dent)->lower_path.dentry = NULL;
	SGFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SGFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}

/**
 * is_sg_directory : This function checks if dentry if of main .sg folder
 * @dentry: dentry to check if it is of .sg folder
 * Returns 1 if is .sg , 0 otherwise
 */
static inline int is_sg_directory(struct dentry* dentry) {

    if (strcmp(dentry->d_name.name,".sg") != 0) {
    	return 0;
    }

    if (strcmp(dentry->d_parent->d_name.name,"/") != 0) {
    	return 0;
    }
    return 1;
}

/**
 * is_inside_sg_directory : This function checks if dentry if of a file 
 * inside main .sg folder
 * @dentry: dentry to check if it is of a file inside .sg folder
 * Returns 1 if is in .sg , 0 otherwise
 */
static inline int is_inside_sg_directory(struct dentry* dentry) {

    if (strcmp(dentry->d_parent->d_name.name,".sg") != 0) {
    	return 0;
    }

    if (strcmp(dentry->d_parent->d_parent->d_name.name,"/") != 0) {
    	return 0;
    }
    return 1;
}

/**
 * getNewFileName : This function extract file name to keep from file name
 * from .sg folder...Removes time/date etc from file
 * @file_name: filename to shorten
 * Returns new file name
 */
static inline char* getNewFileName(const char* file_name) {

    int beginName = 18;
    char *findstart = strstr(file_name,"-");

    printk("%s %s\n", __func__, file_name);
    if (findstart != NULL && strlen(findstart) > beginName) {
        findstart += beginName;
    	printk("%s findstart = %s\n", __func__, findstart);
    } else {
    	findstart = NULL;
    }

    return findstart;
}

/**
 * matchOwner : This function mathces current process 
 * owner with file owner
 * @file_name: filename of file of which we want to match current process 
 * owner with file owner
 * Returns 1 if no match , 0 otherwise
 */
static inline int matchOwner(const char* file_name) {
    int count = 0;
    const struct cred *credentials = current_cred();
    char* currentUid = NULL;
    int remove = 0;
    char *findstart = NULL;

    if (credentials->uid.val == 0) {
    	return 0;
    }

    findstart = strstr(file_name,"-");
    printk("%s Filename = %s Current UID = %d\n", __func__, file_name, 
    			credentials->uid.val);

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
    printk("%s Current remove = %d\n", __func__, remove);
    return remove;
}

static inline void duplicate_attr(struct file *filpFrom, struct file *filpTo){

	filpTo->f_path.dentry->d_inode->i_uid = filpFrom->f_path.dentry->d_inode->i_uid;
	filpTo->f_path.dentry->d_inode->i_mode = filpFrom->f_path.dentry->d_inode->i_mode;
	filpTo->f_path.dentry->d_inode->i_gid = filpFrom->f_path.dentry->d_inode->i_gid;
	filpTo->f_path.dentry->d_inode->i_flags = filpFrom->f_path.dentry->d_inode->i_flags;
	filpTo->f_path.dentry->d_inode->i_opflags = filpFrom->f_path.dentry->d_inode->i_opflags;
}


#endif	/* not _SGFS_H_ */
