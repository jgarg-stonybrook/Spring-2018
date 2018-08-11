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
#include <linux/module.h>

static int create_sg_bin(const char *);
static int isSg_present(const char* );
static int getKeyForEncryption(char* );
struct mount_struct mount_struct;

/*
 * There is no need to lock the sgfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sgfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "sgfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"sgfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct sgfs_sb_info), GFP_KERNEL);
	if (!SGFS_SB(sb)) {
		printk(KERN_CRIT "sgfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sgfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &sgfs_sops;

	sb->s_export_op = &sgfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = sgfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &sgfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	sgfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "sgfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(SGFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

/**
 * sgfs_mount : This function mounts the fs
 * Do not allow mount if .sg is present already as file
 */
struct dentry *sgfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	struct dentry* mountDentry = NULL;
	int errorVal = 0;
	void *lower_path_name = (void *) dev_name;
	char* options = (char*)raw_data;

	printk("%s %s\n", __func__, options);
	printk("%s %s\n", __func__, dev_name);

	errorVal = getKeyForEncryption(options);
	if (errorVal != 0) {
		printk("%s %s %d\n", __func__, "ENC KEY size not 16", errorVal);
		return ERR_PTR(errorVal);
	}

	errorVal = isSg_present(dev_name);

	if (errorVal == -ENOTDIR) {

		printk("%s %s %d\n", __func__, ".sg present as a file", errorVal);
		return ERR_PTR(errorVal);
	}

	mountDentry = mount_nodev(fs_type, flags, lower_path_name,
			   sgfs_read_super);

	printk("%s %s\n", __func__, mountDentry->d_name.name);

    if (errorVal != 1) {
 		create_sg_bin(dev_name);   	
    }

	return mountDentry;
}

/**
 * isSg_present : This function checks whether .sg is already present as 
 * file/folder
 * @dev_name: mount path on which we mount
 * If .sg is present as file, then it returns ENOTDIR
 * If .sg is present as folder, then it copies its dentry globally.
 */
static int isSg_present(const char *dev_name)
{
	mm_segment_t oldfs;
	struct path bin_path;
	char *bin_name = NULL;
	char *sg = "/.sg";
	int errorVal = 0;

	oldfs = get_fs();
    set_fs(get_ds());

	bin_name = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
	mount_struct.mountPath = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
	mount_struct.sgbinPath = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

	if (bin_name == NULL || mount_struct.mountPath  == NULL || 
			mount_struct.sgbinPath == NULL) {
        errorVal = -ENOMEM;
        printk("%s\n", "Buffer not alloacted for name");
        goto clear_out;
    }

    memcpy(bin_name, dev_name, MY_PAGE_SIZE);
    memcpy(mount_struct.mountPath, bin_name, MY_PAGE_SIZE);

    printk("%s %s\n", __func__, mount_struct.mountPath);

    strcat(bin_name, sg);
    memcpy(mount_struct.sgbinPath, bin_name, MY_PAGE_SIZE);

    printk("%s %s\n", __func__, mount_struct.sgbinPath);
    errorVal = kern_path(bin_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&bin_path);
    if (errorVal != -ENOENT) {
    	if (S_ISDIR(bin_path.dentry->d_inode->i_mode)) {
    		printk("%s\n", ".sg is already present as directory.");
    		if (bin_path.dentry->d_inode->i_uid.val != 0) {
    			errorVal = -EPERM;
    			goto clear_out;
    		}
			mount_struct.sgbinDentry = bin_path.dentry;
	    	mount_struct.isbinNew = 0;
	    	errorVal = 1;
		} else {
			printk("%s\n", ".sg is already present as file,so exiting.");
			errorVal = -ENOTDIR;
			if (mount_struct.mountPath != NULL) {
				kfree(mount_struct.mountPath);
			}
			if (mount_struct.sgbinPath != NULL) {
				kfree(mount_struct.sgbinPath);
			}
			if (mount_struct.ENC_KEY != NULL) {
				kfree(mount_struct.ENC_KEY);
			}
		}
	} else {
		errorVal = 0;
	}

clear_out:
	set_fs(oldfs);
	if (bin_name != NULL) {
		kfree(bin_name);
	}
	return errorVal;

}

/**
 * create_sg_bin : This function creates .sg folder at mount point
 * @dev_name: mount path on which we mount
 * Returns 0 on success, error otherwise(Non - Zero)
 */
static int create_sg_bin(const char *dev_name)
{
	mm_segment_t oldfs;
	struct dentry* bin_dentry = NULL;
	struct path lower_path;
	int errorVal = 0;

	oldfs = get_fs();
    set_fs(get_ds());

	printk("Create new .sg folder\n");
	bin_dentry = user_path_create(AT_FDCWD, mount_struct.sgbinPath, 
			&lower_path, 0);
    if (IS_ERR(bin_dentry)) {
    	errorVal = PTR_ERR(bin_dentry);
    	mount_struct.isbinNew = 0;
    	printk("%s %d\n", "Dentry error for name", errorVal);
    	goto clear_out;
    }

    mount_struct.sgbinDentry = bin_dentry;
    mount_struct.isbinNew = 1;
    dget(bin_dentry);

    errorVal = vfs_mkdir(d_inode(lower_path.dentry), bin_dentry, 0777);

    printk("%s %d\n", "errorVal in making sg is", errorVal);

    done_path_create(&lower_path, bin_dentry);

	printk("%s %s\n", "dentry name", mount_struct.sgbinDentry->d_name.name);
	printk("%s %s\n", "parent dentry name", 
		mount_struct.sgbinDentry->d_parent->d_name.name);

clear_out:
	set_fs(oldfs);
	if (errorVal) {
		if (mount_struct.mountPath != NULL) {
			kfree(mount_struct.mountPath);
		}
		if (mount_struct.sgbinPath != NULL) {
			kfree(mount_struct.sgbinPath);
		}
		if (mount_struct.ENC_KEY != NULL) {
			kfree(mount_struct.ENC_KEY);
		}
	}
	return errorVal;
}

/**
 * getKeyForEncryption : This function extract key for enc/dec and saves
 * globally.
 * @key_name: options passed by user
 * Returns 0 on success, error otherwise(Non - Zero)
 */
static int getKeyForEncryption(char* key_name) {

	char *findstart = NULL;
	if (key_name == NULL) {
		mount_struct.iskeyGiven = 0;
		goto out;
	}
    findstart = strstr(key_name,"key=");
    

    if (findstart != NULL) {
    	mount_struct.ENC_KEY = (char *)kmalloc(KEY_SIZE_AES + 1, __GFP_REPEAT);
    	memset(mount_struct.ENC_KEY, '\0', KEY_SIZE_AES + 1);

    	printk("%s ENC_KEY = %s\n", __func__, findstart);
    	findstart += 4;
    	printk("%s %s\n", __func__, findstart);
    	if (strlen(findstart) != 16) {
    		return -EPERM;

    	} else {
    		mount_struct.iskeyGiven = 1;
    		memcpy(mount_struct.ENC_KEY, findstart, strlen(findstart));

    	}
    	
    	printk("%s ENC_KEY = %s Length = %d\n", __func__, mount_struct.ENC_KEY, 
    			(int) strlen(mount_struct.ENC_KEY));
    }
out:
    return 0;
}

static struct file_system_type sgfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SGFS_NAME,
	.mount		= sgfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(SGFS_NAME);

static int __init init_sgfs_fs(void)
{
	int err;

	pr_info("Registering sgfs " SGFS_VERSION "\n");

	err = sgfs_init_inode_cache();
	if (err)
		goto out;
	err = sgfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&sgfs_fs_type);
out:
	if (err) {
		sgfs_destroy_inode_cache();
		sgfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_sgfs_fs(void)
{
	sgfs_destroy_inode_cache();
	sgfs_destroy_dentry_cache();
	unregister_filesystem(&sgfs_fs_type);
	pr_info("Completed sgfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Sgfs " SGFS_VERSION
		   " (http://sgfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_sgfs_fs);
module_exit(exit_sgfs_fs);
