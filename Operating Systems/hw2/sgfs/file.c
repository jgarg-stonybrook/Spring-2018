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
#include <linux/string.h>
#include <linux/fs_struct.h>
#include <linux/ioctl.h>
#include <linux/magic.h>

static int sgfs_rename_fromsg(struct dentry *, char*);
static int do_rename(struct dentry *, struct dentry *);
static int new_filldir(struct dir_context *, const char *, int ,
		   loff_t , u64 , unsigned int );
struct dir_context* old_ctx;
filldir_t old_fsctxActor;

static ssize_t sgfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	lower_file = sgfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t sgfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

static int sgfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct dir_context* tempctxptr;
	struct dir_context tempctx = {&new_filldir, ctx->pos};

	printk("%s %s %s\n", __func__, "Directory name is ", dentry->d_name.name);
	printk("%s %s %s\n", __func__, "Parent Directory name is ", 
			dentry->d_parent->d_name.name);

	lower_file = sgfs_lower_file(file);

	old_fsctxActor = ctx->actor;
	old_ctx = ctx;

	if (is_sg_directory(dentry)) {
		tempctxptr = &tempctx;
		err = iterate_dir(lower_file, tempctxptr);
	} else {
		err = iterate_dir(lower_file, ctx);
	}

	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

/**
 * new_filldir : This function gets called every time when we list files 
 * in .sg folder
 * Returns 0 for files that we do not want to list otherwise calls
 * old actor to get return value. We dont interfere in that.
 */
static int new_filldir(struct dir_context *ctx, const char *name, 
	int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
    int errorVal = 0;
    int remove = 0;

	remove = matchOwner(name);
	printk("%s %s %d\n", __func__, "Value of remove: ", remove);
   	if (remove) {
   		return 0;
   	}

    errorVal = (*old_fsctxActor)(old_ctx, name, namlen, offset, ino, d_type);

    return errorVal;
}

static long sgfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	int remove = 0;
	char *new_file_name = NULL;
	struct file* filpSecond = file;
	struct dentry* undeldentry = NULL;
	int errorVal = 0;

	lower_file = sgfs_lower_file(file);
	filpSecond = lower_file;

	printk("%s IOCTL Code = %u\n", __func__, cmd % 256);

	switch(cmd % 256) {
		case 0 : 
			if (file) {
				undeldentry = file->f_path.dentry;
				if (is_inside_sg_directory(undeldentry) == 1) {
					remove = matchOwner(undeldentry->d_name.name);
					if (remove) {
						return -EPERM;
					} else {
						if (strstr(undeldentry->d_name.name, ".enc") != NULL) {
							if (mount_struct.iskeyGiven == 0) {
								printk("%s %s\n", __func__, 
									"No decryption, No Key");
								return -EPERM;
							}

							filpSecond = decrypto_page_helper(file, &errorVal);
							if (errorVal != 0) {
								return errorVal;
							}
							printk("%s %s\n", __func__, "decrypt ok");
						}

						if (filpSecond != NULL) {
							undeldentry = filpSecond->f_path.dentry;

							new_file_name = 
								getNewFileName(undeldentry->d_name.name);
							printk("%s %s\n", __func__, new_file_name);
							if (new_file_name == NULL) {
								printk("%s %s\n", __func__, 
									"File not deleted through .sg");
								return -EPERM;
							}
							errorVal = sgfs_rename_fromsg(undeldentry, 
									new_file_name);
						}
						if (filpSecond != NULL) {
							filp_close(filpSecond, NULL);
						}
						
						return errorVal;
					}
				} else {
					return -EPERM;
				}
			}
			break;
	}



	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
out:
	return err;
}

/**
 * sgfs_rename_fromsg : This function creates a new file in cwd and move
 * file from .sg to cwd.
 * @dentry: dentry of file that we want to move from .sg
 * @secondFileName: filename of new file that we want to make in cwd
 * If same name if already present in cwd, we start attching -1-, -2- etc
 * in from of it.
 * Returns 0 on success; non-zero error otherwise
 */
static int sgfs_rename_fromsg(struct dentry *dentry, char* secondFileName) 
{
	mm_segment_t oldfs;
    struct dentry* old_file_dentry = NULL;
    struct dentry* new_file_dentry = NULL;
    struct path lower_path;
    struct path lower_fpath;
    struct path checkpath;
    struct path pwd_path;
    char* absoluteFileName = NULL;
    // char* absoluteFileName1 = NULL;
    char* tempbuf = NULL;
    // char* tempbuf1 = NULL;
    int errorVal = 0;
    int err = 0;
    int start = 2;
    char* complete_filename = NULL;
    struct fs_struct *fs = current->fs;

	oldfs = get_fs();
    set_fs(get_ds());

    old_file_dentry = dentry;
    get_fs_pwd(fs, &pwd_path);

    tempbuf = (char*)kmalloc(MY_PAGE_SIZE, GFP_KERNEL);
    complete_filename = (char*)kmalloc(MY_PAGE_SIZE, GFP_KERNEL);

    if (strcmp(pwd_path.dentry->d_sb->s_id, FS_TYPE) == 0) {
		sgfs_get_lower_path(pwd_path.dentry, &lower_path);
		absoluteFileName = d_path(&lower_path, tempbuf, MY_PAGE_SIZE);
    } else {
    	absoluteFileName = d_path(&pwd_path, tempbuf, MY_PAGE_SIZE);
    }
    
    memset(complete_filename, '\0', MY_PAGE_SIZE);
    memcpy(complete_filename, absoluteFileName, strlen(absoluteFileName));
   	memcpy(complete_filename + strlen(complete_filename), "/", 1);
    memcpy(complete_filename + strlen(complete_filename), secondFileName, 
    		strlen(secondFileName));

    if (strcmp(pwd_path.dentry->d_sb->s_id, FS_TYPE) == 0) {
		sgfs_put_lower_path(pwd_path.dentry, &lower_path);
    }

    path_put(&pwd_path);

    while(1) {
    	err = kern_path(complete_filename, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&checkpath);
    	if (err == -ENOENT) {
    		break;
    	} else {
    		memset(complete_filename, '\0', MY_PAGE_SIZE);
    		memcpy(complete_filename, absoluteFileName, strlen(absoluteFileName));
			memcpy(complete_filename + strlen(complete_filename), "/", 1);
    		memcpy(complete_filename + strlen(complete_filename), 
    			secondFileName, strlen(secondFileName));
    		snprintf(complete_filename + strlen(complete_filename), MY_PAGE_SIZE, 
				"%s%d%s", "-", start, "-");
    		start += 1;
    	}
    }

    new_file_dentry = user_path_create(AT_FDCWD, complete_filename, 
    		&lower_fpath, 0);
    if (IS_ERR(new_file_dentry)) {
    	errorVal = PTR_ERR(new_file_dentry);
    	printk("%s %d\n", "Dentry error for name", errorVal);
    	goto clear_out;
    }

	done_path_create(&lower_fpath, new_file_dentry);

	printk("%s %s\n", "Got new dentry with name", complete_filename);

	errorVal = do_rename(old_file_dentry, new_file_dentry);

	printk("%s %s %d\n", __func__, "renamed", errorVal);

clear_out:
	set_fs(oldfs);
	if (tempbuf != NULL) {
		kfree(tempbuf);
	}
	if (complete_filename != NULL) {
		kfree(complete_filename);
	}
	return errorVal;
}

/**
 * do_rename : This function rename lower fs old file to lower fs new file 
 * @lower_old_dentry: dentry of file that we want to move from .sg
 * @lower_new_dentry: dentry of file that we want to move to cwd
 * Returns 0 on success; non-zero error otherwise
 */
static int do_rename(struct dentry *lower_old_dentry, 
		struct dentry *lower_new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;

	lower_old_dir_dentry = lower_old_dentry->d_parent;
	lower_new_dir_dentry = lower_new_dentry->d_parent;

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

	printk("%s %d\n", __func__, err);
	if (err)
		goto out;

	printk("%s %s\n", __func__, "renamed in rename");

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	return err;
}

#ifdef CONFIG_COMPAT
static long sgfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sgfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sgfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "sgfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SGFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "sgfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sgfs_vm_ops;

	file->f_mapping->a_ops = &sgfs_aops; /* set our aops */
	if (!SGFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SGFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sgfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;
	int remove = 0;
	struct dentry* file_dentry = NULL;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file_dentry = file->f_path.dentry;
	printk("%s %s\n", __func__, file_dentry->d_name.name);

	if (is_inside_sg_directory(file_dentry)) {
		remove = matchOwner(file_dentry->d_name.name);
		if (remove) {
			err = -ENOENT;
			return err;
		}
	}

	file->private_data =
		kzalloc(sizeof(struct sgfs_file_info), GFP_KERNEL);
	if (!SGFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sgfs's file struct to lower's */
	sgfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sgfs_lower_file(file);
		if (lower_file) {
			sgfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sgfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SGFS_F(file));
	else
		fsstack_copy_attr_all(inode, sgfs_lower_inode(inode));
out_err:
	return err;
}

static int sgfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sgfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);
	if (lower_file) {
		sgfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SGFS_F(file));
	return 0;
}

static int sgfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sgfs_lower_file(file);
	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sgfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sgfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sgfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sgfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sgfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sgfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	printk("%s\n", __func__);
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Sgfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sgfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sgfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sgfs_read,
	.write		= sgfs_write,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.mmap		= sgfs_mmap,
	.open		= sgfs_open,
	.flush		= sgfs_flush,
	.release	= sgfs_file_release,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
	.read_iter	= sgfs_read_iter,
	.write_iter	= sgfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sgfs_dir_fops = {
	.llseek		= sgfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sgfs_readdir,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.open		= sgfs_open,
	.release	= sgfs_file_release,
	.flush		= sgfs_flush,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
};
