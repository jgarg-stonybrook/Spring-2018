#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <linux/rwsem.h>
#include <linux/namei.h>
#include <crypto/hash.h>
#include "common.h"

asmlinkage extern long (*sysptr)(void *arg);

#define EXTRA_CREDIT 1

#define printS(dOption, str)  if(dOption == 1) printk(KERN_INFO"%s\n", str)
#define printSS(dOption, str1, str2)  if(dOption == 1) printk(KERN_INFO"%s %s\n", str1, str2)
#define printSD(dOption, str, num)  if(dOption == 1) printk(KERN_INFO"Value of %s is %ld\n", str, (long int) num)
#define printSO(dOption, str, num)  if(dOption == 1) printk(KERN_INFO"Value of %s is %o\n", str, num)
#define printSSD(dOption, str, num) if(dOption == 1) printk(KERN_INFO"Value of %s of %s is %ld\n", str,(long int) num)

static int my_readfs_file(struct file *, char *, size_t, loff_t *);
static int my_writefs_file(struct file *, char *, size_t, loff_t *);
static int checkPermAndOwner(struct file *, struct file *);
static int unlinkFile(struct file *);
static int areFilesHardLink(struct file *, struct file *, long *, long*);
static int compareFileNormal(struct file *, struct file *, long *);
static int compareFilePartial(struct file *, struct file *, long *, struct file *);
static int checkFileDir_NReg(char *, int); 
static int linkFile(struct file *, char *);
static int renameFile(struct file *, char *);
static int readWriteDirectly(struct file *, struct file * , long );
static int partialNoWrite(struct file *, struct file *, long*);
static int sameInfileOutfile(struct file*, struct file*, struct file*);
static int closeAll(struct file *, struct file *, struct file *, char *);

#ifdef EXTRA_CREDIT
static int calculateHash(struct file *, char*, char*, int);
#endif


int dOption;

asmlinkage long xdedup(void *arg)
{
    struct file *filpFirst = NULL;
    struct file *filpSecond = NULL;
    struct file *filpOut = NULL;
    char *tempbuf = NULL;
    char *absoluteName = NULL;
    int errorVal = 0;
    int fileHardLink = 0;
    int anyFileDir_NReg = 0;
	int permOwnerCheck;
    int nOption = 0;
    int pOption = 0;
    int sOption = 0;
    int filesExact = 0;
	long bytesDeduped = 0;
    long firstsize = 0;
    long secondSize = 0;
    struct argStructure *myargs;

    if (arg == NULL)
        return -EINVAL;

    myargs = kmalloc(sizeof(struct argStructure), GFP_KERNEL);

    if (myargs == NULL) {
        printS(dOption, "No Memmory available");
        return -ENOMEM;
    } else {
        if (copy_from_user(myargs, arg, sizeof(struct argStructure))) {
            printS(dOption, "Copy not successful");
            return -EFAULT;
        }   
    }
	
	if (myargs->infile1 == NULL || myargs->infile2 == NULL) {
		return -EINVAL;
	} else {

        if ((myargs->flags & D_OPTION)) {
            dOption = 1;
        }

        if ((myargs->flags & P_OPTION)) {
            pOption = 1;
        }
                
        if ((myargs->flags & N_OPTION)) {
            nOption = 1;
        }

        if ((myargs->flags & S_OPTION)) {
            sOption = 1;
        }

        printSS(dOption, "File infile1 is", myargs->infile1);
        printSS(dOption, "File infile2 is", myargs->infile2);
        printSS(dOption, "File outfile is", myargs->outfile);

        anyFileDir_NReg = checkFileDir_NReg(myargs->infile1,0);
        if (anyFileDir_NReg) {
            printS(dOption, "Infile 1 cannt be opened or does not exists");
            return anyFileDir_NReg;
        } else {
            filpFirst = filp_open(myargs->infile1, O_RDONLY | AT_SYMLINK_FOLLOW, 0);
        }

        anyFileDir_NReg = checkFileDir_NReg(myargs->infile2,0);
        if (anyFileDir_NReg) {
            printS(dOption, "Infile 2 cannt be opened or does not exists");
            closeAll(filpFirst, filpSecond, filpOut, tempbuf);
            return anyFileDir_NReg;
        } else {
            filpSecond = filp_open(myargs->infile2, O_RDONLY | AT_SYMLINK_FOLLOW, 0);
        }

        #ifdef EXTRA_CREDIT
        if (sOption) {
            if (myargs->outfile == NULL) {
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                return -EINVAL;
            } else {
                errorVal = calculateHash(filpFirst, myargs->infile1, myargs->outfile, 0);
                errorVal = calculateHash(filpSecond, myargs->infile2, myargs->outfile, 1);
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                return errorVal;
            }
        }

        #endif

        if ((nOption == 0) && (pOption == 1)) {
            if (myargs->outfile == NULL) {
                printS(dOption, "Outfile is null");
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                return -EINVAL;
            } else {
                anyFileDir_NReg = checkFileDir_NReg(myargs->outfile,1);
                if (anyFileDir_NReg) {
                    printS(dOption, "Outfile cannt be opened or does not exists");
                    closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                    return anyFileDir_NReg;
                } else {
                    filpOut = filp_open(myargs->outfile, O_WRONLY | AT_SYMLINK_FOLLOW | O_CREAT, 0644);
                    errorVal = sameInfileOutfile(filpFirst, filpSecond, filpOut);
                    if (errorVal == 0) {
                        printS(dOption, "Infile and outfile are same. Returning...");
                        return -EINVAL;
                    }
                }
            }
        }

        tempbuf = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
        if (tempbuf == NULL) {
            closeAll(filpFirst, filpSecond, filpOut, tempbuf);
            return -ENOMEM;
        }
        absoluteName = d_path(&filpSecond->f_path, tempbuf, MY_PAGE_SIZE);

        fileHardLink = areFilesHardLink(filpFirst, filpSecond, &firstsize, &secondSize);
        printSD(dOption, "filehardlink", fileHardLink);

        if (fileHardLink) {
            if (pOption && !nOption) {
                printS(dOption, "Files are same so we just write directly.....");
                errorVal = readWriteDirectly(filpFirst, filpOut, firstsize);
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                if (errorVal < 0) {
                    return errorVal;
                }
                return firstsize;
            } else if (!nOption && !pOption) {
                printS(dOption, "Files already hardlinked.");
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                return -EINVAL;
            }
            closeAll(filpFirst, filpSecond, filpOut,tempbuf);
            return firstsize;
        }

        if ((pOption == 0)) {
            permOwnerCheck = checkPermAndOwner(filpFirst, filpSecond);
            printSD(dOption, "permOwnerCheck", permOwnerCheck);
            if (permOwnerCheck != 1) {
                printS(dOption, "Size or Owner not Equal");
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                return permOwnerCheck;
            }
        }

        if (pOption && nOption) {
            printS(dOption, "N and P together. So compare partial also.");
            errorVal = partialNoWrite(filpFirst, filpSecond, &bytesDeduped);
            closeAll(filpFirst, filpSecond, filpOut, tempbuf);
            if (errorVal == 1) {
                printS(dOption, "number of same bytes in n and p option");
                return bytesDeduped;
            }
            return errorVal;
        } else if (pOption) {
            printS(dOption, "Go for partial checking");
            errorVal = compareFilePartial(filpFirst, filpSecond, &bytesDeduped, filpOut);
            closeAll(filpFirst, filpSecond, filpOut, tempbuf);
            if (errorVal) {
                return errorVal;
            }
            return bytesDeduped;
        }

        // Will come here either only nOption or no option is given
        if (firstsize != secondSize) {
            printS(dOption, "Size not Equal. returning");
            closeAll(filpFirst, filpSecond, filpOut, tempbuf);
            return -EPERM;
        }

        filesExact = compareFileNormal(filpFirst, filpSecond, &bytesDeduped);
        if (filesExact == 1) {
            printS(dOption, "Files are exactly same");
            if (nOption) {
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                return bytesDeduped;
            } 
            
            errorVal = unlinkFile(filpSecond);
            if (!errorVal) {
                printS(dOption, "File2 deleted. No option -n");
            } else {
                printS(dOption, "Sorry can not unlink the file");
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                return -EPERM;
            }

            errorVal = linkFile(filpFirst, absoluteName);
            if (!errorVal) {
                printS(dOption, "File2 linked with file 1. No option -n");
            } else {
                printS(dOption, "Sorry can not link the file");
                closeAll(filpFirst, filpSecond, filpOut, tempbuf);
                return -EPERM;
            }
            closeAll(filpFirst, filpSecond, filpOut, tempbuf);
            return bytesDeduped;
        } else if (filesExact == -ENOENT) {
            printS(dOption, "File not opened properly.");
            closeAll(filpFirst, filpSecond, filpOut, tempbuf);
            return -ENOENT;
        } else {
            printS(dOption, "Files not same in content.");
            closeAll(filpFirst, filpSecond, filpOut, tempbuf);
            return -EPERM;
        }

	}
    closeAll(filpFirst, filpSecond, filpOut, tempbuf);
    return 0;
}

static int closeAll(struct file * first, struct file *second, struct file *third, char * tempbuf) 
{
    printS(dOption, "Cleaning all memory...");
    if (tempbuf != NULL) {
        kfree(tempbuf);
    }
    if (first != NULL) {
        filp_close(first, NULL);
    }
    if (second != NULL) {
        filp_close(second, NULL);
    }
    if (third != NULL) {
        filp_close(third, NULL);
    }
    return 1;
}

static int sameInfileOutfile(struct file* firstFilp, struct file* secondFilp, struct file* outFilp)
{
    struct dentry* dentryFirst;
    struct dentry* dentrySecond;
    struct dentry* dentryOut;
    int index = 0;

    dentryFirst = firstFilp->f_path.dentry;
    dentrySecond = secondFilp->f_path.dentry;
    dentryOut = outFilp->f_path.dentry;

    if (dentryFirst->d_inode->i_ino == dentryOut->d_inode->i_ino) {
        for (index = 0; index < 16; ++index) {
            if (dentryFirst->d_sb->s_uuid[index] != dentryOut->d_sb->s_uuid[index]) {
                break;
            }
        }
        if (index == 16) {
            return 0;
        }
    }

    if (dentrySecond->d_inode->i_ino == dentryOut->d_inode->i_ino) {
        for (index = 0; index < 16; ++index) {
            if (dentrySecond->d_sb->s_uuid[index] != dentryOut->d_sb->s_uuid[index]) {
                break;
            }
        }
        if (index == 16) {
            return 0;
        }
    }
    return 1;
}

static int checkFileDir_NReg(char *firstFileName, int isout) 
{
    struct file *filpFirst;
    int flags = 0;
    char *buf = NULL;
    int errorVal = 0;

    buf = (char *)kmalloc(4096, __GFP_REPEAT);
    if (buf == NULL) {
        errorVal = -ENOMEM;
        return errorVal;
    }

    if (isout == 0) {
        flags |= (O_RDONLY | AT_SYMLINK_FOLLOW);
    } else {
        flags |= (O_WRONLY | AT_SYMLINK_FOLLOW | O_CREAT);
    }

    filpFirst = filp_open(firstFileName, flags, 0644);
    if (!filpFirst || IS_ERR(filpFirst)) {
        //This will also check whether first file  exists or not.
        printSD(dOption, "Cannot open file in checkFileDir_NReg", (int) PTR_ERR(filpFirst));
        return (int) PTR_ERR(filpFirst);
    } else {
        if (S_ISDIR(filpFirst->f_path.dentry->d_inode->i_mode)) {
            filp_close(filpFirst, NULL);
            return -EISDIR;
        }
        if (!S_ISREG(filpFirst->f_path.dentry->d_inode->i_mode)) {
            filp_close(filpFirst, NULL);
            return -EINVAL;
        }
        printSS(dOption, firstFileName, " File is not a directory and is a regular file");
    }

    filp_close(filpFirst, NULL);
    return 0;
}

static int areFilesHardLink(struct file *filpFirst, struct file *filpSecond, long *firstsize, long *secondSize)
{
    struct dentry* dentryFirst;
    struct dentry* dentrySecond;
    int index = 0;

    if (!filpFirst || IS_ERR(filpFirst)) {
        printSD(dOption, "File err in areFilesHardLink function", (int) PTR_ERR(filpFirst));
        return (int) PTR_ERR(filpFirst);
    }

    if (!filpSecond || IS_ERR(filpSecond)) {
        printSD(dOption, "File err in areFilesHardLink function", (int) PTR_ERR(filpSecond));
        return (int) PTR_ERR(filpSecond);
    }

    dentryFirst = filpFirst->f_path.dentry;
    dentrySecond = filpSecond->f_path.dentry;

    *firstsize = dentryFirst->d_inode->i_size;
    *secondSize = dentrySecond->d_inode->i_size;

    printSD(dOption, "file size 1 ",dentryFirst->d_inode->i_size);
    printSD(dOption, "file size 2 ",dentrySecond->d_inode->i_size);

    printSD(dOption, "file inode 1 ", dentryFirst->d_inode->i_ino);
    printSD(dOption, "file inode 2 ", dentrySecond->d_inode->i_ino);

    if (dentryFirst->d_inode->i_ino != dentrySecond->d_inode->i_ino) {
        printS(dOption, "Files inode number not same");
        return 0;
    }

    for (index = 0; index < 16; ++index) {
        if (dentryFirst->d_sb->s_uuid[index] != dentrySecond->d_sb->s_uuid[index]) {
            printS(dOption, "superblock not equal");
            return 0;
        }
    }

    return 1;
}

static int checkPermAndOwner(struct file *filpFirst, struct file *filpSecond)
{
    struct dentry* dentryFirst;
    struct dentry* dentrySecond;
    int uidResult;

    if (!filpFirst || IS_ERR(filpFirst)) {
        printSD(dOption, "File err in checkPermAndOwner function", (int) PTR_ERR(filpFirst));
        return (int) PTR_ERR(filpFirst);
    }

    if (!filpSecond || IS_ERR(filpSecond)) {
        printSD(dOption, "File err in checkPermAndOwner function", (int) PTR_ERR(filpSecond));
        return (int) PTR_ERR(filpSecond);
    }

    dentryFirst = filpFirst->f_path.dentry;
    dentrySecond = filpSecond->f_path.dentry;

    uidResult = uid_eq(dentryFirst->d_inode->i_uid, dentrySecond->d_inode->i_uid);
    printSD(dOption, "uidResult", uidResult);

    if (!uidResult)
    {
    	printS(dOption, "UID not equal");
    	return -EPERM;
    }   

    //Permission should also be equal 
    printSO(dOption, "file mode 1 ",dentryFirst->d_inode->i_mode);
    printSO(dOption, "file mode 2 ",dentrySecond->d_inode->i_mode);

    if (dentryFirst->d_inode->i_mode != dentrySecond->d_inode->i_mode)
    {
        return -EPERM;
    }

    return 1;
}

static int compareFileNormal(struct file *filpFirst, struct file *filpSecond, long *bytesDeduped)
{
    loff_t offsetFirst = 0;
    loff_t offsetSecond = 0;
    int bytes_read_first = 0;
    int bytes_read_second = 0;
    char* bufFile1 = NULL;
    char* bufFile2 = NULL;
    int terminate_flag = 0;
    int errorVal = 0;
    int index = 0;
    bufFile1 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
    bufFile2 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

    if ((bufFile1 == NULL) || (bufFile2 == NULL)) {
        errorVal = -ENOMEM;
        goto clear_and_exit;
    }

    while (1) {

        bytes_read_first = my_readfs_file(filpFirst, bufFile1 , MY_PAGE_SIZE, &offsetFirst);

        bytes_read_second = my_readfs_file(filpSecond, bufFile2 , MY_PAGE_SIZE, &offsetSecond);

        if ((bytes_read_first == -ENOENT) || (bytes_read_second == -ENOENT)) {
            printS(dOption, "Error in reading file");
            errorVal = -ENOENT;
            goto clear_and_exit;
        }

        if (bytes_read_first != bytes_read_second) {
            errorVal = -EPERM;
            goto clear_and_exit;
        }

        index = 0;
        while (index < bytes_read_first && index < bytes_read_second) {
            if (bufFile1[index] != bufFile2[index]) {
                terminate_flag = 1;
                errorVal = -EPERM;
                break;
            } else {
                index += 1;
            }
        }

        if (terminate_flag == 1) {
            goto clear_and_exit;
        }

        if ((bytes_read_first != MY_PAGE_SIZE) || (bytes_read_second != MY_PAGE_SIZE)) {
            *bytesDeduped = offsetFirst;
            printSD(dOption, "bytesDeduped are :", offsetFirst);
            errorVal = 1;
            goto clear_and_exit;
        }

    }

clear_and_exit:
    if (bufFile1) {
        kfree(bufFile1);
    }
    if (bufFile2) {
        kfree(bufFile2);
    }
    return errorVal;
}

static int compareFilePartial(struct file *filpFirst, struct file *filpSecond, long *bytesDeduped, struct file* outFilp)
{
    loff_t offsetFirst = 0;
    loff_t offsetSecond = 0;
    loff_t write_offset = 0;
    struct file* tempfilp = NULL;
    int bytes_read_first = 0;
    int bytes_read_second = 0;
    char* bufFile1 = NULL;
    char* bufFile2 = NULL;
    char* writebuffer= NULL;
    char* tempFile = "xyzabc";
    char *absoluteName = NULL;
    char *tempbuf;
    int max_bytes_towrite = 0;
    int errorVal = 0;
    int index = 0;
    int isNewFileCreated = 0;
    int terminate_flag = 0;
    int totalBytesCopied = 0;
    int work_done = 0;

    bufFile1 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
    bufFile2 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
    writebuffer = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
    tempbuf = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

    if ((bufFile1 == NULL) || (bufFile2 == NULL) || (writebuffer == NULL) || (tempbuf == NULL)) {
        errorVal = -ENOMEM;
        goto clear_and_exit;
    }
    printSS(dOption, "file here is ", tempFile);
    tempfilp = filp_open(tempFile, O_WRONLY | O_CREAT | O_TRUNC, outFilp->f_path.dentry->d_inode->i_mode);
    if (!tempfilp || IS_ERR(tempfilp)) {
        printSD(dOption, "my_writefs_file err", (int) PTR_ERR(tempfilp));
        return -ENOENT;
    }

    absoluteName = d_path(&outFilp->f_path, tempbuf, MY_PAGE_SIZE);
    printSS(dOption, "Absolute out name is ", absoluteName);

    while (1) {

        bytes_read_first = my_readfs_file(filpFirst, bufFile1 , MY_PAGE_SIZE, &offsetFirst);

        bytes_read_second = my_readfs_file(filpSecond, bufFile2 , MY_PAGE_SIZE, &offsetSecond);

        if ((bytes_read_first == -ENOENT) || (bytes_read_second == -ENOENT)) {
            printS(dOption, "Error in reading file");
            errorVal = -ENOENT;
            goto clear_and_exit;
        }

        max_bytes_towrite = (bytes_read_first < bytes_read_second) ? bytes_read_first : bytes_read_second;

        index = 0;
        while (index < max_bytes_towrite) {
            if (bufFile1[index] != bufFile2[index]) {
                terminate_flag = 1;
                break;
            } else {
                writebuffer[index] = bufFile1[index];
                index += 1;
            }
        }

        if (index > 0 ) {
            errorVal = my_writefs_file(tempfilp, writebuffer, index, &write_offset);
            if (errorVal == -ENOENT) {
                printS(dOption, "Error in File Writing. This should not happen at all");
                goto clear_and_exit;
            }
        }

        isNewFileCreated = 1;

        // printSD(dOption, "Offest Now is", write_offset);
        totalBytesCopied += index;
        if ((bytes_read_first != MY_PAGE_SIZE) || (terminate_flag == 1) || (bytes_read_second != MY_PAGE_SIZE)) {
            *bytesDeduped = totalBytesCopied;
            printSD(dOption, "totalBytesCopied", totalBytesCopied);
            errorVal = 1;
            work_done = 1;
            goto clear_and_exit;
        }
    }

clear_and_exit:

    if (bufFile1) {
        kfree(bufFile1);
    }
    if (bufFile2) {
        kfree(bufFile2);
    }
    if (writebuffer) {
        kfree(writebuffer);
    }

    if (work_done) {
        errorVal = unlinkFile(outFilp);
        printSD(dOption, "unlink outfile returned", errorVal);
        if (errorVal) {
            printS(dOption, "Sorry can not unlink the file");
            errorVal = unlinkFile(tempfilp);
            return -EPERM;
        } else {
            errorVal = renameFile(tempfilp, absoluteName);
            if (errorVal) {
                printS(dOption, "Sorry can not rename the temp to outfile");
                return -EPERM;
            }
        }
    } else if (isNewFileCreated) {
        errorVal = unlinkFile(tempfilp);
        if (errorVal) {
            printS(dOption, "Sorry can not unlink the tempFile");
            return -EPERM;
        }
    }
    if (tempbuf) {
        kfree(tempbuf);
    }
    if (tempfilp != NULL) {
        filp_close(tempfilp, NULL);
    }
    return errorVal;
}

static int my_readfs_file(struct file *filp, char *buf, size_t size, loff_t *offset)
{
    mm_segment_t oldfs;
    int bytes;

    if (!filp || IS_ERR(filp)) {
		printSD(dOption, "wrapfss_read_file err", (int) PTR_ERR(filp));
        return -ENOENT;
	}

    /* now read len bytes from offset */
    oldfs = get_fs();
    set_fs(get_ds());

    bytes = vfs_read(filp, buf, size, offset);

    set_fs(oldfs);

    printSD(dOption, "bytes read", bytes);

    printS(dOption, "File Read Successful");

    return bytes;
 
}

static int my_writefs_file(struct file *filp, char *buf, size_t size, loff_t *offset)
{
    mm_segment_t oldfs;
    int bytes;
    // int outfilePerm = 0644;

    if (!filp || IS_ERR(filp)) {
        printSD(dOption, "my_writefs_file err", (int) PTR_ERR(filp));
        return -ENOENT;
    }

    /* now write size bytes from offset*/
    oldfs = get_fs();
    set_fs(get_ds());

    bytes = vfs_write(filp, buf, size, offset);

    set_fs(oldfs);

    printSD(dOption, "bytes write", bytes);

    return bytes;

}

static int partialNoWrite(struct file *filpFirst, struct file *filpSecond, long* bytesDeduped)
{
    loff_t offsetFirst = 0;
    loff_t offsetSecond = 0;
    int bytes_read_first = 0;
    int bytes_read_second = 0;
    char* bufFile1 = NULL;
    char* bufFile2 = NULL;
    int errorVal = 0;
    int terminate_flag = 0;
    int totalBytesCopied = 0;
    int max_bytes_towrite = 0;
    int index = 0;

    bufFile1 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
    bufFile2 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

    if ((bufFile1 == NULL) || (bufFile2 == NULL)) {
        errorVal = -ENOMEM;
        goto clear_and_exit;
    }

    while (1) {

        bytes_read_first = my_readfs_file(filpFirst, bufFile1 , MY_PAGE_SIZE, &offsetFirst);

        bytes_read_second = my_readfs_file(filpSecond, bufFile2 , MY_PAGE_SIZE, &offsetSecond);

        if ((bytes_read_first == -ENOENT) || (bytes_read_second == -ENOENT)) {
            printS(dOption, "Error in reading file");
            errorVal = -ENOENT;
            goto clear_and_exit;
        }

        max_bytes_towrite = (bytes_read_first < bytes_read_second) ? bytes_read_first : bytes_read_second;

        index = 0;
        while (index < max_bytes_towrite) {
            if (bufFile1[index] != bufFile2[index]) {
                terminate_flag = 1;
                break;
            } else {
                index += 1;
            }
        }

        totalBytesCopied += index;
        if ((bytes_read_first != MY_PAGE_SIZE) || (terminate_flag == 1) || (bytes_read_second != MY_PAGE_SIZE)) {
            *bytesDeduped = totalBytesCopied;
            printSD(dOption, "totalBytesCopied are:", totalBytesCopied);
            errorVal = 1;
            goto clear_and_exit;
        }
    }

clear_and_exit:
    if (bufFile1) {
        kfree(bufFile1);
    }
    if (bufFile2) {
        kfree(bufFile2);
    }
    return errorVal;
}

static int readWriteDirectly(struct file *filpFirst, struct file* outfilp, long max_bytes_towrite)
{
    loff_t offsetFirst = 0;
    loff_t write_offset = 0;
    int bytes_read_first = 0;
    char* bufFile1 = NULL;
    char* absoluteName = NULL;
    char* tempbuf = NULL;
    struct file* tempfilp = NULL;
    char* tempFile = "xyzabc";
    int errorVal = 0;
    int isNewFileCreated = 0;
    int totalBytesCopied = 0;

    bufFile1 = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);
    tempbuf = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

    if ((bufFile1 == NULL) || (tempbuf == NULL)) {
        errorVal = -ENOMEM;
        goto clear_and_exit;
    }

    tempfilp = filp_open(tempFile, O_WRONLY | O_CREAT | AT_SYMLINK_FOLLOW | O_TRUNC, outfilp->f_path.dentry->d_inode->i_mode);
    if (!tempfilp || IS_ERR(tempfilp)) {
        printSD(dOption, "readWriteDirectly file opening err", (int) PTR_ERR(tempfilp));
        return -ENOENT;
    }

    absoluteName = d_path(&outfilp->f_path, tempbuf, MY_PAGE_SIZE);
    printSS(dOption, "Absolute out name is ", absoluteName);

    while (totalBytesCopied < max_bytes_towrite) {

        bytes_read_first = my_readfs_file(filpFirst, bufFile1 , MY_PAGE_SIZE, &offsetFirst);

        if ((bytes_read_first == -ENOENT)) {
            printS(dOption, "Error in reading file");
            errorVal = -ENOENT;
            goto clear_and_exit;
        }

        errorVal = my_writefs_file(tempfilp, bufFile1, bytes_read_first, &write_offset);
        if (errorVal == -ENOENT) {
            printS(dOption, "Error in File Writing. This should not happen at all");
            goto clear_and_exit;
        }

        isNewFileCreated = 1;
        totalBytesCopied += bytes_read_first;

        if ((bytes_read_first != MY_PAGE_SIZE)) {
            printSD(dOption, "totalBytesCopied", totalBytesCopied);
            goto clear_and_exit;
        }
    }

clear_and_exit:
    if (bufFile1) {
        kfree(bufFile1);
    }
    if (totalBytesCopied == max_bytes_towrite) {
        errorVal = unlinkFile(outfilp);
        if (errorVal) {
            printS(dOption, "Sorry can not unlink the file");
            errorVal = unlinkFile(tempfilp);
            return -EPERM;
        } else {
            errorVal = renameFile(tempfilp, absoluteName);
            if (errorVal) {
                printS(dOption, "Sorry can not rename the temp to outfile");
                return -EPERM;
            }
        }
    } else if (isNewFileCreated) {
        errorVal = unlinkFile(tempfilp);
        if (errorVal) {
            printS(dOption, "Sorry can not unlink the tempFile");
            return -EPERM;
        }
    }
    if (tempfilp != NULL) {
        filp_close(tempfilp, NULL);
    }
    return errorVal;
}

static int renameFile(struct file *firstFilp, char *secondFileName) 
{
    mm_segment_t oldfs;
    struct file* secondFilp;
    struct inode* delegated_inode = NULL;
    struct dentry* trapEntry;
    struct dentry* old_file_dentry;
    struct dentry* new_file_dentry;
    int flags = 0;
    int errorVal = 0;

    if (!firstFilp || IS_ERR(firstFilp)) {
        printSD(dOption, "file error in renaming", (int) PTR_ERR(firstFilp));
        return -ENOENT;
    }

    secondFilp = filp_open(secondFileName, O_RDWR | O_CREAT | AT_SYMLINK_FOLLOW, 0644);
    if (!secondFilp || IS_ERR(secondFilp)) {
        printSD(dOption, "second file error in renaming", (int) PTR_ERR(secondFilp));
        return -ENOENT;
    }

    oldfs = get_fs();
    set_fs(get_ds());

    old_file_dentry = firstFilp->f_path.dentry;

    new_file_dentry = secondFilp->f_path.dentry;

    if (IS_ERR(new_file_dentry)) {
        printS(dOption, "Unable to get both the Dentries");
        errorVal = PTR_ERR(new_file_dentry);
        goto exit_second;
    }

    trapEntry = lock_rename(firstFilp->f_path.dentry->d_parent, secondFilp->f_path.dentry->d_parent);
    if (trapEntry == old_file_dentry || trapEntry == new_file_dentry) {
        errorVal = -EINVAL;
        goto exit_first;
    }

    printS(dOption, "Got both the dentryies");
    printS(dOption, "Got both the locks");

    errorVal = vfs_rename(old_file_dentry->d_parent->d_inode, old_file_dentry, new_file_dentry->d_parent->d_inode, new_file_dentry, &delegated_inode, flags);

exit_first:
    unlock_rename(firstFilp->f_path.dentry->d_parent, secondFilp->f_path.dentry->d_parent);
    printS(dOption, "released lock in renaming");
    
exit_second:

    set_fs(oldfs);
    return errorVal;
}

static int linkFile(struct file *firstFilp, char *secondFileName)
{
    mm_segment_t oldfs;
    struct path newPath;
    struct inode* delegated_inode = NULL;
    struct dentry* old_file_dentry;
    struct dentry* new_file_dentry;
    int errorVal = 0;

    if (!firstFilp || IS_ERR(firstFilp)) {
        printSD(dOption, "read file error in linking", (int) PTR_ERR(firstFilp));
        return -ENOENT;
    }

    printS(dOption, "File opened for linking");
    oldfs = get_fs();
    set_fs(get_ds());

    printSS(dOption, "File 2 for linking", secondFileName);
    // Locked is taken in this function. So no need to take again.
    new_file_dentry = user_path_create(AT_FDCWD, secondFileName, &newPath, 0);

    if (IS_ERR(new_file_dentry)) {
        errorVal = PTR_ERR(new_file_dentry);
        goto clear_and_exit;
    }

    printS(dOption, "Lock granted for linking");

    old_file_dentry = firstFilp->f_path.dentry;

    errorVal = vfs_link(old_file_dentry, newPath.dentry->d_inode, new_file_dentry, &delegated_inode);
    printSD(dOption, "errorVal in linking is", errorVal);

    done_path_create(&newPath, new_file_dentry);
    printS(dOption, "Lock released after linking");

    set_fs(oldfs);
clear_and_exit:
    return errorVal;
 
}


static int unlinkFile(struct file *filp)
{
    mm_segment_t oldfs;
    int errorVal = -1;
    struct inode* delegated_inode = NULL;
    struct dentry* file_dentry;
    struct path file_path;

    if (!filp || IS_ERR(filp)) {
        printSD(dOption, "read file error in unlinking.", (int) PTR_ERR(filp));
        errorVal = -ENOENT;
        return errorVal;
    }

    printS(dOption, "File opened for deletion");
    oldfs = get_fs();
    set_fs(get_ds());

    file_path = filp->f_path; 

    file_dentry = file_path.dentry;
    mutex_lock_nested( &(file_dentry->d_parent->d_inode->i_mutex), I_MUTEX_PARENT);
    printS(dOption, "Lock granted for deletion");

    if (!IS_ERR(file_dentry)){
        errorVal = vfs_unlink(file_dentry->d_parent->d_inode, file_dentry, &delegated_inode);
        printSD(dOption, "errorVal returned from vfs_unlink", errorVal);
    } 

    mutex_unlock(&(file_dentry->d_parent->d_inode->i_mutex));
    printS(dOption, "Lock released after deletion.");

    set_fs(oldfs);
	return errorVal;
}

#ifdef EXTRA_CREDIT

static int calculateHash(struct file *filp, char* filename, char* outFile, int mode)
{
    mm_segment_t oldfs;
    int errorVal = 0;
    int bytes_read_first = 0;
    loff_t offset = 0;
    struct file* filpOut = NULL;
    char* tempBuf = NULL;
    u8 cal_digest[20];
    int index = 0;
    int size = 0;
    int bytes = 0;
    char* writebuffer = NULL;
    struct crypto_shash* cryptotfm;
    struct shash_desc* shaDesc;
    int flags = 0;

    oldfs = get_fs();
    set_fs(get_ds());

    if (mode == 0) {
        flags |= (O_WRONLY | AT_SYMLINK_FOLLOW | O_CREAT | O_TRUNC);
    } else {
        flags |= (O_WRONLY | AT_SYMLINK_FOLLOW | O_APPEND);
    }

    filpOut = filp_open(outFile, flags, 0644);
    if (!filpOut || IS_ERR(filpOut)) {
        printSD(dOption, "Cannot open file in hashing", (int) PTR_ERR(filpOut));
        goto clear_and_exit;
        return (int) PTR_ERR(filpOut);
    }

    cryptotfm = crypto_alloc_shash("sha1", 0, CRYPTO_ALG_ASYNC);
    if (!cryptotfm || IS_ERR(cryptotfm)) {
        printS(dOption, "Buffer not allocated");
        errorVal = -1;
        goto clear_and_exit;
    }

    shaDesc = kmalloc(sizeof(struct shash_desc), __GFP_REPEAT);
    if(shaDesc == NULL || IS_ERR(shaDesc)) {
        errorVal = (int) PTR_ERR(shaDesc);
        printS(dOption, "Could not alloacte shaDesc");
        goto clear_and_exit;
    }

    shaDesc->tfm = cryptotfm;
    shaDesc->flags = 0;

    errorVal = crypto_shash_init(shaDesc);
    if(errorVal < 0) {
        printS(dOption, "Could not crypto api");
        goto clear_and_exit;
    }

    tempBuf = (char *)kmalloc(MY_PAGE_SIZE, __GFP_REPEAT);

    if (tempBuf == NULL) {
        errorVal = -ENOMEM;
        printS(dOption, "Buffer not alloacted for hashing");
        goto clear_and_exit;
    }
    printS(dOption, "here already");
    while(1) {
        bytes_read_first = my_readfs_file(filp, tempBuf , MY_PAGE_SIZE, &offset);
        if (bytes_read_first < 0) {
            printS(dOption, "Error in reading file");
            errorVal = bytes_read_first;
            goto clear_and_exit;
        }
        if (bytes_read_first == 0) {
            break;
        }
        errorVal = crypto_shash_update(shaDesc, tempBuf, bytes_read_first);
        if (errorVal < 0) {
            printS(dOption, "Error in updating");
            goto clear_and_exit;
        }
        if (bytes_read_first < MY_PAGE_SIZE) {
            break;
        }
    }

    errorVal = crypto_shash_final(shaDesc, cal_digest);
    if (errorVal < 0) {
        printS(dOption, "Failed");
        goto clear_and_exit;
    }
    // printk("%d", sizeof(cal_digest));
    size = 40 + sizeof(filename) + 2;
    writebuffer = kmalloc(size, __GFP_REPEAT);
    for (index = 0; index < 20; ++index) {
        sprintf(writebuffer + 2*index, "%02x", cal_digest[index]);
    }

    strcat(writebuffer, " ");
    strcat(writebuffer, filename);
    strcat(writebuffer, "\n");

    bytes = vfs_write(filpOut, writebuffer, strlen(writebuffer), &filpOut->f_pos);

clear_and_exit:
    set_fs(oldfs);
    if (writebuffer != NULL) {
        kfree(writebuffer);
    }

    if (tempBuf != NULL) {
        kfree(tempBuf);      
    }

    return errorVal;
}
#endif

static int __init init_sys_xdedup(void)
{
	printk("installed new sys_xdedup module\n");
	if (sysptr == NULL)
		sysptr = xdedup;
	return 0;
}

static void  __exit exit_sys_xdedup(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xdedup module\n");
}

module_init(init_sys_xdedup);
module_exit(exit_sys_xdedup);
MODULE_LICENSE("GPL");
