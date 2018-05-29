// SPDX-License-Identifier: GPL-2.0
/*
 * fs-verity: read-only file-based integrity/authenticity
 *
 * ioctl.c: fs-verity ioctls
 *
 * Copyright (C) 2018, Google, Inc.
 *
 * Originally written by Jaegeuk Kim and Michael Halcrow;
 * heavily rewritten by Eric Biggers.
 */

#include "fsverity_private.h"

#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/uaccess.h>

/**
 * fsverity_ioctl_enable - enable fs-verity on a file
 *
 * Enable the fs-verity bit on a file.  Userspace must have already appended the
 * fs-verity metadata to the file.
 *
 * Enabling fs-verity makes the file contents immutable, and the filesystem
 * doesn't allow disabling it (other than by replacing the file).
 *
 * To avoid races with the file contents being modified, no processes must have
 * the file open for writing.  This includes the caller!
 *
 * Return: 0 on success, -errno on failure
 */
int fsverity_ioctl_enable(struct file *filp, const void __user *arg)
{
	struct inode *inode = file_inode(filp);
	struct fsverity_info *vi;
	int err;

	if (!capable(CAP_SYS_ADMIN)) {
		pr_debug("Process '%s' is not authorized to enable fs-verity\n",
			 current->comm);
		err = -EACCES;
		goto out;
	}

	if (arg) {
		pr_debug("FS_IOC_ENABLE_VERITY doesn't take an argument\n");
		err = -EINVAL;
		goto out;
	}

	if (S_ISDIR(inode->i_mode))  {
		pr_debug("Inode is a directory\n");
		err = -EISDIR;
		goto out;
	}

	if (!S_ISREG(inode->i_mode)) {
		pr_debug("Inode is not a regular file\n");
		err = -EINVAL;
		goto out;
	}

	err = mnt_want_write_file(filp);
	if (err)
		goto out;

	/*
	 * Temporarily lock out writers via writable file descriptors or
	 * truncate().  This should stabilize the contents of the file as well
	 * as its size.  Note that at the end of this ioctl we will unlock
	 * writers, but at that point the fs-verity bit will be set (if the
	 * ioctl succeeded), preventing future writers.
	 */
	err = deny_write_access(filp);
	if (err) {
		pr_debug("File is open for writing!\n");
		goto out_drop_write;
	}

	/*
	 * fsync so that the fs-verity bit can't be persisted to disk prior to
	 * the data, causing verification errors after a crash.
	 */
	err = vfs_fsync(filp, 1);
	if (err) {
		pr_debug("I/O error occurred during fsync\n");
		goto out_allow_write;
	}

	/* Serialize concurrent use of this ioctl on the same inode */
	inode_lock(inode);

	if (inode->i_sb->s_vop->is_verity(inode)) {
		pr_debug("Fs-verity is already enabled on this file\n");
		err = -EEXIST;
		goto out_unlock;
	}

	/* Validate the fs-verity footer */
	vi = create_fsverity_info(inode);
	if (IS_ERR(vi)) {
		pr_debug("create_fsverity_info() failed\n");
		err = PTR_ERR(vi);
		goto out_unlock;
	}

	/* Set the fs-verity bit */
	err = inode->i_sb->s_vop->set_verity(inode);
	if (err) {
		pr_debug("Filesystem ->set_verity() method failed\n");
		goto out_free_vi;
	}

	/* Invalidate all cached pages, forcing re-verification */
	truncate_inode_pages(inode->i_mapping, 0);

	/* Set ->i_verity_info */
	if (set_fsverity_info(inode, vi))
		vi = NULL;
	err = 0;
out_free_vi:
	free_fsverity_info(vi);
out_unlock:
	inode_unlock(inode);
out_allow_write:
	allow_write_access(filp);
out_drop_write:
	mnt_drop_write_file(filp);
out:
	if (err)
		pr_debug("Failed to enable fs-verity on inode %lu (err=%d)\n",
			 inode->i_ino, err);
	else
		pr_debug("Successfully enabled fs-verity on inode %lu\n",
			 inode->i_ino);
	return err;
}
EXPORT_SYMBOL_GPL(fsverity_ioctl_enable);
