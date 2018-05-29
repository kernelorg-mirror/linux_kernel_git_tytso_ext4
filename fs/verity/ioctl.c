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

#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
/**
 * fsverity_ioctl_set_measurement - set a verity file's expected measurement
 *
 * The FS_IOC_SET_VERITY_MEASUREMENT ioctl informs the kernel which
 * "measurement" (hash of the Merkle tree root hash and the fsverity footer) is
 * expected for an fs-verity file.  If the actual measurement matches the
 * expected one, then the ioctl succeeds and further reads from the file are
 * allowed without warnings.  Additionally, the inode is pinned in memory so
 * that the "authenticated" status doesn't get lost on eviction.  Otherwise,
 * reads from the file are forbidden and the ioctl fails.
 *
 * Return: 0 on success, -errno on failure
 */
int fsverity_ioctl_set_measurement(struct file *filp, const void __user *_uarg)
{
	const struct fsverity_measurement __user *uarg = _uarg;
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct fsverity_measurement arg;
	u8 digest[FS_VERITY_MAX_DIGEST_SIZE];
	const struct fsverity_hash_alg *hash_alg;
	struct fsverity_info *vi;
	int err;

	if (!capable(CAP_SYS_ADMIN)) {
		pr_debug("Process '%s' is not authorized to provide fs-verity measurements\n",
			 current->comm);
		err = -EACCES;
		goto out;
	}

	if (copy_from_user(&arg, uarg, sizeof(arg))) {
		err = -EFAULT;
		goto out;
	}

	hash_alg = fsverity_check_measurement_struct(&arg);
	if (IS_ERR(hash_alg)) {
		err = PTR_ERR(hash_alg);
		goto out;
	}

	if (copy_from_user(digest, uarg->digest, hash_alg->digest_size)) {
		err = -EFAULT;
		goto out;
	}

	vi = get_fsverity_info(inode);
	if (!vi) {
		pr_debug("File does not have fs-verity enabled\n");
		err = -EINVAL;
		goto out;
	}

	inode_lock(inode);

	if (hash_alg != vi->hash_alg) {
		pr_warn("Hash algorithm mismatch: provided %s, but file uses %s\n",
			hash_alg->friendly_name, vi->hash_alg->friendly_name);
		err = -EBADMSG;
		vi->mode = FS_VERITY_MODE_AUTHENTICATION_FAILED;
		truncate_inode_pages(inode->i_mapping, 0);
		goto out_unlock;
	}

	if (memcmp(digest, vi->measurement, hash_alg->digest_size)) {
		if (vi->mode == FS_VERITY_MODE_AUTHENTICATED)
			pr_warn("Inconsistent measurements were provided! %*phN and %*phN\n",
				hash_alg->digest_size, digest,
				hash_alg->digest_size, vi->measurement);
		else
			pr_warn("File corrupted!  Wanted measurement: %*phN, real measurement: %*phN\n",
				hash_alg->digest_size, digest,
				hash_alg->digest_size, vi->measurement);
		vi->mode = FS_VERITY_MODE_AUTHENTICATION_FAILED;
		truncate_inode_pages(inode->i_mapping, 0);
		err = -EBADMSG;
		goto out_unlock;
	}

	if (vi->mode == FS_VERITY_MODE_AUTHENTICATED) {
		pr_debug("Measurement already being enforced: %*phN\n",
			 hash_alg->digest_size, vi->measurement);
	} else {
		pr_debug("Measurement validated: %*phN\n",
			 hash_alg->digest_size, vi->measurement);
		vi->mode = FS_VERITY_MODE_AUTHENTICATED;

		/*
		 * No need to truncate pages here.  Any pages that were read
		 * without authentication still had their integrity verified up
		 * to ->root_hash, so now we know they are authentic as we've
		 * just authenticated ->root_hash.
		 */

		/* Pin the inode so that the measurement doesn't go away */
		ihold(inode);
		spin_lock(&sb->s_inode_fsveritylist_lock);
		list_add(&inode->i_fsverity_list, &sb->s_inodes_fsverity);
		spin_unlock(&sb->s_inode_fsveritylist_lock);
	}
	err = 0;
out_unlock:
	inode_unlock(inode);
out:
	if (err)
		pr_debug("FS_IOC_SET_VERITY_MEASUREMENT failed on inode %lu (err %d)\n",
			 inode->i_ino, err);
	else
		pr_debug("FS_IOC_SET_VERITY_MEASUREMENT succeeded on inode %lu\n",
			 inode->i_ino);
	return err;
}
EXPORT_SYMBOL_GPL(fsverity_ioctl_set_measurement);
#endif /* CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY */
