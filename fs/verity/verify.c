// SPDX-License-Identifier: GPL-2.0
/*
 * fs-verity: read-only file-based integrity/authenticity
 *
 * verify.c: data verification functions, i.e. hooks for ->readpages()
 *
 * Copyright (C) 2018, Google, Inc.
 *
 * Originally written by Jaegeuk Kim and Michael Halcrow;
 * heavily rewritten by Eric Biggers.
 */

#include "fsverity_private.h"

#include <crypto/hash.h>
#include <linux/bio.h>
#include <linux/ratelimit.h>

struct workqueue_struct *fsverity_read_workqueue;

/**
 * hash_at_level() - compute the location of the block's hash at the given level
 *
 * @vi:		(in) the file's verity info
 * @dindex:	(in) the index of the data block being verified
 * @level:	(in) the level of hash we want
 * @hindex:	(out) the index of the hash block containing the wanted hash
 * @hoffset:	(out) the byte offset to the wanted hash within the hash block
 */
static void hash_at_level(const struct fsverity_info *vi, pgoff_t dindex,
			  unsigned int level, pgoff_t *hindex,
			  unsigned int *hoffset)
{
	pgoff_t hoffset_in_lvl;

	/*
	 * Compute the offset of the hash within the level's region, in hashes.
	 * For example, with 4096-byte blocks and 32-byte hashes, there are
	 * 4096/32 = 128 = 2^7 hashes per hash block, i.e. log_arity = 7.  Then,
	 * if the data block index is 65668 and we want the level 1 hash, it is
	 * located at 65668 >> 7 = 513 hashes into the level 1 region.
	 */
	hoffset_in_lvl = dindex >> (level * vi->log_arity);

	/*
	 * Compute the index of the hash block containing the wanted hash.
	 * Continuing the above example, the block would be at index 513 >> 7 =
	 * 4 within the level 1 region.  To this we'd add the index at which the
	 * level 1 region starts.
	 */
	*hindex = vi->hash_lvl_region_idx[level] +
		  (hoffset_in_lvl >> vi->log_arity);

	/*
	 * Finally, compute the index of the hash within the block rather than
	 * the region, and multiply by the hash size to turn it into a byte
	 * offset.  Continuing the above example, the hash would be at byte
	 * offset (513 & ((1 << 7) - 1)) * 32 = 32 within the block.
	 */
	*hoffset = (hoffset_in_lvl & ((1 << vi->log_arity) - 1)) *
		   vi->hash_alg->digest_size;
}

/* Extract a hash from a hash page */
static void extract_hash(struct page *hpage, unsigned int hoffset,
			 unsigned int hsize, u8 *out)
{
	void *virt = kmap_atomic(hpage);

	memcpy(out, virt + hoffset, hsize);
	kunmap_atomic(virt);
}

static int hash_page(struct fsverity_info *vi, struct page *page,
		     const struct fsverity_patch *patch, u8 *out)
{
	SHASH_DESC_ON_STACK(desc, vi->hash_alg->tfm);
	void *virt;
	int err;

	desc->tfm = vi->hash_alg->tfm;
	desc->flags = 0;

	err = crypto_shash_init(desc);
	if (err)
		return err;

	err = crypto_shash_update(desc, vi->salt, FS_VERITY_SALT_SIZE);
	if (err)
		return err;

	virt = kmap_atomic(page);
	if (patch) {
		unsigned int patch_offset = patch->offset;
		unsigned int patch_length = patch->length;
		unsigned int patch_skip = 0;

		if (patch->index != page->index) {
			/* Patch started on a prior page */
			BUG_ON(patch->index > page->index);
			patch_skip = (PAGE_SIZE - patch_offset) +
				     ((page->index - patch->index - 1) <<
				      PAGE_SHIFT);
			patch_offset = 0;
			patch_length -= patch_skip;
		}
		patch_length = min_t(unsigned int, patch_length,
				     PAGE_SIZE - patch_offset);

		err = crypto_shash_update(desc, virt, patch_offset);
		if (!err)
			err = crypto_shash_update(desc,
						  patch->patch + patch_skip,
						  patch_length);
		if (!err)
			err = crypto_shash_update(desc,
				virt + patch_offset + patch_length,
				PAGE_SIZE - patch_offset - patch_length);
	} else {
		/* Normal case: no patch, just hash the page */
		err = crypto_shash_update(desc, virt, PAGE_SIZE);
	}
	kunmap_atomic(virt);
	if (err)
		return err;

	return fsverity_finalize_hash(vi, desc, out);
}

/*
 * Find the patch, if any, that needs to be applied to the page at the specified
 * index when verifying.
 */
static const struct fsverity_patch *find_patch(struct fsverity_info *vi,
					       pgoff_t index)
{
#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
	const struct fsverity_patch *patch;

	list_for_each_entry(patch, &vi->patches, link) {
		if (index < patch->index)
			break; /* list is sorted, so can stop here */
		if (index <= (patch_end_byte(patch) - 1) >> PAGE_SHIFT)
			return patch;
	}
#endif
	return NULL;
}

/*
 * Determine whether the given page index is elided (bypasses verification).  If
 * so, return true.  Else, return false and adjust the page index to account for
 * any previous elisions.
 */
static bool page_elided(struct fsverity_info *vi, pgoff_t *index_p)
{
#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
	const struct fsverity_elision *elision;
	pgoff_t orig_idx = *index_p;
	pgoff_t elided_idx = *index_p;

	list_for_each_entry(elision, &vi->elisions, link) {
		if (orig_idx < elision->index)
			break; /* list is sorted, so can stop here */
		if (orig_idx < elision->index + elision->nr_pages)
			return true;
		elided_idx -= elision->nr_pages;
	}
	*index_p = elided_idx;
#endif
	return false;
}

static inline int compare_hashes(const u8 *want_hash, const u8 *real_hash,
				 int digest_size, struct inode *inode,
				 pgoff_t index, int level, const char *algname)
{
	if (memcmp(want_hash, real_hash, digest_size) == 0)
		return 0;

	pr_warn_ratelimited("VERIFICATION FAILURE!  ino=%lu, index=%lu, level=%d, want_hash=%*phN, real_hash=%*phN, alg=%s\n",
			    inode->i_ino, index, level, digest_size, want_hash,
			    digest_size, real_hash, algname);
	return -EBADMSG;
}

/**
 * fsverity_verify_page - verify a data page
 *
 * Verify the integrity and/or authenticity of a page that has just been read
 * from the file.  The page is assumed to be a pagecache page.
 *
 * Return: true if the page is valid, else false.
 */
bool fsverity_verify_page(struct page *data_page)
{
	struct address_space *mapping = data_page->mapping;
	struct inode *inode = mapping->host;
	struct fsverity_info *vi = get_fsverity_info(inode);
	pgoff_t index = data_page->index;
	int level = 0;
	u8 _want_hash[FS_VERITY_MAX_DIGEST_SIZE];
	u8 *want_hash = NULL;
	u8 real_hash[FS_VERITY_MAX_DIGEST_SIZE];
	struct page *hpages[FS_VERITY_MAX_LEVELS];
	unsigned int hoffsets[FS_VERITY_MAX_LEVELS];
	const struct fsverity_patch *patch;
	int err;

	/*
	 * It shouldn't be possible to get here without ->i_verity_info set,
	 * since it's set on ->open().
	 */
	if (WARN_ON_ONCE(!vi))
		return false;

	/* The page must not be unlocked until verification has completed. */
	if (WARN_ON_ONCE(!PageLocked(data_page)))
		return false;

#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
	/*
	 * Reads are forbidden if the measurement being enforced doesn't match
	 * the expected one.  Otherwise reads are allowed, but we warn if they
	 * are unauthenticated, i.e. if FS_IOC_SET_VERITY_MEASUREMENT hasn't
	 * been called yet.  (Some users need to use unauthenticated reads to
	 * find a signature stored in the file.  Allowing these doesn't actually
	 * decrease security, since an attacker could just replace the file with
	 * a non-verity one anyway.)
	 */
	switch (vi->mode) {
	case FS_VERITY_MODE_NEED_AUTHENTICATION:
		pr_warn_ratelimited("Unauthenticated read; ino=%lu, index=%lu\n",
				    inode->i_ino, index);
		break;
	case FS_VERITY_MODE_AUTHENTICATION_FAILED:
		pr_warn("Root authentication failed, failing read; inode=%lu, index=%lu\n",
			inode->i_ino, index);
		return false;
	case FS_VERITY_MODE_AUTHENTICATED:
	case FS_VERITY_MODE_INTEGRITY_ONLY:
		break;
	default:
		WARN_ON_ONCE(1);
		return false;
	}
#endif /* CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY */

	/*
	 * Since ->i_size is overridden with ->data_i_size, and fs-verity avoids
	 * recursing into itself when reading hash pages, we shouldn't normally
	 * get here with a page beyond ->data_i_size.  But, it can happen if a
	 * read is issued at or beyond EOF since the VFS doesn't check i_size
	 * before calling ->readpage().  Thus, just skip verification if the
	 * page is beyond ->data_i_size.
	 */
	if (index >= (vi->data_i_size + PAGE_SIZE - 1) >> PAGE_SHIFT) {
		pr_debug("Page %lu is in metadata region\n", index);
		return true;
	}

	patch = find_patch(vi, index);
	if (patch)
		pr_debug("Selected patch: index=%lu, offset=%u, length=%u for page index %lu\n",
			 patch->index, patch->offset, patch->length, index);

	if (page_elided(vi, &index)) {
		pr_debug("Page %lu is elided, not verifying!\n", index);
		return true;
	}
	if (index != data_page->index)
		pr_debug_ratelimited("Adjusted index because of elisions: %lu => %lu\n",
				     data_page->index, index);

	pr_debug_ratelimited("Verifying data page %lu...\n", index);

	/*
	 * Starting at the leaves, ascend the tree saving hash pages along the
	 * way until we find a verified hash page, indicated by PageChecked; or
	 * until we reach the root.
	 */
	for (level = 0; level < vi->depth; level++) {
		pgoff_t hindex;
		unsigned int hoffset;
		struct page *hpage;

		hash_at_level(vi, index, level, &hindex, &hoffset);

		pr_debug_ratelimited("Level %d: hindex=%lu, hoffset=%u\n",
				     level, hindex, hoffset);

		hpage = inode->i_sb->s_vop->read_metadata_page(inode, hindex);
		if (IS_ERR(hpage)) {
			err = PTR_ERR(hpage);
			goto out;
		}

		if (PageChecked(hpage)) {
			want_hash = _want_hash;
			extract_hash(hpage, hoffset, vi->hash_alg->digest_size,
				     want_hash);
			put_page(hpage);
			pr_debug_ratelimited("Hash page already checked, want %s %*phN\n",
					     vi->hash_alg->friendly_name,
					     vi->hash_alg->digest_size,
					     want_hash);
			break;
		}
		pr_debug_ratelimited("Hash page not yet checked\n");
		hpages[level] = hpage;
		hoffsets[level] = hoffset;
	}

	if (!want_hash) {
		want_hash = vi->root_hash;
		pr_debug("Want root hash: %s %*phN\n",
			 vi->hash_alg->friendly_name, vi->hash_alg->digest_size,
			 want_hash);
	}

	/* Descend the tree verifying hash pages */
	for (; level > 0; level--) {
		struct page *hpage = hpages[level - 1];
		unsigned int hoffset = hoffsets[level - 1];

		err = hash_page(vi, hpage, NULL, real_hash);
		if (err)
			goto out;
		err = compare_hashes(want_hash, real_hash,
				     vi->hash_alg->digest_size,
				     inode, index, level - 1,
				     vi->hash_alg->friendly_name);
		if (err)
			goto out;
		SetPageChecked(hpage);
		want_hash = _want_hash;
		extract_hash(hpage, hoffset, vi->hash_alg->digest_size,
			     want_hash);
		put_page(hpage);
		pr_debug("Verified hash page at level %d, now want %s %*phN\n",
			 level - 1, vi->hash_alg->friendly_name,
			 vi->hash_alg->digest_size, want_hash);
	}

	/* Finally, verify the data page */
	err = hash_page(vi, data_page, patch, real_hash);
	if (err)
		goto out;
	err = compare_hashes(want_hash, real_hash, vi->hash_alg->digest_size,
			     inode, index, -1, vi->hash_alg->friendly_name);
out:
	for (; level > 0; level--)
		put_page(hpages[level - 1]);
	if (err) {
		pr_warn_ratelimited("Error verifying page; ino=%lu, index=%lu (err=%d)\n",
				    inode->i_ino, data_page->index, err);
		return false;
	}
	return true;
}
EXPORT_SYMBOL_GPL(fsverity_verify_page);

/**
 * fsverity_verify_bio - verify a 'read' bio that has just completed
 *
 * Verify the integrity and/or authenticity of a set of pages that have just
 * been read from the file.  The pages are assumed to be pagecache pages.  Pages
 * that fail verification are set to the Error state.  Verification is skipped
 * for pages already in the Error state, e.g. due to fscrypt decryption failure.
 */
void fsverity_verify_bio(struct bio *bio)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (!PageError(page) && !fsverity_verify_page(page))
			SetPageError(page);
	}
}
EXPORT_SYMBOL_GPL(fsverity_verify_bio);

/**
 * fsverity_enqueue_verify_work - enqueue work on the fs-verity workqueue
 *
 * Enqueue verification work for asynchronous processing.
 */
void fsverity_enqueue_verify_work(struct work_struct *work)
{
	queue_work(fsverity_read_workqueue, work);
}
EXPORT_SYMBOL_GPL(fsverity_enqueue_verify_work);
