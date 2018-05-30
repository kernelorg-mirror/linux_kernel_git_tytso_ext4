// SPDX-License-Identifier: GPL-2.0
/*
 * fs-verity: read-only file-based integrity/authenticity
 *
 * setup.c: fs-verity module initialization, footer parsing, and signature
 *	    verification
 *
 * Copyright (C) 2018, Google, Inc.
 *
 * Originally written by Jaegeuk Kim and Michael Halcrow;
 * heavily rewritten by Eric Biggers.
 */

#include "fsverity_private.h"

#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <linux/highmem.h>
#include <linux/list_sort.h>
#include <linux/module.h>
#include <linux/ratelimit.h>
#include <linux/verification.h>
#include <linux/vmalloc.h>

static struct kmem_cache *fsverity_info_cachep;

static void dump_fsverity_footer(const struct fsverity_footer *ftr)
{
	pr_debug("magic = %.*s\n", (int)sizeof(ftr->magic), ftr->magic);
	pr_debug("major_version = %u\n", ftr->major_version);
	pr_debug("minor_version = %u\n", ftr->minor_version);
	pr_debug("log_blocksize = %u\n", ftr->log_blocksize);
	pr_debug("log_arity = %u\n", ftr->log_arity);
	pr_debug("meta_algorithm = %u\n", le16_to_cpu(ftr->meta_algorithm));
	pr_debug("data_algorithm = %u\n", le16_to_cpu(ftr->data_algorithm));
	pr_debug("flags = %#x\n", le32_to_cpu(ftr->flags));
	pr_debug("size = %llu\n", le64_to_cpu(ftr->size));
	pr_debug("authenticated_ext_count = %u\n",
		 ftr->authenticated_ext_count);
	pr_debug("unauthenticated_ext_count = %u\n",
		 ftr->unauthenticated_ext_count);
	pr_debug("salt = %*phN\n", (int)sizeof(ftr->salt), ftr->salt);
}

#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
static int parse_elide_extension(struct fsverity_info *vi,
				 const void *_ext, size_t extra_len)
{
	const struct fsverity_extension_elide *ext = _ext;
	u64 offset = le64_to_cpu(ext->offset);
	u64 length = le64_to_cpu(ext->length);
	struct fsverity_elision *elision;

	pr_debug("Found elide extension: offset=%llu, length=%llu\n",
		 offset, length);

	if ((offset | length) & ~PAGE_MASK) {
		pr_warn("Misaligned elision (offset=%llu, length=%llu)\n",
			offset, length);
		return -EINVAL;
	}

	if (length < 1) {
		pr_warn("Empty elision\n");
		return -EINVAL;
	}

	if (offset >= vi->data_i_size || length > vi->data_i_size - offset) {
		pr_warn("Elision offset and/or length too large (offset=%llu, length=%llu)\n",
			offset, length);
		return -EINVAL;
	}

	if (length >= vi->elided_i_size) {
		pr_warn("Entire file is elided!\n");
		return -EINVAL;
	}

	elision = kmalloc(sizeof(*elision), GFP_NOFS);
	if (!elision)
		return -ENOMEM;

	elision->index = offset >> PAGE_SHIFT;
	elision->nr_pages = length >> PAGE_SHIFT;
	list_add_tail(&elision->link, &vi->elisions);
	vi->elided_i_size -= length;
	return 0;
}

static int cmp_elisions(void *priv, struct list_head *_a, struct list_head *_b)
{
	const struct fsverity_elision *a, *b;

	a = list_entry(_a, struct fsverity_elision, link);
	b = list_entry(_b, struct fsverity_elision, link);
	if (a->index > b->index)
		return 1;
	if (a->index < b->index)
		return -1;
	return 0;
}

/*
 * Sort the elisions (if any) in order of increasing offset, then verify they
 * don't overlap.
 */
static int sort_and_check_elisions(struct fsverity_info *vi)
{
	const struct fsverity_elision *elision;
	pgoff_t next_unelided_index = 0;

	list_sort(NULL, &vi->elisions, cmp_elisions);

	list_for_each_entry(elision, &vi->elisions, link) {
		if (elision->index < next_unelided_index) {
			pr_warn("Elisions overlap\n");
			return -EINVAL;
		}
		next_unelided_index = elision->index + elision->nr_pages;
	}
	return 0;
}

static int parse_patch_extension(struct fsverity_info *vi,
				 const void *_ext, size_t extra_len)
{
	const struct fsverity_extension_patch *ext = _ext;
	u64 offset = le64_to_cpu(ext->offset);
	struct fsverity_patch *patch;

	pr_debug("Found patch extension: offset=%llu, length=%zu\n",
		 offset, extra_len);

	if (extra_len < 1) {
		pr_warn("Patch is empty\n");
		return -EINVAL;
	}

	if (extra_len > FS_VERITY_MAX_PATCH_SIZE) {
		pr_warn("Patch is too long (got %zu, limit is %d)\n",
			extra_len, FS_VERITY_MAX_PATCH_SIZE);
		return -EINVAL;
	}

	if (offset >= vi->data_i_size || extra_len > vi->data_i_size - offset) {
		pr_warn("Patch offset is too large (%llu)\n", offset);
		return -EINVAL;
	}

	pr_debug("databytes=%*phN\n", (int)extra_len, ext->databytes);

	patch = kmalloc(sizeof(*patch) + extra_len, GFP_NOFS);
	if (!patch)
		return -ENOMEM;
	patch->index = offset >> PAGE_SHIFT;
	patch->offset = offset & ~PAGE_MASK;
	patch->length = extra_len;
	memcpy(patch->patch, ext->databytes, extra_len);
	list_add_tail(&patch->link, &vi->patches);
	return 0;
}

static int cmp_patches(void *priv, struct list_head *_a, struct list_head *_b)
{
	const struct fsverity_patch *a, *b;

	a = list_entry(_a, struct fsverity_patch, link);
	b = list_entry(_b, struct fsverity_patch, link);
	if (a->index > b->index)
		return 1;
	if (a->index < b->index)
		return -1;
	return 0;
}

/*
 * Sort the patches (if any) in order of increasing offset, then verify they
 * don't overlap and that no page has multiple patches.
 */
static int sort_and_check_patches(struct fsverity_info *vi)
{
	const struct fsverity_patch *patch;
	u64 next_unpatched_byte = 0;
	pgoff_t prev_patched_index = 0;

	list_sort(NULL, &vi->patches, cmp_patches);

	list_for_each_entry(patch, &vi->patches, link) {
		u64 begin = patch_begin_byte(patch);
		u64 end = patch_end_byte(patch);

		if (begin < next_unpatched_byte) {
			pr_warn("Patches overlap\n");
			return -EINVAL;
		}
		if (next_unpatched_byte != 0 &&
		    patch->index <= prev_patched_index) {
			pr_warn("Multiple patches per page\n");
			return -EINVAL;
		}
		next_unpatched_byte = end;
		prev_patched_index = (end - 1) >> PAGE_SHIFT;
	}
	return 0;
}
#endif /* CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY */

const struct fsverity_hash_alg *
fsverity_check_measurement_struct(const struct fsverity_measurement *m)
{
	const struct fsverity_hash_alg *hash_alg;

	if (m->reserved1 ||
	    memchr_inv(m->reserved2, 0, sizeof(m->reserved2))) {
		pr_warn("Reserved fields are set in fsverity_measurement\n");
		return ERR_PTR(-EINVAL);
	}

	hash_alg = fsverity_get_hash_alg(m->digest_algorithm);
	if (IS_ERR(hash_alg))
		return hash_alg;

	if (m->digest_size != hash_alg->digest_size) {
		pr_warn("Wrong digest_size in fsverity_measurement: wanted %u for algorithm %s, but got %u\n",
			hash_alg->digest_size, hash_alg->friendly_name,
			m->digest_size);
		return ERR_PTR(-EINVAL);
	}

	return hash_alg;
}

static int extract_measurement(void *ctx, const void *data, size_t len,
			       size_t asn1hdrlen)
{
	struct fsverity_info *vi = ctx;
	const struct fsverity_measurement *m;
	const struct fsverity_hash_alg *hash_alg;

	len -= asn1hdrlen;
	data += asn1hdrlen;
	if (len < sizeof(struct fsverity_measurement)) {
		pr_warn("Signed file measurement has unrecognized format\n");
		return -EBADMSG;
	}
	m = (const void *)data;

	hash_alg = fsverity_check_measurement_struct(m);
	if (IS_ERR(hash_alg))
		return PTR_ERR(hash_alg);

	if (len < sizeof(*m) + hash_alg->digest_size) {
		pr_warn("Signed file measurement is truncated\n");
		return -EBADMSG;
	}

	if (hash_alg != vi->hash_alg) {
		pr_warn("Signed file measurement uses %s, but file uses %s\n",
			hash_alg->friendly_name, vi->hash_alg->friendly_name);
		return -EBADMSG;
	}

	memcpy(vi->measurement, m->digest, hash_alg->digest_size);
	vi->have_trusted_measurement = true;
	return 0;
}

/**
 * parse_pkcs7_signature_extension - verify the signed file measurement
 *
 * Verify a signed fsverity_measurement against the kernel's builtin trusted
 * keys.  The signature is given as a PKCS#7 formatted message, and the signed
 * data is included in the message (not detached).
 *
 * Return: 0 if the signature checks out and the fsverity_measurement is
 * well-formed and uses the expected hash algorithm; -EBADMSG on signature
 * verification or malformed data; else another -errno code.
 */
static int parse_pkcs7_signature_extension(struct fsverity_info *vi,
					   const void *_ext, size_t extra_len)
{
	int err;

	if (vi->have_trusted_measurement) {
		pr_warn("Found multiple PKCS#7 signatures\n");
		return -EBADMSG;
	}

	err = verify_pkcs7_signature(NULL, 0, _ext, extra_len, NULL,
				     VERIFYING_UNSPECIFIED_SIGNATURE,
				     extract_measurement, vi);
	if (err)
		pr_warn("PKCS#7 signature verification error: %d\n", err);

	return err;
}

/*
 * The available types of extension items: variable-length metadata items that
 * can follow the fixed-size portion of the fs-verity footer.
 *
 * Extensions can be either authenticated or unauthenticated.  Authenticated
 * extensions are included in the file measurement, while unauthenticated
 * extensions are not.  By default extensions are authenticated; unauthenticated
 * extensions must be explicitly marked as such.  Unauthenticated extensions are
 * needed for metadata involved in establishing the root of trust itself, such
 * as the PKCS#7 signature.  Authenticated extensions are stored first, directly
 * following the fixed-size portion of the fs-verity footer; unauthenticated
 * extensions come afterwards.
 */
static const struct extension_type {
	int (*parse)(struct fsverity_info *vi, const void *_ext,
		     size_t extra_len);
	size_t base_len;
	bool unauthenticated;
} extension_types[] = {
#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
	[FS_VERITY_EXT_ELIDE] = {
		.parse = parse_elide_extension,
		.base_len = sizeof(struct fsverity_extension_elide),
	},
	[FS_VERITY_EXT_PATCH] = {
		.parse = parse_patch_extension,
		.base_len = sizeof(struct fsverity_extension_patch),
	},
#endif
	[FS_VERITY_EXT_PKCS7_SIGNATURE] = {
		.parse = parse_pkcs7_signature_extension,
		.base_len = 0,
		.unauthenticated = true,
	},
};

/*
 * Parse the extension items, if any, following the fixed-size portion of the
 * fs-verity footer.  The fsverity_info is updated accordingly.
 *
 * Return: On success, the size of the authenticated portion of the footer (the
 *         fixed-size portion plus the authenticated extensions).
 *         Otherwise, a -errno value.
 */
static int parse_extensions(struct fsverity_info *vi,
			    const struct fsverity_footer *ftr, int ftr_len)
{
	const struct fsverity_extension *ext_hdr = (const void *)(ftr + 1);
	const void * const end = (const void *)ftr + ftr_len;
	const void *auth_end = ext_hdr;
	int i;
	int err;
	int num_extensions = ftr->authenticated_ext_count +
			     ftr->unauthenticated_ext_count;

	for (i = 0; i < num_extensions; i++) {
		const struct extension_type *type;
		u32 len, rounded_len;
		u16 type_code;
		bool unauthenticated = (i >= ftr->authenticated_ext_count);

		if (end - (const void *)ext_hdr < sizeof(*ext_hdr)) {
			pr_warn("Extension list overflows buffer\n");
			return -EINVAL;
		}
		type_code = le16_to_cpu(ext_hdr->type);
		if (type_code >= ARRAY_SIZE(extension_types) ||
		    !extension_types[type_code].parse) {
			pr_warn("Unknown extension type: %u\n", type_code);
			return -EINVAL;
		}
		type = &extension_types[type_code];
		if (unauthenticated != type->unauthenticated) {
			pr_warn("Extension type %u must be %sauthenticated\n",
				type_code, type->unauthenticated ? "un" : "");
			return -EINVAL;
		}
		if (ext_hdr->reserved) {
			pr_warn("Reserved bits set in extension header\n");
			return -EINVAL;
		}
		len = le32_to_cpu(ext_hdr->length);
		if (len < sizeof(*ext_hdr)) {
			pr_warn("Invalid length in extension header\n");
			return -EINVAL;
		}
		rounded_len = round_up(len, 8);
		if (rounded_len == 0 ||
		    rounded_len > end - (const void *)ext_hdr) {
			pr_warn("Extension item overflows buffer\n");
			return -EINVAL;
		}
		if (len < sizeof(*ext_hdr) + type->base_len) {
			pr_warn("Extension length too small for type\n");
			return -EINVAL;
		}
		err = type->parse(vi, ext_hdr + 1,
				  len - sizeof(*ext_hdr) - type->base_len);
		if (err)
			return err;
		ext_hdr = (const void *)ext_hdr + rounded_len;
		if (!unauthenticated)
			auth_end = ext_hdr;
	}

#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
	err = sort_and_check_elisions(vi);
	if (err)
		return err;

	err = sort_and_check_patches(vi);
	if (err)
		return err;
#endif

	return auth_end - (const void *)ftr;
}
/*
 * Parse an fs-verity footer, loading information into the fsverity_info.
 *
 * Return: On success, the size of the authenticated portion of the footer (the
 *         fixed-size portion plus the authenticated extensions).
 *         Otherwise, a -errno value.
 */
static int parse_footer(struct fsverity_info *vi,
			const struct fsverity_footer *ftr, int ftr_len,
			loff_t ftr_start)
{
	unsigned int alg_num;

	/* magic */
	if (memcmp(ftr->magic, FS_VERITY_MAGIC, sizeof(ftr->magic))) {
		pr_warn("fs-verity footer not found\n");
		return -EINVAL;
	}

	/* major_version */
	if (ftr->major_version != FS_VERITY_MAJOR) {
		pr_warn("Unsupported major version (%u)\n", ftr->major_version);
		return -EINVAL;
	}

	/* minor_version */
	if (ftr->minor_version != FS_VERITY_MINOR) {
		pr_warn("Unsupported minor version (%u)\n", ftr->minor_version);
		return -EINVAL;
	}

	/* data_algorithm and meta_algorithm */
	alg_num = le16_to_cpu(ftr->data_algorithm);
	if (alg_num != le16_to_cpu(ftr->meta_algorithm)) {
		pr_warn("Unimplemented case: data (%u) and metadata (%u) hash algorithms differ\n",
			alg_num, le16_to_cpu(ftr->meta_algorithm));
		return -EINVAL;
	}
	vi->hash_alg = fsverity_get_hash_alg(alg_num);
	if (IS_ERR(vi->hash_alg))
		return PTR_ERR(vi->hash_alg);

	/* log_blocksize */
	if (ftr->log_blocksize != PAGE_SHIFT) {
		pr_warn("Unsupported log_blocksize (%u).  Need block_size == PAGE_SIZE.\n",
			ftr->log_blocksize);
		return -EINVAL;
	}
	vi->block_bits = ftr->log_blocksize;

	/* log_arity */
	vi->log_arity = ftr->log_arity;
	if (vi->log_arity !=
	    vi->block_bits - ilog2(vi->hash_alg->digest_size)) {
		pr_warn("Unsupported log_arity (%u)\n", vi->log_arity);
		return -EINVAL;
	}

	/* flags */
	vi->flags = le32_to_cpu(ftr->flags);
	if (vi->flags & ~FS_VERITY_FLAG_INTEGRITY_ONLY) {
		pr_warn("Unsupported flags (%#x)\n", vi->flags);
		return -EINVAL;
	}

	/* reserved fields */
	if (ftr->reserved1 ||
	    memchr_inv(ftr->reserved2, 0, sizeof(ftr->reserved2))) {
		pr_warn("Reserved bits set in footer\n");
		return -EINVAL;
	}

	/* size */
	vi->data_i_size = le64_to_cpu(ftr->size);
	if (vi->data_i_size == 0) {
		pr_warn("Original file size is 0; this is not supported\n");
		return -EINVAL;
	}
	if (vi->data_i_size > ftr_start) {
		pr_warn("Original file size is too large (%llu)\n",
			vi->data_i_size);
		return -EINVAL;
	}
	vi->elided_i_size = vi->data_i_size;

	/* salt */
	memcpy(vi->salt, ftr->salt, FS_VERITY_SALT_SIZE);

	/* extensions */
	return parse_extensions(vi, ftr, ftr_len);
}

/*
 * Calculate the depth of the Merkle tree, then create a map from level to the
 * block offset at which that level's hash blocks start.  Level 'depth - 1' is
 * the root and is stored first in the file, in the first block following the
 * original data.  Level 0 is the level directly "above" the data blocks and is
 * stored last in the file, just before the fs-verity footer.
 */
static int compute_tree_depth_and_offsets(struct fsverity_info *vi)
{
	unsigned int hashes_per_block = 1 << vi->log_arity;
	u64 blocks = (vi->elided_i_size + (1 << vi->block_bits) - 1) >>
			vi->block_bits;
	u64 offset = (vi->data_i_size + (1 << vi->block_bits) - 1) >>
			vi->block_bits;
	int depth = 0;
	int i;

	while (blocks > 1) {
		if (depth >= FS_VERITY_MAX_LEVELS) {
			pr_warn("Too many tree levels (max is %d)\n",
				FS_VERITY_MAX_LEVELS);
			return -EINVAL;
		}
		blocks = (blocks + hashes_per_block - 1) >> vi->log_arity;
		vi->hash_lvl_region_idx[depth++] = blocks;
	}
	vi->depth = depth;
	pr_debug("depth = %d\n", depth);

	for (i = depth - 1; i >= 0; i--) {
		u64 next_count = vi->hash_lvl_region_idx[i];

		vi->hash_lvl_region_idx[i] = offset;
		pr_debug("Level %d is [%llu..%llu] (%llu blocks)\n",
			 i, offset, offset + next_count - 1, next_count);
		offset += next_count;
	}
	return 0;
}

static pgoff_t first_unelided_page(struct fsverity_info *vi)
{
	pgoff_t index = 0;
#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
	const struct fsverity_elision *elision;

	list_for_each_entry(elision, &vi->elisions, link) {
		if (index != elision->index)
			break;
		index += elision->nr_pages;
	}
#endif
	return index;
}

/*
 * Compute the hash of the root of the Merkle tree (or of the lone data block
 * for files <= blocksize in length) and store it in vi->root_hash.
 */
static int compute_root_hash(struct inode *inode, struct fsverity_info *vi)
{
	SHASH_DESC_ON_STACK(desc, vi->hash_alg->tfm);
	struct page *root_page;
	pgoff_t root_idx;
	int err;

	desc->tfm = vi->hash_alg->tfm;
	desc->flags = 0;

	if (vi->depth)
		root_idx = vi->hash_lvl_region_idx[vi->depth - 1];
	else
		root_idx = first_unelided_page(vi);

	root_page = inode->i_sb->s_vop->read_metadata_page(inode, root_idx);
	if (IS_ERR(root_page)) {
		pr_warn("Error reading root block: %ld\n", PTR_ERR(root_page));
		return PTR_ERR(root_page);
	}

	err = crypto_shash_init(desc);
	if (!err)
		err = crypto_shash_update(desc, vi->salt, FS_VERITY_SALT_SIZE);
	if (!err) {
		/* atomic, since we aren't using CRYPTO_TFM_REQ_MAY_SLEEP */
		void *root = kmap_atomic(root_page);

		err = crypto_shash_update(desc, root, PAGE_SIZE);
		kunmap_atomic(root);
	}
	if (!err)
		err = fsverity_finalize_hash(vi, desc, vi->root_hash);

	if (err)
		pr_warn("Error computing Merkle tree root hash: %d\n", err);
	else
		pr_debug("Computed Merkle tree root hash: %s %*phN\n",
			 vi->hash_alg->friendly_name,
			 vi->hash_alg->digest_size, vi->root_hash);
	put_page(root_page);

	if (vi->depth == 0) {
		/*
		 * The data page must not be left in the page cache, otherwise
		 * it would appear to have been verified.
		 */
		truncate_inode_pages_range(inode->i_mapping,
				   (loff_t)root_idx << PAGE_SHIFT,
				   (((loff_t)root_idx + 1) << PAGE_SHIFT) - 1);
	}

	return err;
}

static int compute_measurement(struct fsverity_info *vi,
			       const struct fsverity_footer *ftr,
			       int ftr_auth_len, u8 *measurement)
{
	SHASH_DESC_ON_STACK(desc, vi->hash_alg->tfm);
	int err;

	desc->tfm = vi->hash_alg->tfm;
	desc->flags = 0;

	err = crypto_shash_init(desc);
	if (!err)
		err = crypto_shash_update(desc, (const u8 *)ftr, ftr_auth_len);
	if (!err)
		err = crypto_shash_update(desc, vi->root_hash,
					  vi->hash_alg->digest_size);
	if (!err)
		err = fsverity_finalize_hash(vi, desc, measurement);

	if (err)
		pr_warn("Error computing fs-verity measurement: %d\n", err);
	return err;
}

/*
 * Verify that the file's actual measurement matches the signed file measurement
 * from the fs-verity footer.  The "measurement" is a hash of the concatenation
 * of the hash of the Merkle tree root block, and the authenticated portion of
 * the fs-verity footer.  In other words it represents the identity of the file
 * contents which fs-verity will validate at read time, along with parameters
 * involved in that validation such as the hash algorithm.
 */
static int verify_file_measurement(struct fsverity_info *vi,
				   const struct fsverity_footer *ftr,
				   int ftr_auth_len)
{
	u8 measurement[FS_VERITY_MAX_DIGEST_SIZE];
	int err;

	if (vi->flags & FS_VERITY_FLAG_INTEGRITY_ONLY) {
#ifdef CONFIG_FS_VERITY_INTEGRITY_ONLY
		pr_warn("Using experimental integrity-only mode!\n");
		return 0;
#else
		pr_warn("Integrity-only mode not supported\n");
		return -EBADMSG;
#endif
	}

	err = compute_measurement(vi, ftr, ftr_auth_len, measurement);
	if (err)
		return err;

	if (!vi->have_trusted_measurement) {
#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
		/*
		 * Allow proceeding with no signature if userspace signature
		 * verification is enabled.  Userspace must instead call
		 * FS_IOC_SET_VERITY_MEASUREMENT to provide the trusted
		 * measurement.
		 */
		vi->mode = FS_VERITY_MODE_NEED_AUTHENTICATION;
		memcpy(vi->measurement, measurement, vi->hash_alg->digest_size);
		pr_debug("Computed measurement: %s %*phN (used ftr_auth_len %d)\n",
			 vi->hash_alg->friendly_name,
			 vi->hash_alg->digest_size, measurement,
			 ftr_auth_len);
		return 0;
#else
		pr_warn("No signature found, measurement is %s %*phN\n",
			vi->hash_alg->friendly_name,
			vi->hash_alg->digest_size, measurement);
		return -EBADMSG;
#endif
	}

	if (!memcmp(measurement, vi->measurement, vi->hash_alg->digest_size)) {
		pr_debug("Verified measurement: %s %*phN (used ftr_auth_len %d)\n",
			 vi->hash_alg->friendly_name,
			 vi->hash_alg->digest_size, measurement, ftr_auth_len);
#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
		vi->mode = FS_VERITY_MODE_AUTHENTICATED;
#endif
		return 0;
	}

	pr_warn("FILE CORRUPTED (actual measurement mismatches signed measurement): "
		"want %s %*phN, real %s %*phN (used ftr_auth_len %d)\n",
		vi->hash_alg->friendly_name,
		vi->hash_alg->digest_size, vi->measurement,
		vi->hash_alg->friendly_name,
		vi->hash_alg->digest_size, measurement, ftr_auth_len);
	return -EBADMSG;
}

static struct fsverity_info *alloc_fsverity_info(void)
{
	struct fsverity_info *vi;

	vi = kmem_cache_zalloc(fsverity_info_cachep, GFP_NOFS);
	if (!vi)
		return NULL;
#ifdef CONFIG_FS_VERITY_USERSPACE_SIG_VERIFY
	INIT_LIST_HEAD(&vi->elisions);
	INIT_LIST_HEAD(&vi->patches);
#endif
	return vi;
}

/* Arbitrary limit */
#define MAX_FOOTER_PAGES	16

void free_fsverity_info(struct fsverity_info *vi)
{
	if (!vi)
		return;
	kmem_cache_free(fsverity_info_cachep, vi);
}

/**
 * map_fsverity_footer - map an inode's fs-verity footer into memory
 *
 * If the footer fits in one page, we use kmap; otherwise we use vmap.
 * unmap_fsverity_footer() must be called to unmap it.
 *
 * It's assumed that the file contents cannot be modified concurrently.
 * (This is guaranteed by either deny_write_access() or by the verity bit.)
 *
 * Return: the virtual address of the start of the footer, in virtually
 * contiguous memory.  Also fills in ftr_pages and returns in *ftr_len the
 * length of the footer including all extensions, and in *ftr_start the offset
 * of the footer from the start of the file, in bytes.
 */
static const struct fsverity_footer *
map_fsverity_footer(struct inode *inode, loff_t full_isize,
		    struct page *ftr_pages[MAX_FOOTER_PAGES],
		    int *nr_ftr_pages, int *ftr_len, loff_t *ftr_start)
{
	const int last_validsize = ((full_isize - 1) & ~PAGE_MASK) + 1;
	const pgoff_t last_pgoff = (full_isize - 1) >> PAGE_SHIFT;
	struct page *last_page;
	const void *last_virt;
	pgoff_t first_pgoff;
	u32 ftr_reverse_offset;
	pgoff_t pgoff;
	const void *ftr_virt;
	int i;
	int err;

	*nr_ftr_pages = 0;
	*ftr_len = 0;
	*ftr_start = 0;

	if (full_isize <= 0) {
		pr_warn("File is empty!\n");
		return ERR_PTR(-EINVAL);
	}

	/*
	 * The footer size is given by the ftr_reverse_offset field in the last
	 * 4 bytes of the file.
	 */
	if (last_validsize < sizeof(__le32)) {
		pr_warn("Misaligned ftr_reverse_offset\n");
		return ERR_PTR(-EINVAL);
	}
	last_page = inode->i_sb->s_vop->read_metadata_page(inode, last_pgoff);
	if (IS_ERR(last_page)) {
		pr_warn("Error reading footer page: %ld\n", PTR_ERR(last_page));
		return ERR_CAST(last_page);
	}
	last_virt = kmap(last_page);
	ftr_reverse_offset = get_unaligned_le32(last_virt + last_validsize -
						sizeof(__le32));
	if (ftr_reverse_offset <
	    sizeof(struct fsverity_footer) + sizeof(__le32) ||
	    ftr_reverse_offset > full_isize) {
		pr_warn("Unexpected ftr_reverse_offset: %u\n",
			ftr_reverse_offset);
		err = -EINVAL;
		goto err_out;
	}
	*ftr_start = full_isize - ftr_reverse_offset;
	if (*ftr_start & 7) {
		pr_warn("fs-verity footer is misaligned (ftr_start=%lld)\n",
			*ftr_start);
		err = -EINVAL;
		goto err_out;
	}

	first_pgoff = *ftr_start >> PAGE_SHIFT;
	if (last_pgoff - first_pgoff >= MAX_FOOTER_PAGES) {
		pr_warn("fs-verity footer is too long (%lu pages)\n",
			last_pgoff - first_pgoff + 1);
		err = -EINVAL;
		goto err_out;
	}

	*ftr_len = ftr_reverse_offset - sizeof(__le32);

	if (first_pgoff == last_pgoff) {
		/* Single-page footer; just use the already-kmapped last page */
		ftr_pages[0] = last_page;
		*nr_ftr_pages = 1;
		return last_virt + (*ftr_start & ~PAGE_MASK);
	}

	/* Multi-page footer; map the additional pages into memory */

	for (pgoff = first_pgoff; pgoff < last_pgoff; pgoff++) {
		struct page *page;

		page = inode->i_sb->s_vop->read_metadata_page(inode, pgoff);
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			pr_warn("Error reading footer page: %d\n", err);
			goto err_out;
		}
		ftr_pages[(*nr_ftr_pages)++] = page;
	}

	ftr_pages[(*nr_ftr_pages)++] = last_page;
	kunmap(last_page);
	last_page = NULL;

	ftr_virt = vmap(ftr_pages, *nr_ftr_pages, VM_MAP, PAGE_KERNEL_RO);
	if (!ftr_virt) {
		err = -ENOMEM;
		goto err_out;
	}

	return ftr_virt + (*ftr_start & ~PAGE_MASK);

err_out:
	for (i = 0; i < *nr_ftr_pages; i++)
		put_page(ftr_pages[i]);
	if (last_page) {
		kunmap(last_page);
		put_page(last_page);
	}
	return ERR_PTR(err);
}

static void unmap_fsverity_footer(const struct fsverity_footer *ftr,
				  struct page *ftr_pages[MAX_FOOTER_PAGES],
				  int nr_ftr_pages)
{
	int i;

	if (is_vmalloc_addr(ftr)) {
		vunmap((void *)((unsigned long)ftr & PAGE_MASK));
	} else {
		WARN_ON(nr_ftr_pages != 1);
		kunmap(ftr_pages[0]);
	}
	for (i = 0; i < nr_ftr_pages; i++)
		put_page(ftr_pages[i]);
}

/*
 * Read the file's fs-verity footer and create an fsverity_info for it.
 */
struct fsverity_info *create_fsverity_info(struct inode *inode)
{
	loff_t full_isize = i_size_read(inode);
	struct fsverity_info *vi;
	const struct fsverity_footer *ftr;
	struct page *ftr_pages[MAX_FOOTER_PAGES];
	int nr_ftr_pages;
	int ftr_len;
	loff_t ftr_start;
	int ftr_auth_len;
	int err;

	vi = alloc_fsverity_info();
	if (!vi)
		return ERR_PTR(-ENOMEM);
	vi->full_i_size = full_isize;

	ftr = map_fsverity_footer(inode, full_isize, ftr_pages, &nr_ftr_pages,
				  &ftr_len, &ftr_start);
	if (IS_ERR(ftr)) {
		err = PTR_ERR(ftr);
		ftr = NULL;
		goto out;
	}

	dump_fsverity_footer(ftr);
	ftr_auth_len = parse_footer(vi, ftr, ftr_len, ftr_start);
	if (ftr_auth_len < 0) {
		err = ftr_auth_len;
		goto out;
	}

	err = compute_tree_depth_and_offsets(vi);
	if (err)
		goto out;
	err = compute_root_hash(inode, vi);
	if (err)
		goto out;
	err = verify_file_measurement(vi, ftr, ftr_auth_len);
out:
	if (ftr)
		unmap_fsverity_footer(ftr, ftr_pages, nr_ftr_pages);
	if (err) {
		free_fsverity_info(vi);
		vi = ERR_PTR(err);
	}
	return vi;
}

/* Ensure the inode has an ->i_verity_info */
static int setup_fsverity_info(struct inode *inode)
{
	struct fsverity_info *vi = get_fsverity_info(inode);

	if (vi)
		return 0;

	vi = create_fsverity_info(inode);
	if (IS_ERR(vi))
		return PTR_ERR(vi);

	if (!set_fsverity_info(inode, vi))
		free_fsverity_info(vi);
	return 0;
}

/**
 * fsverity_file_open - prepare to open an fs-verity file
 * @inode: the inode being opened
 * @filp: the struct file being set up
 *
 * When opening an fs-verity file, deny the open if it is for writing.
 * Otherwise, set up the inode's ->i_verity_info (if not already done) by
 * parsing the fs-verity metadata at the end of the file and verifying the
 * signature.
 *
 * When combined with fscrypt, this must be called after fscrypt_file_open().
 * Otherwise, we won't have the key set up to decrypt the fs-verity metadata.
 *
 * Return: 0 on success, -errno on failure
 */
int fsverity_file_open(struct inode *inode, struct file *filp)
{
	if (filp->f_mode & FMODE_WRITE) {
		pr_debug("Denying opening fs-verity file (ino %lu) for write\n",
			 inode->i_ino);
		return -EPERM;
	}

	pr_debug("Opening fs-verity file (ino %lu)\n", inode->i_ino);

	return setup_fsverity_info(inode);
}
EXPORT_SYMBOL_GPL(fsverity_file_open);

/**
 * fsverity_prepare_setattr - prepare to change an fs-verity inode's attributes
 * @dentry: dentry through which the inode is being changed
 * @attr: attributes to change
 *
 * fs-verity files are immutable, so deny truncates.  This isn't covered by the
 * open-time check because sys_truncate() takes a path, not a file descriptor.
 *
 * Return: 0 on success, -errno on failure
 */
int fsverity_prepare_setattr(struct dentry *dentry, struct iattr *attr)
{
	if (attr->ia_valid & ATTR_SIZE) {
		pr_debug("Denying truncate of fs-verity file (ino %lu)\n",
			 d_inode(dentry)->i_ino);
		return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(fsverity_prepare_setattr);

/**
 * fsverity_prepare_getattr - prepare to get an fsverity inode's attributes
 * @inode: the inode for which the attributes are being retrieved
 *
 * To make st_size exclude the fs-verity metadata even before the file has been
 * opened for the first time, we need to grab the original data size from the
 * fs-verity footer.  Currently, to implement this we just set up the
 * ->i_verity_info, like in the ->open() hook.
 *
 * However, when combined with fscrypt, on an encrypted file this must only be
 * called if the encryption key has been set up!
 *
 * Return: 0 on success, -errno on failure
 */
int fsverity_prepare_getattr(struct inode *inode)
{
	return setup_fsverity_info(inode);
}
EXPORT_SYMBOL_GPL(fsverity_prepare_getattr);

/**
 * fsverity_cleanup_inode - free the inode's verity info, if present
 *
 * Filesystems must call this on inode eviction to free ->i_verity_info.
 */
void fsverity_cleanup_inode(struct inode *inode)
{
	free_fsverity_info(inode->i_verity_info);
	inode->i_verity_info = NULL;
}
EXPORT_SYMBOL_GPL(fsverity_cleanup_inode);

/**
 * fsverity_full_isize - get the full (on-disk) file size
 *
 * If the inode has had its in-memory ->i_size overridden for fs-verity (to
 * exclude the metadata at the end of the file), then return the full i_size
 * which is stored on-disk.  Otherwise, just return the in-memory ->i_size.
 *
 * Return: the full (on-disk) file size
 */
loff_t fsverity_full_isize(struct inode *inode)
{
	struct fsverity_info *vi = get_fsverity_info(inode);

	if (vi)
		return vi->full_i_size;

	return i_size_read(inode);
}
EXPORT_SYMBOL_GPL(fsverity_full_isize);

static int __init fsverity_module_init(void)
{
	int err;

	/*
	 * Use an unbound workqueue to allow bios to be verified in parallel
	 * even when they happen to complete on the same CPU.  This sacrifices
	 * locality, but it's worthwhile since hashing is CPU-intensive.
         *
	 * Also use a high-priority workqueue to prioritize verification work,
	 * which blocks reads from completing, over regular application tasks.
	 */
	err = -ENOMEM;
	fsverity_read_workqueue = alloc_workqueue("fsverity_read_queue",
						  WQ_UNBOUND | WQ_HIGHPRI,
						  num_online_cpus());
	if (!fsverity_read_workqueue)
		goto error;

	err = -ENOMEM;
	fsverity_info_cachep = KMEM_CACHE(fsverity_info, SLAB_RECLAIM_ACCOUNT);
	if (!fsverity_info_cachep)
		goto error_free_workqueue;

	fsverity_check_hash_algs();

	pr_debug("Initialized fs-verity\n");
	return 0;

error_free_workqueue:
	destroy_workqueue(fsverity_read_workqueue);
error:
	return err;
}

static void __exit fsverity_module_exit(void)
{
	destroy_workqueue(fsverity_read_workqueue);
	kmem_cache_destroy(fsverity_info_cachep);
	fsverity_exit_hash_algs();
}

module_init(fsverity_module_init)
module_exit(fsverity_module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("fs-verity: read-only file-based integrity/authenticity");
