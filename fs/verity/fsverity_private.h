/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs-verity: read-only file-based integrity/authenticity
 *
 * Copyright (C) 2018, Google, Inc.
 */

#ifndef _FSVERITY_PRIVATE_H
#define _FSVERITY_PRIVATE_H

#ifdef CONFIG_FS_VERITY_DEBUG
#define DEBUG
#endif

#define pr_fmt(fmt) "fs-verity: " fmt

#include <crypto/sha.h>
#define __FS_HAS_VERITY 1
#include <linux/fsverity.h>

#define FS_VERITY_MAGIC		"TrueBrew"
#define FS_VERITY_MAJOR		1
#define FS_VERITY_MINOR		0
#define FS_VERITY_SALT_SIZE	8

struct fsverity_footer {
	u8 magic[8];		/* must be FS_VERITY_MAGIC */
	u8 major_version;	/* must be FS_VERITY_MAJOR */
	u8 minor_version;	/* must be FS_VERITY_MINOR */
	u8 log_blocksize;	/* log2(data-bytes-per-hash), e.g. 12 for 4KB */
	u8 log_arity;		/* log2(leaves-per-node), e.g. 7 for SHA-256 */
	__le16 meta_algorithm;	/* hash algorithm for tree blocks */
	__le16 data_algorithm;	/* hash algorithm for data blocks */
	__le32 flags;		/* flags */
	__le32 reserved1;	/* must be 0 */
	__le64 size;		/* size of the original, unpadded data */
	u8 authenticated_ext_count; /* number of authenticated extensions */
	u8 unauthenticated_ext_count; /* number of unauthenticated extensions */
	u8 salt[FS_VERITY_SALT_SIZE]; /* used to salt the hashes */
	u8 reserved2[22];	/* must be 0 */
	/* This structure is 64 bytes long */
} __packed;

/* extension types */
#define FS_VERITY_EXT_ELIDE		1
#define FS_VERITY_EXT_PATCH		2
#define FS_VERITY_EXT_SALT		3
#define FS_VERITY_EXT_PKCS7_SIGNATURE	4

/* Header of each variable-length metadata item following the fsverity_footer */
struct fsverity_extension {
	/*
	 * Length of this extension in bytes, including this header.  Must be
	 * rounded up to an 8-byte boundary when advancing to the next
	 * extension.
	 */
	__le32 length;
	__le16 type;		/* Type of this extension (see codes above) */
	__le16 reserved;	/* Reserved, must be 0 */
} __packed;

/*
 * Up to 64 levels are theoretically possible with a very small block size, but
 * we'd like to limit stack usage, and in practice this is plenty.  E.g., with
 * SHA-256 and 4K blocks, a file with size UINT64_MAX bytes needs just 8 levels.
 */
#define FS_VERITY_MAX_LEVELS		16

#define FS_VERITY_MAX_DIGEST_SIZE	SHA256_DIGEST_SIZE

struct fsverity_hash_alg {
	struct crypto_shash *tfm; /* allocated on demand */
	const char *friendly_name;
	const char *algname;
	unsigned int digest_size;
};

/**
 * fsverity_info - cached fs-verity metadata for an inode
 *
 * When a fs-verity file is first opened, an instance of this struct is
 * allocated and stored in ->i_verity_info.  It caches various values from the
 * fs-verity metadata, such as the tree topology and the root hash, which are
 * needed to efficiently verify data read from the file.  Once created, it
 * remains until the inode is evicted.
 */
struct fsverity_info {
	const struct fsverity_hash_alg *hash_alg; /* hash algorithm */
	u8 block_bits;			/* log2(block size) */
	u8 log_arity;			/* log2(hashes per hash block) */
	u8 depth;			/* depth of the Merkle tree */
	u8 salt[FS_VERITY_SALT_SIZE];	/* used to salt the hashes */
	u64 data_i_size;		/* original file size */
	u64 full_i_size;		/* full file size including metadata */
	u8 root_hash[FS_VERITY_MAX_DIGEST_SIZE];   /* Merkle tree root hash */
	u8 measurement[FS_VERITY_MAX_DIGEST_SIZE]; /* file measurement */
	u32 flags;
	bool have_trusted_measurement;

	/* Starting blocks for each tree level. 'depth-1' is the root level. */
	u64 hash_lvl_region_idx[FS_VERITY_MAX_LEVELS];
};

/* hash_algs.c */
const struct fsverity_hash_alg *fsverity_get_hash_alg(unsigned int num);
void __init fsverity_check_hash_algs(void);
void __exit fsverity_exit_hash_algs(void);

/* setup.c */
const struct fsverity_hash_alg *
fsverity_check_measurement_struct(const struct fsverity_measurement *m);
struct fsverity_info *create_fsverity_info(struct inode *inode);
void free_fsverity_info(struct fsverity_info *vi);

static inline struct fsverity_info *get_fsverity_info(const struct inode *inode)
{
	/* pairs with cmpxchg_release() in set_fsverity_info() */
	return smp_load_acquire(&inode->i_verity_info);
}

static inline bool set_fsverity_info(struct inode *inode,
				     struct fsverity_info *vi)
{
	/* pairs with smp_load_acquire() in get_fsverity_info() */
	if (cmpxchg_release(&inode->i_verity_info, NULL, vi) != NULL)
		return false;

	/*
	 * Set the in-memory i_size to the data i_size.  But it should *not* be
	 * written to disk, since then it would no longer be possible to find
	 * the fs-verity footer.
	 */
	i_size_write(inode, vi->data_i_size);
	return true;
}

/* verify.c */
extern struct workqueue_struct *fsverity_read_workqueue;

#endif /* _FSVERITY_PRIVATE_H */
