// SPDX-License-Identifier: GPL-2.0
/*
 * fs-verity: read-only file-based integrity/authenticity
 *
 * hash_algs.c: hash algorithm management
 *
 * Copyright (C) 2018, Google, Inc.
 *
 * Written by Eric Biggers.
 */

#include "fsverity_private.h"

#include <asm/unaligned.h>
#include <crypto/hash.h>

/* The list of hash algorithms supported by fs-verity */
static struct fsverity_hash_alg fsverity_hash_algs[] = {
	[FS_VERITY_ALG_SHA256] = {
		.friendly_name = "SHA-256",
		.algname = "sha256",
		.digest_size = 32,
	},
#ifdef CONFIG_FS_VERITY_INTEGRITY_ONLY
	[FS_VERITY_ALG_CRC32] = {
		.friendly_name = "CRC-32",
		.algname = "crc32",
		.digest_size = 4,
	},
#endif
};

/*
 * Translate the given fs-verity hash algorithm number into a struct describing
 * the algorithm, and ensure it has a hash transform ready to go.  The hash
 * transforms are allocated on-demand firstly to not waste resources when they
 * aren't needed, and secondly because the fs-verity module may be loaded
 * earlier than the needed crypto modules.
 */
const struct fsverity_hash_alg *fsverity_get_hash_alg(unsigned int num)
{
	struct fsverity_hash_alg *alg;
	struct crypto_shash *tfm;
	int err;

	if (num >= ARRAY_SIZE(fsverity_hash_algs) ||
	    !fsverity_hash_algs[num].digest_size) {
		pr_warn("Unknown hash algorithm: %u\n", num);
		return ERR_PTR(-EINVAL);
	}
	alg = &fsverity_hash_algs[num];
retry:
	/* pairs with cmpxchg_release() below */
	tfm = smp_load_acquire(&alg->tfm);
	if (tfm)
		return alg;

	tfm = crypto_alloc_shash(alg->algname, 0, 0);
	if (IS_ERR(tfm)) {
		if (PTR_ERR(tfm) == -ENOENT)
			pr_warn("Algorithm %u (%s) is unavailable\n",
				num, alg->friendly_name);
		else
			pr_warn("Error allocating algorithm %u (%s): %ld\n",
				num, alg->friendly_name, PTR_ERR(tfm));
		return ERR_CAST(tfm);
	}

	err = -EINVAL;
	if (WARN_ON(alg->digest_size != crypto_shash_digestsize(tfm)))
		goto err_free_tfm;

	pr_info("%s using implementation \"%s\"\n", alg->friendly_name,
		crypto_shash_alg(tfm)->base.cra_driver_name);

	/* Set the initial value if required by the algorithm */
	if (num == FS_VERITY_ALG_CRC32) {
		__le32 initial_value = cpu_to_le32(0xFFFFFFFF);

		err = crypto_shash_setkey(tfm, (u8 *)&initial_value, 4);
		if (err) {
			pr_warn("Error setting CRC-32 initial value: %d\n",
				err);
			goto err_free_tfm;
		}
	}

	/* pairs with smp_load_acquire() above */
	if (cmpxchg_release(&alg->tfm, NULL, tfm) != NULL) {
		crypto_free_shash(tfm);
		goto retry;
	}

	return alg;

err_free_tfm:
	crypto_free_shash(tfm);
	return ERR_PTR(err);
}

int fsverity_finalize_hash(struct fsverity_info *vi, struct shash_desc *desc,
			   u8 *out)
{
	int err;

	err = crypto_shash_final(desc, out);
	if (err)
		return err;

	/*
	 * For CRC-32, invert at the end and convert to big-endian format.  This
	 * is done for compatibility with the 'veritysetup' tool, which uses the
	 * crc32 algorithm from libgcrypt, which uses this convention.
	 */
	if (vi->hash_alg == &fsverity_hash_algs[FS_VERITY_ALG_CRC32])
		put_unaligned_be32(~get_unaligned_le32(out), out);
	return 0;
}

void __init fsverity_check_hash_algs(void)
{
	int i;

	/*
	 * Sanity check the digest sizes (could be a build-time check, but
	 * they're in an array)
	 */
	for (i = 0; i < ARRAY_SIZE(fsverity_hash_algs); i++) {
		struct fsverity_hash_alg *alg = &fsverity_hash_algs[i];

		if (!alg->digest_size)
			continue;
		BUG_ON(alg->digest_size > FS_VERITY_MAX_DIGEST_SIZE);
		BUG_ON(!is_power_of_2(alg->digest_size));
	}
}

void __exit fsverity_exit_hash_algs(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fsverity_hash_algs); i++)
		crypto_free_shash(fsverity_hash_algs[i].tfm);
}
