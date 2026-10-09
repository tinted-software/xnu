/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Early-boot C bridge to the RustCrypto-backed SP 800-90A HMAC-SHA256 DRBG.
 */
#include "hmac_drbg.h"

void
hmac_drbg_sha256_instantiate(struct hmac_drbg_sha256 *st,
    const void *entropy, size_t entropy_len,
    const void *nonce, size_t nonce_len,
    const void *personalization, size_t personalization_len)
{
	xnu_rc_hmac_drbg_instantiate(st, entropy, entropy_len, nonce, nonce_len,
	    personalization, personalization_len);
}

void
hmac_drbg_sha256_generate(struct hmac_drbg_sha256 *st, void *out, size_t out_len)
{
	xnu_rc_hmac_drbg_generate(st, out, out_len);
}

void
hmac_drbg_sha256_reseed(struct hmac_drbg_sha256 *st, const void *seed, size_t seed_len)
{
	xnu_rc_hmac_drbg_reseed(st, seed, seed_len);
}
