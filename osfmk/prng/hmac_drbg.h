/* SPDX-License-Identifier: MIT OR Apache-2.0
 * State ABI for the RustCrypto-backed SP 800-90A HMAC-SHA256 DRBG.
 * The early-boot instance is serialized by prng_random.c; runtime and kmem
 * instances use the same primitive with their respective ownership rules.
 */
#ifndef _OSFMK_PRNG_HMAC_DRBG_H_
#define _OSFMK_PRNG_HMAC_DRBG_H_

#include <stddef.h>
#include <stdint.h>

#define HMAC_DRBG_SHA256_OUTLEN 32

struct hmac_drbg_sha256 {
	uint8_t  key[HMAC_DRBG_SHA256_OUTLEN];
	uint8_t  v[HMAC_DRBG_SHA256_OUTLEN];
	uint64_t reseed_counter;
};

/* Instantiate from entropy || nonce || personalization. Entropy must supply
 * at least 32 bytes; a nonce and personalization may be empty. */
void hmac_drbg_sha256_instantiate(struct hmac_drbg_sha256 *st,
    const void *entropy, size_t entropy_len,
    const void *nonce, size_t nonce_len,
    const void *personalization, size_t personalization_len);

/* One SP 800-90A Generate request, at most 65536 bytes. */
void hmac_drbg_sha256_generate(struct hmac_drbg_sha256 *st, void *out, size_t out_len);
/* Mix additional seed material into existing state (at least 32 bytes). */
void hmac_drbg_sha256_reseed(struct hmac_drbg_sha256 *st, const void *seed, size_t seed_len);

void xnu_rc_hmac_drbg_instantiate(struct hmac_drbg_sha256 *st,
    const void *entropy, size_t entropy_len,
    const void *nonce, size_t nonce_len,
    const void *personalization, size_t personalization_len);
void xnu_rc_hmac_drbg_generate(struct hmac_drbg_sha256 *st, void *out, size_t out_len);
void xnu_rc_hmac_drbg_reseed(struct hmac_drbg_sha256 *st, const void *seed, size_t seed_len);

#endif /* _OSFMK_PRNG_HMAC_DRBG_H_ */
