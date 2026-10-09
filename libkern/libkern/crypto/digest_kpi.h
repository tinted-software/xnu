/* RustCrypto-backed implementations of the algorithm-based kernel KPI. */
#ifndef _LIBKERN_CRYPTO_DIGEST_KPI_H_
#define _LIBKERN_CRYPTO_DIGEST_KPI_H_
#include <stdbool.h>
#include <libkern/crypto/ccdigest_abi.h>
/* Caller-provided contexts require 8-byte alignment and at least ctx_size()
 * bytes. Digest outputs must be full length; HMAC tags may be truncated to
 * 1..digest output_size bytes. Invalid verification tag sizes return false.
 * Digest finalization preserves the input context unless output aliases it;
 * HMAC finalization consumes the context, which must be reinitialized to reuse.
 */
#ifdef __cplusplus
extern "C" {
#endif
void xnu_rc_ccdigest_final(const struct ccdigest_info *, ccdigest_ctx_t, void *);
size_t xnu_rc_digest_ctx_size(crypto_digest_alg_t);
void xnu_rc_digest_init(crypto_digest_alg_t, void *, size_t);
void xnu_rc_digest_update(crypto_digest_alg_t, void *, size_t, const void *, size_t);
void xnu_rc_digest_final(crypto_digest_alg_t, void *, size_t, void *, size_t);
void xnu_rc_digest(crypto_digest_alg_t, const void *, size_t, void *, size_t);
size_t xnu_rc_hmac_ctx_size(crypto_digest_alg_t);
void xnu_rc_hmac_init(crypto_digest_alg_t, void *, size_t, const void *, size_t);
void xnu_rc_hmac_update(crypto_digest_alg_t, void *, size_t, const void *, size_t);
void xnu_rc_hmac_final_generate(crypto_digest_alg_t, void *, size_t, void *, size_t);
bool xnu_rc_hmac_final_verify(crypto_digest_alg_t, void *, size_t, const void *, size_t);
void xnu_rc_hmac_generate(crypto_digest_alg_t, const void *, size_t, const void *, size_t, void *, size_t);
bool xnu_rc_hmac_verify(crypto_digest_alg_t, const void *, size_t, const void *, size_t, const void *, size_t);
#ifdef __cplusplus
}
#endif
#endif /* _LIBKERN_CRYPTO_DIGEST_KPI_H_ */
