/*
 * Kernel public-key RSA interface, independently defined for the RustCrypto
 * implementation. Contexts contain only public values and are caller-owned.
 */
#ifndef _LIBKERN_CRYPTO_RSA_ABI_H_
#define _LIBKERN_CRYPTO_RSA_ABI_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <libkern/crypto/cc_abi.h>
#include <libkern/crypto/ccdigest_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XNU_RC_RSA_MAX_KEY_BITS 4096

/*
 * n is the allocation capacity in cc_unit words, not the encoded modulus
 * length. The header is followed by two n-word byte buffers: first the
 * unsigned big-endian modulus, then the unsigned big-endian exponent. The
 * encoded lengths exclude leading zero bytes. Do not alter an initialized
 * context's capacity; initialize a new context with ccrsa_ctx_n instead.
 */
struct ccrsa_pub_ctx {
	cc_size n;
	size_t modulus_nbytes;
	size_t exponent_nbytes;
};
typedef void *ccrsa_pub_ctx_t;

#define ccrsa_pub_ctx_size(_nbytes_) \
	(sizeof(struct ccrsa_pub_ctx) + 2 * ccn_sizeof_size(_nbytes_))
#define ccrsa_pub_ctx_decl(_nbytes_, _name_) \
	cc_unit _name_[ccrsa_pub_ctx_size(_nbytes_) / sizeof(cc_unit)]
#define ccrsa_ctx_n(_ctx_) (((struct ccrsa_pub_ctx *)(void *)(_ctx_))->n)

int ccrsa_make_pub(ccrsa_pub_ctx_t key,
    size_t exponent_nbytes, const uint8_t *exponent,
    size_t modulus_nbytes, const uint8_t *modulus);
int ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key, const uint8_t *oid,
    size_t digest_nbytes, const uint8_t *digest,
    size_t signature_nbytes, const uint8_t *signature, bool *valid);

int xnu_rc_ccrsa_make_pub(ccrsa_pub_ctx_t key,
    size_t exponent_nbytes, const uint8_t *exponent,
    size_t modulus_nbytes, const uint8_t *modulus);
int xnu_rc_ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key, const uint8_t *oid,
    size_t digest_nbytes, const uint8_t *digest,
    size_t signature_nbytes, const uint8_t *signature, bool *valid);

/*
 * Keys accept unsigned big-endian values up to the context capacity and
 * 4096 bits. The modulus must be odd, and 3 <= e < modulus with e odd.
 * Verification requires a signature exactly ceil(bit_length(modulus) / 8)
 * bytes long and less than the modulus.
 * Recognized hash OIDs are MD5, SHA-1, SHA-224/256/384/512 and SHA-512/256;
 * the digest length must match the selected hash. DigestInfo uses the DER
 * AlgorithmIdentifier with an explicit NULL parameter, as specified by
 * RFC 8017. A well-formed operation returns CCERR_OK and sets valid according
 * to the complete encoding match. Invalid arguments return CCERR_PARAMETER;
 * out-of-range signature integers return CCRSA_INVALID_INPUT. On every
 * failure, a supplied valid output is false.
 */

#ifdef __cplusplus
}
#endif
#endif /* _LIBKERN_CRYPTO_RSA_ABI_H_ */
