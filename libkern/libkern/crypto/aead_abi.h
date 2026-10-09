/* Kernel AEAD ABI, independently defined for the RustCrypto implementation. */
#ifndef _LIBKERN_CRYPTO_AEAD_ABI_H_
#define _LIBKERN_CRYPTO_AEAD_ABI_H_
#include <stddef.h>
#include <stdint.h>
#include <libkern/crypto/cc_abi.h>
#ifdef __cplusplus
extern "C" {
#endif

#define CCGCM_IV_NBYTES 12
#define CCGCM_BLOCK_NBYTES 16
typedef struct { uint8_t bytes[16]; } __attribute__((aligned(16))) ccgcm_ctx;
/* Contexts require 16-byte alignment; allocate the selector's size bytes.
 * A keyed context starts ready for an IV. AAD precedes message updates; after
 * finalization, reset before installing another IV. Data updates may be
 * exactly in-place, but partially overlapping buffers are rejected.
 * Decrypted bytes must not be exposed until finalize authenticates them.
 * GCM supports keys of 16/24/32 bytes, nonempty IVs, and tags of
 * 4, 8, or 12 through 16 bytes. Maximum message size is 2^36 - 32 bytes;
 * IV/AAD sizes must fit a 64-bit bit count. */
struct ccmode_gcm {
    size_t size;
    size_t block_size;
    int (*init)(const struct ccmode_gcm *, ccgcm_ctx *, size_t, const void *);
    int (*set_iv)(ccgcm_ctx *, size_t, const void *);
    int (*gmac)(ccgcm_ctx *, size_t, const void *);
    int (*gcm)(ccgcm_ctx *, size_t, const void *, void *);
    int (*finalize)(ccgcm_ctx *, size_t, void *);
    int (*reset)(ccgcm_ctx *);
};
#define ccgcm_ctx_decl(size, name) ccgcm_ctx name[((size) + sizeof(ccgcm_ctx) - 1) / sizeof(ccgcm_ctx)]
#define ccgcm_ctx_clear(size, name) cc_clear((size), (name))
int ccgcm_init(const struct ccmode_gcm *, ccgcm_ctx *, size_t, const void *);
int ccgcm_set_iv(const struct ccmode_gcm *, ccgcm_ctx *, size_t, const void *);
int ccgcm_aad(const struct ccmode_gcm *, ccgcm_ctx *, size_t, const void *);
int ccgcm_update(const struct ccmode_gcm *, ccgcm_ctx *, size_t, const void *, void *);
/* Encryption writes a tag; decryption verifies the supplied tag in constant time. */
int ccgcm_finalize(const struct ccmode_gcm *, ccgcm_ctx *, size_t, void *);
int ccgcm_reset(const struct ccmode_gcm *, ccgcm_ctx *);
int ccgcm_init_with_iv(const struct ccmode_gcm *, ccgcm_ctx *, size_t, const void *, const void *);
/* Increment the low 64 bits of a managed 12-byte IV, rejecting wraparound. */
int ccgcm_inc_iv(const struct ccmode_gcm *, ccgcm_ctx *, void *);
int ccgcm_one_shot(const struct ccmode_gcm *, size_t, const void *, size_t, const void *, size_t, const void *, size_t, const void *, void *, size_t, void *);
const struct ccmode_gcm *xnu_rc_aes_gcm_encrypt_mode(void);
const struct ccmode_gcm *xnu_rc_aes_gcm_decrypt_mode(void);

#define CCCHACHA20_KEY_NBYTES 32
#define CCCHACHA20POLY1305_NONCE_NBYTES 12
#define CCCHACHA20POLY1305_TAG_NBYTES 16
#define CCCHACHA20POLY1305_CTX_NBYTES 1024
typedef struct { uint8_t bytes[CCCHACHA20POLY1305_CTX_NBYTES]; } __attribute__((aligned(8))) ccchacha20poly1305_ctx;
struct ccchacha20poly1305_info { size_t size; };
const struct ccchacha20poly1305_info *ccchacha20poly1305_info(void);
int ccchacha20poly1305_init(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *, const uint8_t *);
int ccchacha20poly1305_reset(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *);
int ccchacha20poly1305_setnonce(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *, const uint8_t *);
int ccchacha20poly1305_incnonce(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *, uint8_t *);
/* ChaCha uses fixed 32-byte keys, 12-byte nonces, and 16-byte tags.
 * Reset retains the key and previously assigned nonce for incnonce;
 * setnonce installs a new nonce before AAD or message updates.
 * incnonce increments the saved 96-bit little-endian nonce without wrapping.
 * Encrypt/finalize and decrypt/verify must not be mixed within a message.
 * The message limit is (2^32 - 1) * 64 bytes; AAD has a 64-bit byte count.
 * Decryption is streaming: discard all plaintext if verify fails. */
int ccchacha20poly1305_aad(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *, size_t, const void *);
int ccchacha20poly1305_encrypt(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *, size_t, const void *, void *);
int ccchacha20poly1305_decrypt(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *, size_t, const void *, void *);
int ccchacha20poly1305_finalize(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *, uint8_t *);
int ccchacha20poly1305_verify(const struct ccchacha20poly1305_info *, ccchacha20poly1305_ctx *, const uint8_t *);
struct ccchacha20poly1305_fns;
const struct ccchacha20poly1305_fns *xnu_rc_chacha20poly1305_fns(void);
#ifdef __cplusplus
}
#endif
#endif
