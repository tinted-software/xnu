/* Kernel block-cipher interface. Independently authored ABI declarations. */
#ifndef _LIBKERN_CRYPTO_CCMODE_ABI_H_
#define _LIBKERN_CRYPTO_CCMODE_ABI_H_

#include <stddef.h>
#include <stdint.h>
#include <libkern/crypto/cc_abi.h>
#include <libkern/crypto/aead_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque storage units retain the alignment of the kernel's fixed contexts. */
typedef struct { uint8_t bytes[16]; } __attribute__((aligned(16))) ccecb_ctx;
typedef struct { uint8_t bytes[16]; } __attribute__((aligned(16))) cccbc_ctx;
typedef struct { uint8_t bytes[16]; } __attribute__((aligned(16))) cccbc_iv;
typedef struct { uint8_t bytes[16]; } __attribute__((aligned(16))) ccctr_ctx;
typedef struct { uint8_t bytes[16]; } __attribute__((aligned(16))) ccxts_ctx;
typedef struct { uint8_t bytes[16]; } __attribute__((aligned(16))) ccxts_tweak;

#define XNU_RC_MODE_STORAGE(_type_, _size_, _name_) \
	_type_ _name_[((_size_) + sizeof(_type_) - 1) / sizeof(_type_)]
#define ccecb_ctx_decl(_size_, _name_) XNU_RC_MODE_STORAGE(ccecb_ctx, _size_, _name_)
#define cccbc_ctx_decl(_size_, _name_) XNU_RC_MODE_STORAGE(cccbc_ctx, _size_, _name_)
#define cccbc_iv_decl(_size_, _name_) XNU_RC_MODE_STORAGE(cccbc_iv, _size_, _name_)
#define ccctr_ctx_decl(_size_, _name_) XNU_RC_MODE_STORAGE(ccctr_ctx, _size_, _name_)
#define ccxts_ctx_decl(_size_, _name_) XNU_RC_MODE_STORAGE(ccxts_ctx, _size_, _name_)
#define ccxts_tweak_decl(_size_, _name_) XNU_RC_MODE_STORAGE(ccxts_tweak, _size_, _name_)
#define ccecb_ctx_clear(_size_, _ctx_) cc_clear((_size_), (_ctx_))
#define cccbc_ctx_clear(_size_, _ctx_) cc_clear((_size_), (_ctx_))
#define cccbc_iv_clear(_size_, _ctx_) cc_clear((_size_), (_ctx_))
#define ccctr_ctx_clear(_size_, _ctx_) cc_clear((_size_), (_ctx_))
#define ccxts_ctx_clear(_size_, _ctx_) cc_clear((_size_), (_ctx_))
#define ccxts_tweak_clear(_size_, _ctx_) cc_clear((_size_), (_ctx_))

#define CCAES_BLOCK_SIZE 16
#define CCDES_BLOCK_SIZE 8
#define XNU_RC_AES_KEY_CTX_SIZE 48
#define XNU_RC_DES_KEY_CTX_SIZE 144
#define XNU_RC_TDES_KEY_CTX_SIZE 400
#define XNU_RC_AES_CTR_CTX_SIZE 96
#define XNU_RC_AES_XTS_CTX_SIZE 80
#define XNU_RC_AES_XTS_TWEAK_SIZE 32

struct ccmode_ecb {
	size_t size;
	size_t block_size;
	int (*init)(const struct ccmode_ecb *, ccecb_ctx *, size_t, const void *);
	int (*ecb)(const ccecb_ctx *, size_t, const void *, void *);
	/* Reserved historical schedule-inspection slot; must be zero. */
	uintptr_t reserved_roundkey;
	uint32_t impl;
};
struct ccmode_cbc {
	size_t size;
	size_t block_size;
	int (*init)(const struct ccmode_cbc *, cccbc_ctx *, size_t, const void *);
	int (*cbc)(const cccbc_ctx *, cccbc_iv *, size_t, const void *, void *);
	const void *custom;
};
struct ccmode_ctr {
	size_t size;
	size_t block_size;
	size_t ecb_block_size;
	int (*init)(const struct ccmode_ctr *, ccctr_ctx *, size_t, const void *, const void *);
	int (*setctr)(const struct ccmode_ctr *, ccctr_ctx *, const void *);
	int (*ctr)(ccctr_ctx *, size_t, const void *, void *);
	const void *custom;
};
struct ccmode_xts {
	size_t size;
	size_t tweak_size;
	size_t block_size;
	int (*init)(const struct ccmode_xts *, ccxts_ctx *, size_t, const void *, const void *);
	void (*key_sched)(const struct ccmode_xts *, ccxts_ctx *, size_t, const void *, const void *);
	int (*set_tweak)(const ccxts_ctx *, ccxts_tweak *, const void *);
	void *(*xts)(const ccxts_ctx *, ccxts_tweak *, size_t, const void *, void *);
	const void *custom;
	const void *custom1;
	uint32_t impl;
};

/*
 * Keys are byte lengths (AES: 16/24/32; DES: 8; 3DES-EDE: 24).
 * Update supports disjoint buffers or exact in-place use, not partial overlap.
 * CBC updates its IV; CTR retains partial keystream and rejects counter reuse
 * after wrap; XTS advances its tweak and caps one data unit at 2^20 blocks.
 * Integer operations return CCMODE_INVALID_INPUT on invalid arguments.
 * One-shot IVs are read-only; clear retained key contexts with *_ctx_clear.
 */
size_t ccecb_context_size(const struct ccmode_ecb *);
size_t ccecb_block_size(const struct ccmode_ecb *);
int ccecb_init(const struct ccmode_ecb *, ccecb_ctx *, size_t, const void *);
int ccecb_update(const struct ccmode_ecb *, const ccecb_ctx *, size_t, const void *, void *);
int ccecb_one_shot(const struct ccmode_ecb *, size_t, const void *, size_t, const void *, void *);
size_t cccbc_context_size(const struct ccmode_cbc *);
size_t cccbc_block_size(const struct ccmode_cbc *);
int cccbc_init(const struct ccmode_cbc *, cccbc_ctx *, size_t, const void *);
int cccbc_copy_iv(cccbc_iv *, const void *, size_t);
int cccbc_clear_iv(cccbc_iv *, size_t);
int cccbc_set_iv(const struct ccmode_cbc *, cccbc_iv *, const void *);
int cccbc_update(const struct ccmode_cbc *, const cccbc_ctx *, cccbc_iv *, size_t, const void *, void *);
int cccbc_one_shot(const struct ccmode_cbc *, size_t, const void *, const void *, size_t, const void *, void *);
size_t ccctr_context_size(const struct ccmode_ctr *);
size_t ccctr_block_size(const struct ccmode_ctr *);
int ccctr_init(const struct ccmode_ctr *, ccctr_ctx *, size_t, const void *, const void *);
int ccctr_setctr(const struct ccmode_ctr *, ccctr_ctx *, const void *);
int ccctr_update(const struct ccmode_ctr *, ccctr_ctx *, size_t, const void *, void *);
int ccctr_one_shot(const struct ccmode_ctr *, size_t, const void *, const void *, size_t, const void *, void *);
size_t ccxts_context_size(const struct ccmode_xts *);
size_t ccxts_tweak_size(const struct ccmode_xts *);
size_t ccxts_block_size(const struct ccmode_xts *);
int ccxts_init(const struct ccmode_xts *, ccxts_ctx *, size_t, const void *, const void *);
void ccxts_key_sched(const struct ccmode_xts *, ccxts_ctx *, size_t, const void *, const void *);
int ccxts_set_tweak(const struct ccmode_xts *, const ccxts_ctx *, ccxts_tweak *, const void *);
void *ccxts_update(const struct ccmode_xts *, const ccxts_ctx *, ccxts_tweak *, size_t, const void *, void *);
int ccxts_one_shot(const struct ccmode_xts *, size_t, const void *, const void *, const void *, size_t, const void *, void *);
/* Length-preserving NIST CBC-CS3. Return zero for invalid input or failure. */
size_t ccpad_cts3_encrypt(const struct ccmode_cbc *, cccbc_ctx *, cccbc_iv *, size_t, const void *, void *);
size_t ccpad_cts3_decrypt(const struct ccmode_cbc *, cccbc_ctx *, cccbc_iv *, size_t, const void *, void *);

#define CCDES_KEY_SIZE 8
int ccdes_key_is_weak(void *, unsigned long);
void ccdes_key_set_odd_parity(void *, unsigned long);

#define XNU_RC_BLOCK_SELECTORS(_prefix_) \
	const struct ccmode_ecb *_prefix_##_ecb_encrypt_mode(void); \
	const struct ccmode_ecb *_prefix_##_ecb_decrypt_mode(void); \
	const struct ccmode_cbc *_prefix_##_cbc_encrypt_mode(void); \
	const struct ccmode_cbc *_prefix_##_cbc_decrypt_mode(void)
XNU_RC_BLOCK_SELECTORS(xnu_rc_aes);
XNU_RC_BLOCK_SELECTORS(xnu_rc_des);
XNU_RC_BLOCK_SELECTORS(xnu_rc_tdes);
const struct ccmode_ctr *xnu_rc_aes_ctr_crypt_mode(void);
const struct ccmode_xts *xnu_rc_aes_xts_encrypt_mode(void);
const struct ccmode_xts *xnu_rc_aes_xts_decrypt_mode(void);
#undef XNU_RC_BLOCK_SELECTORS

#ifdef __cplusplus
}
#endif
#endif
