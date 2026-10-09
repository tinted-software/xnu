/*
 * Clean-room kernel digest/HMAC ABI. Context offsets and descriptor fields
 * preserve the kernel consumer ABI; no third-party implementation is included.
 */
#ifndef _LIBKERN_CRYPTO_CCDIGEST_ABI_H_
#define _LIBKERN_CRYPTO_CCDIGEST_ABI_H_

#include <stddef.h>
#include <stdint.h>
#include <libkern/crypto/cc_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stable algorithm identifiers used by the algorithm-based kernel KPI. */
#ifdef __cplusplus
typedef enum : unsigned int {
#else
typedef unsigned int crypto_digest_alg_t;
enum {
#endif
	CRYPTO_DIGEST_ALG_NONE,
	CRYPTO_DIGEST_ALG_MD5,
	CRYPTO_DIGEST_ALG_SHA1,
	CRYPTO_DIGEST_ALG_SHA256,
	CRYPTO_DIGEST_ALG_SHA384,
	CRYPTO_DIGEST_ALG_SHA512
#ifdef __cplusplus
} crypto_digest_alg_t;
#else
};
#endif

struct ccdigest_ctx {
	uint8_t state[1];
} __attribute__((aligned(8)));
typedef struct ccdigest_ctx *ccdigest_ctx_t;
typedef uint8_t *ccdigest_state_t;

struct ccdigest_info {
	size_t output_size;
	size_t state_size;
	size_t block_size;
	size_t oid_size;
	const unsigned char *oid;
	const void *initial_state;
	void (*compress)(ccdigest_state_t state, size_t nblocks, const void *data);
	void (*final)(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest);
	uint32_t impl;
	void (*compress_parallel)(ccdigest_state_t state1, size_t nblocks1, const void *data1,
	    ccdigest_state_t state2, size_t nblocks2, const void *data2);
};

/* [uint64 compressed-bit count][state][block buffer][uint32 buffered bytes].
 * The public size excludes tail padding; declarations round to 8-byte units.
 * The legacy ABI carries only the low 64 bits of the message bit count.
 */
#define ccdigest_ctx_size(S, B) ((S) + sizeof(uint64_t) + (B) + sizeof(unsigned int))
#define ccdigest_di_size(D) ccdigest_ctx_size((D)->state_size, (D)->block_size)
#define ccdigest_ctx_decl(S, B, N) \
	struct ccdigest_ctx N[(ccdigest_ctx_size(S, B) + sizeof(struct ccdigest_ctx) - 1) / sizeof(struct ccdigest_ctx)]
#define ccdigest_di_decl(D, N) ccdigest_ctx_decl((D)->state_size, (D)->block_size, N)
#define ccdigest_ctx_clear(S, B, N) cc_clear(ccdigest_ctx_size(S, B), (N))
#define ccdigest_di_clear(D, N) cc_clear(ccdigest_di_size(D), (N))
#define ccdigest_nbits(D, C) (*(uint64_t *)((ccdigest_ctx_t)(C))->state)
#define ccdigest_state(D, C) (((ccdigest_ctx_t)(C))->state + sizeof(uint64_t))
#define ccdigest_data(D, C) (((ccdigest_ctx_t)(C))->state + sizeof(uint64_t) + (D)->state_size)
#define ccdigest_num(D, C) (*(unsigned int *)(ccdigest_data(D, C) + (D)->block_size))
#define ccdigest_u8(S) ((uint8_t *)(S))
#define ccdigest_u32(S) ((uint32_t *)(S))
#define ccdigest_u64(S) ((uint64_t *)(S))
#define ccdigest_state_u8(D, C) ccdigest_u8(ccdigest_state(D, C))
#define ccdigest_state_u32(D, C) ccdigest_u32(ccdigest_state(D, C))
#define ccdigest_state_u64(D, C) ccdigest_u64(ccdigest_state(D, C))

void ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx);
void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);
void ccdigest_final_64be(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest);
void ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest);
void ccsha512_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest);
void ccdigest(const struct ccdigest_info *di, size_t len, const void *data, void *digest);
static inline void
ccdigest_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest)
{
	di->final(di, ctx, digest);
}

const struct ccdigest_info *ccmd5_di(void);
const struct ccdigest_info *ccsha1_di(void);
const struct ccdigest_info *ccsha224_di(void);
const struct ccdigest_info *ccsha256_di(void);
const struct ccdigest_info *ccsha384_di(void);
const struct ccdigest_info *ccsha512_di(void);
const struct ccdigest_info *ccsha512_256_di(void);

/* The saved outer state follows the digest context at the target's maximum
 * scalar alignment, matching contexts allocated by existing consumers.
 */
struct cchmac_ctx {
	uint8_t b[1];
} __attribute__((aligned(8)));
typedef struct cchmac_ctx *cchmac_ctx_t;
#if defined(__BIGGEST_ALIGNMENT__)
#define CCHMAC_STATE_ALIGNMENT ((size_t)__BIGGEST_ALIGNMENT__)
#else
#define CCHMAC_STATE_ALIGNMENT ((size_t)16)
#endif
#define cchmac_state_offset(S) (((S) + CCHMAC_STATE_ALIGNMENT - 1) & ~(CCHMAC_STATE_ALIGNMENT - 1))
#define cchmac_ctx_size(S, B) (cchmac_state_offset(ccdigest_ctx_size(S, B)) + (S))
#define cchmac_di_size(D) cchmac_ctx_size((D)->state_size, (D)->block_size)
#define cchmac_ctx_decl(S, B, N) \
	struct cchmac_ctx N[(cchmac_ctx_size(S, B) + sizeof(struct cchmac_ctx) - 1) / sizeof(struct cchmac_ctx)]
#define cchmac_di_decl(D, N) cchmac_ctx_decl((D)->state_size, (D)->block_size, N)
#define cchmac_ctx_clear(S, B, N) cc_clear(cchmac_ctx_size(S, B), (N))
#define cchmac_di_clear(D, N) cc_clear(cchmac_di_size(D), (N))
#define cchmac_digest_ctx(D, C) ((ccdigest_ctx_t)(C))
#define cchmac_ostate(D, C) (((cchmac_ctx_t)(C))->b + cchmac_state_offset(ccdigest_di_size(D)))
#define cchmac_istate(D, C) ccdigest_state(D, C)
#define cchmac_data(D, C) ccdigest_data(D, C)
#define cchmac_num(D, C) ccdigest_num(D, C)
#define cchmac_nbits(D, C) ccdigest_nbits(D, C)
#define cchmac_istate32(D, C) ccdigest_u32(cchmac_istate(D, C))
#define cchmac_ostate32(D, C) ccdigest_u32(cchmac_ostate(D, C))
void cchmac(const struct ccdigest_info *di, size_t key_len, const void *key,
    size_t data_len, const void *data, unsigned char *mac);
void cchmac_init(const struct ccdigest_info *di, cchmac_ctx_t ctx, size_t key_len, const void *key);
void cchmac_update(const struct ccdigest_info *di, cchmac_ctx_t ctx, size_t data_len, const void *data);
void cchmac_final(const struct ccdigest_info *di, cchmac_ctx_t ctx, unsigned char *mac);

/* Algorithm sizes from RFC 1321 and FIPS 180-4. */
#define CCMD5_OUTPUT_SIZE 16
#define CCMD5_STATE_SIZE 16
#define CCMD5_BLOCK_SIZE 64
#define CCSHA1_OUTPUT_SIZE 20
#define CCSHA1_STATE_SIZE 20
#define CCSHA1_BLOCK_SIZE 64
#define CCSHA224_OUTPUT_SIZE 28
#define CCSHA224_STATE_SIZE 32
#define CCSHA224_BLOCK_SIZE 64
#define CCSHA256_OUTPUT_SIZE 32
#define CCSHA256_STATE_SIZE 32
#define CCSHA256_BLOCK_SIZE 64
#define CCSHA384_OUTPUT_SIZE 48
#define CCSHA384_STATE_SIZE 64
#define CCSHA384_BLOCK_SIZE 128
#define CCSHA512_OUTPUT_SIZE 64
#define CCSHA512_STATE_SIZE 64
#define CCSHA512_BLOCK_SIZE 128
#define CCSHA512_256_OUTPUT_SIZE 32
#define CCSHA512_256_STATE_SIZE 64
#define CCSHA512_256_BLOCK_SIZE 128

/* DER OBJECT IDENTIFIER values, including tag and length. */
#define CC_DIGEST_OID_MD5 "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05"
#define CC_DIGEST_OID_SHA1 "\x06\x05\x2b\x0e\x03\x02\x1a"
#define CC_DIGEST_OID_SHA224 "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04"
#define CC_DIGEST_OID_SHA256 "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
#define CC_DIGEST_OID_SHA384 "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02"
#define CC_DIGEST_OID_SHA512 "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03"
#define CC_DIGEST_OID_SHA512_256 "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06"
#define ccoid_md5 ((const unsigned char *)CC_DIGEST_OID_MD5)
#define ccoid_sha1 ((const unsigned char *)CC_DIGEST_OID_SHA1)
#define ccoid_sha224 ((const unsigned char *)CC_DIGEST_OID_SHA224)
#define ccoid_sha256 ((const unsigned char *)CC_DIGEST_OID_SHA256)
#define ccoid_sha384 ((const unsigned char *)CC_DIGEST_OID_SHA384)
#define ccoid_sha512 ((const unsigned char *)CC_DIGEST_OID_SHA512)
#define ccoid_sha512_256 ((const unsigned char *)CC_DIGEST_OID_SHA512_256)
#define ccoid_md5_len 10
#define ccoid_sha1_len 7
#define ccoid_sha224_len 11
#define ccoid_sha256_len 11
#define ccoid_sha384_len 11
#define ccoid_sha512_len 11
#define ccoid_sha512_256_len 11

#ifdef __cplusplus
}
#endif
#endif /* _LIBKERN_CRYPTO_CCDIGEST_ABI_H_ */
