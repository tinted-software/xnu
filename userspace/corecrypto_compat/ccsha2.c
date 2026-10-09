/*
 * SHA-1 / SHA-256 / SHA-384 digest-info tables for the corecrypto/ccdigest
 * shim. The byte-level work is in ccsha2.rs (RustCrypto, no_std).
 */

#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

#define DEFINE_DIGEST(name, outsz, blksz)                                          \
	extern void name##_rs_init(void *ctx);                                     \
	extern void name##_rs_update(void *ctx, const void *data, size_t len);     \
	extern void name##_rs_final(void *ctx, void *out);                         \
	static void name##_init(const struct ccdigest_info *di, void *ctx)         \
	{                                                                          \
		(void)di;                                                          \
		name##_rs_init(ctx);                                               \
	}                                                                          \
	static void name##_update(const struct ccdigest_info *di, void *ctx,       \
	    size_t len, const void *data)                                          \
	{                                                                          \
		(void)di;                                                          \
		name##_rs_update(ctx, data, len);                                  \
	}                                                                          \
	static void name##_final(const struct ccdigest_info *di, void *ctx,        \
	    void *out)                                                             \
	{                                                                          \
		(void)di;                                                          \
		name##_rs_final(ctx, out);                                         \
	}                                                                          \
	static const struct ccdigest_info name##_info = {                          \
		.output_size = (outsz),                                            \
		.state_size = CCDIGEST_MAX_CTX_BYTES,                              \
		.block_size = (blksz),                                             \
		.init = name##_init,                                               \
		.update = name##_update,                                           \
		.final = name##_final,                                             \
	};                                                                         \
	const struct ccdigest_info *name##_di(void)                                \
	{                                                                          \
		return &name##_info;                                               \
	}

DEFINE_DIGEST(ccsha1, CCSHA1_OUTPUT_SIZE, CCSHA1_BLOCK_SIZE)
DEFINE_DIGEST(ccsha256, CCSHA256_OUTPUT_SIZE, CCSHA256_BLOCK_SIZE)
DEFINE_DIGEST(ccsha384, CCSHA384_OUTPUT_SIZE, CCSHA384_BLOCK_SIZE)
