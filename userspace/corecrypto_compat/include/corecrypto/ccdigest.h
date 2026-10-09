/*
 * Replacement for the subset of corecrypto's ccdigest API that libmalloc uses
 * (corecrypto is not published). Implementations live in ../../ccsha2.c over
 * RustCrypto's sha2 crate.
 */

#ifndef _CORECRYPTO_CCDIGEST_H_
#define _CORECRYPTO_CCDIGEST_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct ccdigest_info {
	size_t output_size;
	size_t state_size;
	size_t block_size;
	void (*init)(const struct ccdigest_info *di, void *ctx);
	void (*update)(const struct ccdigest_info *di, void *ctx, size_t len, const void *data);
	void (*final)(const struct ccdigest_info *di, void *ctx, void *out);
};

/* Largest context of any digest in this shim (Rust side asserts it fits). */
#define CCDIGEST_MAX_CTX_BYTES	256

/*
 * Declares a context variable for digest `di`. The context is 16-byte aligned
 * and at least CCDIGEST_MAX_CTX_BYTES long, so any digest here fits.
 */
#define ccdigest_di_decl(di, ctx) \
	uint64_t ctx[(CCDIGEST_MAX_CTX_BYTES + 7) / 8] __attribute__((aligned(16)))

#define ccdigest_init(di, ctx)			((di)->init((di), (ctx)))
#define ccdigest_update(di, ctx, len, data)	((di)->update((di), (ctx), (len), (data)))
#define ccdigest_final(di, ctx, out)		((di)->final((di), (ctx), (out)))
#define ccdigest_di_clear(di, ctx)		memset((ctx), 0, CCDIGEST_MAX_CTX_BYTES)

#endif /* _CORECRYPTO_CCDIGEST_H_ */
