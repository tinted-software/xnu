/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Clean-room kernel RNG ABI. State storage belongs to the Rust implementation.
 */
#ifndef _PRNG_CCRNG_ABI_H_
#define _PRNG_CCRNG_ABI_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ccrng_state {
	int (*generate)(struct ccrng_state *, size_t, void *);
};
#define ccrng_generate(rng, nbytes, out) \
	((rng)->generate((struct ccrng_state *)(rng), (nbytes), (out)))

struct ccrng_state *ccrng(int *error);
/* bound == 0 is invalid; bound == 1 always produces zero. */
int ccrng_uniform(struct ccrng_state *rng, uint64_t bound, uint64_t *out);

struct cckprng_ctx;
typedef int32_t (*cckprng_getentropy)(size_t *, void *, void *);
#define CCKPRNG_GENERATE_MAX_NBYTES ((size_t)256)

/* The registration callback order and signatures are consumer-visible ABI. */
struct cckprng_funcs {
	void (*init)(struct cckprng_ctx *, size_t, const void *, size_t,
	    const void *, cckprng_getentropy, void *);
	void (*initgen)(struct cckprng_ctx *, unsigned);
	void (*reseed)(struct cckprng_ctx *, size_t, const void *);
	void (*refresh)(struct cckprng_ctx *);
	void (*generate)(struct cckprng_ctx *, unsigned, size_t, void *);
	void (*init_with_getentropy)(struct cckprng_ctx *, unsigned, size_t,
	    const void *, size_t, const void *, cckprng_getentropy, void *);
};

struct cckprng_ctx *xnu_rc_kprng_context(void);
void cckprng_init(struct cckprng_ctx *, size_t, const void *, size_t,
    const void *, cckprng_getentropy, void *);
void cckprng_init_with_getentropy(struct cckprng_ctx *, unsigned, size_t,
    const void *, size_t, const void *, cckprng_getentropy, void *);
void cckprng_initgen(struct cckprng_ctx *, unsigned);
void cckprng_reseed(struct cckprng_ctx *, size_t, const void *);
void cckprng_refresh(struct cckprng_ctx *);
void cckprng_generate(struct cckprng_ctx *, unsigned, size_t, void *);

/* Install on the boot CPU after kernel locks/per-CPU storage are available,
 * before VM random-context initialization and secondary CPU startup. */
void xnu_rc_rng_install(void);

/* NULL context uses the synchronized, entropy-refreshed runtime RNG.
 * A non-NULL context is caller-serialized and acquires no lock in generate
 * or uniform, matching the per-CPU kmem random-context contract. */
void xnu_rc_rng_generate(void *ctx, void *out, size_t nbytes);
void xnu_rc_rng_uniform(void *ctx, uint64_t bound, uint64_t *out);
size_t xnu_rc_rng_ctx_size(void);
void xnu_rc_rng_ctx_init(void *ctx);

/* Internal early-boot state serialization; the token preserves IRQ masking. */
uintptr_t xnu_rc_rng_early_lock(void);
void xnu_rc_rng_early_unlock(uintptr_t token);

#ifdef __cplusplus
}
#endif
#endif
