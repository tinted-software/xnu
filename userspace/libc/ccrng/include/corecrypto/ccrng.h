/*
 * ccrng replacement for libc's arc4random (corecrypto is not available in
 * this tree). Implemented in ../ccrng.c over a ChaCha20 DRBG seeded from
 * getentropy(2); see that file for the reseed and fork policy.
 *
 * Only the entry points libc uses are declared.
 */

#ifndef _CORECRYPTO_CCRNG_H_
#define _CORECRYPTO_CCRNG_H_

#include <stddef.h>
#include <stdint.h>

struct ccrng_state;

/*
 * Returns the process-wide generator, seeding it on first use. On failure
 * returns NULL and stores errno in *err.
 */
struct ccrng_state *ccrng(int *err);

/* Fills out with nbytes of random data. Returns 0; aborts if reseeding fails. */
int ccrng_generate(struct ccrng_state *rng, size_t nbytes, void *out);

/* Stores a uniform value in [0, upper_bound) in *rand (0 when upper_bound < 2). */
int ccrng_uniform(struct ccrng_state *rng, uint64_t upper_bound, uint64_t *rand);

#endif /* _CORECRYPTO_CCRNG_H_ */
