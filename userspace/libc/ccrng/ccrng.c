/*
 * ccrng replacement backing arc4random (see include/corecrypto/ccrng.h).
 *
 * Design:
 *  - One process-wide ChaCha20 DRBG. The key comes from getentropy(2) and is
 *    replaced after CCRNG_RESEED_BYTES of output.
 *  - Each generate call takes a fresh nonce from a counter under the lock, so
 *    no (key, nonce) pair repeats even across threads.
 *  - Reseed on PID change: after fork() the child must not replay the
 *    parent's keystream.
 *  - Reseed failure is fatal (abort). Silently continuing with a stale or
 *    zero key would make arc4random output predictable.
 */

#include <corecrypto/ccrng.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int ccrng_rs_entropy(uint8_t *buf, size_t len);
int ccrng_rs_keystream(const uint8_t *key, uint64_t counter, uint8_t *out, size_t len);

#define CCRNG_KEY_BYTES		32
#define CCRNG_RESEED_BYTES	(1ULL << 20)
#define CCRNG_CHUNK_BYTES	(1ULL << 20)	/* bounds the per-call block counter */

struct ccrng_state {
	uint8_t key[CCRNG_KEY_BYTES];
	uint64_t counter;		/* next nonce; advanced under lock */
	uint64_t bytes_since_seed;
	pid_t pid;
	uint8_t seeded;
	uint8_t lock;			/* spinlock: guards every field above */
};

static struct ccrng_state ccrng_global;

static void
ccrng_lock(struct ccrng_state *s)
{
	while (__atomic_test_and_set(&s->lock, __ATOMIC_ACQUIRE)) {
		/* spin: critical sections copy 32 bytes or bump a counter */
	}
}

static void
ccrng_unlock(struct ccrng_state *s)
{
	__atomic_clear(&s->lock, __ATOMIC_RELEASE);
}

static int
entropy_fill(uint8_t *buf, size_t len)
{
	while (len > 0) {
		/* getentropy(2) accepts at most 256 bytes per call. */
		size_t n = len < 256 ? len : 256;

		if (ccrng_rs_entropy(buf, n) != 0) {
			return -1;
		}
		buf += n;
		len -= n;
	}
	return 0;
}

/* Caller holds the lock. */
static int
reseed_locked(struct ccrng_state *s)
{
	if (entropy_fill(s->key, sizeof(s->key)) != 0) {
		return -1;
	}
	s->bytes_since_seed = 0;
	s->pid = getpid();
	s->seeded = 1;
	return 0;
}

struct ccrng_state *
ccrng(int *err)
{
	struct ccrng_state *s = &ccrng_global;

	ccrng_lock(s);
	if (!s->seeded && reseed_locked(s) != 0) {
		int saved = errno;

		ccrng_unlock(s);
		if (err != NULL) {
			*err = saved;
		}
		return NULL;
	}
	ccrng_unlock(s);

	if (err != NULL) {
		*err = 0;
	}
	return s;
}

/* Generates at most CCRNG_CHUNK_BYTES; the caller splits larger requests. */
static void
generate_chunk(struct ccrng_state *s, size_t nbytes, void *out)
{
	uint8_t key[CCRNG_KEY_BYTES];
	uint64_t nonce;

	ccrng_lock(s);
	if (!s->seeded || s->pid != getpid() ||
	    s->bytes_since_seed + nbytes > CCRNG_RESEED_BYTES) {
		if (reseed_locked(s) != 0) {
			ccrng_unlock(s);
			abort();
		}
	}
	memcpy(key, s->key, sizeof(key));
	nonce = s->counter++;
	s->bytes_since_seed += nbytes;
	ccrng_unlock(s);

	if (ccrng_rs_keystream(key, nonce, out, nbytes) != 0) {
		memset(key, 0, sizeof(key));
		abort();
	}
	memset(key, 0, sizeof(key));
}

int
ccrng_generate(struct ccrng_state *s, size_t nbytes, void *out)
{
	uint8_t *p = out;

	while (nbytes > 0) {
		size_t n = nbytes < CCRNG_CHUNK_BYTES ? nbytes : CCRNG_CHUNK_BYTES;

		generate_chunk(s, n, p);
		p += n;
		nbytes -= n;
	}
	return 0;
}

int
ccrng_uniform(struct ccrng_state *s, uint64_t upper_bound, uint64_t *rand)
{
	uint64_t threshold, r;

	if (upper_bound < 2) {
		*rand = 0;
		return 0;
	}

	/* Rejection sampling: discard the 2^64 mod n values that would bias. */
	threshold = (0 - upper_bound) % upper_bound;
	for (;;) {
		ccrng_generate(s, sizeof(r), &r);
		if (r >= threshold) {
			*rand = r % upper_bound;
			return 0;
		}
	}
}
