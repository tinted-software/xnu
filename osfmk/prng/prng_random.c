/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <kern/locks.h>
#include <kern/startup.h>
#include <kern/cpu_number.h>
#include <libkern/section_keywords.h>
#include <libkern/crypto/sha2.h>
#include <machine/machine_cpu.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <sys/random.h>
#include <prng/random.h>
#include <prng/entropy.h>
#include <libkern/crypto/cc_abi.h>
#include <libkern/crypto/ccdigest_abi.h>
#include <prng/ccrng_abi.h>
#include "hmac_drbg.h"

static struct cckprng_ctx *prng_ctx;

static SECURITY_READ_ONLY_LATE(struct cckprng_funcs) prng_funcs;
static SECURITY_READ_ONLY_LATE(int) prng_ready;

#define SEED_SIZE SHA512_DIGEST_LENGTH

#if defined(__x86_64__)
	#define BOOTLOADER_ENTROPY_REQUEST_SIZE 64 // efiboot max
#else
	#define BOOTLOADER_ENTROPY_REQUEST_SIZE 4*SEED_SIZE
#endif

static uint8_t kprngseed[SEED_SIZE];
static uint8_t earlyseed[SEED_SIZE];
static uint8_t entropyseed[SEED_SIZE];
static uint8_t kprng_reseed[SEED_SIZE];

static void
bootseed_init_bootloader(uint32_t request_size, uint8_t *dst)
{
	uint32_t n;

	n = PE_get_random_seed(dst, request_size);
	if (n < request_size) {
		/*
		 * Insufficient entropy is fatal.  We must fill the
		 * entire entropy buffer during initializaton.
		 */
		panic("Expected %u seed bytes from bootloader, but got %u.\n", request_size, n);
	}
}

#if defined(__x86_64__)
#include <i386/cpuid.h>

static void
bootseed_init_native(uint32_t request_size, uint8_t *dst)
{
	uint64_t x;
	uint8_t ok;
	size_t i = 0;
	size_t n;

	assert3u(request_size % sizeof(x), ==, 0);

	if (cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_RDSEED) {
		n = request_size / sizeof(x);

		while (i < n) {
			asm volatile ("rdseed %0; setc %1" : "=r"(x), "=qm"(ok) : : "cc");
			if (ok) {
				memcpy(&dst[i * sizeof(x)], &x, sizeof(x));
				i += 1;
			} else {
				// Intel recommends to pause between unsuccessful rdseed attempts.
				cpu_pause();
			}
		}
	} else if (cpuid_features() & CPUID_FEATURE_RDRAND) {
		// The Intel documentation guarantees a reseed every 512 rdrand calls.
		n = (request_size / sizeof(x)) * 512;

		while (i < n) {
			asm volatile ("rdrand %0; setc %1" : "=r"(x), "=qm"(ok) : : "cc");
			if (ok) {
				if (i % 512 == 0) {
					memcpy(&dst[(i / 512) * sizeof(x)], &x, sizeof(x));
				}
				i += 1;
			} else {
				// Intel does not recommend pausing between unsuccessful rdrand attempts.
			}
		}
	}

	cc_clear(sizeof(x), &x);
}

#else

static void
bootseed_init_native(uint32_t request_size, uint8_t *dst)
{
	/* Hardware entropy is optional; never treat uninitialized memory as input. */
	cc_clear(request_size, dst);
}

#endif

static void
bootseed_init(void)
{
	// Request our starting entropy from the bootloader
	uint8_t bootloader_rand[4 * SEED_SIZE];
	bootseed_init_bootloader(BOOTLOADER_ENTROPY_REQUEST_SIZE, bootloader_rand);

	#if defined(__x86_64__) && BOOTLOADER_ENTROPY_REQUEST_SIZE == 64
	// efiboot can only provide 64 bytes of entropy, so fill the rest of the buffer with zero.
	// We compensate for this by sampling from RDRAND/RDSEED in bootseed_init_native.
	cc_clear(sizeof(bootloader_rand) - BOOTLOADER_ENTROPY_REQUEST_SIZE, bootloader_rand + BOOTLOADER_ENTROPY_REQUEST_SIZE);
	#endif

	/*
	 *  First, we copy out a direct seed for the kprng from the TRNG packet then clear it to prevent reuse.
	 *   | BOOTLOADER_ENTROPY_REQUEST_SIZE |
	 *   | KPRNG |     OPAQUE  ENTROPY     |
	 *   | 00000 |     OPAQUE  ENTROPY     |
	 */
	memcpy(kprngseed, bootloader_rand, SEED_SIZE);
	cc_clear(SEED_SIZE, bootloader_rand);

	uint8_t native_rand[3 * SEED_SIZE] = {0};
	bootseed_init_native(sizeof(native_rand), native_rand);

	const struct ccdigest_info *di = ccsha512_di();
	assert3u(SEED_SIZE, <, di->block_size);

	/* Domain-separated extraction must retain bootloader entropy even on
	 * x86 machines with neither RDSEED nor RDRAND and only a 64-byte packet. */
	uint8_t combined_input[1 + 2 * SEED_SIZE];

	combined_input[0] = 1;
	memcpy(&combined_input[1], &bootloader_rand[1 * SEED_SIZE], SEED_SIZE);
	memcpy(&combined_input[1 + SEED_SIZE], &native_rand[0 * SEED_SIZE], SEED_SIZE);
	cchmac(di, SEED_SIZE, kprngseed, sizeof(combined_input), combined_input, earlyseed);

	combined_input[0] = 2;
	memcpy(&combined_input[1], &bootloader_rand[2 * SEED_SIZE], SEED_SIZE);
	memcpy(&combined_input[1 + SEED_SIZE], &native_rand[1 * SEED_SIZE], SEED_SIZE);
	cchmac(di, SEED_SIZE, kprngseed, sizeof(combined_input), combined_input, entropyseed);

	combined_input[0] = 3;
	memcpy(&combined_input[1], &bootloader_rand[3 * SEED_SIZE], SEED_SIZE);
	memcpy(&combined_input[1 + SEED_SIZE], &native_rand[2 * SEED_SIZE], SEED_SIZE);
	cchmac(di, SEED_SIZE, kprngseed, sizeof(combined_input), combined_input, kprng_reseed);

	cc_clear(sizeof(combined_input), combined_input);

	cc_clear(sizeof(bootloader_rand), bootloader_rand);
	cc_clear(sizeof(native_rand), native_rand);
}

static struct {
	struct hmac_drbg_sha256 drbg;
} erandom;
static int erandom_initialized;

__attribute__((noinline))
static void
early_random_init(void)
{
	uint64_t nonce;
	const char ps[] = "xnu early random";

	bootseed_init();

	/* The timestamp diversifies the state; entropy comes from bootseed_init. */
	assert3u(sizeof(earlyseed), >, sizeof(nonce));
	nonce = ml_get_timebase();
	hmac_drbg_sha256_instantiate(&erandom.drbg, earlyseed, sizeof(earlyseed), &nonce, sizeof(nonce), ps, sizeof(ps) - 1);

	cc_clear(sizeof(nonce), &nonce);
	cc_clear(sizeof(earlyseed), earlyseed);
	erandom_initialized = 1;
}

__static_testable void read_erandom(void * buf, size_t nbytes);

/*
 * Return a uniformly distributed 64-bit random number.
 *
 * This interface should have minimal dependencies on kernel services,
 * and thus be available very early in the life of the kernel.
 *
 * This provides cryptographically secure randomness contingent on the
 * quality of the seed. It is seeded (lazily) with entropy provided by
 * the Booter.
 *
 * The early instance is a serialized HMAC-SHA256 DRBG seeded with a
 * domain-separated derivation of bootloader and optional hardware entropy.
 * After the Rust runtime PRNG is installed, requests use its independent,
 * synchronized CPU generators instead. Early state is then erased.
 */
uint64_t
early_random(void)
{
	uint64_t result;

	read_erandom(&result, sizeof(result));

	return result;
}

static void
read_random_generate(uint8_t *buffer, size_t numbytes);

/* Only used before runtime installation; the caller holds the early lock. */
__attribute__((noinline))
static void
read_erandom_generate(void * buf, size_t nbytes)
{
	uint8_t * buffer_bytes = buf;
	size_t n;

	/* Bound each SP 800-90A Generate request. */
	while (nbytes > 0) {
		n = MIN(nbytes, PAGE_SIZE);

		hmac_drbg_sha256_generate(&erandom.drbg, buffer_bytes, n);

		buffer_bytes += n;
		nbytes -= n;
	}
}

__static_testable __mockable void
read_erandom(void * buf, size_t nbytes)
{
	if (__probable(__atomic_load_n(&prng_ready, __ATOMIC_ACQUIRE))) {
		read_random_generate(buf, nbytes);
		return;
	}

	uintptr_t token = xnu_rc_rng_early_lock();
	if (__atomic_load_n(&prng_ready, __ATOMIC_ACQUIRE)) {
		xnu_rc_rng_early_unlock(token);
		read_random_generate(buf, nbytes);
		return;
	}
	if (!erandom_initialized) {
		early_random_init();
	}
	read_erandom_generate(buf, nbytes);
	xnu_rc_rng_early_unlock(token);
}

void
read_frandom(void * buffer, u_int numBytes)
{
	read_erandom(buffer, numBytes);
}

void
register_and_init_prng(struct cckprng_ctx *ctx, const struct cckprng_funcs *funcs)
{
	assert3s(cpu_number(), ==, boot_cpu_id);
	assert(!__atomic_load_n(&prng_ready, __ATOMIC_ACQUIRE));

	uintptr_t token = xnu_rc_rng_early_lock();
	if (!erandom_initialized) {
		early_random_init();
	}
	xnu_rc_rng_early_unlock(token);

	entropy_init(sizeof(entropyseed), entropyseed);
	/* Serialize seed consumption against genuine early-boot reseeds. */
	token = xnu_rc_rng_early_lock();

	prng_ctx = ctx;
	prng_funcs = *funcs;

	uint64_t nonce = ml_get_timebase();
	prng_funcs.init_with_getentropy(prng_ctx, MAX_CPUS, sizeof(kprngseed), kprngseed, sizeof(nonce), &nonce, entropy_provide, NULL);
	prng_funcs.initgen(prng_ctx, boot_cpu_id);

	/* Mix the independently derived boot key and any early user reseeds. */
	prng_funcs.reseed(prng_ctx, sizeof(kprng_reseed), kprng_reseed);

	cc_clear(sizeof(nonce), &nonce);
	cc_clear(sizeof(entropyseed), entropyseed);
	cc_clear(sizeof(kprngseed), kprngseed);
	cc_clear(sizeof(kprng_reseed), kprng_reseed);
	cc_clear(sizeof(erandom), &erandom);
	__atomic_store_n(&prng_ready, 1, __ATOMIC_RELEASE);
	xnu_rc_rng_early_unlock(token);
}

void
xnu_rc_rng_install(void)
{
	static const struct cckprng_funcs rust_prng_funcs = {
		.init = cckprng_init,
		.initgen = cckprng_initgen,
		.reseed = cckprng_reseed,
		.refresh = cckprng_refresh,
		.generate = cckprng_generate,
		.init_with_getentropy = cckprng_init_with_getentropy,
	};

	if (__atomic_load_n(&prng_ready, __ATOMIC_ACQUIRE)) {
		return;
	}
	register_and_init_prng(xnu_rc_kprng_context(), &rust_prng_funcs);
}

void
random_cpu_init(int cpu)
{
	assert3s(cpu, !=, boot_cpu_id);

	if (!__atomic_load_n(&prng_ready, __ATOMIC_ACQUIRE)) {
		panic("random_cpu_init: kernel prng has not been installed");
	}

	prng_funcs.initgen(prng_ctx, cpu);
}

/* export good random numbers to the rest of the kernel */
__mockable void
read_random(void * buffer, u_int numbytes)
{
	if (__improbable(!__atomic_load_n(&prng_ready, __ATOMIC_ACQUIRE))) {
		/* ZALLOC callers precede per-CPU entropy/lock initialization. */
		if (startup_phase < STARTUP_SUB_EARLY_BOOT) {
			read_erandom(buffer, numbytes);
			return;
		}
		xnu_rc_rng_install();
	}
	prng_funcs.refresh(prng_ctx);
	read_random_generate(buffer, numbytes);
}

static void
ensure_gsbase(void)
{
#if defined(__x86_64__) && (DEVELOPMENT || DEBUG)
	/*
	 * Calling cpu_number() before gsbase is initialized is potentially
	 * catastrophic, so assert that it's not set to the magic value set
	 * in i386_init.c before proceeding with the call.  We cannot use
	 * assert here because it ultimately calls panic, which executes
	 * operations that involve accessing %gs-relative data (and additionally
	 * causes a debug trap which will not work properly this early in boot.)
	 */
	if (rdmsr64(MSR_IA32_GS_BASE) == EARLY_GSBASE_MAGIC) {
		kprintf("[early_random] Cannot proceed: GSBASE is not initialized\n");
		hlt();
		/*NOTREACHED*/
	}
#endif
}

static void
read_random_generate(uint8_t *buffer, size_t numbytes)
{
	ensure_gsbase();

	while (numbytes > 0) {
		size_t n = MIN(numbytes, CCKPRNG_GENERATE_MAX_NBYTES);

		prng_funcs.generate(prng_ctx, cpu_number(), n, buffer);

		buffer += n;
		numbytes -= n;
	}
}

int
write_random(void * buffer, u_int numbytes)
{
	/* User input is mixed into existing state, never credited as entropy.
	 * A fixed-size seed also bounds time spent holding the state lock. */
	uint8_t seed[SHA512_DIGEST_LENGTH] = {0};

	if (numbytes > SHA512_DIGEST_LENGTH) {
		/* hash the input to minimize the time we need to hold the lock */
		SHA512_CTX ctx;
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, buffer, numbytes);
		SHA512_Final(seed, &ctx);
	} else {
		memcpy(seed, buffer, numbytes);
	}

	if (__improbable(!__atomic_load_n(&prng_ready, __ATOMIC_ACQUIRE))) {
		if (startup_phase >= STARTUP_SUB_EARLY_BOOT) {
			xnu_rc_rng_install();
		} else {
			uintptr_t token = xnu_rc_rng_early_lock();
			if (!__atomic_load_n(&prng_ready, __ATOMIC_ACQUIRE)) {
				if (!erandom_initialized) {
					early_random_init();
				}
				hmac_drbg_sha256_reseed(&erandom.drbg, seed, sizeof(seed));
				uint8_t pending[SEED_SIZE];
				cchmac(ccsha512_di(), sizeof(kprng_reseed), kprng_reseed,
				    sizeof(seed), seed, pending);
				memcpy(kprng_reseed, pending, sizeof(pending));
				cc_clear(sizeof(pending), pending);
				xnu_rc_rng_early_unlock(token);
				cc_clear(sizeof(seed), seed);
				return 0;
			}
			xnu_rc_rng_early_unlock(token);
		}
	}

	prng_funcs.reseed(prng_ctx, sizeof(seed), seed);
	cc_clear(sizeof(seed), seed);

	return 0;
}

/*
 * Boolean PRNG for generating booleans to randomize order of elements
 * in certain kernel data structures. The algorithm is a
 * modified version of the KISS RNG proposed in the paper:
 * http://stat.fsu.edu/techreports/M802.pdf
 * The modifications have been documented in the technical paper
 * paper from UCL:
 * http://www0.cs.ucl.ac.uk/staff/d.jones/GoodPracticeRNG.pdf
 */

/* Initialize the PRNG structures. */
void
random_bool_init(struct bool_gen * bg)
{
	/* Seed the random boolean generator */
	read_frandom(bg->seed, sizeof(bg->seed));
	bg->state = 0;
	simple_lock_init(&bg->lock, 0);
}

/* Generate random bits and add them to an entropy pool. */
void
random_bool_gen_entropy(struct bool_gen * bg, unsigned int * buffer, int count)
{
	simple_lock(&bg->lock, LCK_GRP_NULL);
	int i, t;
	for (i = 0; i < count; i++) {
		bg->seed[1] ^= (bg->seed[1] << 5);
		bg->seed[1] ^= (bg->seed[1] >> 7);
		bg->seed[1] ^= (bg->seed[1] << 22);
		t           = bg->seed[2] + bg->seed[3] + bg->state;
		bg->seed[2] = bg->seed[3];
		bg->state   = t < 0;
		bg->seed[3] = t & 2147483647;
		bg->seed[0] += 1411392427;
		buffer[i] = (bg->seed[0] + bg->seed[1] + bg->seed[3]);
	}
	simple_unlock(&bg->lock);
}

/* Get some number of bits from the entropy pool, refilling if necessary. */
unsigned int
random_bool_gen_bits(struct bool_gen * bg, unsigned int * buffer, unsigned int count, unsigned int numbits)
{
	unsigned int index = 0;
	unsigned int rbits = 0;
	for (unsigned int bitct = 0; bitct < numbits; bitct++) {
		/*
		 * Find a portion of the buffer that hasn't been emptied.
		 * We might have emptied our last index in the previous iteration.
		 */
		while (index < count && buffer[index] == 0) {
			index++;
		}

		/* If we've exhausted the pool, refill it. */
		if (index == count) {
			random_bool_gen_entropy(bg, buffer, count);
			index = 0;
		}

		/* Collect-a-bit */
		unsigned int bit = buffer[index] & 1;
		buffer[index]    = buffer[index] >> 1;
		rbits            = bit | (rbits << 1);
	}
	return rbits;
}
