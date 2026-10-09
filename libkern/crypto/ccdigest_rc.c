/*
 * Digest and HMAC framework for the kernel crypto KPI, backed by RustCrypto
 * block compression functions (rust/xnurc). Descriptor field offsets and
 * legacy digest/HMAC context conversions preserve the kernel consumer ABI.
 *
 * Padding and length encoding follow FIPS 180-4 (SHA-1/SHA-2) and RFC 1321
 * (MD5).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <libkern/crypto/ccdigest_abi.h>
#include <libkern/crypto/digest_kpi.h>
#include <kern/debug.h>

/* Block compress functions from rust/xnurc (no_std, panic = abort). */
extern void xnu_rc_sha1_compress(uint32_t *state, size_t nblocks, const void *data);
extern void xnu_rc_md5_compress(uint32_t *state, size_t nblocks, const void *data);
extern void xnu_rc_sha256_compress(uint32_t *state, size_t nblocks, const void *data);
extern void xnu_rc_sha512_compress(uint64_t *state, size_t nblocks, const void *data);

static inline void
rc_store32_be(uint32_t v, unsigned char *p)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

static inline void
rc_store32_le(uint32_t v, unsigned char *p)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

static inline void
rc_store64_be(uint64_t v, unsigned char *p)
{
	for (int i = 0; i < 8; i++) {
		p[i] = (unsigned char)(v >> (56 - 8 * i));
	}
}

static inline void
rc_store64_le(uint64_t v, unsigned char *p)
{
	for (int i = 0; i < 8; i++) {
		p[i] = (unsigned char)(v >> (8 * i));
	}
}

/* ------------------------------------------------------------------------ */
/* Initial hash values (FIPS 180-4 sections 5.3.x, RFC 1321).               */

const uint32_t ccsha1_initial_state[5] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};

const uint32_t ccmd5_initial_state[4] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
};

const uint32_t ccsha224_initial_state[8] = {
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};

const uint32_t ccsha256_initial_state[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

const uint64_t ccsha384_initial_state[8] = {
	0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
	0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
};

const uint64_t ccsha512_initial_state[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

const uint64_t ccsha512_256_initial_state[8] = {
	0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL, 0x2393b86b6f53b151ULL, 0x963877195940eabdULL,
	0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL, 0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL,
};

/* ------------------------------------------------------------------------ */
/* Generic Merkle-Damgard update and finalization.                          */

static void
ccdigest_update_rc(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data)
{
	const unsigned char *in = data;

	if (ccdigest_num(di, ctx) >= di->block_size) {
		panic("ccdigest_update: invalid buffered byte count");
	}

	while (len > 0) {
		if (ccdigest_num(di, ctx) == 0 && len >= di->block_size) {
			size_t nblocks = len / di->block_size;
			size_t nbytes = nblocks * di->block_size;
			di->compress(ccdigest_state(di, ctx), nblocks, in);
			len -= nbytes;
			in += nbytes;
			ccdigest_nbits(di, ctx) += (uint64_t)nbytes * 8;
		} else {
			size_t room = di->block_size - ccdigest_num(di, ctx);
			size_t n = len < room ? len : room;
			memcpy(ccdigest_data(di, ctx) + ccdigest_num(di, ctx), in, n);
			ccdigest_num(di, ctx) += (unsigned int)n;
			len -= n;
			in += n;
			if (ccdigest_num(di, ctx) == di->block_size) {
				di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));
				ccdigest_nbits(di, ctx) += (uint64_t)di->block_size * 8;
				ccdigest_num(di, ctx) = 0;
			}
		}
	}
}

/*
 * Pads the (cloned) context: 0x80, zeros, then the message bit length in the
 * final 8 bytes of the block. `len_bytes` is the length field size (8 for
 * 64-byte blocks, 16 for 128-byte blocks; the high bytes are zero). The
 * length is big-endian for SHA-2 and little-endian for MD5.
 */
static void
ccdigest_pad_and_compress(const struct ccdigest_info *di, ccdigest_ctx_t tmp, unsigned int len_bytes, int big_endian)
{
	uint64_t bits = ccdigest_nbits(di, tmp) + (uint64_t)ccdigest_num(di, tmp) * 8;
	unsigned char *data = ccdigest_data(di, tmp);
	if (ccdigest_num(di, tmp) >= di->block_size) {
		panic("ccdigest_final: invalid buffered byte count");
	}

	data[ccdigest_num(di, tmp)++] = 0x80;

	if (ccdigest_num(di, tmp) > di->block_size - len_bytes) {
		while (ccdigest_num(di, tmp) < di->block_size) {
			data[ccdigest_num(di, tmp)++] = 0;
		}
		di->compress(ccdigest_state(di, tmp), 1, data);
		ccdigest_num(di, tmp) = 0;
	}
	while (ccdigest_num(di, tmp) < di->block_size - len_bytes) {
		data[ccdigest_num(di, tmp)++] = 0;
	}
	for (unsigned int i = 0; i < len_bytes - 8; i++) {
		data[di->block_size - len_bytes + i] = 0;
	}
	if (big_endian) {
		rc_store64_be(bits, data + di->block_size - 8);
	} else {
		rc_store64_le(bits, data + di->block_size - 8);
	}
	di->compress(ccdigest_state(di, tmp), 1, data);
	ccdigest_num(di, tmp) = 0;
}

void
ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx)
{
	memset(ctx, 0, ccdigest_di_size(di));
	memcpy(ccdigest_state(di, ctx), di->initial_state, di->state_size);
}

void
ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data)
{
	ccdigest_update_rc(di, ctx, len, data);
}

void
ccdigest_final_64be(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest)
{
	ccdigest_di_decl(di, tmp);
	memcpy(tmp, ctx, ccdigest_di_size(di));
	ccdigest_pad_and_compress(di, tmp, 8, 1);
	for (unsigned int i = 0; i < di->output_size / 4; i++) {
		rc_store32_be(ccdigest_state_u32(di, tmp)[i], digest + 4 * i);
	}
	ccdigest_di_clear(di, tmp);
}

void
ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest)
{
	ccdigest_di_decl(di, tmp);
	memcpy(tmp, ctx, ccdigest_di_size(di));
	ccdigest_pad_and_compress(di, tmp, 8, 0);
	for (unsigned int i = 0; i < di->output_size / 4; i++) {
		rc_store32_le(ccdigest_state_u32(di, tmp)[i], digest + 4 * i);
	}
	ccdigest_di_clear(di, tmp);
}

/* SHA-384/512/512-256: 128-byte blocks, 128-bit big-endian length, 64-bit words. */
void
ccsha512_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest)
{
	ccdigest_di_decl(di, tmp);
	memcpy(tmp, ctx, ccdigest_di_size(di));
	ccdigest_pad_and_compress(di, tmp, 16, 1);
	for (unsigned int i = 0; i < di->output_size / 8; i++) {
		rc_store64_be(ccdigest_state_u64(di, tmp)[i], digest + 8 * i);
	}
	ccdigest_di_clear(di, tmp);
}

/* ------------------------------------------------------------------------ */
/* Digest descriptors. The public selectors are functions, as in the ABI.   */

static void
ccsha1_compress_rc(ccdigest_state_t state, size_t nblocks, const void *data)
{
	xnu_rc_sha1_compress(ccdigest_u32(state), nblocks, data);
}

static void
ccmd5_compress_rc(ccdigest_state_t state, size_t nblocks, const void *data)
{
	xnu_rc_md5_compress(ccdigest_u32(state), nblocks, data);
}

static void
ccsha256_compress_rc(ccdigest_state_t state, size_t nblocks, const void *data)
{
	xnu_rc_sha256_compress(ccdigest_u32(state), nblocks, data);
}

static void
ccsha512_compress_rc(ccdigest_state_t state, size_t nblocks, const void *data)
{
	xnu_rc_sha512_compress(ccdigest_u64(state), nblocks, data);
}

/* Preserve the descriptor's two-stream ABI on the scalar backend. */
static void
ccsha1_compress_rc_parallel(ccdigest_state_t s1, size_t n1, const void *d1,
    ccdigest_state_t s2, size_t n2, const void *d2)
{
	ccsha1_compress_rc(s1, n1, d1);
	ccsha1_compress_rc(s2, n2, d2);
}

static void
ccmd5_compress_rc_parallel(ccdigest_state_t s1, size_t n1, const void *d1,
    ccdigest_state_t s2, size_t n2, const void *d2)
{
	ccmd5_compress_rc(s1, n1, d1);
	ccmd5_compress_rc(s2, n2, d2);
}

static void
ccsha256_compress_rc_parallel(ccdigest_state_t s1, size_t n1, const void *d1,
    ccdigest_state_t s2, size_t n2, const void *d2)
{
	ccsha256_compress_rc(s1, n1, d1);
	ccsha256_compress_rc(s2, n2, d2);
}

static void
ccsha512_compress_rc_parallel(ccdigest_state_t s1, size_t n1, const void *d1,
    ccdigest_state_t s2, size_t n2, const void *d2)
{
	ccsha512_compress_rc(s1, n1, d1);
	ccsha512_compress_rc(s2, n2, d2);
}

static const unsigned char oid_sha1[] = { 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a };
static const unsigned char oid_md5[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05 };

static const struct ccdigest_info ccsha1_rc_di = {
	.output_size = 20,
	.state_size = 20,
	.block_size = 64,
	.oid_size = sizeof(oid_sha1),
	.oid = oid_sha1,
	.initial_state = ccsha1_initial_state,
	.compress = ccsha1_compress_rc,
	.final = ccdigest_final_64be,
	.compress_parallel = ccsha1_compress_rc_parallel,
};

static const struct ccdigest_info ccmd5_rc_di = {
	.output_size = 16,
	.state_size = 16,
	.block_size = 64,
	.oid_size = sizeof(oid_md5),
	.oid = oid_md5,
	.initial_state = ccmd5_initial_state,
	.compress = ccmd5_compress_rc,
	.final = ccdigest_final_64le,
	.compress_parallel = ccmd5_compress_rc_parallel,
};

static const struct ccdigest_info ccsha256_rc_di = {
	.output_size = 32,
	.state_size = 32,
	.block_size = 64,
	.oid_size = ccoid_sha256_len,
	.oid = ccoid_sha256,
	.initial_state = ccsha256_initial_state,
	.compress = ccsha256_compress_rc,
	.final = ccdigest_final_64be,
	.compress_parallel = ccsha256_compress_rc_parallel,
};

static const struct ccdigest_info ccsha224_rc_di = {
	.output_size = 28,
	.state_size = 32,
	.block_size = 64,
	.oid_size = ccoid_sha224_len,
	.oid = ccoid_sha224,
	.initial_state = ccsha224_initial_state,
	.compress = ccsha256_compress_rc,
	.final = ccdigest_final_64be,
	.compress_parallel = ccsha256_compress_rc_parallel,
};

static const struct ccdigest_info ccsha512_rc_di = {
	.output_size = 64,
	.state_size = 64,
	.block_size = 128,
	.oid_size = ccoid_sha512_len,
	.oid = ccoid_sha512,
	.initial_state = ccsha512_initial_state,
	.compress = ccsha512_compress_rc,
	.final = ccsha512_final,
	.compress_parallel = ccsha512_compress_rc_parallel,
};

static const struct ccdigest_info ccsha384_rc_di = {
	.output_size = 48,
	.state_size = 64,
	.block_size = 128,
	.oid_size = ccoid_sha384_len,
	.oid = ccoid_sha384,
	.initial_state = ccsha384_initial_state,
	.compress = ccsha512_compress_rc,
	.final = ccsha512_final,
	.compress_parallel = ccsha512_compress_rc_parallel,
};

static const struct ccdigest_info ccsha512_256_rc_di = {
	.output_size = 32,
	.state_size = 64,
	.block_size = 128,
	.oid_size = ccoid_sha512_256_len,
	.oid = ccoid_sha512_256,
	.initial_state = ccsha512_256_initial_state,
	.compress = ccsha512_compress_rc,
	.final = ccsha512_final,
	.compress_parallel = ccsha512_compress_rc_parallel,
};

const struct ccdigest_info *ccsha1_di(void) { return &ccsha1_rc_di; }
const struct ccdigest_info *ccmd5_di(void) { return &ccmd5_rc_di; }
const struct ccdigest_info *ccsha224_di(void) { return &ccsha224_rc_di; }
const struct ccdigest_info *ccsha256_di(void) { return &ccsha256_rc_di; }
const struct ccdigest_info *ccsha384_di(void) { return &ccsha384_rc_di; }
const struct ccdigest_info *ccsha512_di(void) { return &ccsha512_rc_di; }
const struct ccdigest_info *ccsha512_256_di(void) { return &ccsha512_256_rc_di; }

/* ------------------------------------------------------------------------ */
/* HMAC (RFC 2104) over the digest descriptors above, using cchmac_ctx layout. */

void
cchmac_init(const struct ccdigest_info *di, cchmac_ctx_t hc, size_t key_len, const void *key_data)
{
	const unsigned char *key = key_data;
	size_t byte = 0;

	/* Store (key XOR opad) in cchmac_data; hash keys longer than a block. */
	if (key_len <= di->block_size) {
		for (; byte < key_len; ++byte) {
			cchmac_data(di, hc)[byte] = key[byte] ^ 0x5c;
		}
	} else {
		ccdigest_init(di, cchmac_digest_ctx(di, hc));
		ccdigest_update(di, cchmac_digest_ctx(di, hc), key_len, key);
		ccdigest_final(di, cchmac_digest_ctx(di, hc), cchmac_data(di, hc));
		key_len = di->output_size;
		for (byte = 0; byte < key_len; ++byte) {
			cchmac_data(di, hc)[byte] ^= 0x5c;
		}
	}
	if (key_len < di->block_size) {
		memset(cchmac_data(di, hc) + key_len, 0x5c, di->block_size - key_len);
	}

	/* Outer state: compress(key XOR opad). */
	memcpy(cchmac_ostate(di, hc), di->initial_state, di->state_size);
	di->compress(cchmac_ostate(di, hc), 1, cchmac_data(di, hc));

	/* Inner state: compress(key XOR ipad), derived from (key XOR opad). */
	for (byte = 0; byte < di->block_size; ++byte) {
		cchmac_data(di, hc)[byte] ^= (0x5c ^ 0x36);
	}
	memcpy(cchmac_istate(di, hc), di->initial_state, di->state_size);
	di->compress(cchmac_istate(di, hc), 1, cchmac_data(di, hc));

	cchmac_num(di, hc) = 0;
	cchmac_nbits(di, hc) = di->block_size * 8;
}

void
cchmac_update(const struct ccdigest_info *di, cchmac_ctx_t hc, size_t data_len, const void *data)
{
	ccdigest_update(di, cchmac_digest_ctx(di, hc), data_len, data);
}

void
cchmac_final(const struct ccdigest_info *di, cchmac_ctx_t hc, unsigned char *mac)
{
	/* Inner hash H((K XOR ipad) || m), kept in cchmac_data for the outer round. */
	ccdigest_final(di, cchmac_digest_ctx(di, hc), cchmac_data(di, hc));

	/* Outer hash H((K XOR opad) || inner): restart from the saved outer state. */
	cchmac_num(di, hc) = (unsigned int)di->output_size;
	cchmac_nbits(di, hc) = di->block_size * 8;
	memcpy(cchmac_istate(di, hc), cchmac_ostate(di, hc), di->state_size);
	ccdigest_final(di, cchmac_digest_ctx(di, hc), mac);
}

void
cchmac(const struct ccdigest_info *di, size_t key_len, const void *key, size_t data_len, const void *data, unsigned char *mac)
{
	cchmac_di_decl(di, hc);
	cchmac_init(di, hc, key_len, key);
	cchmac_update(di, hc, data_len, data);
	cchmac_final(di, hc, mac);
	cchmac_di_clear(di, hc);
}

void
ccdigest(const struct ccdigest_info *di, size_t len, const void *data, void *digest)
{
	ccdigest_di_decl(di, dc);
	ccdigest_init(di, dc);
	ccdigest_update(di, dc, len, data);
	ccdigest_final(di, dc, digest);
	ccdigest_di_clear(di, dc);
}

void
xnu_rc_ccdigest_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
	ccdigest_final(di, ctx, digest);
}

static const struct ccdigest_info *
rc_digest_for_alg(crypto_digest_alg_t alg)
{
	switch (alg) {
	case CRYPTO_DIGEST_ALG_MD5: return ccmd5_di();
	case CRYPTO_DIGEST_ALG_SHA1: return ccsha1_di();
	case CRYPTO_DIGEST_ALG_SHA256: return ccsha256_di();
	case CRYPTO_DIGEST_ALG_SHA384: return ccsha384_di();
	case CRYPTO_DIGEST_ALG_SHA512: return ccsha512_di();
	default: panic("crypto digest: unsupported algorithm %u", (unsigned int)alg);
	}
}

static void
rc_check_context(void *ctx, size_t size, size_t needed)
{
	if (ctx == NULL || size < needed || ((uintptr_t)ctx & 7) != 0) {
		panic("crypto digest: invalid context storage");
	}
}

static void
rc_check_data(const void *data, size_t size)
{
	if (size != 0 && data == NULL) {
		panic("crypto digest: missing input");
	}
}

static void
rc_check_output(const struct ccdigest_info *di, const void *out, size_t size, bool hmac)
{
	if (out == NULL || size == 0 || size > di->output_size ||
	    (!hmac && size != di->output_size)) {
		panic("crypto digest: invalid output size");
	}
}

size_t
xnu_rc_digest_ctx_size(crypto_digest_alg_t alg)
{
	return ccdigest_di_size(rc_digest_for_alg(alg));
}

void
xnu_rc_digest_init(crypto_digest_alg_t alg, void *ctx, size_t ctx_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	rc_check_context(ctx, ctx_size, ccdigest_di_size(di));
	ccdigest_init(di, ctx);
}

void
xnu_rc_digest_update(crypto_digest_alg_t alg, void *ctx, size_t ctx_size,
    const void *data, size_t data_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	rc_check_context(ctx, ctx_size, ccdigest_di_size(di));
	rc_check_data(data, data_size);
	ccdigest_update(di, ctx, data_size, data);
}

void
xnu_rc_digest_final(crypto_digest_alg_t alg, void *ctx, size_t ctx_size,
    void *digest, size_t digest_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	rc_check_context(ctx, ctx_size, ccdigest_di_size(di));
	rc_check_output(di, digest, digest_size, false);
	ccdigest_final(di, ctx, digest);
}

void
xnu_rc_digest(crypto_digest_alg_t alg, const void *data, size_t data_size,
    void *digest, size_t digest_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	rc_check_data(data, data_size);
	rc_check_output(di, digest, digest_size, false);
	ccdigest(di, data_size, data, digest);
}

size_t
xnu_rc_hmac_ctx_size(crypto_digest_alg_t alg)
{
	return cchmac_di_size(rc_digest_for_alg(alg));
}

void
xnu_rc_hmac_init(crypto_digest_alg_t alg, void *ctx, size_t ctx_size,
    const void *key, size_t key_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	rc_check_context(ctx, ctx_size, cchmac_di_size(di));
	rc_check_data(key, key_size);
	cchmac_init(di, ctx, key_size, key);
}

void
xnu_rc_hmac_update(crypto_digest_alg_t alg, void *ctx, size_t ctx_size,
    const void *data, size_t data_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	rc_check_context(ctx, ctx_size, cchmac_di_size(di));
	rc_check_data(data, data_size);
	cchmac_update(di, ctx, data_size, data);
}

void
xnu_rc_hmac_final_generate(crypto_digest_alg_t alg, void *ctx, size_t ctx_size,
    void *tag, size_t tag_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	unsigned char full[CCSHA512_OUTPUT_SIZE];
	rc_check_context(ctx, ctx_size, cchmac_di_size(di));
	rc_check_output(di, tag, tag_size, true);
	if (tag_size == di->output_size) {
		cchmac_final(di, ctx, tag);
	} else {
		cchmac_final(di, ctx, full);
		memcpy(tag, full, tag_size);
		cc_clear(sizeof(full), full);
	}
}

bool
xnu_rc_hmac_final_verify(crypto_digest_alg_t alg, void *ctx, size_t ctx_size,
    const void *tag, size_t tag_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	unsigned char full[CCSHA512_OUTPUT_SIZE];
	rc_check_context(ctx, ctx_size, cchmac_di_size(di));
	if (tag == NULL || tag_size == 0 || tag_size > di->output_size) {
		return false;
	}
	cchmac_final(di, ctx, full);
	bool valid = cc_cmp_safe(tag_size, full, tag) == 0;
	cc_clear(sizeof(full), full);
	return valid;
}

void
xnu_rc_hmac_generate(crypto_digest_alg_t alg, const void *key, size_t key_size,
    const void *data, size_t data_size, void *tag, size_t tag_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	cchmac_di_decl(di, ctx);
	rc_check_data(key, key_size);
	rc_check_data(data, data_size);
	cchmac_init(di, ctx, key_size, key);
	cchmac_update(di, ctx, data_size, data);
	xnu_rc_hmac_final_generate(alg, ctx, cchmac_di_size(di), tag, tag_size);
	cchmac_di_clear(di, ctx);
}

bool
xnu_rc_hmac_verify(crypto_digest_alg_t alg, const void *key, size_t key_size,
    const void *data, size_t data_size, const void *tag, size_t tag_size)
{
	const struct ccdigest_info *di = rc_digest_for_alg(alg);
	cchmac_di_decl(di, ctx);
	rc_check_data(key, key_size);
	rc_check_data(data, data_size);
	cchmac_init(di, ctx, key_size, key);
	cchmac_update(di, ctx, data_size, data);
	bool valid = xnu_rc_hmac_final_verify(alg, ctx, cchmac_di_size(di), tag, tag_size);
	cchmac_di_clear(di, ctx);
	return valid;
}
