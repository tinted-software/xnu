/*
 * Boot-time known-answer test for the kernel digest and HMAC API. Code
 * signing (cdhash, trust caches) hashes through the SHA-1/SHA-256 entry points
 * below, and userspace verifies those hashes, so a changed digest would break
 * binaries that run later. Vectors are the FIPS 180-4 and RFC 4231-style
 * examples. Any mismatch panics the boot.
 */

#include <string.h>

#include <kern/startup.h>
#include <libkern/libkern.h>
#include <libkern/crypto/sha1.h>
#include <libkern/crypto/sha2.h>

#include <libkern/crypto/md5.h>
#include <libkern/crypto/crypto_internal.h>
#include <libkern/crypto/ccdigest_abi.h>

static const char kat_abc[] = "abc";
static const char kat_two_block[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const char kat_hmac_key[] = "key";
static const char kat_hmac_msg[] = "The quick brown fox jumps over the lazy dog";


static const unsigned char exp_md5_abc[16] = {
	0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
	0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
};
static const unsigned char exp_sha1_abc[20] = {
	0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
	0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
};
static const unsigned char exp_sha1_two_block[20] = {
	0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
	0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
};
static const unsigned char exp_sha256_abc[32] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};
static const unsigned char exp_sha256_two_block[32] = {
	0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
	0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
};
static const unsigned char exp_sha384_abc[48] = {
	0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
	0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
	0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
};
static const unsigned char exp_sha512_two_block[64] = {
	0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
	0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
	0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
	0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45,
};
static const unsigned char exp_hmac256[32] = {
	0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
	0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8,
};

/* RFC 4231 test case 6: a key longer than the SHA-256 block size. */
static const unsigned char exp_hmac256_long_key[32] = {
	0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
	0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
	0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
	0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
};

static void
crypto_kat_fail(const char *what)
{
	panic("crypto self-test failed: %s", what);
}

static void
crypto_kat_check(const char *what, const unsigned char *got, const unsigned char *want, size_t n)
{
	if (memcmp(got, want, n) != 0) {
		crypto_kat_fail(what);
	}
}

static void
crypto_kat_modern_digest(crypto_digest_alg_t alg, const char *message,
    const unsigned char *expected, size_t digest_size)
{
	ccdigest_ctx_decl(CCSHA512_STATE_SIZE, CCSHA512_BLOCK_SIZE, ctx);
	unsigned char out[CCSHA512_OUTPUT_SIZE];
	size_t size = g_crypto_funcs->digest_ctx_size_fn(alg);
	if (size > sizeof(ctx)) {
		crypto_kat_fail("modern digest context size");
	}
	g_crypto_funcs->digest_fn(alg, message, strlen(message), out, digest_size);
	crypto_kat_check("modern digest one-shot", out, expected, digest_size);
	g_crypto_funcs->digest_init_fn(alg, ctx, sizeof(ctx));
	g_crypto_funcs->digest_update_fn(alg, ctx, sizeof(ctx), message, 1);
	g_crypto_funcs->digest_update_fn(alg, ctx, sizeof(ctx), NULL, 0);
	g_crypto_funcs->digest_update_fn(alg, ctx, sizeof(ctx), message + 1, strlen(message) - 1);
	g_crypto_funcs->digest_final_fn(alg, ctx, sizeof(ctx), out, digest_size);
	crypto_kat_check("modern digest multipart", out, expected, digest_size);
	cc_clear(sizeof(ctx), ctx);
}

__startup_func
static void
crypto_selftest(void)
{
	unsigned char out[64];
	SHA1_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;
	SHA384_CTX sha384;
	MD5_CTX md5;
	const struct ccdigest_info *di = ccsha256_di();
	cchmac_di_decl(di, hc);

	MD5Init(&md5);
	MD5Update(&md5, kat_abc, (unsigned int)strlen(kat_abc));
	MD5Final(out, &md5);
	crypto_kat_check("md5 abc", out, exp_md5_abc, sizeof(exp_md5_abc));

	SHA1Init(&sha1);
	SHA1Update(&sha1, kat_abc, strlen(kat_abc));
	SHA1Final(out, &sha1);
	crypto_kat_check("sha1 abc", out, exp_sha1_abc, 20);

	SHA1Init(&sha1);
	SHA1Update(&sha1, kat_two_block, 28);
	SHA1Update(&sha1, kat_two_block + 28, strlen(kat_two_block) - 28);
	SHA1Final(out, &sha1);
	crypto_kat_check("sha1 two-block", out, exp_sha1_two_block, 20);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, kat_abc, strlen(kat_abc));
	SHA256_Final(out, &sha256);
	crypto_kat_check("sha256 abc", out, exp_sha256_abc, 32);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, kat_two_block, strlen(kat_two_block));
	SHA256_Final(out, &sha256);
	crypto_kat_check("sha256 two-block", out, exp_sha256_two_block, 32);

	SHA384_Init(&sha384);
	SHA384_Update(&sha384, kat_abc, strlen(kat_abc));
	SHA384_Final(out, &sha384);
	crypto_kat_check("sha384 abc", out, exp_sha384_abc, 48);

	SHA512_Init(&sha512);
	SHA512_Update(&sha512, kat_two_block, strlen(kat_two_block));
	SHA512_Final(out, &sha512);
	crypto_kat_check("sha512 two-block", out, exp_sha512_two_block, 64);

	cchmac_init(di, hc, strlen(kat_hmac_key), kat_hmac_key);
	cchmac_update(di, hc, strlen(kat_hmac_msg), kat_hmac_msg);
	cchmac_final(di, hc, out);
	crypto_kat_check("hmac-sha256", out, exp_hmac256, 32);
	cchmac_di_clear(di, hc);

	crypto_kat_modern_digest(CRYPTO_DIGEST_ALG_MD5, kat_abc, exp_md5_abc, sizeof(exp_md5_abc));
	crypto_kat_modern_digest(CRYPTO_DIGEST_ALG_SHA1, kat_abc, exp_sha1_abc, sizeof(exp_sha1_abc));
	crypto_kat_modern_digest(CRYPTO_DIGEST_ALG_SHA256, kat_abc, exp_sha256_abc, sizeof(exp_sha256_abc));
	crypto_kat_modern_digest(CRYPTO_DIGEST_ALG_SHA384, kat_abc, exp_sha384_abc, sizeof(exp_sha384_abc));
	crypto_kat_modern_digest(CRYPTO_DIGEST_ALG_SHA512, kat_two_block, exp_sha512_two_block, sizeof(exp_sha512_two_block));

	g_crypto_funcs->hmac_generate_fn(CRYPTO_DIGEST_ALG_SHA256,
	    kat_hmac_key, strlen(kat_hmac_key), kat_hmac_msg, strlen(kat_hmac_msg), out, 32);
	crypto_kat_check("modern HMAC generate", out, exp_hmac256, 32);
	if (!g_crypto_funcs->hmac_verify_fn(CRYPTO_DIGEST_ALG_SHA256,
	    kat_hmac_key, strlen(kat_hmac_key), kat_hmac_msg, strlen(kat_hmac_msg), out, 32)) {
		crypto_kat_fail("modern HMAC verify");
	}
	out[0] ^= 1;
	if (g_crypto_funcs->hmac_verify_fn(CRYPTO_DIGEST_ALG_SHA256,
	    kat_hmac_key, strlen(kat_hmac_key), kat_hmac_msg, strlen(kat_hmac_msg), out, 32)) {
		crypto_kat_fail("modern HMAC accepts invalid tag");
	}

	unsigned char long_key[131];
	const char long_key_message[] = "Test Using Larger Than Block-Size Key - Hash Key First";
	memset(long_key, 0xaa, sizeof(long_key));
	cchmac(di, sizeof(long_key), long_key, sizeof(long_key_message) - 1, long_key_message, out);
	crypto_kat_check("HMAC long key", out, exp_hmac256_long_key, 32);
	size_t hmac_size = g_crypto_funcs->hmac_ctx_size_fn(CRYPTO_DIGEST_ALG_SHA256);
	if (hmac_size > sizeof(hc)) {
		crypto_kat_fail("modern HMAC context size");
	}
	g_crypto_funcs->hmac_init_fn(CRYPTO_DIGEST_ALG_SHA256, hc, sizeof(hc), long_key, sizeof(long_key));
	g_crypto_funcs->hmac_update_fn(CRYPTO_DIGEST_ALG_SHA256, hc, sizeof(hc), long_key_message, 17);
	g_crypto_funcs->hmac_update_fn(CRYPTO_DIGEST_ALG_SHA256, hc, sizeof(hc),
	    long_key_message + 17, sizeof(long_key_message) - 1 - 17);
	g_crypto_funcs->hmac_final_generate_fn(CRYPTO_DIGEST_ALG_SHA256, hc, sizeof(hc), out, 32);
	crypto_kat_check("modern HMAC multipart", out, exp_hmac256_long_key, 32);
	g_crypto_funcs->hmac_init_fn(CRYPTO_DIGEST_ALG_SHA256, hc, sizeof(hc), long_key, sizeof(long_key));
	g_crypto_funcs->hmac_update_fn(CRYPTO_DIGEST_ALG_SHA256, hc, sizeof(hc),
	    long_key_message, sizeof(long_key_message) - 1);
	if (!g_crypto_funcs->hmac_final_verify_fn(CRYPTO_DIGEST_ALG_SHA256, hc, sizeof(hc), out, 16)) {
		crypto_kat_fail("modern HMAC truncated verify");
	}
	cchmac_di_clear(di, hc);
	cc_clear(sizeof(long_key), long_key);

	printf("crypto self-test: digest and HMAC known-answer tests passed\n");
}
STARTUP(EARLY_BOOT, STARTUP_RANK_LAST, crypto_selftest);
