/* Built-in RustCrypto provider registration. This is not a loadable kmod or
 * a FIPS-validated provider; no module-identity or POST-success API is exposed. */
#define XNU_KERNEL_PRIVATE 1
#include <libkern/libkern.h>
#include <libkern/crypto/register_crypto.h>
#include <libkern/section_keywords.h>
#include <kern/startup.h>

#include <libkern/crypto/digest_kpi.h>

static SECURITY_READ_ONLY_LATE(struct crypto_functions) rustcrypto_functions;

static void
rustcrypto_register(void)
{
	rustcrypto_functions = (struct crypto_functions) {
		.ccdigest_init_fn = ccdigest_init,
		.ccdigest_update_fn = ccdigest_update,
		.ccdigest_final_fn = xnu_rc_ccdigest_final,
		.ccdigest_fn = ccdigest,
		.ccmd5_di = ccmd5_di(),
		.ccsha1_di = ccsha1_di(),
		.ccsha256_di = ccsha256_di(),
		.ccsha384_di = ccsha384_di(),
		.ccsha512_di = ccsha512_di(),
		.cchmac_init_fn = cchmac_init,
		.cchmac_update_fn = cchmac_update,
		.cchmac_final_fn = cchmac_final,
		.cchmac_fn = cchmac,
		.ccaes_ecb_encrypt = xnu_rc_aes_ecb_encrypt_mode(),
		.ccaes_ecb_decrypt = xnu_rc_aes_ecb_decrypt_mode(),
		.ccaes_cbc_encrypt = xnu_rc_aes_cbc_encrypt_mode(),
		.ccaes_cbc_decrypt = xnu_rc_aes_cbc_decrypt_mode(),
		.ccaes_ctr_crypt = xnu_rc_aes_ctr_crypt_mode(),
		.ccaes_xts_encrypt = xnu_rc_aes_xts_encrypt_mode(),
		.ccaes_xts_decrypt = xnu_rc_aes_xts_decrypt_mode(),
		.ccaes_gcm_encrypt = xnu_rc_aes_gcm_encrypt_mode(),
		.ccaes_gcm_decrypt = xnu_rc_aes_gcm_decrypt_mode(),
		.ccgcm_init_with_iv_fn = ccgcm_init_with_iv,
		.ccgcm_inc_iv_fn = ccgcm_inc_iv,
		.ccchacha20poly1305_fns = xnu_rc_chacha20poly1305_fns(),
		.ccdes_ecb_encrypt = xnu_rc_des_ecb_encrypt_mode(),
		.ccdes_ecb_decrypt = xnu_rc_des_ecb_decrypt_mode(),
		.ccdes_cbc_encrypt = xnu_rc_des_cbc_encrypt_mode(),
		.ccdes_cbc_decrypt = xnu_rc_des_cbc_decrypt_mode(),
		.cctdes_ecb_encrypt = xnu_rc_tdes_ecb_encrypt_mode(),
		.cctdes_ecb_decrypt = xnu_rc_tdes_ecb_decrypt_mode(),
		.cctdes_cbc_encrypt = xnu_rc_tdes_cbc_encrypt_mode(),
		.cctdes_cbc_decrypt = xnu_rc_tdes_cbc_decrypt_mode(),
		.ccdes_key_is_weak_fn = ccdes_key_is_weak,
		.ccdes_key_set_odd_parity_fn = ccdes_key_set_odd_parity,
		.ccpad_cts3_encrypt_fn = ccpad_cts3_encrypt,
		.ccpad_cts3_decrypt_fn = ccpad_cts3_decrypt,
		.ccrng_fn = ccrng,
		.ccrsa_make_pub_fn = xnu_rc_ccrsa_make_pub,
		.ccrsa_verify_pkcs1v15_fn = xnu_rc_ccrsa_verify_pkcs1v15,
		.random_generate_fn = xnu_rc_rng_generate,
		.random_uniform_fn = xnu_rc_rng_uniform,
		.random_kmem_ctx_size_fn = xnu_rc_rng_ctx_size,
		.random_kmem_init_fn = xnu_rc_rng_ctx_init,
		.digest_ctx_size_fn = xnu_rc_digest_ctx_size,
		.digest_init_fn = xnu_rc_digest_init,
		.digest_update_fn = xnu_rc_digest_update,
		.digest_final_fn = xnu_rc_digest_final,
		.digest_fn = xnu_rc_digest,
		.hmac_ctx_size_fn = xnu_rc_hmac_ctx_size,
		.hmac_init_fn = xnu_rc_hmac_init,
		.hmac_update_fn = xnu_rc_hmac_update,
		.hmac_final_generate_fn = xnu_rc_hmac_final_generate,
		.hmac_final_verify_fn = xnu_rc_hmac_final_verify,
		.hmac_generate_fn = xnu_rc_hmac_generate,
		.hmac_verify_fn = xnu_rc_hmac_verify,
	};
	if (register_crypto_functions(&rustcrypto_functions) != 0) {
		panic("RustCrypto provider registered twice");
	}
	xnu_rc_rng_install();
}

/* VM initializes its per-CPU random contexts at EARLY_BOOT/MIDDLE; the
 * provider selftest runs at EARLY_BOOT/LAST, before read-only lockdown. */
STARTUP(EARLY_BOOT, STARTUP_RANK_FIRST, rustcrypto_register);
