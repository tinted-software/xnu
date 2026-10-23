/*
 * Register the corecrypto built from apple/corecrypto as the kernel's crypto
 * provider at EARLY_BOOT.  The kernel uses g_crypto_funcs before any kext can
 * start (entropy_init() hashes the boot entropy with SHA-512, and
 * vm_map_store_crypto_init() sizes its RNG context), so the same objects that
 * the corecrypto kext would use are linked into the kernel and registered
 * here first.  A corecrypto kext loaded later then fails to register (by
 * design: register_crypto_functions() keeps the first provider).
 */
#include <mach/kmod.h>
#include <mach/mach_types.h>
#include <kern/startup.h>

extern kern_return_t corecrypto_kext_start(kmod_info_t *ki, void *d);
extern char _mh_execute_header[];

__startup_func
static void
corecrypto_static_register(void)
{
	kmod_info_t ki = { .address = (vm_offset_t)(uintptr_t)_mh_execute_header };

	corecrypto_kext_start(&ki, NULL);
}
STARTUP(EARLY_BOOT, STARTUP_RANK_FIRST, corecrypto_static_register);
