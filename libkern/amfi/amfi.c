#define XNU_KERNEL_PRIVATE 1
#include <kern/startup.h>
#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/amfi/amfi.h>

/*
 * The AMFI interface is provided by the com.apple.driver.AppleMobileFileIntegrity
 * kext (security/amfi_kext/), which registers itself in its start routine. There
 * is no built-in implementation: a kernel without the kext has no AMFI.
 */
SECURITY_READ_ONLY_LATE(const amfi_t*) amfi = NULL;
SECURITY_READ_ONLY_LATE(const CEKernelAPI_t*) libCoreEntitlements = NULL;

void
amfi_interface_register(const amfi_t *mfi)
{
	if (amfi) {
		panic("AppleMobileFileIntegrity interface already set");
	}
	amfi = mfi;
}

void
amfi_core_entitlements_register(const CEKernelAPI_t *implementation)
{
	if (libCoreEntitlements) {
		panic("libCoreEntitlements interface already set");
	}
	libCoreEntitlements = implementation;
}
