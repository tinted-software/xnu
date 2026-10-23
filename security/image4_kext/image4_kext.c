/*
 * com.apple.driver.AppleImage4: the Image4 interface provider, as a kext in
 * the kernelcache.  Apple's own kext is arm64e-only; this is the minimal
 * interface (version and the tables the trust-cache runtime reads) so that
 * bsd/kern/kern_trustcache.c can initialise. AMFI declares this kext as a
 * dependency, so the kext loader starts it before AMFI.
 */
#define XNU_KERNEL_PRIVATE 1
#include <libkern/libkern.h>
#include <libkern/img4/interface.h>
#include <mach/kmod.h>

struct _img4_chip { int unused; };
struct _img4_nonce_domain { int unused; };
struct _img4_object_spec { int unused; };

static const img4_runtime_t g_img4_runtime_default = { .i4rt_version = 0 };
static const img4_runtime_t g_img4_runtime_pmap_cs = { .i4rt_version = 0 };
static const struct _img4_nonce_domain g_img4_nonce_domain_trust_cache = {0};
static const struct _img4_chip g_img4_chip_ap_sha1 = {0};
static const struct _img4_chip g_img4_chip_ap_sha2_384 = {0};
static const struct _img4_chip g_img4_chip_ap_hybrid = {0};
static const struct _img4_chip g_img4_chip_ap_reduced = {0};
static const struct _img4_chip g_img4_chip_ap_permissive = {0};
static const struct _img4_object_spec g_img4_firmware_spec = {0};
static const struct _img4_object_spec g_img4_chip_spec = {0};
static const struct _img4_object_spec g_img4_pmap_data_spec = {0};

static const img4_interface_t g_builtin_img4_interface = {
	.i4if_version = IMG4_INTERFACE_VERSION,
	.i4if_v1 = {
		.nonce_domain_trust_cache = (const img4_nonce_domain_t *)&g_img4_nonce_domain_trust_cache,
	},
	.i4if_v7 = {
		.chip_ap_sha1 = (const img4_chip_t *)&g_img4_chip_ap_sha1,
		.chip_ap_sha2_384 = (const img4_chip_t *)&g_img4_chip_ap_sha2_384,
		.chip_ap_hybrid = (const img4_chip_t *)&g_img4_chip_ap_hybrid,
		.chip_ap_reduced = (const img4_chip_t *)&g_img4_chip_ap_reduced,
		.firmware_spec = (const img4_object_spec_t *)&g_img4_firmware_spec,
		.chip_spec = (const img4_object_spec_t *)&g_img4_chip_spec,
		.runtime_default = &g_img4_runtime_default,
		.runtime_pmap_cs = &g_img4_runtime_pmap_cs,
	},
	.i4if_v8 = {
		.chip_ap_permissive = (const img4_chip_t *)&g_img4_chip_ap_permissive,
	},
	.i4if_v13 = {
		.pmap_data_spec = (const img4_object_spec_t *)&g_img4_pmap_data_spec,
	},
};


__attribute__((section("__TEXT,__info"), used))
static const char image4_info_plist[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\">\n"
    "<dict>\n"
    "\t<key>CFBundleIdentifier</key>\n\t<string>com.apple.driver.AppleImage4</string>\n"
    "\t<key>CFBundleName</key>\n\t<string>AppleImage4</string>\n"
    "\t<key>CFBundleExecutable</key>\n\t<string>AppleImage4</string>\n"
    "\t<key>CFBundlePackageType</key>\n\t<string>KEXT</string>\n"
    "\t<key>CFBundleShortVersionString</key>\n\t<string>1.0</string>\n"
    "\t<key>CFBundleVersion</key>\n\t<string>1.0</string>\n"
    "\t<key>OSBundleCompatibleVersion</key>\n\t<string>1.0</string>\n"
    "\t<key>OSBundleRequired</key>\n\t<string>Root</string>\n"
    "\t<key>OSBundleLibraries</key>\n\t<dict>\n"
    "\t\t<key>com.apple.kpi.libkern</key>\n\t\t<string>10.0.0</string>\n"
    "\t</dict>\n"
    "</dict>\n"
    "</plist>\n";

static kern_return_t
image4_kext_start(kmod_info_t *ki __unused, void *d __unused)
{
	if (img4if == NULL) {
		img4_interface_register(&g_builtin_img4_interface);
	}
	return KERN_SUCCESS;
}

static kern_return_t
image4_kext_stop(kmod_info_t *ki __unused, void *d __unused)
{
	return KERN_FAILURE;
}

KMOD_EXPLICIT_DECL(com.apple.driver.AppleImage4, "1.0", image4_kext_start, image4_kext_stop)
