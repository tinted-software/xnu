// SPDX-License-Identifier: GPL-2.0
/*
 * com.apple.driver.AppleMobileFileIntegrity: our implementation of the AMFI
 * interface, as a kext in the kernelcache (tools/buck/kernelcache.py).
 *
 * Trust caches: implements the TrustCache interface (libkern/amfi/amfi.h) for
 * static trust caches in the version 2 layout (EXTERNAL_HEADERS/TrustCache/
 * RawTypes.h). The kernel loads the static trust cache at boot through
 * loadModule(); query() answers cdhash lookups from those modules.
 *
 * Platform status: mpo_vnode_check_signature sets CS_PLATFORM_BINARY on a
 * signature whose cdhash is in a static trust cache. This is the decision
 * ubc_subr.c reads back into csb_platform_binary.
 *
 * Not implemented (fail closed, as the kernel's builtin did): dynamic trust
 * caches (load, engineering, loadable queries), entitlements (OSEntitlements
 * answers "absent"), CoreEntitlements, MTE opt-outs. Flagged in the report.
 */
#define XNU_KERNEL_PRIVATE 1
#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/codesign.h>
#include <sys/vnode.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>
#include <libkern/amfi/amfi.h>
#include <mach/kmod.h>
#include <security/mac_policy.h>
#include <string.h>

#define AMFI_POLICY_NAME "AMFI"
#define AMFI_STATIC_TC_MAX 8

/* Version 2 static trust cache module, RawTypes.h. */
#define TC2_VERSION 2
#define TC2_HEADER_SIZE 24
#define TC2_ENTRY_SIZE 24
#define TC2_CDHASH_OFF 0
#define TC2_HASHTYPE_OFF 20
#define TC2_FLAGS_OFF 21
#define TC2_CONSTRAINT_OFF 22

#define TC2_CAPABILITIES (kTCCapabilityHashType | kTCCapabilityFlags | kTCCapabilityConstraintsCategory)

/* Static trust caches loaded by the kernel (module 0 and, if allowed, 1). */
static TrustCache_t *amfi_static_tc[AMFI_STATIC_TC_MAX];
static unsigned int amfi_static_tc_count;

static inline uint32_t
tc2_u32(const uint8_t *p)
{
	uint32_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline const uint8_t *
tc2_entry(const TrustCache_t *tc, uint32_t i)
{
	return (const uint8_t *)tc->module + TC2_HEADER_SIZE + (size_t)i * TC2_ENTRY_SIZE;
}

static inline uint32_t
tc2_count(const TrustCache_t *tc)
{
	return tc2_u32((const uint8_t *)tc->module + 20);
}

/* ---- TrustCache interface ------------------------------------------------ */

static TCReturn_t
amfi_tc_loadModule(TrustCacheRuntime_t *runtime __unused, const TCType_t type,
    TrustCache_t *trustCache, const uintptr_t dataAddr, const size_t dataSize)
{
	if (type != kTCTypeStatic || amfi_static_tc_count >= AMFI_STATIC_TC_MAX) {
		/* Dynamic/engineering caches are not supported here. */
		return buildTCRet(kTCComponentLoadModule, kTCReturnError, 0);
	}
	if (dataSize < TC2_HEADER_SIZE) {
		return buildTCRet(kTCComponentLoadModule, kTCReturnError, 1);
	}
	const uint8_t *data = (const uint8_t *)dataAddr;
	if (tc2_u32(data) != TC2_VERSION) {
		return buildTCRet(kTCComponentLoadModule, kTCReturnError, 2);
	}
	uint32_t count = tc2_u32(data + 20);
	size_t needed = TC2_HEADER_SIZE + (size_t)count * TC2_ENTRY_SIZE;
	if (count > (dataSize - TC2_HEADER_SIZE) / TC2_ENTRY_SIZE || needed > dataSize) {
		return buildTCRet(kTCComponentLoadModule, kTCReturnError, 3);
	}

	trustCache->type = type;
	trustCache->module = (const TrustCacheModuleBase_t *)dataAddr;
	trustCache->moduleSize = needed;
	amfi_static_tc[amfi_static_tc_count++] = trustCache;
	return buildTCRet(kTCComponentLoadModule, kTCReturnSuccess, 0);
}

static TCReturn_t
amfi_tc_load(TrustCacheRuntime_t *runtime __unused, TCType_t type __unused,
    TrustCache_t *trustCache __unused, const uintptr_t payloadAddr __unused,
    const size_t payloadSize __unused, const uintptr_t manifestAddr __unused,
    const size_t manifestSize __unused)
{
	return buildTCRet(kTCComponentLoad, kTCReturnError, 0);
}

static TCReturn_t
amfi_tc_query(const TrustCacheRuntime_t *runtime __unused, TCQueryType_t queryType,
    const uint8_t CDHash[kTCEntryHashSize], TrustCacheQueryToken_t *queryToken)
{
	if (queryType == kTCQueryTypeLoadable) {
		return buildTCRet(kTCComponentQuery, kTCReturnNotFound, 0);
	}
	for (unsigned int t = 0; t < amfi_static_tc_count; t++) {
		TrustCache_t *tc = amfi_static_tc[t];
		uint32_t count = tc2_count(tc);
		for (uint32_t i = 0; i < count; i++) {
			const uint8_t *e = tc2_entry(tc, i);
			if (memcmp(e + TC2_CDHASH_OFF, CDHash, kTCEntryHashSize) == 0) {
				queryToken->trustCache = tc;
				queryToken->trustCacheEntry = e;
				return buildTCRet(kTCComponentQuery, kTCReturnSuccess, 0);
			}
		}
	}
	return buildTCRet(kTCComponentQuery, kTCReturnNotFound, 0);
}

static TCReturn_t
amfi_tc_getCapabilities(const TrustCache_t *trustCache __unused, TCCapabilities_t *capabilities)
{
	if (capabilities) {
		*capabilities = TC2_CAPABILITIES;
	}
	return buildTCRet(kTCComponentModuleCapabilities, kTCReturnSuccess, 0);
}

static TCReturn_t
amfi_tc_queryGetTCType(const TrustCacheQueryToken_t *queryToken, TCType_t *typeRet)
{
	*typeRet = queryToken->trustCache->type;
	return buildTCRet(kTCComponentQueryTCType, kTCReturnSuccess, 0);
}

static TCReturn_t
amfi_tc_queryGetCapabilities(const TrustCacheQueryToken_t *queryToken __unused, TCCapabilities_t *capabilities)
{
	*capabilities = TC2_CAPABILITIES;
	return buildTCRet(kTCComponentQuery, kTCReturnSuccess, 0);
}

static TCReturn_t
amfi_tc_queryGetHashType(const TrustCacheQueryToken_t *queryToken, uint8_t *hashTypeRet)
{
	*hashTypeRet = ((const uint8_t *)queryToken->trustCacheEntry)[TC2_HASHTYPE_OFF];
	return buildTCRet(kTCComponentQueryHashType, kTCReturnSuccess, 0);
}

static TCReturn_t
amfi_tc_queryGetFlags(const TrustCacheQueryToken_t *queryToken, uint64_t *flagsRet)
{
	*flagsRet = ((const uint8_t *)queryToken->trustCacheEntry)[TC2_FLAGS_OFF];
	return buildTCRet(kTCComponentQueryFlags, kTCReturnSuccess, 0);
}

static TCReturn_t
amfi_tc_queryGetConstraintCategory(const TrustCacheQueryToken_t *queryToken, uint8_t *constraintCategoryRet)
{
	*constraintCategoryRet = ((const uint8_t *)queryToken->trustCacheEntry)[TC2_CONSTRAINT_OFF];
	return buildTCRet(kTCComponentQueryConstraintCategory, kTCReturnSuccess, 0);
}

static TCReturn_t
amfi_tc_queryGetUUID(const TrustCacheQueryToken_t *queryToken, uint8_t returnUUID[kUUIDSize])
{
	memcpy(returnUUID, (const uint8_t *)queryToken->trustCache->module + 4, kUUIDSize);
	return buildTCRet(kTCComponentGetUUID, kTCReturnSuccess, 0);
}

static TCReturn_t
amfi_tc_checkRuntimeForUUID(const TrustCacheRuntime_t *runtime __unused, const uint8_t checkUUID[kUUIDSize] __unused,
    const TrustCache_t **trustCacheRet __unused)
{
	return buildTCRet(kTCComponentCheckRuntimeForUUID, kTCReturnNotFound, 0);
}

/* ---- OSEntitlements: absent, as the builtin answered ---------------------- */

static kern_return_t
amfi_oe_adjustContext(void *os_entitlements __unused, struct cs_blob *code_signing_blob __unused, const CEContext_t *ce_ctx __unused)
{
	return KERN_SUCCESS;
}

static kern_return_t
amfi_oe_adjustContextWithMonitor(void *os_entitlements __unused, const CEQueryContext_t ce_ctx __unused,
    const void *monitor_sig_obj __unused, const char *identity __unused, const uint32_t code_signing_flags __unused)
{
	return KERN_SUCCESS;
}

static kern_return_t
amfi_oe_adjustContextWithoutMonitor(void *os_entitlements __unused, struct cs_blob *code_signing_blob __unused)
{
	return KERN_SUCCESS;
}

static kern_return_t
amfi_oe_queryEntitlementBoolean(const void *os_entitlements __unused, const char *entitlement_name __unused)
{
	return KERN_FAILURE;
}

static kern_return_t
amfi_oe_queryEntitlementBooleanWithProc(const proc_t proc __unused, const char *entitlement_name __unused)
{
	return KERN_FAILURE;
}

static kern_return_t
amfi_oe_queryEntitlementString(const void *os_entitlements __unused, const char *entitlement_name __unused,
    const char *entitlement_value __unused)
{
	return KERN_FAILURE;
}

static kern_return_t
amfi_oe_queryEntitlementStringWithProc(const proc_t proc __unused, const char *entitlement_name __unused,
    const char *entitlement_value __unused)
{
	return KERN_FAILURE;
}

static kern_return_t
amfi_oe_copyEntitlementAsOSObject(const void *os_entitlements __unused, const char *entitlement_name __unused,
    void **entitlement_object __unused)
{
	return KERN_FAILURE;
}

static kern_return_t
amfi_oe_copyEntitlementAsOSObjectWithProc(const proc_t proc __unused, const char *entitlement_name __unused,
    void **entitlement_object __unused)
{
	return KERN_FAILURE;
}

static const amfi_t amfi_kext_interface = {
	.TrustCache = {
		.version = TRUST_CACHE_INTERFACE_VERSION,
		.loadModule = amfi_tc_loadModule,
		.load = amfi_tc_load,
		.query = amfi_tc_query,
		.getCapabilities = amfi_tc_getCapabilities,
		.queryGetTCType = amfi_tc_queryGetTCType,
		.queryGetCapabilities = amfi_tc_queryGetCapabilities,
		.queryGetHashType = amfi_tc_queryGetHashType,
		.queryGetFlags = amfi_tc_queryGetFlags,
		.queryGetConstraintCategory = amfi_tc_queryGetConstraintCategory,
		.queryGetUUID = amfi_tc_queryGetUUID,
		.checkRuntimeForUUID = amfi_tc_checkRuntimeForUUID,
	},
	.OSEntitlements = {
		.version = OSENTITLEMENTS_INTERFACE_VERSION,
		.adjustContext = amfi_oe_adjustContext,
		.adjustContextWithMonitor = amfi_oe_adjustContextWithMonitor,
		.adjustContextWithoutMonitor = amfi_oe_adjustContextWithoutMonitor,
		.queryEntitlementBoolean = amfi_oe_queryEntitlementBoolean,
		.queryEntitlementBooleanWithProc = amfi_oe_queryEntitlementBooleanWithProc,
		.queryEntitlementString = amfi_oe_queryEntitlementString,
		.queryEntitlementStringWithProc = amfi_oe_queryEntitlementStringWithProc,
		.copyEntitlementAsOSObject = amfi_oe_copyEntitlementAsOSObject,
		.copyEntitlementAsOSObjectWithProc = amfi_oe_copyEntitlementAsOSObjectWithProc,
	},
};

/* ---- MAC policy: platform status from the static trust cache -------------- */

static int
amfi_vnode_check_signature(struct vnode *vp __unused, struct label *label __unused,
    cpu_type_t cpu_type __unused, struct cs_blob *cs_blob, unsigned int *cs_flags,
    unsigned int *signer_type __unused, int flags __unused, unsigned int platform __unused,
    char **fatal_failure_desc __unused, size_t *fatal_failure_desc_len __unused)
{
	const uint8_t *cdhash = csblob_get_cdhash(cs_blob);
	if (cdhash == NULL) {
		return 0;
	}
	/*
	 * The blob carries a code directory: the process has a signature. The
	 * kernel only trusts csproc_get_blob() (and so csops status, platform
	 * state) for processes marked CS_SIGNED, and leaves that to the MAC policy.
	 */
	*cs_flags |= CS_SIGNED;
	TrustCacheQueryToken_t qt;
	TCReturn_t ret = amfi_kext_interface.TrustCache.query(NULL, kTCQueryTypeStatic, cdhash, &qt);
	if (ret.error == kTCReturnSuccess) {
		*cs_flags |= CS_PLATFORM_BINARY;
	}
	return 0;
}

static const char *amfi_labelnames[] = { "amfi" };

static struct mac_policy_ops amfi_policy_ops = {
	.mpo_vnode_check_signature = amfi_vnode_check_signature,
};

static struct mac_policy_conf amfi_policy_conf = {
	.mpc_name = AMFI_POLICY_NAME,
	.mpc_fullname = "AppleMobileFileIntegrity (trust cache stand-in)",
	.mpc_field_off = NULL,
	.mpc_labelnames = amfi_labelnames,
	.mpc_labelname_count = 1,
	.mpc_ops = &amfi_policy_ops,
	.mpc_loadtime_flags = 0,
	.mpc_runtime_flags = 0,
};

static mac_policy_handle_t amfi_policy_handle;

/*
 * The kext's Info.plist, read by kernelcache.py for the collection's prelink
 * plist.
 */
__attribute__((section("__TEXT,__info"), used))
static const char amfi_info_plist[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\">\n"
    "<dict>\n"
    "\t<key>CFBundleDevelopmentRegion</key>\n\t<string>English</string>\n"
    "\t<key>CFBundleExecutable</key>\n\t<string>AppleMobileFileIntegrity</string>\n"
    "\t<key>CFBundleIdentifier</key>\n\t<string>com.apple.driver.AppleMobileFileIntegrity</string>\n"
    "\t<key>CFBundleInfoDictionaryVersion</key>\n\t<string>6.0</string>\n"
    "\t<key>CFBundleName</key>\n\t<string>AppleMobileFileIntegrity</string>\n"
    "\t<key>CFBundlePackageType</key>\n\t<string>KEXT</string>\n"
    "\t<key>CFBundleShortVersionString</key>\n\t<string>1.0</string>\n"
    "\t<key>CFBundleSignature</key>\n\t<string>\?\?\?\?</string>\n"
    "\t<key>CFBundleVersion</key>\n\t<string>1.0</string>\n"
    "\t<key>OSBundleCompatibleVersion</key>\n\t<string>1.0.0d1</string>\n"
    "\t<key>OSBundleRequired</key>\n\t<string>Root</string>\n"
    "\t<key>OSBundleLibraries</key>\n\t<dict>\n"
    "\t\t<key>com.apple.kpi.bsd</key>\n\t\t<string>12.0.0</string>\n"
    "\t\t<key>com.apple.kpi.libkern</key>\n\t\t<string>10.0.0</string>\n"
    "\t\t<key>com.apple.kpi.private</key>\n\t\t<string>10.0.0</string>\n"
    "\t</dict>\n"
    "</dict>\n"
    "</plist>\n";

static kern_return_t
amfi_kext_start(kmod_info_t *ki __unused, void *d __unused)
{
	/*
	 * Registered before load_static_trust_cache() and before lockdown: the
	 * interface pointer is read-only-late. The kernel's builtin is removed
	 * (libkern/amfi/amfi.c), so there is exactly one registration.
	 */
	amfi_interface_register(&amfi_kext_interface);

	int error = mac_policy_register(&amfi_policy_conf, &amfi_policy_handle, NULL);
	if (error != 0) {
		printf("com.apple.driver.AppleMobileFileIntegrity: mac_policy_register failed: %d\n", error);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

static kern_return_t
amfi_kext_stop(kmod_info_t *ki __unused, void *d __unused)
{
	/* Interface and policy stay registered for the life of the system. */
	return KERN_FAILURE;
}

KMOD_EXPLICIT_DECL(com.apple.driver.AppleMobileFileIntegrity, "1.0", amfi_kext_start, amfi_kext_stop)
