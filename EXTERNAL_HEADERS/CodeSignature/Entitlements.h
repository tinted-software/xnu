#ifndef libCodeSignature_Entitlements_h
#define libCodeSignature_Entitlements_h

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Default to __single indexable pointers for Firebloom */
__ptrcheck_abi_assume_single();

#include <CodeSignature/Return.h>
#include <stdint.h>

#pragma mark Entitlement Names

/* Debugger */
#define kCSDebuggerEntitlement "com.apple.private.cs.debugger"

/* JIT */
#define kCSPlatformJITEntitlement "dynamic-codesigning"
#define kCSDeveloperJITEntitlement "com.apple.developer.cs.allow-jit"
#define kCSAlternateJITEntitlement kCSDeveloperJITEntitlement

/* Web Browser */
#define kCSWebBrowserHostEntitlement                                           \
  "com.apple.developer.web-browser-engine.host"
#define kCSWebBrowserGPUEntitlement                                            \
  "com.apple.developer.web-browser-engine.rendering"
#define kCSWebBrowserNetworkEntitlement                                        \
  "com.apple.developer.web-browser-engine.networking"
#define kCSWebBrowserWebContentEntitlement                                     \
  "com.apple.developer.web-browser-engine.webcontent"
#define kCSEmbeddedWebBrowserEntitlement                                       \
  "com.apple.developer.embedded-web-browser-engine"
#define kCSWebBrowserEntitlement kCSWebBrowserWebContentEntitlement

/* OOP-JIT */
#define kCSOOPJITLoaderEntitlement "com.apple.private.oop-jit.loader"
#define kCSOOPJITRunnerEntitlement "com.apple.private.oop-jit.runner"

#pragma mark Abstraction

/*
 * Some build environments do not have any access to CoreEntitlements, which is
 * the de-facto method for parsing and managing entitlements by this library.
 *
 * Our goal here is to allow entitlements based operations to be opt-outable in
 * environments where CoreEntitlements isn't available or when entitlements are
 * not required or supported.
 */

#if libCodeSignature_Config_NoEntitlements
/* Configuration is opting out of supporting entitlements */
#define libCodeSignature_Include_Entitlements 0
#elif __has_include(<CoreEntitlements/V2/API.h>)
/* Configuration is not opting out of supporting entitlements */
#define libCodeSignature_Include_Entitlements 1
#else
/* Configuration doesn't support CoreEntitlements */
#define libCodeSignature_Include_Entitlements 0
#endif /* libCodeSignature_Config_NoEntitlements */

/*
 * The entitlements validation object becomes the abstraction layer for any and
 * all operations against entitlement blobs. When CoreEntitlements is available
 * and supported, all operations make use of it.
 *
 * When CoreEntitlements isn't available or not supported, all operations on
 * entitlements return with an unsupported error.
 */
#if libCodeSignature_Include_Entitlements
#include <CoreEntitlements/V2/API.h>

typedef struct CERuntime EntitlementsRuntime_t;
typedef CEContext_t EntitlementsContext_t;

typedef CEContextType_t EntitlementsContextType_t;
enum {
  kEntitlementsContextTypeSignature = kCEContextTypeEntitlements,
  kEntitlementsContextTypeProfile =
      kCEContextTypeProvisioningProfileEntitlements
};

typedef CEType_t EntitlementsType_t;
enum {
  kEntitlementTypeUnknown = kCETypeUnknown,
  kEntitlementTypeBool = kCETypeBool,
  kEntitlementTypeInteger = kCETypeInteger,
  kEntitlementTypeString = kCETypeString,
  kEntitlementTypeSequence = kCETypeSequence,
  kEntitlementTypeDictionary = kCETypeDictionary,
  kEntitlementTypeData = kCETypeData
};

#else

typedef uint8_t EntitlementsRuntime_t;
typedef uint8_t EntitlementsContext_t;

typedef uint8_t EntitlementsContextType_t;
enum { kEntitlementsContextTypeSignature = 0, kEntitlementsContextTypeProfile };

typedef uint8_t EntitlementsType_t;
enum {
  kEntitlementTypeUnknown = 0,
  kEntitlementTypeBool,
  kEntitlementTypeInteger,
  kEntitlementTypeString,
  kEntitlementTypeSequence,
  kEntitlementTypeDictionary,
  kEntitlementTypeData
};

#endif

#pragma mark API

/**
 * Initialize an entitlements context with a provided DER entitlements blob. The
 * DER blob range is sanity checked to ensure there are no overflows on the
 * range.
 *
 * If entitlements are not supported by the environment, then this function will
 * return `kCSReturnUnsupported`.
 */
CSReturn_t entitlementsInit(const EntitlementsRuntime_t *runtime,
                            EntitlementsContextType_t type,
                            EntitlementsContext_t *entitlements,
                            const uint8_t *__counted_by(derBlobSize) derBlob,
                            size_t derBlobSize);

/**
 * Perform a subset validation of two entitlement contexts to ensure that one
 * context is a complete subset of the other. Both contexts must have originally
 * been setup using `entitlementsInit`.
 *
 * If entitlements are not supported by the environment, then this function will
 * return `kCSReturnUnsupported`.
 */
CSReturn_t entitlementsSubsetVerify(const EntitlementsContext_t *subSet,
                                    const EntitlementsContext_t *superSet);

/**
 * Get the type represented by a particular entitlement within the entitlements
 * context. If the context does not hold the entitlement, then a not found error
 * is returned.
 *
 * NOTE: The library only exports a certain subset of the types supported by the
 * entitlements. The `EntitlementsType_t` is an alias of `CEType_t` and callers
 * outside of the library can match against all exported definitions for that
 * type.
 *
 * If entitlements are not supported by the environment, then this function will
 * return `kCSReturnUnsupported`.
 */
CSReturn_t entitlementsGetType(const EntitlementsContext_t *entitlements,
                               const char *entitlementName,
                               EntitlementsType_t *typeRet);

/**
 * Match the value of an entitlement within a context against a boolean value.
 * The entitlement's value must be a boolean type.
 *
 * If entitlements are not supported by the environment, then this function will
 * return `kCSReturnUnsupported`.
 */
CSReturn_t entitlementsMatchBoolean(const EntitlementsContext_t *ctx,
                                    const char *entitlementName, bool value);

/**
 * Match the value of an entitlement within a context against an integer value.
 * The entitlement's value must be an integer type.
 *
 * If entitlements are not supported by the environment, then this function will
 * return `kCSReturnUnsupported`.
 */
CSReturn_t entitlementsMatchInteger(const EntitlementsContext_t *ctx,
                                    const char *entitlementName,
                                    uint64_t value);

/**
 * Match the value of an entitlement within a context against a string value.
 * The entitlement's value may be a string type or a sequence type.
 *
 * If entitlements are not supported by the environment, then this function will
 * return `kCSReturnUnsupported`.
 */
CSReturn_t entitlementsMatchString(const EntitlementsContext_t *ctx,
                                   const char *entitlementName,
                                   const char *value);

__END_DECLS
#endif /* libCodeSignature_Entitlements_h */
