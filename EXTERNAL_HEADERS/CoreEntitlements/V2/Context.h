#ifndef CoreEntitlements_V2_Context_h
#define CoreEntitlements_V2_Context_h

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Default to __single indexable pointers for Firebloom */
__ptrcheck_abi_assume_single();

#include <stdint.h>
#include <CoreEntitlements/V2/Return.h>

#pragma mark Type Defines

typedef CEQueryOperation_t CEQuerySequence_t;
typedef uint32_t CEApplicationVersion_t;

#pragma mark Types

typedef struct _CEElement {
    DERItem derData;
    DERDecodedInfo derDecoded;
} CEElement_t;

typedef struct _CEElementIndex {
    /*
     * Offset of the key and value from the beginning of the index. Spec validation
     * doesn't really care if the offset is larger than UINT32_MAX, but we enforce that
     * for acceleration, a context becomes ineligible if it is very large.
     */
    uint32_t keyOffset;
    uint32_t valueOffset;
} CEElementIndex_t;

/*
 * We need to be very conservative with how much memory we consume for acceleration
 * of a context. Many other components are tied to the idea of each indexed element
 * only consuming 8 bytes (such as PPL/AMFI/TXM).
 */
_Static_assert(sizeof(CEElementIndex_t) == 8, "sizeof(CEElementIndex_t) != 8");

/*
 * Each context type maps to a set of constraints, which are validated when a context
 * is initialized. Each context can be limited in the set of types it supports along
 * with some other bespoke rules.
 */
typedef struct _CEContextConstraints {
    struct {
        bool boolean : 1;
        bool integer : 1;
        bool string : 1;
        bool array : 1;
        bool dictionary : 1;
        bool data : 1;
        bool utcTime : 1;
        bool numericString : 1;
        bool application : 1;
    } allowedTypes;

    /*
     * Constraint to allow heterogenous elements in arrays. When this is enabled,
     * we let array values contain elements of different types. Otherwise, the type
     * of the first element in the array is considered the de-facto type for each
     * of the elements in the array.
     */
    bool allowMultiTypeArrays : 1;

    /*
     * The version of the DER encoding imposes certain constraints. This is set as
     * a runtime parameter on the constraints.
     *
     * 1. Version 0 encoding is not expected to have sorted keys, whereas version 1
     * and above are.
     */
    CEApplicationVersion_t version;
} CEContextConstraints_t;

typedef enum __attribute__((enum_extensibility(closed))) : uint8_t {
    kCEContextTypeEntitlements = 0,
    kCEContextTypeProvisioningProfileEntitlements = 1,
    kCEContextTypeProvisioningProfile = 2,
    kCEContextTypeLWCR = 3,
    kCEContextTypeGeneric = 4,
    kCEContextTypeTotal,
} CEContextType_t;

typedef struct _CEContextInfo {
    CEContextType_t type;
    CEApplicationVersion_t version;
} CEContextInfo_t;

typedef struct _CEContext {
    CEContextInfo_t info;
    CEElement_t dictionary;

    /* Acceleration index */
    const CEElementIndex_t *__counted_by(indexCount) index;
    size_t indexCount;

    /* Context used with the legacy setup API */
    struct CEQueryContext legacyContext;
    bool legacyContextSetup;
} CEContext_t;

__END_DECLS
#endif /* CoreEntitlements_V2_Context_h */
