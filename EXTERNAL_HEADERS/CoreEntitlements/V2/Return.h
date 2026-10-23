#ifndef CoreEntitlements_V2_Return_h
#define CoreEntitlements_V2_Return_h

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Default to __single indexable pointers for Firebloom */
__ptrcheck_abi_assume_single();

/* Need this to be able to include the private header files */
#ifndef CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING
#define CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING 1
#endif

#include <stdint.h>
#include <string.h>
#include <os/overflow.h>
#include <libDER/asn1Types.h>
#include <libDER/DER_Decode.h>
#include <libDER/libDER.h>
#include <CoreEntitlements/CoreEntitlements.h>
#include <CoreEntitlements/CoreEntitlementsPriv.h>

typedef enum __attribute__((enum_extensibility(closed))) : uint16_t {
    kCEReturnSuccess = 0x0000,
    kCEReturnError = 0x0001,
    kCEReturnStackProtector = 0x0002,
    kCEReturnOverflow = 0x0003,
    kCEReturnDuplicateKey = 0x0004,
    kCEReturnNotPermitted = 0x0005,
    kCEReturnNotSupported = 0x0006,
    kCEReturnNotFound = 0x0007,
    kCEReturnMismatch = 0x0008,
    kCEReturnMismatchType = 0x0009,
    kCEReturnInvalidOperation = 0x000A,
    kCEReturnInvalidArgument = 0x000B,
    kCEReturnInvalidElement = 0x000C,
    kCEReturnEmptyElement = 0x000D,
    kCEReturnOutOfMemory = 0x000E,
    kCEReturnNoAcceleration = 0x000F,
    kCEReturnUserDefined = 0x0010,
    kCEReturnPotentialMemoryLeak = 0x0011,
    kCEReturnAccelerationIneligible = 0x0012,

    /* Return codes for element constraints */
    kCEReturnBooleanNotPermitted = 0x00A0,
    kCEReturnIntegerNotPermitted = 0x00A1,
    kCEReturnStringNotPermitted = 0x00A2,
    kCEReturnArrayNotPermitted = 0x00A3,
    kCEReturnDictionaryNotPermitted = 0x00A4,
    kCEReturnDataNotPermitted = 0x00A5,
    kCEReturnUTCTimeNotPermitted = 0x00A6,
    kCEReturnNumericStringNotPermitted = 0x00A7,
    kCEReturnApplicationNotPermitted = 0x00A8,

    /* Return codes for policy constraints */
    kCEReturnMultiTypeArrayNotPermitted = 0x00B0,

    /* Return codes for specification errors */
    kCEReturnSpecInvalid = 0x00C0,
    kCEReturnSpecElementTag = 0x00C1,
    kCEReturnSpecBooleanTag = 0x00C2,
    kCEReturnSpecBooleanInvalid = 0x00C3,
    kCEReturnSpecIntegerTag = 0x00C4,
    kCEReturnSpecIntegerInvalid = 0x00C5,
    kCEReturnSpecStringTag = 0x00C6,
    kCEReturnSpecStringEmpty = 0x00C7,
    kCEReturnSpecStringInvalid = 0x00C8,
    kCEReturnSpecDataTag = 0x00C9,
    kCEReturnSpecDataEmpty = 0x00CA,
    kCEReturnSpecArrayTag = 0x00CB,
    kCEReturnSpecArrayEmpty = 0x00CC,
    kCEReturnSpecArrayInvalid = 0x00CD,
    kCEReturnSpecDictionaryTag = 0x00CE,
    kCEReturnSpecDictionaryEmpty = 0x00CF,
    kCEReturnSpecDictionaryUnsorted = 0x00D0,
    kCEReturnSpecDictionaryInvalid = 0x00D1,
    kCEReturnSpecKeyValuePairTag = 0x00D2,
    kCEReturnSpecKeyValuePairInvalid = 0x00D3,
    kCEReturnSpecKeyValuePairKey = 0x00D4,
    kCEReturnSpecKeyValuePairValue = 0x00D5,
    kCEReturnSpecApplicationTag = 0x00D6,
    kCEReturnSpecApplicationFormat = 0x00D7,
    kCEReturnSpecApplicationNotSupported = 0x00D8,

    /*
     * Return codes mapped into the V2 implementation from CoreEntitlements_V2.
     */
    kCEReturnV1APIMisuse = 0xFF00,
    kCEReturnV1InvalidArgument = 0xFF01,
    kCEReturnV1AllocationFailed = 0xFF02,
    kCEReturnV1MalformedEntitlements = 0xFF03,
    kCEReturnV1QueryCannotBeSatisfied = 0xFF04,
    kCEReturnV1NotEligibleForAcceleration = 0xFF05,
    kCEReturnV1Error = 0xFF06,

    /*
     * Return codes mapped into the V2 implementation from libDER.
     */
    kCEReturnDEREndOfSequence = 0xFF10,
    kCEReturnDERUnexpectedTag = 0xFF11,
    kCEReturnDERDecodeError = 0xFF12,
    kCEReturnDERNotImplemented = 0xFF13,
    kCEReturnDERIncompleteSequence = 0xFF14,
    kCEReturnDERParameterError = 0xFF15,
    kCEReturnDERBufferOverflow = 0xFF16,
    kCEReturnDERError = 0xFF17
} CEReturn_t;

__END_DECLS
#endif /* CoreEntitlements_V2_Return_h */
