/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
 */
#ifndef libCodeSignature_Return_h
#define libCodeSignature_Return_h

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Default to __single indexable pointers for Firebloom */
__ptrcheck_abi_assume_single();

#include <stdint.h>

enum {
    /* Public API -- Signature Validation Object */
    kCSComponentInitSignature = 0x00,
    kCSComponentParseSignature = 0x01,
    kCSComponentEvaluateTrust = 0x02,
    kCSComponentValidateConstraints = 0x03,
    kCSComponentParseEntitlements = 0x04,
    kCSComponentAssociateProfile = 0x05,
    kCSComponentDisassociateProfile = 0x06,
    kCSComponentLibraryValidation = 0x07,
    kCSComponentGetTrustLevel = 0x08,
    kCSComponentGetProfile = 0x09,
    kCSComponentGetAddr = 0x0A,
    kCSComponentGetBlobCount = 0x0B,
    kCSComponentGetCodeDirectory = 0x0C,
    kCSComponentGetBlobAtSlot = 0x0D,
    kCSComponentGetBlobAtIndex = 0x0E,
    kCSComponentGetEntitlementsContext = 0x0F,
    kCSComponentCheckBoolEntitlement = 0x10,
    kCSComponentCheckStringEntitlement = 0x11,
    kCSComponentShrink = 0x12,
    kCSComponentGetBlobInfo = 0x13,
    kCSComponentValidateBlobIntegrity = 0x14,
    kCSComponentGetUnusedBuffer = 0x15,
    kCSComponentSetPath = 0x16,
    kCSComponentGetUnusedBufferSize = 0x17,
    kCSComponentGetRestrictedModePerms = 0x18,

    /* Public API -- Profile Validation Object */
    kCSComponentProfileInit = 0x20,
    kCSComponentProfileVerify = 0x21,
    kCSComponentProfileTrust = 0x22,
    kCSComponentProfileGetData = 0x23,
    kCSComponentProfileCheckCompat = 0x24,
    kCSComponentProfileMatchEntitlements = 0x25,
    kCSComponentProfileMatchTeamID = 0x26,
    kCSComponentProfileMatchCert = 0x27,
    kCSComponentProfileGetProperties = 0x28,
    kCSComponentProfileGetCMS = 0x29,
    kCSComponentProfileGetTeamID = 0x2A,
    kCSComponentProfileGetContext = 0x2B,

    /* Public API -- Code Directory */
    kCSComponentGetVersion = 0x30,
    kCSComponentGetFlags = 0x31,
    kCSComponentGetSigningID = 0x32,
    kCSComponentGetSpecialSlots = 0x33,
    kCSComponentGetCodeSlots = 0x34,
    kCSComponentGetCodeLimit = 0x35,
    kCSComponentGetHashInfo = 0x36,
    kCSComponentGetPlatformIdentifier = 0x37,
    kCSComponentGetPageSize = 0x38,
    kCSComponentGetTeamID = 0x39,
    kCSComponentGetExecSeg = 0x3A,
    kCSComponentGetRuntimeVersion = 0x3B,
    kCSComponentGetLinkageHash = 0x3C,
    kCSComponentGetLinkageApplication = 0x3D,
    kCSComponentEvaluateCodeSlot = 0x3E,
    kCSComponentEvaluateSpecialSlot = 0x3F,
    kCSComponentGetSpecialSlot = 0x80,

    /* Public API -- Entitlements */
    kCSComponentEntitlementsInit = 0x40,
    kCSComponentEntitlementsSubsetVerify = 0x41,
    kCSComponentEntitlementsGetType = 0x42,
    kCSComponentEntitlementsMatchBool = 0x43,
    kCSComponentEntitlementsMatchInt = 0x44,
    kCSComponentEntitlementsMatchString = 0x45,

    /* Public API -- CMS Blobs */
    kCSComponentCMSBlobInit = 0x50,
    kCSComponentCMSBlobVerify = 0x51,
    kCSComponentCMSBlobVerifyWithKey = 0x52,
    kCSComponentCMSBlobVerifyAgilityHash = 0x53,
    kCSComponentCMSBlobGetData = 0x54,
    kCSComponentCMSBlobGetContent = 0x55,
    kCSComponentCMSBlobGetLeafCert = 0x56,
    kCSComponentCMSBlobGetDigestType = 0x57,
    kCSComponentCMSBlobGetPolicyFlags = 0x58,

    /* Internal validation functions */
    kCSComponentValidateSuperblob = 0x60,
    kCSComponentValidateGenericBlob = 0x61,
    kCSComponentValidateCodeDirectory = 0x62,
    kCSComponentValidateEntitlements = 0x63,

    /* Internal code directory functions */
    kCSComponentValidate0x20100 = 0x70,
    kCSComponentValidate0x20200 = 0x71,
    kCSComponentValidate0x20400 = 0x72,
    kCSComponentValidate0x20500 = 0x73,
    kCSComponentValidate0x20600 = 0x74,
    kCSComponentFindCodeDirectory = 0x75,
    kCSComponentValidateCodeDirectorySpecialBlobs = 0x76,
    kCSComponentMatchCodeDirectory = 0x77,

    /* Internal trust functions */
    kCSComponentTrustCache = 0x90,
    kCSComponentCoreTrust = 0x91,
    kCSComponentLocalSigning = 0x92,
    kCSComponentCompilationService = 0x93,
    kCSComponentOOPJit = 0x94,

    /* Internal constraint functions */
    kCSComponentConstraintsEntitlements = 0xA0,
    kCSComponentConstraintsSignatureType = 0xA1,
    kCSComponentConstraintsDeveloperMode = 0xA2,
    kCSComponentConstraintPlatform = 0xA3,
    kCSComponentConstraintCompilationService = 0xA4,
    kCSComponentConstraintLocalSigning = 0xA5,
    kCSComponentConstraintProfile = 0xA6,
    kCSComponentConstraintOOPJit = 0xA7,
    kCSComponentConstraintPlatformCodeOnly = 0xA8,
    kCSComponentConstraintTrustCacheCodeOnly = 0xA9,
    kCSComponentConstraintResearchMode = 0xAA,
    kCSComponentConstraintExResearchMode = 0xAB,
    kCSComponentConstraintDeveloperLimit = 0xAC,

    /* Internal library validation functions */
    kCSComponentLVCompilationService = 0xB0,
    kCSComponentLVOOPJit = 0xB1,
    kCSComponentLVMobileAsset = 0xB2,

    /* Internal profile validation functions */
    kCSComponentProfileEntitlements = 0xC0,
    kCSComponentProfileSetupProperties = 0xC1,
    kCSComponentProfileEnforceProperties = 0xC2,
    kCSComponentProfileMatchUPPTeam = 0xC3,
    kCSComponentProfileMatchRPPTeam = 0xC4,
    kCSComponentProfileVerifyUDID = 0xC5,
    kCSComponentProfileMatchAudience = 0xC6,

    /* Other internal functions */
    kCSComponentComputeHash = 0xE0,
    kCSComponentComputeCoreTrustHash = 0xE1,
    kCSComponentRestrictedModeStatus = 0xE2,
    kCSComponentRestrictedModeEnable = 0xE3,
    kCSComponentRestrictedModePermit = 0xE4,
    kCSComponentRestrictedModeAdjust = 0xE5,

    /* Cannot exceed this value */
    kCSComponentTotal = 0xFF,
};

enum {
    kCSReturnSuccess = 0x00,

    /* Generic error condition - avoid using this */
    kCSReturnError = 0x01,

    /* Missing initialization for components */
    kCSReturnInitConfig = 0x02,
    kCSReturnInitSignature = 0x03,
    kCSReturnInitParse = 0x04,
    kCSReturnInitInterimTrust = 0x05,
    kCSReturnInitConstraints = 0x06,
    kCSReturnInitCMS = 0x07,
    kCSReturnInitProfile = 0x08,

    /* Missing specific blobs */
    kCSReturnMissingCodeDirectory = 0x10,
    kCSReturnMissingEntitlements = 0x11,
    kCSReturnMissingProfile = 0x12,

    /* Specific error conditions */
    kCSReturnUnderflow = 0x20,
    kCSReturnOverflow = 0x21,
    kCSReturnNoTrust = 0x22,
    kCSReturnInsufficientLength = 0x23,
    kCSReturnMissingData = 0x24,
    kCSReturnExtraData = 0x25,
    kCSReturnIncorrectType = 0x26,
    kCSReturnIncorrectOffset = 0x27,
    kCSReturnUnsupported = 0x28,
    kCSReturnMismatch = 0x29,
    kCSReturnAlignmentIssue = 0x2A,
    kCSReturnDuplicate = 0x2B,
    kCSReturnInvalidArguments = 0x2C,
    kCSReturnInvalidSignatureType = 0x2D,
    kCSReturnInvalidBinaryType = 0x2E,
    kCSReturnInvalidProfile = 0x2F,
    kCSReturnNotPermitted = 0x30,
    kCSReturnInvalidString = 0x31,
    kCSReturnShrinkNotSupported = 0x32,
    kCSReturnUnsatisfiedEntitlement = 0x33,
    kCSReturnDoubleInvocation = 0x34,
    kCSReturnCoreTrustParseCMS = 0x35,
    kCSReturnCoreTrustVerifyCMS = 0x36,
    kCSReturnCoreTrustVerifyCerts = 0x37,
    kCSReturnCoreTrustPolicyMismatch = 0x38,
    kCSReturnCoreTrustParseKey = 0x39,
    kCSReturnNotEnabled = 0x3A,
    kCSReturnAuxiliaryFail = 0x3B,
    kCSReturnStale = 0x3C,

    /* Cannot exceed this value */
    kCSReturnTotal = 0xFF
};

typedef struct _CSReturn {
    union {
        /* Raw 32 bit representation of the return code */
        uint32_t rawValue;

        /* Formatted representation of the return code */
        struct {
            /* Component of the library which is returning the code */
            uint8_t component;

            /* Error code which is being returned */
            uint8_t error;

            /* Unique error path within the component */
            uint16_t uniqueError;
        } __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed)) CSReturn_t;

/* Ensure the size of the structure remains as expected */
_Static_assert(sizeof(CSReturn_t) == sizeof(uint32_t),
               "sizeof(CSReturn_t) != sizeof(uint32_t)");

static inline CSReturn_t
buildCSRet(uint8_t component,
           uint8_t error,
           uint16_t uniqueError)
{
    CSReturn_t ret = {
        .component = component,
        .error = error,
        .uniqueError = uniqueError
    };

    return ret;
}

__END_DECLS
#endif /* libCodeSignature_Return_h */
