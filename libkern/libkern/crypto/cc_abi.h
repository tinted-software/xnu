/* Independently defined kernel crypto utilities and consumer ABI. */
#ifndef _LIBKERN_CRYPTO_CC_ABI_H_
#define _LIBKERN_CRYPTO_CC_ABI_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uintptr_t cc_unit;
typedef size_t cc_size;

#define cc_ctx_sizeof(type, nbytes) \
    ((((nbytes) + sizeof(type) - 1) / sizeof(type)) * sizeof(type))
#define cc_ctx_decl(type, nbytes, name) \
    type name[cc_ctx_sizeof(type, nbytes) / sizeof(type)]
#define cc_ctx_clear(type, nbytes, name) cc_clear(cc_ctx_sizeof(type, nbytes), name)
#define ccn_nof(nbits) (((nbits) + sizeof(cc_unit) * 8 - 1) / (sizeof(cc_unit) * 8))
#define ccn_sizeof(nbits) (ccn_nof(nbits) * sizeof(cc_unit))
#define ccn_sizeof_size(nbytes) cc_ctx_sizeof(cc_unit, nbytes)
#define cc_copy(nbytes, dst, src) memcpy((dst), (src), (nbytes))
#define cc_zero(nbytes, dst) memset((dst), 0, (nbytes))

/* Shared return codes. Success is zero; authentication failure is distinct. */
enum {
    CCERR_OK = 0,
    CCERR_PARAMETER = -7,
    CCERR_MEMORY = -8,
    CCERR_INTERNAL = -1,
    CCERR_CALL_SEQUENCE = -86,
    CCERR_INTEGRITY = -2,
    CCERR_OUT_OF_ENTROPY = -10,
    CCERR_OVERFLOW = -12,
    CCERR_DEVICE = -3,
    CCERR_RNG_NOT_SEEDED = -162,
    CCERR_NOT_SUPPORTED = -173,
    CCMODE_INVALID_INPUT = -67,
    CCMODE_INVALID_CALL_SEQUENCE = -68,
    CCMODE_INTEGRITY_FAILURE = -69,
    CCMODE_NOT_SUPPORTED = -70,
    CCMODE_INTERNAL_ERROR = -71,
    CCRSA_INVALID_INPUT = -23,
    CCRSA_INVALID_CONFIG = -24,
    CCRSA_ENCODING_ERROR = -25
};

void cc_clear(size_t nbytes, void *memory);
int cc_cmp_safe(size_t nbytes, const void *a, const void *b);

/* Entitlements transports a DER cursor; it does not call a DER codec here. */
typedef unsigned long ccder_tag;
typedef struct {
    const uint8_t *der;
    const uint8_t *der_end;
} ccder_read_blob;

/* ASN.1 tag numbers and encoded class/construction bits (ITU-T X.690). */
#define CCDER_SEQUENCE 16UL
#define CCDER_CONSTRUCTED (1UL << (sizeof(ccder_tag) * 8 - 3))
#define CCDER_APPLICATION (1UL << (sizeof(ccder_tag) * 8 - 2))

#ifdef __cplusplus
}
#endif
#endif
