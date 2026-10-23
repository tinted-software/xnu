#ifndef CORE_ENTITLEMENTS_V2_KERNEL_H
#define CORE_ENTITLEMENTS_V2_KERNEL_H

#include <stdbool.h>
#include <stdint.h>
#include <CoreEntitlements/CoreEntitlements.h>
#include <CoreEntitlements/der_vm.h>

struct CEQueryContext;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct coreentitlements_kernel_api {
    uint32_t version;
    CEError_t kNoError;
    CEError_t kMalformedEntitlements;
    CEError_t kNotEligibleForAcceleration;

    const char *(*GetErrorString)(CEError_t error);

    CEError_t (*ContextQuery)(CEQueryContext_t ctx,
        const CEQueryOperation_t *__counted_by(queryLength) query,
        size_t queryLength);

    CEError_t (*Validate)(const CERuntime_t rt,
        CEValidationResult *result,
        const uint8_t *__ended_by(blob_end) blob,
        const uint8_t *blob_end);

    CEError_t (*AcquireUnmanagedContext)(const CERuntime_t rt,
        CEValidationResult validationResult,
        struct CEQueryContext *ctx);

    der_vm_context_t (*der_vm_context_create)(const CERuntime_t rt,
        ccder_tag dictionary_tag,
        bool sorted_keys,
        const uint8_t *__ended_by(der_end) der,
        const uint8_t *der_end);

    der_vm_context_t (*der_vm_execute)(der_vm_context_t context,
        CEQueryOperation_t op);

    der_vm_context_t (*der_vm_execute_seq)(der_vm_context_t context,
        const CEQueryOperation_t *__counted_by(queryLength) query,
        size_t queryLength);

    bool (*der_vm_context_is_valid)(der_vm_context_t context);
    bool (*der_vm_bool_from_context)(der_vm_context_t context);

    CEError_t (*IndexSizeForContext)(CEQueryContext_t ctx, size_t *size);
    CEError_t (*BuildIndexForContext)(CEQueryContext_t ctx);
    bool (*ContextIsAccelerated)(CEQueryContext_t ctx);
} coreentitlements_kernel_api;

typedef struct coreentitlements_kernel_api CEKernelAPI_t;

#ifdef __cplusplus
}
#endif

#endif /* CORE_ENTITLEMENTS_V2_KERNEL_H */
