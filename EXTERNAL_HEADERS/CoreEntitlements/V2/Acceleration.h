#ifndef CoreEntitlements_V2_Acceleration_h
#define CoreEntitlements_V2_Acceleration_h

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Default to __single indexable pointers for Firebloom */
__ptrcheck_abi_assume_single();

#include <stdint.h>
#include <CoreEntitlements/V2/Return.h>

/*
 * The environment where the library is being linked must provide the implementation
 * for the following functions in order to make use of the acceleration APIS.
 *
 * extern uint8_t *__counted_by(allocSize)
 * CEEnvironmentAllocate(size_t allocSize);
 *
 * extern void
 * CEEnvironmentFree(uint8_t *__counted_by(allocSize) allocData,
 *                   size_t allocSize);
 */

/*
 * Macro to calculate the length of the acceleration index based on the number of
 * elements present.
 */
#define CEIndexLengthForCount(num) (num * sizeof(CEElementIndex_t))

/**
 * Evaluate the DER data range within the CoreEntitlements context to check if the
 * context is eligible for acceleration or not. As part of this, the API also returns
 * the size of the allocation required for accelerating the context.
 *
 * Acceleration requires the environment to support both allocation and deallocation
 * of memory.
 */
CEReturn_t
CEContextEvaluateAcceleration(const CEContext_t *context,
                              size_t *sizeRet);

/**
 * Check if the provided CoreEntitlements context to see if it has been accelerated
 * or not. If accelerated, this function will return `kCEReturnSuccess` or the error
 * `kCEReturnNoAcceleration` otherwise.
 */
CEReturn_t
CEContextCheckAcceleration(const CEContext_t *context);

/**
 * Evaluate the DER data range within the CoreEntitlements context, and if eligible,
 * create a memory allocation through the environment for an index which will then be
 * used to improve performance of key look ups against the CoreEntitlements context.
 *
 * This operation requires environmental support for allocating and deallocating
 * memory, as the acceleration algorithm creates an index which aids with look ups.
 *
 * The size of the required allocation can be found by calling `CEEvaluateAcceleration`.
 * This can be useful for certain environments, which may need to ensure that the required
 * amount of memory is made available ahead of time, before attempting to actually
 * accelerate the context.
 *
 * The only operation which is accelerated is `CESearchKey`.
 */
CEReturn_t
CEContextAccelerate(CEContext_t *context);

/**
 * Free the index allocation made previously and return the memory back to the caller.
 * After this operation, key look ups against the CoreEntitlements context will no
 * longer go through the index, but instead go through the slower path.
 */
CEReturn_t
CEContextDecelerate(CEContext_t *context);

__END_DECLS
#endif /* CoreEntitlements_V2_Acceleration_h */
