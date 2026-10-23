#ifndef CoreEntitlements_V2_Closure_h
#define CoreEntitlements_V2_Closure_h

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Default to __single indexable pointers for Firebloom */
__ptrcheck_abi_assume_single();

#include <stdint.h>
#include <CoreEntitlements/V2/Return.h>

/* Closure based functions provided by default */
#ifndef libCoreEntitlements_Config_Closure
#ifdef __BLOCKS__
#define libCoreEntitlements_Config_Closure 1
#else
#define libCoreEntitlements_Config_Closure 0
#endif
#endif /* !defined(libCoreEntitlements_Config_Closure) */

/* Validate that we can use closures */
#if libCoreEntitlements_Config_Closure && !defined(__BLOCKS__)
#error "Configured libCoreEntitlements_Config_Closure without __BLOCKS__"
#endif

#if libCoreEntitlements_Config_Closure

#pragma mark Type Defines

typedef CEReturn_t
(^CEDictionaryIterateClosure_t)(const CEKeyValuePair_t *keyValuePair,
                                CEIterateArgs_t *iterateArgs);

typedef CEReturn_t
(^CEElementIterateClosure_t)(const CEValueTypePair_t *valueTypePair,
                             CEIterateArgs_t *iterateArgs);

#pragma mark Types

typedef struct _CEClosureFunctionPointer {
    const CEDictionaryIterateClosure_t dictionaryIterate;
    const CEElementIterateClosure_t elementIterate;
} CEClosureFunctionPointer_t;

#pragma mark Static Functions

static inline CEReturn_t
_CEClosureCallbackDictionary(const CEKeyValuePair_t *keyValuePair,
                             CEIterateArgs_t *iterateArgs)
{
    const CEClosureFunctionPointer_t *__single args = (CEClosureFunctionPointer_t*)iterateArgs->userData;

    /* Directly call the iterator */
    return args->dictionaryIterate(keyValuePair, iterateArgs);
}

static inline CEReturn_t
_CEClosureCallbackElement(const CEValueTypePair_t *valueTypePair,
                          CEIterateArgs_t *iterateArgs)
{
    const CEClosureFunctionPointer_t *__single args = (CEClosureFunctionPointer_t*)iterateArgs->userData;

    /* Directly call the iterator */
    return args->elementIterate(valueTypePair, iterateArgs);
}

/**
 * Iterate through all the key-value pairs within a dictionary and perform any
 * required operation.
 *
 * This function behaves identically to `CEDictionaryIterate`, except that it
 * uses a closure block instead of a function pointer.
 *
 * The `userData` field of the `iterateArgs` parameter should not be mutated
 * by the closure.
 */
static inline CEReturn_t
CEDictionaryIterateWithClosure(const CEElement_t *derDictionary,
                               const CEDictionaryIterateClosure_t iterateClosure)
{
    CEClosureFunctionPointer_t callback = {
        .dictionaryIterate = iterateClosure
    };
    return CEDictionaryIterate(derDictionary, _CEClosureCallbackDictionary, &callback);
}

/**
 * Iterate through all the elements within an iterable element type and perform any
 * required operation.
 *
 * This function behaves identically to `CEElementIterate`, except that it
 * uses a closure block instead of a function pointer.
 *
 * The `userData` field of the `iterateArgs` parameter should not be mutated
 * by the closure.
 */
static inline CEReturn_t
CEElementIterateWithClosure(const CEElement_t *derElement,
                            const CEElementIterateClosure_t iterateClosure)
{
    CEClosureFunctionPointer_t callback = {
        .elementIterate = iterateClosure
    };
    return CEElementIterate(derElement, _CEClosureCallbackElement, &callback);
}

#endif /* libCoreEntitlements_Config_Closure */

__END_DECLS
#endif /* CoreEntitlements_V2_Closure_h */
