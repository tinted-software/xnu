#ifndef CoreEntitlements_V2_API_h
#define CoreEntitlements_V2_API_h

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Default to __single indexable pointers for Firebloom */
__ptrcheck_abi_assume_single();

#include <stdint.h>
#include <CoreEntitlements/V2/Context.h>

#pragma mark Types

/**
 * ASN1 strings (specifically UTF8STRING) are not NULL terminated, which makes
 * them different from C-strings.
 *
 * This data type is used to provide a representation for such types.
 */
typedef struct _CEString {
    const uint8_t *__counted_by(length) data;
    size_t length;
} CEString_t;

/**
 * This data type is used to provide a representation for ASN1 based OCTET-STRING
 * types.
 */
typedef struct _CEData {
    const uint8_t *__counted_by(length) data;
    size_t length;
} CEData_t;

/**
 * This data type is used as a generic buffer for holding arbitrary data. This is
 * separated from "CEString_t" and "CEData_t" as those types are for specific ASN1
 * types.
 */
typedef struct _CEBuffer {
    const uint8_t *__counted_by(length) data;
    size_t length;
} CEBuffer_t;

typedef struct _CEIterateArgs {
    size_t index;
    void *userData;

    /*
     * In some cases, a caller may wish to halt iteration of further elements even
     * when there is no error encountered. For such situations, the caller may set
     * this value in their iteration function.
     */
    bool stopIteration;
} CEIterateArgs_t;

typedef struct _CEValueTypePair {
    /*
     * The type and value of the element being operated on for the current invocation
     * of the iteration function.
     */
    CEType_t derType;
    CEElement_t derValue;
} CEValueTypePair_t;

typedef struct _CEKeyValuePair {
    /*
     * The DER key present within a dictionary. The key is always paired with a
     * value, and the key is always expected to be of type kCETypeString.
     */
    CEElement_t derKey;

    /*
     * The DER value paired with the key represented by derKey. The value can be
     * of any supported type.
     */
    CEValueTypePair_t valueTypePair;
} CEKeyValuePair_t;

typedef CEReturn_t
(*CEDictionaryIterate_t)(const CEKeyValuePair_t *keyValuePair,
                         CEIterateArgs_t *iterateArgs);

typedef CEReturn_t
(*CEElementIterate_t)(const CEValueTypePair_t *valueTypePair,
                      CEIterateArgs_t *iterateArgs);

#pragma mark API - Context

/**
 * Initialize a CoreEntitlements context based on a DER data range against constraints
 * specific for a specific context type. This is currently not supported.
 */
CEReturn_t
CEContextInitWithType(const CEContextType_t type,
                      CEContext_t *context,
                      const uint8_t *__counted_by(derLength) derData,
                      size_t derLength);

/**
 * Initialize a CoreEntitlements context based on a DER data range against constraints
 * specific for a specific context type. This uses the older legacy validation routines,
 * and requires the legacy runtime structure to be provided.
 */
CEReturn_t
CEContextInitWithTypeLegacy(const struct CERuntime *runtime,
                            const CEContextType_t type,
                            CEContext_t *context,
                            const uint8_t *__counted_by(derLength) derData,
                            size_t derLength);

/**
 * Return an opaque pointer to the legacy context structure used by the V1 implementation
 * of CoreEntitlements. This API is only functional when the context is initialized using
 * the `CEContextInitWithTypeLegacy` API.
 *
 * This API is primed for deprecation soon, and should not be used unless the caller
 * understands what they're doing.
 */
CEReturn_t
CEContextGetLegacyContext(const CEContext_t *context,
                          const void **legacyContext);

/**
 * Create the context structure used by the V1 implementation of CoreEntitlements. This
 * API can be useful when the context is initialized using the `CEContextInitWithType`
 * API, but a legacy context is required sometimes for compatibility. Legacy context
 * will not include any acceleration information, even if the context is accelerated.
 *
 * This API requires the caller to provide an allocated instance of the legacy context
 * structure. This API does not perform any allocations on its own.
 *
 * This API is primed for deprecation soon, and should not be used unless the caller
 * understands what they're doing.
 */
CEReturn_t
CEContextCreateAsLegacyContext(const CEContext_t *context,
                               const struct CERuntime *legacyRuntime,
                               struct CEQueryContext *legacyContext);

/**
 * Return the top-level dictionary associated with this CoreEntitlements context. This
 * dictionary can then be operated and iterated upon using any of the element parsing
 * APIs.
 *
 * This dictionary is tied to the life-time of the `derData` which was used to setup the
 * context and is managed by the caller directly.
 */
CEReturn_t
CEContextGetDictionary(const CEContext_t *context,
                       const CEElement_t **derDictionary);

/**
 * Iterate through the top-level dictionary within the CoreEntitlements context and
 * match against a specified key.
 *
 * This is the only method to take advantage of context acceleration for supported
 * environments. Accelerated queries run in `O(log(n))` instead of `O(n)`, where
 * `n` is the number of keys within the top-level dictionary. This results in a significant
 * performance boost.
 */
CEReturn_t
CEContextValueForKey(const CEContext_t *context,
                     const char *keyName,
                     CEElement_t *derValue);

/**
 * This is the same as `CEContextValueForKey` except this operation can be used for
 * selecting a key from a source which does not have a NULL terminated key name.
 *
 * This is useful in cases where the `keyName` itself is obtained from another DER
 * formatted data structure.
 */
CEReturn_t
CEContextValueForKeyAsCEString(const CEContext_t *context,
                               const CEString_t *keyName,
                               CEElement_t *derValue);

/**
 * Check if a context is a subset of another context. Each context represents a
 * dictionary, and this verifies that all the elements from the `subset` dictionary
 * are fully contained within the `superset` dictionary.
 *
 * The definition of containership in this case is complex. These are the rules by which
 * containership is assessed:
 *
 *  - Every key within the `subset` must exist within the `superset`.
 *
 *  - The type of the key in the `superset` must either match the type of the `subset`
 *  or it must be a container type. The only valid container type is `kCETypeSequence`,
 *  and the containership only applies when the key within the `subset` is of type
 *  `kCETypeInteger` or `kCETypeString`.
 *
 *  - Value matching rules for every key in the `subset`:
 *   - Booleans must match the `superset`  _as is_.
 *   - Integers must be contained within the `superset` (`CEElementContainsInteger`).
 *   - Strings must be contained within the `superset`  (`CEElementContainsString`).
 *   - All elements of an array must exist in the `superset` and match based on the
 *   above rules.
 *
 *  - If the value of a key within the `superset` is `*`, then the `subset` is allowed to
 *  have any value and type for that same key.
 *
 *  - All nested dictionaries within the `subset` are evaluated recursively based on the
 *  above rule set.
 *
 * This operation is currently only supported under very specific circumstances.
 * The `superset` must be `kCEContextTypeProvisioningProfileEntitlements` and the
 * subset must be `kCEContextTypeEntitlements`.
 *
 * If the subset check is successful, a `kCEReturnSuccess` is returned, or an error
 * otherwise.
 */
CEReturn_t
CEContextCheckSubset(const CEContext_t *subset,
                     const CEContext_t *superset);

#pragma mark API - Element Iterate

/**
 * Iterate through all the key-value pairs within a dictionary and perform any
 * required operation.
 *
 * Returning anything other than `kCEReturnSuccess` from the `iterationFunction`
 * results in termination of the iteration, with the error value being returned from
 * this function.
 *
 * Using this API on anything other than an element of type `kCETypeDictionary` will
 * return `kCEReturnNotSupported`.
 */
CEReturn_t
CEDictionaryIterate(const CEElement_t *derDictionary,
                    const CEDictionaryIterate_t iterateFunction,
                    void *userCtx);

/**
 * Iterate through all the elements within an iterable element type and perform any
 * required operation. For more information on the iteration, take a look at the definition
 * for `CEElementIterate_t`.
 *
 * Returning anything other than `kCEReturnSuccess` from the `iterationFunction`
 * results in termination of the iteration, with the error value being returned from
 * this function.
 *
 * Using this API on non-iterable types will return `kCEReturnNotSupported`. Only
 * arrays and dictionaries are iterable types.
 *
 * A dictionary is a sequence of sequences. The inner level sequence will contain two
 * elements -- a key (UTF8STRING) and a value (any supported type).
 */
CEReturn_t
CEElementIterate(const CEElement_t *derElement,
                 const CEElementIterate_t iterateFunction,
                 void *userCtx);

#pragma mark API - Index Query

/**
 * Get the count of nested elements residing under container elements such as sequences
 * and dictionaries. For sequences, this function returns the number of elements within the
 * sequence, and for dictionaries, it returns the number of key-value pairs.
 *
 * Only elements of typr `kCETypeSequence` and `kCETypeDictionary` are supported
 * through this API.
 */
CEReturn_t
CEElementGetIndexCount(const CEElement_t *derElement,
                       size_t *indexCount);

/**
 * Iterate through a sequence and return the value of the element present at the
 * specified index.
 *
 * This function should only be used when the caller knows the index they're looking
 * for. Using this function to iterate over the sequence will result in a O(n^2) operation.
 * For iterating over the sequence, we recommend using the `CEElementIterate`
 * function.
 */
CEReturn_t
CESequenceValueForIndex(const CEElement_t *derSequence,
                        size_t index,
                        CEElement_t *derValue);

/**
 * Iterate through a dictionary and return the key-value pair present at the specified
 * index.
 *
 * This function should only be used when the caller knows the index they're looking
 * for. Using this function to iterate over the dictionary will result in a O(n^2) operation.
 * For iterating over the dictionary, we recommend using the `CEDictionaryIterate`
 * function.
 */
CEReturn_t
CEDictionaryValueForIndex(const CEElement_t *derDictionary,
                          size_t index,
                          CEKeyValuePair_t *keyValuePair);

#pragma mark API - Key Query

/**
 * Iterate through all the keys within a dictionary and search for a particular key.
 * If the key is matched on, then its value is returned through the arguments.
 */
CEReturn_t
CEDictionaryValueForKey(const CEElement_t *derDictionary,
                        const char *keyName,
                        CEElement_t *derValue);

/**
 * This is the same as `CEDictionaryValueForKey` except this operation can be used
 * for selecting a key from a source which does not have a NULL terminated key name.
 *
 * This is useful in cases where the `keyName` itself is obtained from another DER
 * formatted data structure.
 */
CEReturn_t
CEDictionaryValueForKeyAsCEString(const CEElement_t *derDictionary,
                                  const CEString_t *keyName,
                                  CEElement_t *derValue);

#pragma mark API - Element Query

/**
 * Parse the type of an element and return its value. Not all ASN1 types are supported
 * and upon success, the value returned will be one of the types supported by the
 * library.
 */
CEReturn_t
CEElementGetType(const CEElement_t *derElement,
                 CEType_t *typeRet);

/**
 * Acquire the raw bytes which represent the DER element. These raw bytes include
 * the tag and the length bytes of the DER element.
 */
CEReturn_t
CEElementGetCEBuffer(const CEElement_t *derElement,
                     CEBuffer_t *bufferRet);

/**
 * Acquire the raw bytes which represent the value of the DER element. These raw
 * bytes do not include the tag and the length bytes, but only the value bytes.
 */
CEReturn_t
CEElementGetValueAsCEBuffer(const CEElement_t *derElement,
                            CEBuffer_t *bufferRet);

/**
 * Attempt to parse the element as a boolean and return its value. Upon success, the
 * value of the boolean element is returned, otherwise an appropriate error.
 */
CEReturn_t
CEElementGetBool(const CEElement_t *derElement,
                 bool *valueRet);

/**
 * Attempt to parse the element as an integer and return its value. Upon success, the
 * value of the integer element is returned, otherwise an appropriate error.
 */
CEReturn_t
CEElementGetInteger(const CEElement_t *derElement,
                    int64_t *valueRet);

/**
 * Attempt to parse the element as a string and return its value. Upon success, the
 * value of the string element is returned, otherwise an appropriate error.
 *
 * The string returned may not be NULL terminated.
 */
CEReturn_t
CEElementGetString(const CEElement_t *derElement,
                   CEString_t *valueRet);

/**
 * Attempt to parse the element as data and return its value. Upon success, a pointer
 * to the data and its length is returned, otherwise an appropriate error.
 */
CEReturn_t
CEElementGetData(const CEElement_t *derElement,
                 CEData_t *valueRet);

/**
 * Match an element against a boolean value. The element is parsed as a boolean
 * before the match, and the match is attempted only when the parsing is successful.
 */
CEReturn_t
CEElementMatchBool(const CEElement_t *derElement,
                   bool matchBool);

/**
 * Match an element against an integer value. The element is parsed as an integer
 * before the match, and the match is attempted only when the parsing is successful.
 */
CEReturn_t
CEElementMatchInteger(const CEElement_t *derElement,
                      uint64_t matchInteger);

/**
 * Match an element against a string value. The element is parsed as a string
 * before the match, and the match is attempted only when the parsing is successful.
 *
 * This API _does not_ perform a wildcard match, and if the `derElement` contains
 * any `*` characters, they are treated as regular character bytes.
 */
CEReturn_t
CEElementMatchString(const CEElement_t *derElement,
                     const char *matchString);

/**
 * Same as `CEElementMatchString` except this API can be used for matching against
 * strings which may not be NULL terminated.
 */
CEReturn_t
CEElementMatchStringWithCEString(const CEElement_t *derElement,
                                 const CEString_t *matchString);

/**
 * Match an element against a string value. The element is parsed as a string
 * before the match, and the match is attempted only when the parsing is successful.
 *
 * This API _does_ perform a wildcard match. The wildcard `*` is only honored:
 *  - When it appears on `derElement`, AND
 *  - When it is the _last_ character in the string.
 *
 * In all other cases, a `*` is treated as a regular character byte.
 */
CEReturn_t
CEElementMatchStringWithWildcard(const CEElement_t *derElement,
                                 const char *matchString);

/**
 * Same as `CEElementMatchStringWithWildcard` except this API can be used for matching
 * against strings which may not be NULL terminated.
 */
CEReturn_t
CEElementMatchStringWithCEStringAndWildcard(const CEElement_t *derElement,
                                            const CEString_t *matchString);

/**
 * Match an element against some data. The element is parsed as data before the
 * match, and the match is attempted only when the parsing is successful.
 */
CEReturn_t
CEElementMatchData(const CEElement_t *derElement,
                   const CEData_t *matchData);

/**
 * Same as `CEElementMatchInteger` except this API will also accept the `derElement`
 * as an array, and perform a containership check for the integer within the array.
 */
CEReturn_t
CEElementContainsInteger(const CEElement_t *derElement,
                         int64_t containedInteger);

/**
 * Same as `CEElementMatchString` except this API will also accept the `derElement`
 * as an array, and perform a containership check for the string within the array.
 */
CEReturn_t
CEElementContainsString(const CEElement_t *derElement,
                        const char *containedString);

/**
 * Same as `CEElementContainsString` except this API can be used for
 * performing a containership check for a string which may not be NULL terminated.
 */
CEReturn_t
CEElementContainsStringWithCEString(const CEElement_t *derElement,
                                    const CEString_t *containedString);

/**
 * Same as `CEElementMatchStringWithWildcard` except this API will also accept the
 * `derElement` as an array, and perform a containership check for the string with a
 * wildcard within the array.
 */
CEReturn_t
CEElementContainsStringWithWildcard(const CEElement_t *derElement,
                                    const char *containedString);

/**
 * Same as `CEElementContainsStringWithWildcard` except this API can be used for
 * performing a containership check for a string with a wildcard which may not be NULL
 * terminated.
 */
CEReturn_t
CEElementContainsStringWithCEStringAndWildcard(const CEElement_t *derElement,
                                               const CEString_t *containedString);

/**
 * Same as `CEElementMatchData` except this API will also accept the `derElement`
 * as an array, and perform a containership check for the data within the array.
 */
CEReturn_t
CEElementContainsData(const CEElement_t *derElement,
                      const CEData_t *containedData);

#pragma mark API - CEString

int32_t
CEStringCompare(const CEString_t *derString,
                const char *string);

int32_t
CEStringCompareWithCEString(const CEString_t *derString0,
                            const CEString_t *derString1);

int32_t
CEStringComparePrefix(const CEString_t *derString,
                      const char *prefix);

int32_t
CEStringComparePrefixWithCEString(const CEString_t *derString,
                                  const CEString_t *derPrefix);

#pragma mark API - Conditional

#include <CoreEntitlements/V2/Closure.h>
#include <CoreEntitlements/V2/StackProtector.h>
#include <CoreEntitlements/V2/Acceleration.h>

__END_DECLS
#endif /* CoreEntitlements_V2_API_h */
