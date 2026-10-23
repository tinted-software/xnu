#ifndef CoreEntitlements_V2_StackProtector_h
#define CoreEntitlements_V2_StackProtector_h

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Default to __single indexable pointers for Firebloom */
__ptrcheck_abi_assume_single();

#include <stdint.h>
#include <CoreEntitlements/V2/Return.h>

/* Stack protector not required by default */
#ifndef libCoreEntitlements_Config_StackProtector
#define libCoreEntitlements_Config_StackProtector 0
#endif

#if libCoreEntitlements_Config_StackProtector

/**
 * The environment defined `CEEnvironmentStackCheck` function is called before the
 * library begins iterating into a nested type such as an array or a dictionary. This
 * provides the environment an opportunity to catch stack overflows, and instead
 * return safely.
 *
 * A return of `kCEReturnSuccess` means the library is safe to proceed with the
 * iteration, and a return of any other value halts the iteration and returns an error.
 */
extern CEReturn_t
CEEnvironmentStackCheck(void);

#else

static inline __attribute__((always_inline)) CEReturn_t
CEEnvironmentStackCheck(void)
{
    return kCEReturnSuccess;
}

#endif /* libCoreEntitlements_Config_StackProtector */

__END_DECLS
#endif /* CoreEntitlements_V2_StackProtector_h */
