#ifndef _PTHREAD_KEXT_COMPAT_H
#define _PTHREAD_KEXT_COMPAT_H
/*
 * XNU_KERNEL_PRIVATE hides VM_MAKE_TAG in <mach/vm_statistics.h>.
 * Apple's pthread kext still uses the public encoding.
 */
#ifndef VM_MAKE_TAG
#define VM_MAKE_TAG(tag) ((tag) << 24)
#endif
/* user.h pulls signalvar.h before proc_t is normally defined. */
#include <sys/kernel_types.h>

/* In-kernel VM API only exports the _external variant, not the bare name. */
#define mach_vm_allocate mach_vm_allocate_external
#endif
