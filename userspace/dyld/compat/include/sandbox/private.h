/*
 * Compatibility <sandbox/private.h> (Apple's is unpublished): only the
 * sandbox_check() surface dyld uses. This port has no sandbox, so
 * sandbox_check() never reports a denial (see compat.c). Constant values are
 * private to this port.
 */
#ifndef DYLD_COMPAT_SANDBOX_PRIVATE_H
#define DYLD_COMPAT_SANDBOX_PRIVATE_H

#include <sys/types.h>

typedef enum {
	SANDBOX_FILTER_NONE = 0,
	SANDBOX_FILTER_PATH = 1,
	SANDBOX_FILTER_SYSCALL_NUMBER = 2,
} sandbox_filter_type_values;
typedef int sandbox_filter_type;

#define SANDBOX_CHECK_NO_REPORT 0x40000000

#ifdef __cplusplus
extern "C" {
#endif
/* Returns > 0 if the operation is denied, 0 if allowed, < 0 on error. */
int sandbox_check(pid_t pid, const char *operation, sandbox_filter_type type, ...);
#ifdef __cplusplus
}
#endif

#endif
