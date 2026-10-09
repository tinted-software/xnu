/*
 * Compatibility libamfi.h (Apple's is unpublished).
 *
 * This is an open-source port policy, not Apple's AMFI: there is no
 * code-signing enforcement here and dyld is told every restricted-process
 * feature is allowed, so things AMFI normally blocks (DYLD_* variables,
 * @-paths, library insertion/interposing, custom shared caches) keep working.
 * See compat.c for amfi_check_dyld_policy_self().
 *
 * The flag bit values are private to this port: dyld passes them to
 * amfi_check_dyld_policy_self() and reads them back, and compat.c is the only
 * other party. Bits 0..7 of the output match the fallback enum dyld carries
 * in DyldDelegates.cpp, so both spellings agree.
 */
#ifndef DYLD_COMPAT_LIBAMFI_H
#define DYLD_COMPAT_LIBAMFI_H

#include <stdint.h>

enum amfi_dyld_policy_input_flag_set {
	AMFI_DYLD_INPUT_PROC_IN_SIMULATOR     = (1 << 0),
	AMFI_DYLD_INPUT_PROC_HAS_RESTRICT_SEG = (1 << 1),
	AMFI_DYLD_INPUT_PROC_IS_ENCRYPTED     = (1 << 2),
};

enum amfi_dyld_policy_output_flag_set {
	AMFI_DYLD_OUTPUT_ALLOW_AT_PATH                  = (1 << 0),
	AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS                = (1 << 1),
	AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE      = (1 << 2),
	AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS           = (1 << 3),
	AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS               = (1 << 4),
	AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION = (1 << 5),
	AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING      = (1 << 6),
	AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS            = (1 << 7),
	AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS         = (1 << 8),
	AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE       = (1 << 9),
};

#ifdef __cplusplus
extern "C" {
#endif
/* Returns 0 on success and fills *output_flags. */
int amfi_check_dyld_policy_self(uint64_t input_flags, uint64_t *output_flags);
#ifdef __cplusplus
}
#endif

#endif
