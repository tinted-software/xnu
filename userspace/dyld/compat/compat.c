/*
 * Implementations for the dyld compat headers (see include/).
 *
 * This is port policy, not Apple behavior:
 *  - AMFI: no enforcement; every dyld policy output flag is allowed.
 *  - sandbox: never denies.
 *  - crash log message: kept in __crashreporter_info__.
 */
#include <CrashReporterClient.h>
#include <libamfi.h>
#include <sandbox/private.h>

int
amfi_check_dyld_policy_self(uint64_t input_flags, uint64_t *output_flags)
{
	(void)input_flags;
	if (output_flags == 0) {
		return -1;
	}
	*output_flags = AMFI_DYLD_OUTPUT_ALLOW_AT_PATH |
	    AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS |
	    AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE |
	    AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS |
	    AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS |
	    AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION |
	    AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING |
	    AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS |
	    AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS |
	    AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE;
	return 0;
}

int
sandbox_check(pid_t pid, const char *operation, sandbox_filter_type type, ...)
{
	(void)pid;
	(void)operation;
	(void)type;
	return 0;
}

/* Read by crash reporters from the image; the second message is kept apart. */
const char *__crashreporter_info__;
static const char *crash_message2;

void
CRSetCrashLogMessage(const char *msg)
{
	__crashreporter_info__ = msg;
}

void
CRSetCrashLogMessage2(const char *msg)
{
	crash_message2 = msg;
}

const char *
CRGetCrashLogMessage(void)
{
	return __crashreporter_info__ != 0 ? __crashreporter_info__ : crash_message2;
}
