/*
 * Compatibility CrashReporterClient.h (Apple's is unpublished): the crash-log
 * message calls dyld uses. The message lives in __crashreporter_info__, the
 * long-standing symbol crash reporters read from a process image, so a
 * crash reporter can still pick it up. Implemented in compat.c.
 */
#ifndef DYLD_COMPAT_CRASHREPORTERCLIENT_H
#define DYLD_COMPAT_CRASHREPORTERCLIENT_H

#ifdef __cplusplus
extern "C" {
#endif
void CRSetCrashLogMessage(const char *msg);
void CRSetCrashLogMessage2(const char *msg);
const char *CRGetCrashLogMessage(void);
#ifdef __cplusplus
}
#endif

#endif
