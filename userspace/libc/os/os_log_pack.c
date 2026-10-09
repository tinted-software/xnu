/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Compatibility implementations of the libsystem_trace entry points that
 * libc's crash path calls. See os/log_private.h for the fidelity caveats.
 *
 * libc's os/assumes.c already degrades when libsystem_trace is not loaded:
 * _os_crash_fmt_impl() checks dlopen("libsystem_trace.dylib", RTLD_NOLOAD)
 * before calling os_log_pack_send_and_compose(). These definitions exist so
 * that libc's crash path links and still hands CrashReporter the message
 * text via abort_with_payload().
 */

#include <os/log_private.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

char *
os_log_send_and_compose(uint32_t flags, const char **fmt_out, char *buf,
    size_t buf_size, os_log_t oslog, os_log_type_t type, const char *format, ...)
{
	va_list ap;
	int n;

	(void)oslog;
	(void)type;
	(void)flags;	/* no libsystem_trace transport in this port */

	/*
	 * libc keeps just the format string for the CrashReporter buffer, so
	 * report it even when there is no room to compose.
	 */
	if (fmt_out != NULL) {
		*fmt_out = format;
	}

	if (buf == NULL || buf_size == 0) {
		return buf;
	}

	va_start(ap, format);
	n = vsnprintf(buf, buf_size, format, ap);
	va_end(ap);
	if (n < 0) {
		buf[0] = '\0';
	}

	return buf;
}

char *
_os_log_send_and_compose_impl(uint32_t flags, const char **fmt_out, char *buf,
    size_t buf_size, void *dso, os_log_t oslog, os_log_type_t type,
    const char *format, uint8_t *fmt_buf, uint32_t fmt_buf_size)
{
	(void)flags;	/* no libsystem_trace transport in this port */
	(void)dso;
	/* The packed arguments are only meaningful to libsystem_trace. */
	(void)fmt_buf;
	(void)fmt_buf_size;

	if (fmt_out != NULL) {
		*fmt_out = format;
	}
	if (buf == NULL || buf_size == 0) {
		return buf;
	}
	if (format == NULL) {
		buf[0] = '\0';
		return buf;
	}
	/*
	 * Composing the packed buffer needs libsystem_trace's decoder, so the
	 * format string is what can be composed here.
	 */
	strlcpy(buf, format, buf_size);

	return buf;
}

char *
os_log_pack_send_and_compose(os_log_pack_t pack, os_log_t oslog,
    os_log_type_t type, char *buf, size_t buf_size)
{
	(void)oslog;
	(void)type;
	(void)buf;
	(void)buf_size;

	if (pack == NULL) {
		return NULL;
	}

	/* Argument metadata is not reproduced: the pack carries the format. */
	return (char *)pack->olp_format;
}
