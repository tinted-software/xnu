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
 * Compatibility provider for the private libsystem_trace surface that libc's
 * crash path consumes (os/assumes.h, os/assumes.c).
 *
 * libsystem_trace is not published by Apple. The only <os/log_private.h> in
 * this tree is the kernel variant (libkern/os/log_private.h), which is a
 * different contract (firehose encoded-log API) and does not declare the
 * symbols below. This header is placed first on libc's include path
 * (-Iuserspace/libc precedes -Ilibkern) so <os/log_private.h> resolves here.
 *
 * Fidelity: the real OS_LOG_F_* values and the os_log_pack_s ABI are
 * unpublished, and no published source defines them. The flags below are
 * internal to this provider - they are only read by the
 * os_log_send_and_compose() implemented alongside it - so their values need
 * only be self-consistent. The pack layout mirrors the reconstruction in
 * ravynOS (Kernel/xnu/libkern/os/log_private.h); it is not a published ABI.
 * libc reads only olp_format.
 */

#ifndef __os_log_private_h
#define __os_log_private_h

#include <os/log.h>
/* os/assumes.h declares os_assert_mach()/os_assert_mach_port_status() with
 * kern_return_t, mach_port_t and mach_port_status_t in the same block this
 * header unlocks, and it calls strerror(); nothing else in that block brings
 * those in. */
#include <mach/kern_return.h>
#include <mach/port.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/*
 * struct timespec is not spelled out here on purpose: it is 16 bytes with
 * 8-byte alignment on arm64, and this header must not pull <time.h> into
 * every libc translation unit that includes os/assumes.h.
 */
typedef struct os_log_pack_s {
	uint64_t olp_continuous_time;
	uint64_t olp_wall_time[2];	/* struct timespec */
	const void *olp_mh;		/* mach header of caller */
	const void *olp_pc;		/* return address of caller */
	const char *olp_format;
	uint8_t olp_data[0];
} os_log_pack_s;
typedef os_log_pack_s *os_log_pack_t;

/* Provider-internal; libsystem_trace's own values are unpublished. */
#define OS_LOG_F_SEND		0x1u
#define OS_LOG_F_COMPOSE	0x2u

/*!
 * @function os_log_send_and_compose
 *
 * Composes fmt/... into buf (bounded) and reports the format string through
 * fmt_out. OS_LOG_F_SEND has no transport in this port: libsystem_trace is
 * absent, and the composed text still reaches CrashReporter through
 * abort_with_payload().
 */
char *
os_log_send_and_compose(uint32_t flags, const char **fmt_out, char *buf,
    size_t buf_size, os_log_t oslog, os_log_type_t type, const char *format,
    ...) __printflike(7, 8);

/*!
 * @function _os_log_send_and_compose_impl
 *
 * The entry point libsystem_trace's os_log_send_and_compose() macro calls:
 * binaries built against the real SDK reach this symbol, with dso, the packed
 * os_log format buffer and its size. Only the format string is composed here;
 * the packed arguments are not decoded, because the encoder lives in
 * libsystem_trace.
 */
char *
_os_log_send_and_compose_impl(uint32_t flags, const char **fmt_out, char *buf,
    size_t buf_size, void *dso, os_log_t oslog, os_log_type_t type,
    const char *format, uint8_t *fmt_buf, uint32_t fmt_buf_size);

/*!
 * @function os_log_pack_send_and_compose
 *
 * Returns the message recorded in the pack. Encoded argument metadata is not
 * reproduced in this port.
 */
char *
os_log_pack_send_and_compose(os_log_pack_t pack, os_log_t oslog,
    os_log_type_t type, char *buf, size_t buf_size);

__END_DECLS

#endif /* __os_log_private_h */
