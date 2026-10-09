/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * PORT STAND-IN. The rwx and TPRO implementations (os_thread_self_restrict_*)
 * are unpublished Apple code; upstream xnu ships only this empty guard. This port
 * reports the rwx mechanism as unsupported, so every caller takes its existing
 * "unsupported" path: pthread_jit_write_protect_np and the JIT allowlist are
 * no-ops, and pthread_jit_write_with_callback_np invokes the callback directly.
 * Consequence: no hardware W^X toggling of JIT pages in this port.
 */
#ifndef OS_THREAD_SELF_RESTRICT_H
#define OS_THREAD_SELF_RESTRICT_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline bool
os_thread_self_restrict_rwx_is_supported(void)
{
	return false;
}

static inline void
os_thread_self_restrict_rwx_to_rx(void)
{
}

static inline void
os_thread_self_restrict_rwx_to_rw(void)
{
}

/*
 * TPRO: per-thread toggle of the hardware-assisted read-only mapping
 * (APRR-based, Apple silicon only). The register interface is unpublished
 * and QEMU does not model it, so this port reports TPRO as unsupported.
 * Consequence: dyld and libpthread keep TPRO regions writable; there is no
 * hardware write protection for them. `is_writable` is true so a caller that
 * reaches it without checking `is_supported` sees the regions as writable
 * rather than as protected.
 */
static inline bool
os_thread_self_restrict_tpro_is_supported(void)
{
	return false;
}

static inline bool
os_thread_self_restrict_tpro_is_writable(void)
{
	return true;
}

static inline void
os_thread_self_restrict_tpro_to_rw(void)
{
}

static inline void
os_thread_self_restrict_tpro_to_ro(void)
{
}

#ifdef __cplusplus
}
#endif

#endif /* OS_THREAD_SELF_RESTRICT_H */
