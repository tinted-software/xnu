/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

extern void iokit_post_constructor_init(void);

static void __attribute__((used))
last_kernel_constructor(void)
{
	iokit_post_constructor_init();
}

/*
 * Registered by hand rather than with __attribute__((constructor)): a
 * kernelcache's MH_FILESET boot code requires a non-empty __LASTDATA_CONST (it
 * ends the kernel's constant data, with the kexts' following it), and the
 * constructor that must run after every other one belongs there. The pointer
 * is plain, like any compiler-emitted constructor; the kernel signs it at boot
 * (OSRuntimeSignStructors).
 */
__asm__(".pushsection __LASTDATA_CONST,__mod_init_func,mod_init_funcs\n"
    "\t.p2align 3\n"
    "\t.quad _last_kernel_constructor\n"
    "\t.popsection\n");

__asm__(".globl _last_kernel_symbol");
__asm__(".zerofill __LAST, __last, _last_kernel_symbol, 0");
