/*
 * Copyright (c) 1998-2012 Apple Inc. All rights reserved.
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
#include <pexpert/arm64/board_config.h>
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

const char * gIOKernelConfigTables =
    "("
    "   {"
    "     'IOClass'         = AppleARMPE;"
    "     'IOProviderClass' = IOPlatformExpertDevice;"
    "     'IOProbeScore'    = 1000:32;"
    "     'IONameMatch'     = 'device-tree';"
    "   },"
#if OSS_HARDWARE
    /*
     * Embedded fallback platform expert for non-Apple-silicon boards
     * (QEMU, SUPERBIRD, IPAD41, ...) whose minimal device trees may not
     * satisfy AppleARMPE's IONameMatch above. See IOOSSPlatformExpert in
     * IOPlatformExpert.cpp for details. Scored below AppleARMPE so real
     * hardware still prefers it, but above IOPanicPlatform so these
     * boards always end up with a live IOPlatformExpert.
     */
    "   {"
    "     'IOClass'         = IOOSSPlatformExpert;"
    "     'IOProviderClass' = IOPlatformExpertDevice;"
    "     'IOProbeScore'    = 500:32;"
    "   },"
#endif /* OSS_HARDWARE */
    "   {"
    "     'IOClass'         = IOPanicPlatform;"
    "     'IOProviderClass' = IOPlatformExpertDevice;"
    "     'IOProbeScore'    = 0:32;"
    "   },"
    "   {"
    "     'IOClass'         = IOExclaveProxy;"
    "     'IOProviderClass' = IOService;"
    "     'IOExclaveProxy'  = 1:32;"
    "   }"
    ")";
