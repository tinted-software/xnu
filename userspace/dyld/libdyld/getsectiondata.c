/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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
 * Vendored from apple-oss-distributions/cctools libmacho/getsecbyname.c
 * (https://github.com/apple-oss-distributions/cctools/blob/main/libmacho/getsecbyname.c),
 * licensed under the Apple Public Source License 2.0. Only getsectiondata() is
 * taken: libdyld exports it (mach-o/getsect.h) and no other file in this tree
 * defines it.
 */
#include <stdint.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>


/*
 * This routine returns the a pointer to the section contents of the named
 * section in the named segment if it exists in the image pointed to by the
 * mach header.  Otherwise it returns zero.
 */
uint8_t*
getsectiondata(
#if __LP64__
  const struct mach_header_64* mh,
#else
  const struct mach_header* mh,
#endif
  const char* segname, const char* sectname, unsigned long* size)
{
    unsigned startOffset = (mh->magic == MH_MAGIC_64) ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    struct load_command* lc = (struct load_command*)((uint8_t*)mh + startOffset);
    uintptr_t slide = 0;
    for (int i=0; i < mh->ncmds; ++i){
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (struct segment_command_64*)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                slide = (uintptr_t)mh - seg->vmaddr;
            }
            if (strncmp(seg->segname, segname, 16) == 0) {
                const struct section_64* sect = (struct section_64*)((uint8_t*)seg + sizeof(struct segment_command_64));
                for (int j = 0; j < seg->nsects; ++j){
                    if ((strncmp(sect[j].sectname, sectname, 16) == 0) && (strncmp(sect[j].segname, segname, 16) == 0)) {
                        *size = sect[j].size;
                        uint8_t* result = (uint8_t*)(sect[j].addr + slide);
                        return result;
                    }
                }
            }
        }
        else if (lc->cmd == LC_SEGMENT) {
            const struct segment_command* seg = (struct segment_command*)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                slide = (uintptr_t)mh - seg->vmaddr;
            }
            if (strncmp(seg->segname, segname, 16) == 0) {
                const struct section* sect = (struct section*)((uint8_t*)seg + sizeof(struct segment_command));
                for (int j = 0; j < seg->nsects; ++j){
                    if ((strncmp(sect[j].sectname, sectname, 16) == 0) && (strncmp(sect[j].segname, segname, 16) == 0)) {
                        *size = sect[j].size;
                        return (uint8_t*)(sect[j].addr + slide);
                    }
                }
            }
        }
        lc = (struct load_command*)((uint8_t*)lc + lc->cmdsize);
    }
    return NULL;
}

