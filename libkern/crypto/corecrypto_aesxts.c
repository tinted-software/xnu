/*
 * Copyright (c) 2012 Apple Computer, Inc. All rights reserved.
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

#include <libkern/crypto/crypto_internal.h>
#include <libkern/libkern.h>
#include <libkern/crypto/aesxts.h>
#include <libkern/crypto/ccmode_abi.h>
#include <kern/debug.h>

/*
 * These are the interfaces required for XTS-AES support
 */

uint32_t
xts_start(uint32_t cipher __unused, // ignored - we're doing this for xts-aes only
    const uint8_t *IV __unused,               // ignored
    const uint8_t *key1, int keylen,
    const uint8_t *key2, int tweaklen,
    uint32_t num_rounds __unused,               // ignored
    uint32_t options __unused,                  // ignored
    symmetric_xts *xts)
{
	const struct ccmode_xts *enc, *dec;

	if (!xts || !key1 || !key2 || keylen != tweaklen ||
	    (keylen != 16 && keylen != 24 && keylen != 32)) {
		if (xts) {
			cc_clear(sizeof(*xts), xts);
		}
		return CCMODE_INVALID_INPUT;
	}

	if (!g_crypto_funcs) {
		panic("%s: RustCrypto provider not registered!", __FUNCTION__);
	}

	enc = g_crypto_funcs->ccaes_xts_encrypt;
	dec = g_crypto_funcs->ccaes_xts_decrypt;

	if (!enc || !dec) {
		panic("%s: xts mode not registered? enc=%p, dec=%p", __FUNCTION__, enc, dec);
	}

	/* Make sure the context size for the mode fits in the one we have */
	if ((enc->size > sizeof(xts->enc)) || (dec->size > sizeof(xts->dec))) {
		panic("%s: inconsistent size for AES-XTS context", __FUNCTION__);
	}

	int rc = ccxts_init(enc, xts->enc, (size_t)keylen, key1, key2);
	if (rc == 0) {
		rc = ccxts_init(dec, xts->dec, (size_t)keylen, key1, key2);
	}
	if (rc != 0) {
		cc_clear(sizeof(*xts), xts);
	}
	return rc;
}

int
xts_encrypt(const uint8_t *pt, unsigned long ptlen,
    uint8_t *ct,
    const uint8_t *iv,                     // this can be considered the sector IV for this use
    symmetric_xts *xts)
{
	const struct ccmode_xts *xtsenc = g_crypto_funcs->ccaes_xts_encrypt;
	ccxts_tweak_decl(xtsenc->tweak_size, tweak);

	if (!xts || ptlen % 16 || ptlen / 16 > (1UL << 20)) {
		return CCMODE_INVALID_INPUT;
	}

	int rc = ccxts_set_tweak(xtsenc, xts->enc, tweak, iv);
	if (rc == 0 && ccxts_update(xtsenc, xts->enc, tweak,
	    ptlen / 16, pt, ct) == NULL) {
		rc = CCMODE_INVALID_INPUT;
	}
	ccxts_tweak_clear(xtsenc->tweak_size, tweak);
	return rc;
}

int
xts_decrypt(const uint8_t *ct, unsigned long ptlen,
    uint8_t *pt,
    const uint8_t *iv,                             // this can be considered the sector IV for this use
    symmetric_xts *xts)
{
	const struct ccmode_xts *xtsdec = g_crypto_funcs->ccaes_xts_decrypt;
	ccxts_tweak_decl(xtsdec->tweak_size, tweak);

	if (!xts || ptlen % 16 || ptlen / 16 > (1UL << 20)) {
		return CCMODE_INVALID_INPUT;
	}

	int rc = ccxts_set_tweak(xtsdec, xts->dec, tweak, iv);
	if (rc == 0 && ccxts_update(xtsdec, xts->dec, tweak,
	    ptlen / 16, ct, pt) == NULL) {
		rc = CCMODE_INVALID_INPUT;
	}
	ccxts_tweak_clear(xtsdec->tweak_size, tweak);
	return rc;
}

void
xts_done(symmetric_xts *xts)
{
	if (!xts) {
		return;
	}
	cc_clear(sizeof(xts->enc), xts->enc);
	cc_clear(sizeof(xts->dec), xts->dec);
}
