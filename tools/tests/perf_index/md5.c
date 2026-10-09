/* MD5 adapter for perf_index using the platform CommonCrypto API. */

#include "md5.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <string.h>

void
md5_hash(uint8_t *message, uint64_t len, uint32_t *hash)
{
	if (len > UINT32_MAX) {
		abort();
	}
	if (CC_MD5(message, (CC_LONG)len, (unsigned char *)hash) == NULL) {
		abort();
	}
}
