/* SHA-1 entry point (dyld's code-signature checks). See ../../ccsha2.c. */
#ifndef _CORECRYPTO_CCSHA1_H_
#define _CORECRYPTO_CCSHA1_H_

#include <corecrypto/ccdigest.h>

#define CCSHA1_OUTPUT_SIZE	20
#define CCSHA1_BLOCK_SIZE	64

#ifdef __cplusplus
extern "C" {
#endif
const struct ccdigest_info *ccsha1_di(void);
#ifdef __cplusplus
}
#endif

#endif
