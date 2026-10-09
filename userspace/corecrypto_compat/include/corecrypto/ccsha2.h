/*
 * SHA-256 / SHA-384 entry points used from corecrypto. Implemented in
 * ../../ccsha2.c over the Rust primitives in ../../ccsha2.rs.
 */

#ifndef _CORECRYPTO_CCSHA2_H_
#define _CORECRYPTO_CCSHA2_H_

#include <corecrypto/ccdigest.h>

#define CCSHA256_OUTPUT_SIZE	32
#define CCSHA256_BLOCK_SIZE	64
#define CCSHA384_OUTPUT_SIZE	48
#define CCSHA384_BLOCK_SIZE	128

#ifdef __cplusplus
extern "C" {
#endif
const struct ccdigest_info *ccsha256_di(void);
const struct ccdigest_info *ccsha384_di(void);
#ifdef __cplusplus
}
#endif

#endif /* _CORECRYPTO_CCSHA2_H_ */
