/*
 * sart.h is not present in this open-source xnu drop. SART (Secure Address
 * Range Table) is Apple-silicon-specific DMA range-protection hardware;
 * this board (Amlogic G12A) has none, so sart_bootstrap() is implemented
 * as a device-tree lookup that finds no "sart" node and returns.
 */

#ifndef _ARM64_PPL_SART_H_
#define _ARM64_PPL_SART_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

void sart_bootstrap(void);

__END_DECLS

#endif /* _ARM64_PPL_SART_H_ */
