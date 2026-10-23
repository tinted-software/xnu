/*
 * sart.c is not present in this open-source xnu drop. SART (Secure Address
 * Range Table) is Apple-silicon-specific DMA range-protection hardware.
 * This board (Amlogic G12A) has none: sart_bootstrap() looks for an
 * "sart" node in the boot device tree (exactly like a real implementation
 * would), finds none since no such node is ever populated for this board,
 * and returns.
 */

#include <arm64/ppl/sart.h>
#include <pexpert/device_tree.h>

void
sart_bootstrap(void)
{
	DTEntry sart_node;

	if (SecureDTLookupEntry(NULL, "/arm-io/sart", &sart_node) != kSuccess) {
		return;
	}
}
