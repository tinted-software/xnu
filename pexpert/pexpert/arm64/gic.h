/*
 * Minimal GIC-400 (GICv2) MMIO driver interface for open-hardware ARM64
 * boards (e.g. SUPERBIRD/Amlogic S905D2) that have no Apple Interrupt
 * Controller and no GICv3 redistributor/ICC_* system registers. Register
 * offsets/constants live in the board header (e.g. arm64/SUPERBIRD.h)
 * since they are architecturally fixed by the GICv2 spec, not board data;
 * only the physical base addresses are board-specific.
 */
#ifndef _PEXPERT_ARM64_GIC_H
#define _PEXPERT_ARM64_GIC_H

#ifndef ASSEMBLER

#include <stdint.h>

/* Called once, from PE_init_platform() after the VM is up (needs ml_io_map
 * for the GICD/GICC MMIO windows). Maps the distributor + CPU interface,
 * enables both interrupt groups, unmasks all priorities, and installs
 * itself as the primary IRQ dispatcher via ml_install_interrupt_handler().
 * No-op if GICD_PHYS_BASE is not defined for this board. */
void gic_init(void);

/* Enable (unmask) forwarding of the given GIC interrupt ID (SPI or PPI,
 * i.e. the GIC-numbered IRQ, not the DT PPI/SPI-relative number) at the
 * distributor. SGIs (0-15) are always enabled and need no call here. */
void gic_enable_interrupt(uint32_t irq);

#endif /* !ASSEMBLER */

#endif /* !_PEXPERT_ARM64_GIC_H */
