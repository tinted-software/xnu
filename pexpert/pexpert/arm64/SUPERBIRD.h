/*
 * Board support header for the Spotify Car Thing ("superbird"), Amlogic
 * S905D2 / G12A, quad Cortex-A53 (ARMv8.0-A, no PAC, no LSE, no FEAT_PAN3).
 *
 * Unlike the Apple SoC headers in this directory, this board has none of
 * Apple's silicon: no AMCC read-only-region controller, no paravirtualized
 * PAC/CTRR, no GICv3, no proprietary SMP bring-up registers. Everything
 * gated behind those features must stay off.
 */

#ifndef _PEXPERT_ARM64_SUPERBIRD_H
#define _PEXPERT_ARM64_SUPERBIRD_H

#define NO_MONITOR                1
#define SUPERBIRD                 1
/*
 * Generic flag for non-Apple-silicon boards: no Tightbeam/exclaves (no
 * SEP/secure-enclave coprocessor to talk to), no per-SoC blob. Reused by
 * any future open-hardware board, not just this one.
 */
#define OSS_HARDWARE               1
#define NO_ECORE                  1

/*
 * No Apple Silicon PAC/CTRR/SME/PAN3 - Cortex-A53 is plain ARMv8.0-A.
 * Deliberately do NOT define CPU_HAS_APPLE_PAC, HAS_PARAVIRTUALIZED_PAC,
 * HAS_PARAVIRTUALIZED_CTRR, HAS_ARM_FEAT_SSBS2/SME/SME2/PAN3: none exist
 * on this CPU and defining them would emit instructions that #UD here.
 */

/*
 * Deliberately left UNDEFINED, not `#define __ARM_16K_PG__ 0` - see
 * pexpert/pexpert/arm64/QEMU.h's comment: osfmk/arm64/proc_reg.h mixes
 * `#ifdef __ARM_16K_PG__` and `#if __ARM_16K_PG__` guards, which
 * disagree if this is defined-but-zero, producing a self-inconsistent
 * TCR_EL1 (16K-style T0SZ with a 4K TG0) that instruction-aborts at
 * SCTLR_EL1.M-enable time.
 */
#define __ARM_RANGE_TLBI__        0

#define ARM_PARAMETERIZED_PMAP    1

#include <pexpert/arm64/apple_arm64_common.h>
#undef  BTI_ENFORCED
#define BTI_ENFORCED 0
#undef  __ARM64_PMAP_SUBPAGE_L1__
#undef  __ARM64_PMAP_KERN_SUBPAGE_L1__
/* Crypto extensions unconfirmed on this SoC's A53 SKU - use generic C. */
#undef  __ARM_V8_CRYPTO_EXTENSIONS__
/* This is not Apple silicon: no coherent-fabric assumptions, no Apple
 * cache-maintenance helpers (nopreempt/mva_ops), no eng-fused sysctl. */
#undef  APPLE_ARM64_ARCH_FAMILY

/*
 * Console: none. The Car Thing exposes no accessible UART; the only
 * available output path at boot is the LCD framebuffer u-boot's bootxnu
 * hands off via xnu_boot_arguments.video_information. Do not define
 * PL011_UART / APPLE_UART / DOCKCHANNEL_UART - no serial driver exists
 * for this board and none is wired up.
 */
#ifndef ASSEMBLER
#define PLATFORM_PANIC_LOG_DISABLED
#endif /* ! ASSEMBLER */

/*
 * GIC-400 (GICv2) interrupt controller, per meson-g12-common.dtsi:
 *   GICD @ 0xffc01000 (distributor)
 *   GICC @ 0xffc02000 (CPU interface, MMIO - no ICC_* system registers)
 *   GICH @ 0xffc04000 (hypervisor interface, unused)
 *   GICV @ 0xffc06000 (virtual CPU interface, unused)
 * This is architecturally different from the GICv3 code in
 * pexpert/arm/pe_fiq.c and osfmk/arm64/sleh.c (which assume ICC_* sysreg
 * + redistributor access) - HAS_GIC_V3 MUST stay undefined here, and a
 * GICv2 MMIO variant of that interrupt bring-up/EOI path is still needed.
 */
#define GIC_SPURIOUS_IRQ          1023

#define GICD_PHYS_BASE            0xffc01000ULL
#define GICD_SIZE                 0x1000
#define GICC_PHYS_BASE            0xffc02000ULL
#define GICC_SIZE                 0x2000

#define GICD_CTLR                 0x0
#define GICD_CTLR_ENABLEGRP0      0x1
#define GICD_CTLR_ENABLEGRP1      0x2

#define GICC_CTLR                 0x0
#define GICC_PMR                  0x4
#define GICC_BPR                  0x8
#define GICC_IAR                  0xc
#define GICC_EOIR                 0x10
#define GICC_CTLR_ENABLEGRP0      0x1
#define GICC_CTLR_ENABLEGRP1      0x2

#endif /* ! _PEXPERT_ARM64_SUPERBIRD_H */
