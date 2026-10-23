/*
 * Board support header for QEMU's aarch64 "virt" machine modelled as a
 * Cortex-A55 (`qemu-system-aarch64 -M virt -cpu cortex-a55`), booted by
 * u-boot's generic `bootxnu` command (../u-boot/cmd/bootxnu.c).
 *
 * The Cortex-A55 is plain ARMv8.2-A: it supports the 16K translation
 * granule (like every ARMv8-A core) but has **no** pointer
 * authentication, no PPL/SPTM, no KTRR/AMCC, no Apple Interrupt
 * Controller.  The kernel is therefore built for the plain `arm64`
 * target (not `arm64e`), with __ARM_16K_PG__=1 passed on the command
 * line so proc_reg.h/start.s take the 16K-page branches consistently.
 * Do not define CPU_HAS_APPLE_PAC (or any PAC feature): neither this CPU
 * model nor real A55 silicon implements PAC, and pac* instructions would
 * be undefined there.
 */

#ifndef _PEXPERT_ARM64_QEMU_A55_H
#define _PEXPERT_ARM64_QEMU_A55_H

#define NO_MONITOR                1
#define QEMU                      1
/*
 * Generic flag for non-Apple-silicon boards: no Tightbeam/exclaves (no
 * SEP/secure-enclave coprocessor to talk to), no per-SoC blob.
 */
#define OSS_HARDWARE               1
#define NO_ECORE                  1

/*
 * No Apple Silicon PAC/CTRR/SME/PAN3: the A55 is plain ARMv8.2-A.
 * HAS_PARAVIRTUALIZED_PAC/CTRR, HAS_ARM_FEAT_SSBS2/SME/SME2/PAN3 are all
 * deliberately left undefined.
 */

#define __ARM_RANGE_TLBI__        0

#define ARM_PARAMETERIZED_PMAP    1

#include <pexpert/arm64/apple_arm64_common.h>
#undef  BTI_ENFORCED
#define BTI_ENFORCED 0
#undef  __ARM64_PMAP_SUBPAGE_L1__
#undef  __ARM64_PMAP_KERN_SUBPAGE_L1__
/* Keep the generic C crypto paths: no NEON crypto assumptions. */
#undef  __ARM_V8_CRYPTO_EXTENSIONS__
/* This is not Apple silicon: no coherent-fabric assumptions, no Apple
 * cache-maintenance helpers (nopreempt/mva_ops), no eng-fused sysctl. */
#undef  APPLE_ARM64_ARCH_FAMILY

/*
 * Console: PL011 UART at 0x09000000 (`-M virt`'s pl011@9000000). The
 * driver already exists in pexpert/arm/pe_serial.c, gated on
 * PL011_UART; boot_args.command_line's `serial-device-name=uart0`
 * selects it through the AFDT the bootloader synthesizes.
 */
#define PL011_UART 1

#ifndef ASSEMBLER
#define PLATFORM_PANIC_LOG_DISABLED
#endif /* ! ASSEMBLER */

/*
 * GICv2, `-M virt`'s default (`gic-version=2`): distributor at
 * 0x08000000, banked MMIO CPU interface at 0x08010000.  No ICC_*
 * system registers, so HAS_GIC_V3 must stay undefined.
 */
#define GIC_SPURIOUS_IRQ          1023

#define GICD_PHYS_BASE            0x08000000ULL
#define GICD_SIZE                 0x1000
#define GICC_PHYS_BASE            0x08010000ULL
#define GICC_SIZE                 0x1000

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

#endif /* ! _PEXPERT_ARM64_QEMU_A55_H */
