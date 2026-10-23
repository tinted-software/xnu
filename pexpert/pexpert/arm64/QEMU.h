/*
 * Board support header for QEMU's aarch64 "virt" machine
 * (`qemu-system-aarch64 -M virt -cpu cortex-a53`), booted the same way as
 * SUPERBIRD: u-boot's generic `bootxnu` command (../u-boot/cmd/bootxnu.c -
 * board-agnostic, just parses the Mach-O this build produces and jumps
 * into it with a boot_args struct) run from u-boot built with
 * qemu_arm64_defconfig.
 *
 * `-cpu cortex-a53` is plain ARMv8.0-A, same silicon class as SUPERBIRD:
 * no PAC, no PPL/SPTM, no KTRR/AMCC, no Apple Interrupt Controller.
 * Everything gated behind those features must stay off, same as
 * SUPERBIRD.h.
 */

#ifndef _PEXPERT_ARM64_QEMU_H
#define _PEXPERT_ARM64_QEMU_H

#define NO_MONITOR                1
#define QEMU                      1
/*
 * Generic flag for non-Apple-silicon boards: no Tightbeam/exclaves (no
 * SEP/secure-enclave coprocessor to talk to), no per-SoC blob.
 */
#define OSS_HARDWARE               1
#define NO_ECORE                  1

/*
 * No Apple Silicon PAC/CTRR/SME/PAN3 - `-cpu cortex-a53` is plain
 * ARMv8.0-A. Deliberately do NOT define CPU_HAS_APPLE_PAC,
 * HAS_PARAVIRTUALIZED_PAC, HAS_PARAVIRTUALIZED_CTRR,
 * HAS_ARM_FEAT_SSBS2/SME/SME2/PAN3: none exist on this CPU model and
 * defining them would emit instructions that #UD here.
 */

/*
 * Deliberately left UNDEFINED, not `#define __ARM_16K_PG__ 0`: this is a
 * 4K-page device, but osfmk/arm64/proc_reg.h guards T0SZ_BOOT with
 * `#ifdef __ARM_16K_PG__` (true if *defined*, even to 0) while it guards
 * TCR_TG0_GRANULE_SIZE/ARM_TT_L2_SIZE/ARM_PGSHIFT with
 * `#if __ARM_16K_PG__` (true only if *nonzero*). Defining this to 0 trips
 * the former into the 16K-page T0SZ (17, expecting a 4-level walk) while
 * everything else takes the 4K-page branch (T0SZ 25, 3-level
 * start.s bootstrap tables + TG0=4K) - a self-inconsistent TCR_EL1 that
 * instruction-aborts the moment SCTLR_EL1.M is set. Leaving it undefined
 * makes both guards agree on the 4K-page branch, matching real Apple
 * boards, which never define this macro for 4K-page devices.
 */
#define __ARM_RANGE_TLBI__        0

#define ARM_PARAMETERIZED_PMAP    1

#include <pexpert/arm64/apple_arm64_common.h>
#undef  BTI_ENFORCED
#define BTI_ENFORCED 0
#undef  __ARM64_PMAP_SUBPAGE_L1__
#undef  __ARM64_PMAP_KERN_SUBPAGE_L1__
/* Crypto extensions unconfirmed for QEMU's cortex-a53 model - use generic C. */
#undef  __ARM_V8_CRYPTO_EXTENSIONS__
/* This is not Apple silicon: no coherent-fabric assumptions, no Apple
 * cache-maintenance helpers (nopreempt/mva_ops), no eng-fused sysctl. */
#undef  APPLE_ARM64_ARCH_FAMILY

/*
 * Console: PL011 UART at 0x09000000 (`-M virt`'s pl011@9000000). The
 * driver already exists in pexpert/arm/pe_serial.c, gated on
 * PL011_UART; it just needed a board that enables it and an AFDT
 * describing the device (arm-io/defaults/pl011 nodes - see
 * tools/qemu-boot/boot.zig's AFDT builder, the only source of the
 * device tree this board boots with, and boot_args.command_line's
 * `serial-device-name=uart0` selecting it via pe_serial.c's
 * get_serial_device_phandle()).
 */
#define PL011_UART 1

#ifndef ASSEMBLER
#define PLATFORM_PANIC_LOG_DISABLED
#endif /* ! ASSEMBLER */

/*
 * GICv2, `-M virt`'s default (`gic-version=2`; `gic-version=3` would need
 * the ICC_*-system-register driver in pexpert/arm/pe_fiq.c instead, not
 * this MMIO one):
 *   GICD @ 0x08000000 (distributor)
 *   GICC @ 0x08010000 (CPU interface, MMIO - no ICC_* system registers)
 * Same architecture as SUPERBIRD's GIC-400 - HAS_GIC_V3 must stay
 * undefined here. The physical bases are injected into
 * pexpert/gic/gic.zig at build-graph time (tools/zig/boards.zig
 * GicBases), not read from this header; they are restated here only for
 * documentation.
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

#endif /* ! _PEXPERT_ARM64_QEMU_H */
