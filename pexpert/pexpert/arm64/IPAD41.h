/*
 * Board support header for the iPad Air (iPad4,1), Apple A7 / s5l8960x,
 * dual Cyclone (ARMv8.0-A). Targeted for boot via pongoOS (checkm8/KPF),
 * which loads the raw Mach-O this build produces.
 *
 * A7 predates nearly every Apple-silicon feature this tree guards on:
 * no PPL/SPTM, no KTRR/AMCC (those arrive with A10), no PAC, no PAN,
 * no GIC — interrupts are the Samsung-derived AICv1. Like SUPERBIRD.h,
 * everything gated behind those features must stay off.
 */

#ifndef _PEXPERT_ARM64_IPAD41_H
#define _PEXPERT_ARM64_IPAD41_H

#define NO_MONITOR                1
#define IPAD41                    1
/* proc_reg.h cache-geometry arm key (Cyclone predates APPLETYPHOON). */
#define APPLECYCLONE              1

/*
 * No SEP/Tightbeam/exclaves path bring-up for this port (A7's SEP exists
 * but is unused here); reuse the non-Apple-silicon escape hatch so the
 * same source guards apply.
 */
#define OSS_HARDWARE               1
#define NO_ECORE                  1

/*
 * No PAC/PAN/SME/PAN3 - Cyclone is plain ARMv8.0-A. Deliberately do NOT
 * define CPU_HAS_APPLE_PAC, HAS_PARAVIRTUALIZED_PAC,
 * HAS_PARAVIRTUALIZED_CTRR, HAS_ARM_FEAT_SSBS2/SME/SME2/PAN3: none exist
 * on this CPU and defining them would emit instructions that #UD here.
 * A7 also predates PPL entirely; the SPTM pmap variant
 * (osfmk/arm64/sptm/pmap.c) must not be selected for this board — the
 * kernel config side of that choice is still TODO.
 */

/*
 * Deliberately left UNDEFINED, not `#define __ARM_16K_PG__ 0` (A7 is a
 * 4K-page device) - see pexpert/pexpert/arm64/QEMU.h's comment:
 * osfmk/arm64/proc_reg.h mixes `#ifdef __ARM_16K_PG__` and
 * `#if __ARM_16K_PG__` guards, which disagree if this is
 * defined-but-zero, producing a self-inconsistent TCR_EL1 (16K-style
 * T0SZ with a 4K TG0) that instruction-aborts at SCTLR_EL1.M-enable
 * time.
 */
#define __ARM_RANGE_TLBI__        0

#define ARM_PARAMETERIZED_PMAP    1

#include <pexpert/arm64/apple_arm64_common.h>
#undef  BTI_ENFORCED
#define BTI_ENFORCED 0
#undef  __ARM64_PMAP_SUBPAGE_L1__
#undef  __ARM64_PMAP_KERN_SUBPAGE_L1__
/* Not treated as an Apple-arch-family target here: skips Apple-specific
 * cache-maintenance helpers this fork does not bring up. */
#undef  APPLE_ARM64_ARCH_FAMILY

/*
 * Console: A7 exposes a Samsung-style UART (uart0 @ 0x20a0c0000 per the
 * iPad4,1 device tree) usable with `serial=3` under pongoOS; no driver
 * is wired up in this tree yet. pongoOS also hands a framebuffer via
 * xnu_boot_arguments.video_information for early panic display.
 */
#ifndef ASSEMBLER
#define PLATFORM_PANIC_LOG_DISABLED
#endif /* ! ASSEMBLER */

/*
 * Interrupt controller: AICv1 (aic@20e100000 in the iPad4,1 device tree).
 * There is no GIC at all; do NOT define HAS_GIC_V3 or GICD/GICC_* here.
 * The driver is pexpert/aic/aic.zig, built by the zig build for this
 * board and exporting the gic_init/gic_enable_interrupt ABI.
 */
#define AIC_PHYS_BASE             0x20e100000ULL
#define AIC_SIZE                  0x8000
#define AIC_SPURIOUS_IRQ          192 /* A7 AIC advertises 192 lines */

#endif /* ! _PEXPERT_ARM64_IPAD41_H */
