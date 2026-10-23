/*
 * Minimal GIC-400 (GICv2) MMIO driver, shared by every board that uses a
 * plain GICv2 distributor + banked CPU interface (no ICC_* system registers).
 */
#include <stdint.h>
#include <stddef.h>
#include <pexpert/pexpert.h>
#include <pexpert/arm64/gic.h>

#ifndef GIC_SPURIOUS_IRQ
#define GIC_SPURIOUS_IRQ 1023
#endif

#ifndef GIC_IRQ_MASK
#define GIC_IRQ_MASK 0x3ff
#endif

#ifndef MAX_IRQS
#define MAX_IRQS 1020
#endif

#ifndef GICD_CTLR
#define GICD_CTLR 0x000
#endif

#ifndef GICD_ISENABLER
#define GICD_ISENABLER 0x100
#endif

#ifndef GICC_CTLR
#define GICC_CTLR 0x000
#endif

#ifndef GICC_PMR
#define GICC_PMR 0x004
#endif

#ifndef GICC_BPR
#define GICC_BPR 0x008
#endif

#ifndef GICC_IAR
#define GICC_IAR 0x00c
#endif

#ifndef GICC_EOIR
#define GICC_EOIR 0x010
#endif

#ifndef GICD_CTLR_ENABLEGRP0
#define GICD_CTLR_ENABLEGRP0 (1 << 0)
#endif

#ifndef GICD_CTLR_ENABLEGRP1
#define GICD_CTLR_ENABLEGRP1 (1 << 1)
#endif

#ifndef GICC_CTLR_ENABLEGRP0
#define GICC_CTLR_ENABLEGRP0 (1 << 0)
#endif

#ifndef GICC_CTLR_ENABLEGRP1
#define GICC_CTLR_ENABLEGRP1 (1 << 1)
#endif

extern vm_offset_t ml_io_map(vm_offset_t phys_addr, vm_size_t size);
extern void ml_install_interrupt_handler(
    void *nub,
    int source,
    void *target,
    void (*handler)(void *, void *, void *, int),
    void *ref_con
);
extern boolean_t ml_get_timer_pending(void);
extern void rtclock_intr(unsigned int is_user_context);

/* GICv2 INTID for the ARM generic virtual EL1 timer PPI, as wired up by
 * QEMU's virt machine device tree (PPI #11 -> GIC INTID 27). */
#ifndef GIC_VIRT_TIMER_IRQ
#define GIC_VIRT_TIMER_IRQ 27
#endif

static vm_offset_t gicd_base = 0;
static vm_offset_t gicc_base = 0;

static inline uint32_t mmio_read32(vm_offset_t addr) {
    return *(volatile uint32_t *)addr;
}

static inline void mmio_write32(vm_offset_t addr, uint32_t val) {
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t gicd_read(uint32_t offset) {
    return mmio_read32(gicd_base + offset);
}

static inline void gicd_write(uint32_t offset, uint32_t val) {
    mmio_write32(gicd_base + offset, val);
}

static inline uint32_t gicc_read(uint32_t offset) {
    return mmio_read32(gicc_base + offset);
}

static inline void gicc_write(uint32_t offset, uint32_t val) {
    mmio_write32(gicc_base + offset, val);
}

static void gic_dispatch(void *target, void *refCon, void *nub, int source) {
    (void)target;
    (void)refCon;
    (void)nub;
    (void)source;
    while (1) {
        uint32_t iar = gicc_read(GICC_IAR);
        uint32_t irq = iar & GIC_IRQ_MASK;
        if (irq >= GIC_SPURIOUS_IRQ) {
            break;
        }
        if (irq == GIC_VIRT_TIMER_IRQ || ml_get_timer_pending()) {
            rtclock_intr(TRUE);
        }
        gicc_write(GICC_EOIR, iar);
    }
}

void gic_init(void) {
    if (gicd_base != 0) {
        return;
    }
#if defined(GICD_PHYS_BASE) && defined(GICC_PHYS_BASE)
    gicd_base = ml_io_map(GICD_PHYS_BASE, GICD_SIZE);
    gicc_base = ml_io_map(GICC_PHYS_BASE, GICC_SIZE);

    gicd_write(GICD_CTLR, 0);
    gicd_write(GICD_CTLR, GICD_CTLR_ENABLEGRP0 | GICD_CTLR_ENABLEGRP1);

    gicc_write(GICC_PMR, 0xff);
    gicc_write(GICC_BPR, 0);
    gicc_write(GICC_CTLR, GICC_CTLR_ENABLEGRP0 | GICC_CTLR_ENABLEGRP1);

    gicd_write(GICD_ISENABLER + (GIC_VIRT_TIMER_IRQ / 32) * 4, 1U << (GIC_VIRT_TIMER_IRQ % 32));

    ml_install_interrupt_handler(NULL, 0, NULL, gic_dispatch, NULL);
#endif
}

void gic_enable_interrupt(uint32_t irq) {
    if (gicd_base == 0 || irq >= MAX_IRQS) {
        return;
    }
    uint32_t reg = GICD_ISENABLER + (irq / 32) * 4;
    uint32_t shift = irq % 32;
    gicd_write(reg, (1U << shift));
}
