/*
 * AICv1 (Apple Interrupt Controller, pre-AIC2) driver skeleton for iPad4,1 / A7 (s5l8960x).
 */
#include <stdint.h>
#include <stddef.h>
#include <pexpert/pexpert.h>
#include <pexpert/arm64/gic.h>

#ifndef AIC_PHYS_BASE
#define AIC_PHYS_BASE 0x20e100000ULL
#endif

#ifndef AIC_SIZE
#define AIC_SIZE 0x8000
#endif

#ifndef AIC_CONFIG
#define AIC_CONFIG 0x2000
#endif

#ifndef AIC_MASK_SET
#define AIC_MASK_SET 0x3c00
#endif

#ifndef AIC_MASK_CLR
#define AIC_MASK_CLR 0x3c04
#endif

#ifndef AIC_EVENT
#define AIC_EVENT 0x3804
#endif

#ifndef AIC_SPURIOUS_IRQ
#define AIC_SPURIOUS_IRQ 192
#endif

#ifndef MAX_IRQS
#define MAX_IRQS AIC_SPURIOUS_IRQ
#endif

extern vm_offset_t ml_io_map(vm_offset_t phys_addr, vm_size_t size);
extern void ml_install_interrupt_handler(
    void *nub,
    int source,
    void *target,
    void (*handler)(void *, void *, void *, int),
    void *ref_con
);

static vm_offset_t aic_base = 0;

static inline uint32_t mmio_read32(vm_offset_t addr) {
    return *(volatile uint32_t *)addr;
}

static inline void mmio_write32(vm_offset_t addr, uint32_t val) {
    *(volatile uint32_t *)addr = val;
}

static inline uint32_t aic_read(uint32_t offset) {
    return mmio_read32(aic_base + offset);
}

static inline void aic_write(uint32_t offset, uint32_t val) {
    mmio_write32(aic_base + offset, val);
}

static void aic_dispatch(void *target, void *refCon, void *nub, int source) {
    (void)target;
    (void)refCon;
    (void)nub;
    (void)source;
    while (1) {
        uint32_t irq = aic_read(AIC_EVENT);
        if (irq >= AIC_SPURIOUS_IRQ) {
            break;
        }
        aic_write(AIC_EVENT, irq);
    }
}

void gic_init(void) {
    if (aic_base != 0) {
        return;
    }
    aic_base = ml_io_map(AIC_PHYS_BASE, AIC_SIZE);
    aic_write(AIC_MASK_SET, 0xffffffff);
    ml_install_interrupt_handler(NULL, 0, NULL, aic_dispatch, NULL);
}

void gic_enable_interrupt(uint32_t irq) {
    if (aic_base == 0 || irq >= MAX_IRQS) {
        return;
    }
    aic_write(AIC_MASK_CLR, (1U << (irq % 32)));
}
