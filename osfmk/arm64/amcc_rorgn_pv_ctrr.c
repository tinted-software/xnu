/*
 * amcc_rorgn_pv_ctrr.c is not present in this open-source xnu drop. Its
 * public API is entirely gated behind KERNEL_INTEGRITY_PV_CTRR, which this
 * board does not define (no paravirtualized CTRR hardware), so a faithful
 * implementation for this board is an empty translation unit.
 */

#include <arm64/amcc_rorgn.h>

#if defined(KERNEL_INTEGRITY_PV_CTRR)
#error "amcc_rorgn_pv_ctrr.c stub used on a board that requested paravirtualized CTRR"
#endif
