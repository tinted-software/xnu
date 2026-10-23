/*
 * amcc_rorgn_ppl_amcc.c is not present in this open-source xnu drop. Its
 * public API is entirely gated behind KERNEL_INTEGRITY_KTRR /
 * KERNEL_INTEGRITY_CTRR / KERNEL_INTEGRITY_PV_CTRR, none of which this
 * board defines (no AMCC controller, no CTRR), so a faithful implementation
 * for this board is an empty translation unit.
 */

#include <arm64/amcc_rorgn.h>

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) || defined(KERNEL_INTEGRITY_PV_CTRR)
#error "amcc_rorgn_ppl_amcc.c stub used on a board that requested AMCC/CTRR kernel integrity enforcement"
#endif
