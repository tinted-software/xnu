/*
 * arm64/tunables/tunables.s is not present in this open-source xnu drop:
 * it dispatches on MIDR_EL1 to apply per-Apple-SoC IMPLEMENTATION DEFINED
 * errata/tunable register writes. This board (Cortex-A53, Amlogic G12A)
 * has no Apple silicon and none of those tunables apply, so APPLY_TUNABLES
 * is a no-op here.
 *
 * @param $0 MIDR_EL1 value (unused)
 * @param $1 scratch register (unused)
 * @param $2 scratch register (unused)
 */
.macro APPLY_TUNABLES
.endmacro
