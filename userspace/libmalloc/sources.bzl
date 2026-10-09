# libmalloc.xcodeproj/project.pbxproj, 3FE91FE416A90AEC00D1238A Sources.
# The normal macOS arm64 allocator retains every C translation unit in the
# upstream phase. magmallocProvider.d is handled by the DTrace header action.
MALLOC_NORMAL_SRCS = [
    "src/instrumentation.c",
    "src/bitarray.c",
    "src/xzone_malloc/xzone_segment.c",
    "src/malloc_common.c",
    "src/purgeable_malloc.c",
    "src/sanitizer_malloc.c",
    "src/magazine_large.c",
    "src/magazine_malloc.c",
    "src/magazine_small.c",
    "src/stack_trace.c",
    "src/xzone_malloc/xzone_metapool.c",
    "src/magazine_rack.c",
    "src/legacy_malloc.c",
    "src/malloc_config.c",
    "src/vm.c",
    "src/malloc_type.c",
    "src/msl_lite_support.c",
    "src/early_malloc.c",
    "src/xzone_malloc/xzone_introspect.c",
    "src/has_section.c",
    "src/pgm_malloc.c",
    "src/nanov2_malloc.c",
    "src/wrapper_zones.c",
    "resolver/resolver.c",
    "src/nano_malloc_common.c",
    "src/xzone_malloc/xzone_malloc.c",
    "src/malloc.c",
    "src/magazine_medium.c",
    "src/frozen_malloc.c",
    "src/magazine_tiny.c",
    "src/malloc_printf.c",
]

# Both resolved targets use libmalloc_resolved.xcconfig, whose unconditional
# EXCLUDED_SOURCE_FILE_NAMES = * excludes their complete source phases.
# SUPPORTED_PLATFORMS also excludes macOS. They contribute no alternative
# allocator implementations or renamed symbols to the normal macOS library.
MALLOC_RESOLVED_SRCS = []

# libmalloc.xcconfig's runtime closure is intentionally recorded rather than
# represented by invented Buck targets or an unresolved shared library.
# system_c, system_blocks, corecrypto and system_featureflags are upward links.
MALLOC_RUNTIME_LIBRARIES = [
    "compiler_rt",
    "dyld",
    "system_kernel",
    "system_platform",
    "system_pthread",
    "system_featureflags",
    "system_c",
    "system_blocks",
    "corecrypto",
]

# Apply only when the complete runtime closure can produce the actual dylib.
# link_whole on the object archive represents the upstream -all_load setting.
MALLOC_DYLIB_LINKER_FLAGS = [
    "-nostdlib",
    "-flto",
    "-Wl,-install_name,/usr/lib/system/libsystem_malloc.dylib",
    "-Wl,-umbrella,System",
    "-Wl,-upward-lsystem_featureflags",
    "-Wl,-upward-lsystem_c",
    "-Wl,-upward-lsystem_blocks",
    "-Wl,-upward-lcorecrypto",
    "-Wl,-interposable_list,$(location //userspace/libmalloc:interposable_list)",
]

# These are real external compile prerequisites, not allocator feature toggles.
# The DTrace provider header must come from a Darwin-compatible dtrace -h tool.
# os/feature_private.h belongs to system_featureflags, absent from this checkout.
# corecrypto/ccsha2.h (and its dependent headers/runtime) is published at
# https://github.com/apple/corecrypto, linked by https://developer.apple.com/security/.
# Its internal-use-only license does not authorize general redistribution.
