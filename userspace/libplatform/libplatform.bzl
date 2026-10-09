load("//xnu:kernel.bzl", "target_triple")
# Normal macOS arm64 configuration from xcodeconfig/libplatform.xcconfig,
# atomics.xcconfig, os.xcconfig and perarch.xcconfig. The vendored tree has
# generic string implementations, not an arm64 string assembly directory.
_PLATFORM_HEADERS = {
    "setjmp.h": "include/setjmp.h",
    "timingsafe.h": "include/timingsafe.h",
    "ucontext.h": "include/ucontext.h",
    "libkern/OSAtomic.h": "include/libkern/OSAtomic.h",
    "libkern/OSAtomicDeprecated.h": "include/libkern/OSAtomicDeprecated.h",
    "libkern/OSAtomicQueue.h": "include/libkern/OSAtomicQueue.h",
    "libkern/OSCacheControl.h": "include/libkern/OSCacheControl.h",
    "libkern/OSSpinLockDeprecated.h": "include/libkern/OSSpinLockDeprecated.h",
    "libkern/OSAtomicPrivate.h": "private/libkern/OSAtomicPrivate.h",
    "os/lock.h": "include/os/lock.h",
    "os/os_sync_wait_on_address.h": "include/os/os_sync_wait_on_address.h",
    "os/security_config.h": "include/os/security_config.h",
    "os/alloc_once_impl.h": "private/os/alloc_once_impl.h",
    "os/apt_private.h": "private/os/apt_private.h",
    "os/crashlog_private.h": "private/os/crashlog_private.h",
    "os/lock_private.h": "private/os/lock_private.h",
    "os/log_simple_private.h": "private/os/log_simple_private.h",
    "os/log_simple_private_impl.h": "private/os/log_simple_private_impl.h",
    "os/once_private.h": "private/os/once_private.h",
    "os/script_config_private.h": "private/os/script_config_private.h",
    "os/security_config_private.h": "private/os/security_config_private.h",
    "os/semaphore_private.h": "private/os/semaphore_private.h",
    "platform/compat.h": "private/platform/compat.h",
    "platform/string.h": "private/platform/string.h",
    "_simple.h": "private/_simple.h",
    "os/internal.h": "internal/os/internal.h",
    "os/internal_asm.h": "internal/os/internal_asm.h",
    "os/yield.h": "internal/os/yield.h",
    "resolver.h": "src/os/resolver/resolver.h",
    "resolver_internal.h": "src/os/resolver/resolver_internal.h",
}

# PLATFORM_LIBRARIES in libplatform.xcconfig:71. Architecture slices in the
# other directories and the exclavekit configuration are deliberately absent.
# The common/generic files retain their upstream architecture guards.
_PLATFORM_SOURCES = {
    "libsimple": [
        "src/simple/asl.c",
        ("src/simple/getenv.c", ["-fno-builtin"]),
        "src/simple/log_simple.c",
        "src/simple/string_io.c",
    ],
    "libatomics": [
        "src/atomics/init.c",
        "src/atomics/common/MKGetTimeBaseInfo.c",
        "src/atomics/arm64/OSAtomic.c",
    ],
    "libcachecontrol": [
        "src/cachecontrol/generic/cache.c",
        "src/cachecontrol/arm64/cache.s",
    ],
    "libos": [
        "src/os/alloc_once.c",
        "src/os/apt_private.c",
        "src/os/atomic.c",
        "src/os/lock.c",
        "src/os/script_config.c",
        "src/os/security_config.c",
        "src/os/semaphore.c",
    ],
    "libsetjmp": [
        "src/setjmp/generic/sigaction.c",
        "src/setjmp/generic/sigtramp.c",
        "src/setjmp/generic/setjmperr.c",
        "src/setjmp/arm64/setjmp.s",
    ],
    "libstring": [
        "src/string/generic/bzero.c",
        "src/string/generic/ffsll.c",
        "src/string/generic/flsll.c",
        "src/string/generic/memccpy.c",
        "src/string/generic/memchr.c",
        "src/string/generic/memcmp.c",
        "src/string/generic/memcmp_zero.c",
        "src/string/generic/memmove.c",
        "src/string/generic/memset_pattern.c",
        "src/string/generic/strchr.c",
        "src/string/generic/strcmp.c",
        "src/string/generic/strcpy.c",
        "src/string/generic/strlcat.c",
        "src/string/generic/strlcpy.c",
        "src/string/generic/strlen.c",
        "src/string/generic/strncmp.c",
        "src/string/generic/strncpy.c",
        "src/string/generic/strnlen.c",
        "src/string/generic/strstr.c",
    ],
    "libucontext": [
        "src/ucontext/generic/getmcontext.c",
        "src/ucontext/generic/makecontext.c",
        "src/ucontext/generic/setcontext.c",
        "src/ucontext/generic/swapcontext.c",
        "src/ucontext/arm64/_ctx_start.s",
        "src/ucontext/arm64/_setcontext.s",
        "src/ucontext/arm64/getcontext.s",
        "src/ucontext/arm64/mcontext.c",
    ],
    "libtimingsafe": [
        "src/timingsafe/arm64/timingsafe.c",
    ],
}

_PLATFORM_FLAGS = [
    "-target", target_triple(),
    "-nostdlibinc",
    "-Os",
    "-fstrict-aliasing",
    "-fno-stack-protector",
    "-fdollars-in-identifiers",
    "-fno-common",
    "-momit-leaf-frame-pointer",
    # <machine/cpu_capabilities.h> is gated on PRIVATE in this tree (the SDK's is not).
    "-DPRIVATE",
    # Single modern macOS ABI, matching the generated libc-features.h.
    "-D__DARWIN_ONLY_VERS_1050=1",
    "-D__DARWIN_ONLY_UNIX_CONFORMANCE=1",
    "-D__DARWIN_ONLY_64_BIT_INO_T=1",
    "-D_FORTIFY_SOURCE=0",
    "-DCONFIG_MTE=1",
    "-DTARGET_OS_EXCLAVECORE=0",
    "-DTARGET_OS_EXCLAVEKIT=0",
    "-DOSATOMIC_USE_INLINED=0",
    "-DOSATOMIC_DEPRECATED=0",
    "-Iuserspace/libplatform/private",
    "-Iuserspace/libplatform/include",
    "-Iuserspace/libplatform/internal",
    "-Iuserspace/libplatform/src/os/resolver",
    "-Ilibsyscall/wrappers",
    "-I$(location //userspace:system_headers)",
    "-I$(location //:userspace_generated)/include",
    "-I$(location //userspace/libc:libc_features)/arm64",
    "-Iuserspace/libc/include",
    "-Ilibsyscall/mach",
    "-Ilibsyscall/wrappers/libproc",
    "-Ilibsyscall",
    "-IEXTERNAL_HEADERS",
    "-Iuserspace/dyld/include",
    "-Ilibkern",
    "-Iosfmk",
    "-Ibsd",
    "-Iuserspace/libmalloc/include",
    "-Iuserspace/libmalloc/private",
    "-Isubprojects/libpthread/include",
    "-Isubprojects/libpthread/private",
]

_PLATFORM_DEPS = [
    ":headers",
    "//userspace:system_headers",
    "//userspace/libc:libc_features",
    "//:userspace_generated",
]

_NORMAL_LOCK_FLAGS = [
    "-DOSSPINLOCK_USE_INLINED=1",
    "-DOS_UNFAIR_LOCK_INLINE=0",
]


def libplatform_libraries():
    native.cxx_library(
        name = "headers",
        exported_headers = _PLATFORM_HEADERS,
        header_namespace = "",
        default_target_platform = "//platforms:aarch64-darwin",
        visibility = ["PUBLIC"],
    )
    native.export_file(
        name = "libplatform_aliases",
        src = "xcodeconfig/libplatform.aliases",
        visibility = ["PUBLIC"],
    )
    for variant, variant_flags in {
        "": [],
        "_dyld": [
            "-DVARIANT_DYLD=1",
            "-DVARIANT_NO_RESOLVERS=1",
            "-DVARIANT_STATIC=1",
        ],
    }.items():
        for name, srcs in _PLATFORM_SOURCES.items():
            if name == "libos":
                flags = [
                    "-fvisibility=hidden",
                    "-DOSSPINLOCK_USE_INLINED=0",
                    "-DOSSPINLOCK_DEPRECATED=0",
                ]
            elif name == "libatomics":
                flags = []
            else:
                flags = _NORMAL_LOCK_FLAGS
            native.cxx_library(
                name = name + variant,
                srcs = srcs,
                # Local quoted headers are not installed interfaces.
                headers = {
                    "OSAtomicFifo.h": "src/atomics/OSAtomicFifo.h",
                    "lock_internal.h": "src/os/lock_internal.h",
                    "asm_help.h": "src/ucontext/arm64/asm_help.h",
                },
                header_namespace = "",
                deps = _PLATFORM_DEPS,
                compiler_flags = _PLATFORM_FLAGS + flags + variant_flags,
                # libsimple reaches dyld's mach-o/dyld.h, which uses these aliases.
                lang_compiler_flags = {"c": ["-include", "EXTERNAL_HEADERS/xros_availability_aliases.h"]} if name == "libsimple" else {},
                preferred_linkage = "static",
                link_style = "static_pic",
                # This is the native cxx equivalent of upstream -all_load.
                link_whole = True,
                default_target_platform = "//platforms:aarch64-darwin",
                visibility = ["PUBLIC"],
            )
    native.cxx_library(
        name = "libsystem_platform_objects",
        srcs = ["src/init.c"],
        deps = _PLATFORM_DEPS + [":" + name for name in _PLATFORM_SOURCES],
        exported_deps = [":headers"],
        compiler_flags = _PLATFORM_FLAGS + _NORMAL_LOCK_FLAGS,
        preferred_linkage = "static",
        link_style = "static_pic",
        link_whole = True,
        default_target_platform = "//platforms:aarch64-darwin",
        visibility = ["PUBLIC"],
    )
    # Upstream libplatform_dyld archives PLATFORM_LIBRARIES; its static
    # configuration does not contribute the normal shared-library initializer.
    native.cxx_library(
        name = "libsystem_platform_dyld",
        deps = [":" + name + "_dyld" for name in _PLATFORM_SOURCES],
        exported_deps = [":headers"],
        preferred_linkage = "static",
        link_style = "static_pic",
        link_whole = True,
        default_target_platform = "//platforms:aarch64-darwin",
        visibility = ["PUBLIC"],
    )
    native.cxx_library(
        name = "libsystem_platform",
        deps = [
            ":libsystem_platform_objects",
            "//:libsystem_kernel",
        ],
        exported_deps = [":headers"],
        preferred_linkage = "shared",
        link_style = "static_pic",
        soname = "libsystem_platform.dylib",
        linker_flags = ["-nostdlib"],
        post_linker_flags = [
            "-Wl,-install_name,/usr/lib/system/libsystem_platform.dylib",
            "-Wl,-umbrella,System",
            "-Wl,-alias_list,$(location :libplatform_aliases)",
            "-Wl,-simulator_support",
        ],
        # libplatform.xcconfig:104-118 intentionally omits libdyld on macOS
        # to avoid the libSystem dependency cycle. Do not substitute an umbrella
        # dependency or dynamic_lookup for missing bottom-of-stack providers.
        default_target_platform = "//platforms:aarch64-darwin",
        visibility = ["PUBLIC"],
    )
