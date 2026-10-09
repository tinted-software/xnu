load("//xnu:kernel.bzl", "target_triple")
def system_libraries():
    native.genrule(
        name = "system_headers",
        srcs = glob(["libsystem/*.h"]),
        out = "system_headers",
        cmd = "mkdir -p $OUT/os && " +
              "cp libsystem/*.h $OUT/os/",
        default_target_platform = "//platforms:aarch64-darwin",
        visibility = ["PUBLIC"],
    )
    native.cxx_library(
        name = "libSystem.B.dylib",
        srcs = ["libsystem/CompatibilityHacks.c"],
        # Umbrella: Apple's libsystem_* dylibs are merged into this one image
        # (per-library static archives are kept so they can be split out later).
        deps = [
            "//:libsystem_kernel_static",
            "//:libsystem_kernel_glue",
            "//:libsystem_pthread_objects",
            "//userspace/libplatform:libsystem_platform_objects",
            "//userspace/libc:libsystem_c_objects",
            "//userspace/libc:libsystem_trace_compat",
            "//userspace/libmalloc:libsystem_malloc_objects",
            "//userspace/libclosure:libclosure_objects",
            "//userspace/dyld:libdyld_client_objects",
            "//userspace/libm:libm_objects",
        ],
        preferred_linkage = "shared",
        link_style = "static_pic",
        soname = "libSystem.B.dylib",
        compiler_flags = [
            "-target", target_triple(),
            "-nostdlibinc",
            "-DTARGET_OS_EXCLAVEKIT=0",
            "-IEXTERNAL_HEADERS",
        ],
        linker_flags = ["-nostdlib"],
        post_linker_flags = [
            "-Wl,-install_name,/usr/lib/libSystem.B.dylib",
            "-Wl,-alias_list,$(location //userspace/libplatform:libplatform_aliases)",
            "-Wl,-alias_list,$(location //userspace/libc:alias_list)",
        ],
        default_target_platform = "//platforms:aarch64-darwin",
        visibility = ["PUBLIC"],
    )
    native.prebuilt_cxx_library(
        name = "System",
        shared_lib = ":libSystem.B.dylib",
        preferred_linkage = "shared",
        visibility = ["PUBLIC"],
    )
