load("@prelude//cxx:cxx_toolchain_types.bzl", "CxxToolchainInfo")
load("//userspace/libc:sources.bzl", "LIBC_INCLUDE_FLAGS")

# libc's own include environment (LIBC_INCLUDE_FLAGS), minus the entries that
# are $(location) references. Those are passed as dependencies and expanded in
# the rule, so the layout tool sees the same header set libc compiles with.
_LIBC_LITERAL_INCLUDE_FLAGS = [f for f in LIBC_INCLUDE_FLAGS if "$(location" not in f]

# Header configuration only, not a libc++.a provider. The eventual bootstrap
# libc++ archive must use this same ABI/configuration or supply matching headers.
def _libcxx_config_impl(ctx):
    values = {
        "_LIBCPP_ABI_VERSION": "1",
        "_LIBCPP_ABI_NAMESPACE": "__1",
        "_LIBCPP_ABI_FORCE_ITANIUM": "0",
        "_LIBCPP_ABI_FORCE_MICROSOFT": "0",
        "_LIBCPP_HAS_THREADS": "1",
        "_LIBCPP_HAS_MONOTONIC_CLOCK": "1",
        "_LIBCPP_HAS_MUSL_LIBC": "0",
        "_LIBCPP_HAS_THREAD_API_PTHREAD": "1",
        "_LIBCPP_HAS_THREAD_API_EXTERNAL": "0",
        "_LIBCPP_HAS_THREAD_API_WIN32": "0",
        "_LIBCPP_HAS_THREAD_API_C11": "0",
        "_LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS": "1",
        "_LIBCPP_HAS_FILESYSTEM": "1",
        "_LIBCPP_HAS_RANDOM_DEVICE": "1",
        "_LIBCPP_HAS_LOCALIZATION": "1",
        "_LIBCPP_HAS_UNICODE": "1",
        "_LIBCPP_HAS_WIDE_CHARACTERS": "1",
        "_LIBCPP_HAS_TIME_ZONE_DATABASE": "1",
        "_LIBCPP_INSTRUMENTED_WITH_ASAN": "0",
        "_LIBCPP_PSTL_BACKEND_SERIAL": "1",
        "_LIBCPP_HARDENING_MODE_DEFAULT": "2",
        "_LIBCPP_ASSERTION_SEMANTIC_DEFAULT": "_LIBCPP_ASSERTION_SEMANTIC_IGNORE",
        "_LIBCPP_LIBC_PICOLIBC": "0",
        "_LIBCPP_LIBC_NEWLIB": "0",
        "_LIBCPP_LIBC_LLVM_LIBC": "0",
        "_LIBCPP_NO_EXCEPTIONS": "1",
    }
    output = ctx.actions.write("__config_site", "\n".join(
        ["#ifndef _LIBCPP___CONFIG_SITE", "#define _LIBCPP___CONFIG_SITE"] +
        ["#define {} {}".format(key, value) for key, value in values.items()] +
        ["#endif", ""],
    ))
    return [DefaultInfo(default_output = output)]

libcxx_config_site = rule(impl = _libcxx_config_impl, attrs = {})

# The upstream script uses clang record-layout text, not source checksums or an
# invented constant. This action uses Buck's configured C++ compiler to perform
# the same syntax-only operation; it produces no runtime objects. All actual
# assembly/C/C++ object generation belongs to native cxx_library targets.
def _prebuilt_loader_version_impl(ctx):
    probe = ctx.actions.write("layout.cpp", """#include "PrebuiltLoader.h"
#include "PrebuiltObjC.h"
#include "OptimizerObjC.h"
int foo() { return sizeof(dyld4::PrebuiltLoader)+sizeof(mach_o::LinkedDylibAttributes)+sizeof(dyld4::PrebuiltLoaderSet)+sizeof(dyld4::ObjCBinaryInfo)+sizeof(dyld4::Loader::DylibPatch)+sizeof(dyld4::Loader::FileValidationInfo)+sizeof(prebuilt_objc::ObjCSelectorMapOnDisk)+sizeof(prebuilt_objc::ObjCObjectMapOnDisk)+sizeof(objc::SelectorHashTable); }
""")
    layouts = ctx.actions.declare_output("record-layouts.txt")
    compiler = ctx.attrs._cxx_toolchain[CxxToolchainInfo].cxx_compiler_info
    command = cmd_args([
        "sh", "-ec", 'out="$1"; shift; "$@" > "$out"', "layout",
        layouts.as_output(), compiler.compiler,
        "-target", "arm64-apple-macos13.0", "-std=c++20", "-nostdinc++",
        "-nostdlibinc", "-DBUILDING_DYLD=1", "-fno-exceptions", "-fno-rtti",
        "-fblocks", "-w", "-fsyntax-only", "-Xclang", "-fdump-record-layouts",
        "-D__DARWIN_UNIX03=1", "-D__DARWIN_64_BIT_INO_T=1", "-D__DARWIN_NON_CANCELABLE=1",
        "-D__DARWIN_VERS_1050=1", "-D__DARWIN_ONLY_VERS_1050=1",
        "-D__DARWIN_ONLY_UNIX_CONFORMANCE=1", "-D__DARWIN_ONLY_64_BIT_INO_T=1",
        cmd_args(ctx.attrs.libcxx_site, parent = 1, format = "-I{}"),
        cmd_args(ctx.attrs.libcxx_assertion_handler, parent = 1, format = "-I{}"),
        "-I", "subprojects/llvm-project/libcxx/include",
        cmd_args(ctx.attrs.system_headers[DefaultInfo].default_outputs, format = "-I{}"),
        cmd_args(ctx.attrs.userspace_generated[DefaultInfo].default_outputs, format = "-I{}/include"),
        "-Iuserspace/dyld/common", "-Iuserspace/dyld/dyld",
        "-Iuserspace/dyld/include", "-Iuserspace/dyld/cache_builder",
        "-Iuserspace/dyld/lsl", "-Iuserspace/dyld/mach_o",
        "-Iuserspace/dyld/include/mach-o", "-Iuserspace/libc/include",
        "-IEXTERNAL_HEADERS", "-Iuserspace/CarbonHeaders/include", "-Iuserspace/dyld/compat/include", probe,
    ] + _LIBC_LITERAL_INCLUDE_FLAGS + [
        cmd_args(ctx.attrs.libc_features[DefaultInfo].default_outputs, format = "-I{}/arm64"),
        cmd_args(ctx.attrs.availability_headers[DefaultInfo].default_outputs, format = "-I{}"),
        cmd_args(ctx.attrs.system_framework_headers[DefaultInfo].default_outputs, format = "-I{}"),
        "-include", "EXTERNAL_HEADERS/xros_availability_aliases.h",
        "-include", cmd_args(ctx.attrs.availability_headers[DefaultInfo].default_outputs, format = "{}/Availability.h"),
    ], hidden = ctx.attrs.headers)
    ctx.actions.run(command, category = "dyld_prebuilt_layout")
    output = ctx.actions.declare_output("PrebuiltLoader_version.h")
    # Preserve upstream window sizes, order, first sizeof= terminator, newline
    # spelling and md5's leading 32 bits. Missing layouts are errors, never zero.
    filters = [
        ("class dyld4::PrebuiltLoader", 100),
        ("struct dyld4::PrebuiltLoaderSet", 100),
        ("struct dyld4::ObjCBinaryInfo", 100),
        ("union mach_o::LinkedDylibAttributes", 100),
        ("struct dyld4::Loader::DylibPatch", 100),
        ("struct dyld4::Loader::FileValidationInfo", 100),
        ("class dyld3::MapView<struct prebuilt_objc::ObjCStringKeyOnDisk", 100),
        ("class dyld3::MultiMapView<struct prebuilt_objc::ObjCStringKeyOnDisk", 100),
        ("class objc::SelectorHashTable", 100),
        ("struct dyld4::PrebuiltLoader::BindTargetRef::Absolute", 6),
    ]
    script = "set -e\ninput=\"$1\"\noutput=\"$2\"\ntmp=$(mktemp -d)\ntrap 'rm -rf \"$tmp\"' EXIT\n" + "\n".join([
        "grep -A{} '{}' \"$input\" | grep -B100 -m1 sizeof= > \"$tmp/{}\"".format(window, name, index)
        for index, (name, window) in enumerate(filters)
    ]) + "\ncat " + " ".join(["\"$tmp/{}\"".format(index) for index in range(len(filters))]) + " | md5sum | awk '{print \"#define PREBUILTLOADER_VERSION 0x\" substr($0,1,8)}' > \"$output\"\n"
    # Each extraction has its own status checked; upstream grep -m1 deliberately
    # closes its pipe early, so pipefail would turn valid large dumps into errors.
    ctx.actions.run(
        cmd_args(["bash", "-ec", script, "hash", layouts, output.as_output()]),
        category = "dyld_prebuilt_hash",
    )
    return [DefaultInfo(default_output = output)]

prebuilt_loader_version = rule(
    impl = _prebuilt_loader_version_impl,
    attrs = {
        "headers": attrs.list(attrs.source()),
        "libcxx_site": attrs.source(),
        "libcxx_assertion_handler": attrs.source(),
        "system_headers": attrs.dep(),
        "userspace_generated": attrs.dep(),
        "libc_features": attrs.dep(),
        "availability_headers": attrs.dep(),
        "system_framework_headers": attrs.dep(),
        "_cxx_toolchain": attrs.toolchain_dep(default = "toolchains//:cxx"),
    },
)
