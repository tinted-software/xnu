# dyld-1378, Xcode 16 synchronized groups in dyld.xcodeproj/project.pbxproj.
# Explicit translation units are intentional: directory globs include unrelated
# builders, tests, alternate architectures and incompatible target configurations.
DYLD_VERSION = "1378"
DYLD_UPSTREAM_REVISION = "fd8d0c4d52320ebf64db34f3cb280310d905c5ae"

# PBXFileSystemSynchronizedBuildFileExceptionSet C18F012D2D729A11009E49DD.
MACH_O_SRCS = ["mach_o/" + name for name in [
    "Architecture.cpp", "Archive.cpp", "BindOpcodes.cpp", "ChainedFixups.cpp",
    "CompactUnwind.cpp", "DataInCode.cpp", "DwarfDebug.cpp", "Error.cpp",
    "ExportsTrie.cpp", "Fixups.cpp", "FunctionStarts.cpp", "FunctionVariants.cpp",
    "GradedArchitectures.cpp", "Image.cpp", "Instructions.cpp", "LazyLoadDylib.cpp",
    "LinkerOptimizationHints.cpp", "LoggingStub.cpp", "Misc.cpp",
    "NListSymbolTable.cpp", "ObjC.cpp", "Platform.cpp", "Policy.cpp",
    "RebaseOpcodes.cpp", "SplitSeg.cpp", "Symbol.cpp", "Universal.cpp",
    "UnsafeHeader.cpp", "Version32.cpp", "Version64.cpp",
]]

# dyld-mighty: C18F00152D72995B009E49DD (common),
# C18F006D2D72995E009E49DD (lsl), C18FFE882D729951009E49DD (dyld).
DYLD_COMMON_SRCS = ["common/" + name for name in [
    "AAREncoder.cpp", "CachePatching.cpp", "CRC32c.cpp", "Diagnostics.cpp",
    "DyldSharedCache.cpp", "FileManager.cpp", "MachOAnalyzer.cpp", "MachOFile.cpp",
    "MachOLayout.cpp", "MachOLoaded.cpp", "MetadataVisitor.cpp", "MurmurHash.cpp",
    "ObjCVisitor.cpp", "OptimizerSwift.cpp", "PerfectHash.cpp", "ProcessAtlas.cpp",
    "PropertyList.cpp", "SwiftVisitor.cpp", "TargetPolicy.cpp", "Utilities.cpp",
]]
DYLD_LSL_SRCS = [
    "lsl/Allocator.cpp",
    "lsl/ProtectedStack.s",
    "lsl/PVLEInt64.cpp",
]
DYLD_RUNTIME_SRCS = ["dyld/" + name for name in [
    "DyldAPIs.cpp", "DyldDelegates.cpp", "dyldMain.cpp", "DyldProcessConfig.cpp",
    "DyldRuntimeState.cpp", "dyldStartup.s", "ExternallyViewableState.cpp", "glue.c",
    "JustInTimeLoader.cpp", "Loader.cpp", "PrebuiltLoader.cpp", "PrebuiltObjC.cpp",
    "PrebuiltSwift.cpp", "PremappedLoader.cpp", "RemoteNotificationResponder.cpp",
    "SharedCacheRuntime.cpp", "Tracing.cpp",
]]
DYLD_INTROSPECTION_SRC = "libdyld_introspection/dyld_introspection.cpp"

# libdyld_introspection_static has a distinct configuration/source closure:
# C18F002C2D72995B009E49DD (common), C18F00752D72995E009E49DD (lsl),
# and its synchronized libdyld_introspection group. Do not link this archive
# alongside dyld-mighty's BUILDING_DYLD copies of these same translation units.
INTROSPECTION_COMMON_SRCS = ["common/" + name for name in [
    "CachePatching.cpp", "Diagnostics.cpp", "DyldSharedCache.cpp", "FileManager.cpp",
    "MachOFile.cpp", "MachOLayout.cpp", "MachOLoaded.cpp", "ProcessAtlas.cpp",
    "TargetPolicy.cpp", "Utilities.cpp",
]]
INTROSPECTION_LSL_SRCS = ["lsl/Allocator.cpp", "lsl/PVLEInt64.cpp"]

# Upstream MH_DYLINKER link contract. The //userspace/dyld:dyld target mirrors it
# with this port's archives. Differences from configure-dyld-archives.sh, which
# consumes SDKROOT/usr/local/lib/dyld/*.a: no libCrashReporterClient/corecrypto_static
# (replaced by dyld_compat and corecrypto_compat), and the dirty-data list and
# __TPRO_CONST section order are not yet applied.
DYLD_FINAL_LINK_FLAGS = [
    "-e", "__dyld_start",
    "-Wl,-exported_symbol,__dyld_start",
    "-Wl,-exported_symbol,_lldb_image_notifier",
    "-Wl,-exported_symbol,_dyld_all_image_infos",
    "-Wl,-no_inits", "-nostdlib", "-Wl,-dylinker",
    "-Wl,-dylinker_install_name,/usr/lib/dyld",
    "-Wl,-fixup_chains", "-Wl,-data_const", "-fapple-link-rtlib",
    "-Wl,-section_order,__TPRO_CONST,__data:__auth_got:__allocator",
]
# Also required: the upstream dirty-data list, real dyld-local libc++.a with
# matching __1 ABI/no-exceptions configuration and its C++ ABI allocation/guard/
# termination closure, static platform/libc/kernel/pthread providers, and any
# enabled CrashReporter/corecrypto/compression/Blocks providers. Normal shared
# libSystem/libsystem_* targets are not substitutes for these bootstrap archives.

# libdyld.dylib (dyld.xcodeproj target "libdyld.dylib", product libdyld.dylib,
# configs/libdyld.xcconfig: BUILDING_LIBDYLD, not BUILDING_DYLD). Its own
# libdyld/ group (platform-filtered members are all present on macOS), the
# libdyld_introspection/ member, and explicit membership of these common/ and
# lsl/ translation units (C18F0017, C18F006E membership exceptions).
DYLD_LIBDYLD_SRCS = ["libdyld/" + name for name in [
    "LibSystemHelpers.cpp", "ThreadLocalVariables.cpp", "dyld_process_info.cpp",
    "dyld_process_info_notify.cpp", "libdyldGlue.cpp", "utils.cpp",
    "threadLocalHelpers.s", "getsectiondata.c",
]] + ["common/" + name for name in [
    "CRC32c.cpp", "Diagnostics.cpp", "DyldSharedCache.cpp", "FileManager.cpp",
    "MachOFile.cpp", "MachOLayout.cpp", "MachOLoaded.cpp", "ProcessAtlas.cpp",
    "SafeVMPrimitives.cpp", "TargetPolicy.cpp", "Utilities.cpp",
]] + [
    "lsl/Allocator.cpp", "lsl/PVLEInt64.cpp",
    DYLD_INTROSPECTION_SRC,
]
