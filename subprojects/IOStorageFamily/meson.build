project('iostorage', ['cpp'], meson_version: '>=1.12.0')

srcroot = meson.global_source_root()
buildroot = meson.global_build_root()
gen_dir = buildroot / 'gen'

target_triple = meson.get_external_property('target_triple', '')
if target_triple == ''
    target_cpu_family = host_machine.cpu_family()
    if target_cpu_family == 'aarch64'
        target_arch = 'arm64'
    elif target_cpu_family == 'x86_64'
        target_arch = 'x86_64'
    else
        target_arch = target_cpu_family
    endif
    target_triple = target_arch + '-apple-macos'
else
    target_arch = target_triple.split('-')[0]
endif

iostorage_srcs = files(
    'IOAppleLabelScheme.cpp',
    'IOApplePartitionScheme.cpp',
    'IOBlockStorageDevice.cpp',
    'IOBlockStorageDriver.cpp',
    'IOFDiskPartitionScheme.cpp',
    'IOFilterScheme.cpp',
    'IOGUIDPartitionScheme.cpp',
    'IOMedia.cpp',
    'IOMediaBSDClient.cpp',
    'IOPartitionScheme.cpp',
    'IORequest.cpp',
    'IORequestsPool.cpp',
    'IOStorage.cpp',
    'IOUserBlockStorageDevice_kext.cpp',
)

# Generate IIG for IOUserBlockStorageDevice
# Resolved to the tools/iig build of the main project (meson.override_find_program).
iig = find_program('iig')
iig_cflags = [
    '-x',
    'c++',
    '-std=gnu++2c',
    '-D__IIG=1',
    '-DDRIVERKIT_PRIVATE=1',
    '-DPRIVATE_WIFI_ONLY=1',
    '-I' + meson.current_source_dir(),
    '-I' + srcroot / 'iokit',
    '-I' + srcroot / 'osfmk',
    '-I' + srcroot / 'bsd',
    '-I' + srcroot / 'EXTERNAL_HEADERS',
    '-I' + gen_dir,
    '-I' + gen_dir / 'export',
    '-I' + buildroot / 'syscalls',
]

iig_block_dev = custom_target(
    'iig-IOUserBlockStorageDevice',
    output: ['IOUserBlockStorageDevice.iig.cpp', 'IOUserBlockStorageDevice.h'],
    input: files('BlockStorageDeviceDriverKit/IOUserBlockStorageDevice.iig'),
    command: [
        find_program('python3'),
        '-c',
        'import os,sys,subprocess,shutil; os.makedirs(sys.argv[1], exist_ok=True); subprocess.check_call([sys.argv[4], "--def", sys.argv[5], "--header", sys.argv[3], "--impl", sys.argv[2], "--framework-name", "DriverKit", "--"] + sys.argv[6:]); shutil.copy2(sys.argv[3], os.path.join(sys.argv[1], os.path.basename(sys.argv[3])))',
        gen_dir / 'export/DriverKit',
        '@OUTPUT0@',
        '@OUTPUT1@',
        iig,
        '@INPUT@',
    ] + iig_cflags,
)

# Header shims for storage
run_command(
    find_program('python3'),
    '-c',
    '''import os, shutil, glob, sys
gen_export = os.path.join(sys.argv[1], "export", "IOKit", "storage")
gen_iokit = os.path.join(sys.argv[1], "IOKit", "storage")
os.makedirs(gen_export, exist_ok=True)
os.makedirs(gen_iokit, exist_ok=True)
for h in glob.glob(os.path.join(sys.argv[2], "*.h")):
    shutil.copy(h, gen_export)
    shutil.copy(h, gen_iokit)
''',
    gen_dir,
    meson.current_source_dir(),
    check: true,
)

iostorage_includes = [
    '-I' + meson.current_source_dir(),
    '-I' + meson.current_build_dir(),
    '-I' + srcroot,
    '-I' + buildroot,
    '-I' + gen_dir,
    '-I' + gen_dir / 'export' / 'IOKit' / 'storage',
    '-I' + gen_dir / 'export' / 'DriverKit',
    '-I' + gen_dir / 'export',
    '-I' + srcroot / 'osfmk',
    '-I' + gen_dir / 'export' / 'osfmk',
    '-I' + srcroot / 'bsd',
    '-I' + srcroot / 'iokit',
    '-I' + srcroot / 'libkern',
    '-I' + srcroot / 'libsa',
    '-I' + srcroot / 'pexpert',
    '-I' + srcroot / 'security',
    '-I' + srcroot / 'EXTERNAL_HEADERS',
    '-I' + buildroot / 'syscalls',
    '-I' + buildroot / 'assym',
    '-I' + buildroot / 'mig',
    '-I' + buildroot / 'mig/ks',
    '-I' + buildroot / 'mig/mach',
    '-I' + buildroot / 'mig/ks/mach',
    '-I' + buildroot / 'iig',
]

iostorage_flags = [
    '-target',
    target_triple,
    '-ffreestanding',
    '-fno-builtin',
    '-fno-common',
    '-fno-stack-protector',
    '-fno-strict-aliasing',
    '-fno-exceptions',
    '-momit-leaf-frame-pointer',
    '-nostdlibinc',
    '-ftrivial-auto-var-init=zero',
    '-fmerge-all-constants',
    '-Os',
    '-D' + target_arch,
    '-D' + target_arch.to_upper(),
    '-D__' + target_arch.to_upper() + '__',
    '-DLP64',
    '-DPAGE_SIZE_FIXED',
    '-UARM_LARGE_MEMORY',
    '-UARM_LARGE_MEMORY_KERNONLY',
    '-DAPPLE',
    '-DKERNEL',
    '-DKERNEL_PRIVATE',
    '-DXNU_KERNEL_PRIVATE',
    '-DPRIVATE',
    '-DDRIVER_PRIVATE',
    '-DIOKIT_KERNEL_PRIVATE',
    '-DDRIVERKIT_PRIVATE=1',
    '-DIOMATCHDEBUG=1',
    '-DIOALLOCDEBUG=1',
    '-DPRIVATE_WIFI_ONLY=1',
    '-DIOASSERT=1',
    '-DXNU_PLATFORM_MacOSX',
    '-DXNU_TARGET_OS_OSX',
    '-include',
    gen_dir / 'master_config.h',
    '-include',
    gen_dir / 'meta_features.h',
]

iostorage_cxxflags = iostorage_includes + iostorage_flags + [
    '-std=gnu++2c',
    '-fno-rtti',
    '-fno-c++-static-destructors',
    '-fsized-deallocation',
    '-Wno-enum-enum-conversion',
]

xnu_iostorage = static_library(
    'xnu_iostorage',
    iostorage_srcs + [iig_block_dev[0]],
    cpp_args: iostorage_cxxflags,
    pic: false,
    implicit_include_directories: false,
)
