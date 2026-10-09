project('msdosfs', ['c'], meson_version: '>=1.12.0')

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

msdosfs_sources = files(
    'msdosfs.kextproj/msdosfs.kmodproj/msdosfs_conv.c',
    'msdosfs.kextproj/msdosfs.kmodproj/msdosfs_denode.c',
    'msdosfs.kextproj/msdosfs.kmodproj/msdosfs_fat.c',
    'msdosfs.kextproj/msdosfs.kmodproj/msdosfs_lookup.c',
    'msdosfs.kextproj/msdosfs.kmodproj/msdosfs_vfsops.c',
    'msdosfs.kextproj/msdosfs.kmodproj/msdosfs_vnops.c',
)
kmod_dir = meson.current_source_dir() / 'msdosfs.kextproj/msdosfs.kmodproj'

msdosfs_includes = [
    '-I' + kmod_dir,
    '-I' + meson.current_source_dir(),
    '-I' + srcroot,
    '-I' + buildroot,
    '-I' + gen_dir,
    '-I' + srcroot / 'osfmk',
    '-I' + gen_dir / 'export' / 'osfmk',
    '-I' + srcroot / 'bsd',
    '-I' + srcroot / 'iokit',
    '-I' + srcroot / 'libkern',
    '-I' + srcroot / 'libsa',
    '-I' + srcroot / 'pexpert',
    '-I' + srcroot / 'security',
    '-I' + gen_dir / 'export',
    '-I' + srcroot / 'EXTERNAL_HEADERS',
    '-I' + buildroot / 'syscalls',
    '-I' + buildroot / 'assym',
    '-I' + buildroot / 'mig',
    '-I' + buildroot / 'mig/ks',
    '-I' + buildroot / 'mig/mach',
    '-I' + buildroot / 'mig/ks/mach',
    '-I' + buildroot / 'iig',
]

msdosfs_flags = [
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
    '-D_KERNEL_BUILD',
    '-DKERNEL_BUILD',
    '-DMACH_KERNEL',
    '-DBSD_BUILD',
    '-DBSD_KERNEL_PRIVATE',
    '-DMSDOSFS_AUTO_UNLOAD=0',
    '-DDEBUG=0',
    '-DXNU_PLATFORM_MacOSX',
    '-DXNU_TARGET_OS_OSX',
    '-include',
    gen_dir / 'master_config.h',
    '-include',
    gen_dir / 'meta_features.h',
    '-std=gnu17',
]

xnu_msdosfs = static_library(
    'xnu_msdosfs',
    msdosfs_sources,
    c_args: msdosfs_includes + msdosfs_flags,
    pic: false,
    implicit_include_directories: false,
)
