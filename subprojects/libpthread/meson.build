project('libpthread', ['c'], meson_version: '>=1.12.0')

srcroot = meson.global_source_root()
buildroot = meson.global_build_root()
gen_dir = buildroot / 'gen'
overlay_dir = srcroot / 'subprojects/packagefiles/libpthread/overlay'

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

pthread_sources = files(
    'kern/kern_init.c',
    'kern/kern_support.c',
    'kern/kern_synch.c',
)

pthread_includes = [
    '-I' + overlay_dir,
    '-I' + meson.current_source_dir(),
    '-I' + meson.current_source_dir() / 'include',
    '-I' + meson.current_source_dir() / 'private',
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

pthread_flags = [
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
    '-DABSOLUTETIME_SCALAR_TYPE',
    '-DNEEDS_SCHED_CALL_T',
    '-D__PTHREAD_EXPOSE_INTERNALS__',
    '-DPTHREAD_INTERNAL',
    '-Dpthread_kern=pthread_kext_kern',
    '-Dcurrent_uthread=pthread_kext_current_uthread',
    '-Wno-int-conversion',
    '-DXNU_PLATFORM_MacOSX',
    '-DXNU_TARGET_OS_OSX',
    '-include',
    overlay_dir / 'pthread_kext_compat.h',
    '-include',
    gen_dir / 'master_config.h',
    '-include',
    gen_dir / 'meta_features.h',
    '-std=gnu17',
]

xnu_libpthread = static_library(
    'xnu_libpthread',
    pthread_sources,
    c_args: pthread_includes + pthread_flags,
    pic: false,
    implicit_include_directories: false,
)
