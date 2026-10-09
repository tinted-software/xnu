load("//xnu:codegen.bzl", "codegen_outs", "jobs_json")
load("//xnu:flags.bzl", "GEN", "c_flags", "genassym_flags")
load("//xnu:kernel.bzl", "BOARDS", "board", "kernel_config", "page_size", "target_triple")
load("//xnu:kernel_defs.bzl", "kernel_library_args")

# The source tree the code generators read: every subsystem's headers and
# config, which MIG/IIG/genassym include from.
_TREE_SRCS = glob([
    "config/MASTER*",
    "config/version.c.template",
    "osfmk/**",
    "bsd/**",
    "iokit/**",
    "libkern/**",
    "libsa/**",
    "pexpert/**",
    "security/**",
    "san/**",
    "EXTERNAL_HEADERS/**",
    "subprojects/IOStorageFamily/*.h",
    "subprojects/IOStorageFamily/*.cpp",
    "subprojects/IOStorageFamily/BlockStorageDeviceDriverKit/*",
], exclude = [
    "**/Makefile",
    "**/*.md",
])

_CODEGEN_OUTS = codegen_outs(glob(["subprojects/IOStorageFamily/*.h"]))

# ---------------------------------------------------------------------------
# Configure-time code generation: MASTER config, MIG stubs, IIG sources,
# syscall tables, version.c. See tools/buck/gen_tree.py; the job tables are in
# //xnu:codegen.bzl.
#
# `outs` declares every produced file so the whole tree materialises intact
# on a cache hit.
# ---------------------------------------------------------------------------
genrule(
    name = "xnu_codegen",
    srcs = _TREE_SRCS + [
        "tools/buck/xnu_config.py",
        "tools/buck/stamp_version.py",
        "tools/buck/run_makesyscalls.sh",
        "tools/buck/gen_tree.py",
    ],
    outs = _CODEGEN_OUTS,
    cmd = "python3 tools/buck/gen_tree.py --outdir $OUT --srcroot . " +
          "--board " + board() + " --kernel-config " + kernel_config() +
          " --page-size " + page_size() + " --triple " + target_triple() +
          " --jobs " + jobs_json() +
          " --mig $(exe //tools/migcom:mig) --iig $(exe //tools/iig:iig)",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

# `assym.h` and `assym.s`: struct offsets for assembly, from compiling
# osfmk/arm64/genassym.c with the kernel's own osfmk flags (//xnu:flags.bzl)
# so the header and the sources that include it are preprocessed identically.
# genassym only needs struct offsets, which a __ptrauth qualifier does not
# change; the system clang can't parse the 4-arg form (see toolchains/BUCK,
# _NO_AUTH_NULL_SCHEMA), so it takes the 3-arg fallback here.
genrule(
    name = "xnu_assym",
    srcs = _TREE_SRCS + ["tools/buck/extract_assym.py"],
    outs = {"all": ["assym.h", "assym.s"]},
    cmd = "set -e; clang -S -fno-integrated-as -o $TMP/genassym.s " +
          " ".join(genassym_flags()) +
          " -DXNU_PTRAUTH_NO_AUTH_NULL_SCHEMA osfmk/arm64/genassym.c; " +
          "python3 tools/buck/extract_assym.py $TMP/genassym.s $OUT/assym.h $OUT/assym.s",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

# ---------------------------------------------------------------------------
# Userspace generated headers. The Apple sources expect an SDK that already
# contains the libsyscall MIG user headers (with LIBSYSCALL_INTERFACE), the
# syscall table headers, and a handful of derived availability/feature
# headers. Xcode produced these at build time; this rule reproduces them.
# ---------------------------------------------------------------------------
# Libsyscall_static's .defs inputs from Libsyscall.xcodeproj/project.pbxproj.
# ledger.defs is not an input of that target.
_LIBSYSCALL_MIG = [
    "clock",
    "clock_priv",
    "clock_reply",
    "exc",
    "host_priv",
    "host_security",
    "mach_eventlink",
    "mach_host",
    "mach_port",
    "mach_vm",
    "mach_voucher",
    "memory_entry",
    "notify",
    "processor",
    "processor_set",
    "restartable",
    "task",
    "thread_act",
    "vm_map",
]

_LIBSYSCALL_MIG_INTERNAL = [
    "mach_port",
    "mach_vm",
    "task",
    "thread_act",
    "vm_map",
]

_USERSPACE_AVAILABILITY_HEADERS = [
    "Availability.h",
    "AvailabilityInternal.h",
    "AvailabilityInternalLegacy.h",
    "AvailabilityInternalPrivate.h",
    "AvailabilityMacros.h",
    "AvailabilityProhibitedInternal.h",
    "AvailabilityVersions.h",
    "os/availability.h",
]

_USERSPACE_GENERATED_HEADERS = (
    ["include/mach/" + s + ".h" for s in _LIBSYSCALL_MIG] +
    ["include/servers/netname.h", "include/mach/clock_reply_server.h"] +
    ["include/mach/" + s + "_internal.h" for s in _LIBSYSCALL_MIG_INTERNAL] +
    ["include/" + s for s in _USERSPACE_AVAILABILITY_HEADERS] +
    [
        "include/mach/arm64/asm.h",
        "include/libc-features.h",
        "include/pthread_workqueue.h",
        "include/sys/_posix_availability.h",
        "include/sys/_symbol_aliasing.h",
        "include/sys/syscall.h",
        "include/sys/sysproto.h",
        "include/IOKit/IOKitLib.h",
        "include/IOKit/IOCFPlugIn.h",
    ]
)

# Public/install headers use MACHINE_ARCH=armv7, exactly as mach_install_mig.sh
# requires for arm64 builds. Actual stubs have distinct arm64 build headers:
# their vm_map ABI and _kernelrpc_ entry points must not leak into the SDK view.
_USERSPACE_MIG_BUILD_HEADERS = (
    ["users/" + s + ".h" for s in _LIBSYSCALL_MIG] +
    ["users/netname.h", "users/excServer.h"]
)
_USERSPACE_GENERATED_USERS = (
    ["users/" + s + "User.c" for s in _LIBSYSCALL_MIG] +
    ["users/netnameUser.c", "users/excServer.c"]
)

# make_symbol_aliasing.sh normally obtains release lists from availability.pl
# in an installed SDK. Use the vendored availability release tokens instead,
# retaining its numeric encodings and omission of tertiary iOS releases.
_USERSPACE_SYMBOL_ALIASING_CMD = r"""perl -0777 -ne '
sub release {
    my ($platform, $major, $minor, $patch) = @_;
    return if $platform eq "IPHONE" && defined $patch;
    my $name = "__${platform}_${major}_${minor}";
    $name .= "_$patch" if $patch;
    my $value = $platform eq "MAC" && ($major < 10 || ($major == 10 && $minor < 10))
        ? $major * 100 + $minor * 10
        : $major * 10000 + $minor * 100 + ($patch || 0);
    $versions{$name} = [$platform, $value];
}
while (/__(MAC|IPHONE)_(\d+)_(\d+)(?:_(\d+))?/g) { release($1, $2, $3, $4); }
while (/MAC_OS_X_VERSION_(\d+)_(\d+)(?:_(\d+))?/g) { release("MAC", $1, $2, $3); }
END {
    print "/* Generated using bsd/sys/make_symbol_aliasing.sh release gates. */\n";
    print "#ifndef _CDEFS_H_\n#error Use <sys/cdefs.h> instead.\n#endif\n\n";
    for my $name (sort keys %versions) {
        my ($platform, $value) = @{$versions{$name}};
        my $env = $platform eq "MAC" ? "MAC_OS_X" : "IPHONE_OS";
        my $alias = "__DARWIN_ALIAS_STARTING_${platform}_${name}";
        print "#if defined(__ENVIRONMENT_${env}_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_${env}_VERSION_MIN_REQUIRED__ >= $value\n";
        print "#define $alias(x) x\n#else\n#define $alias(x)\n#endif\n\n";
    }
}
' $(location //userspace/AvailabilityVersions:headers)/AvailabilityInternal.h $(location //userspace/AvailabilityVersions:headers)/AvailabilityMacros.h $(location //userspace/AvailabilityVersions:headers)/AvailabilityVersions.h > $OUT/include/sys/_symbol_aliasing.h
"""

genrule(
    name = "userspace_generated",
    srcs = glob([
        "libsyscall/mach/**",
        "osfmk/**",
        "bsd/**",
        "EXTERNAL_HEADERS/**",
    ], exclude = ["**/Makefile"]) + [
        "libsyscall/xcodescripts/filter_mig.awk",
        "subprojects/libpthread/private/pthread/workqueue_private.h",
        # liblaunch installs this as servers/bootstrap.h; libc's daemon.c and
        # utmpx-darwin.c include it by that path.
        "//userspace:liblaunch_bootstrap",
        "//userspace/IOKitUser:IOKitLibHeader",
        "//userspace/IOKitUser:IOCFPlugInHeader",
        "//userspace/libc:libc_features",
        "//userspace/AvailabilityVersions:headers",
        ":xnu_codegen",
    ],
    outs = {
        "all": _USERSPACE_GENERATED_HEADERS + _USERSPACE_MIG_BUILD_HEADERS + _USERSPACE_GENERATED_USERS,
        "headers": _USERSPACE_GENERATED_HEADERS,
        "build_headers": _USERSPACE_MIG_BUILD_HEADERS,
        "users": _USERSPACE_GENERATED_USERS,
    },
    cmd = "set -e\n" +
          "mkdir -p $OUT/include/mach/arm64 $OUT/include/servers $OUT/include/sys $OUT/include/os $OUT/include/IOKit $OUT/users\n" +
          "cp $(location //userspace:liblaunch_bootstrap) $OUT/include/servers/bootstrap.h\n" +
          "for h in " + " ".join(_USERSPACE_AVAILABILITY_HEADERS) + "; do cp $(location //userspace/AvailabilityVersions:headers)/$h $OUT/include/$h; done\n" +
          "MIG=$(exe //tools/migcom:mig)\n" +
          "BASE=\"-novouchers -I$OUT/include -IEXTERNAL_HEADERS -Iosfmk -Ibsd -Ilibsyscall/mach\"\n" +
          "for s in " + " ".join(_LIBSYSCALL_MIG) + "; do\n" +
          "  $MIG $BASE -target armv7-apple-ios -DLIBSYSCALL_INTERFACE -user /dev/null -header $OUT/include/mach/${s}.h -server /dev/null -sheader /dev/null libsyscall/mach/${s}.defs\n" +
          "  awk -f libsyscall/xcodescripts/filter_mig.awk libsyscall/mach/add_attributes_to_mig.txt $OUT/include/mach/${s}.h > $OUT/include/mach/${s}.tmp.h\n" +
          "  mv $OUT/include/mach/${s}.tmp.h $OUT/include/mach/${s}.h\n" +
          "  server=/dev/null; sheader=/dev/null\n" +
          "  if [ \"$s\" = exc ]; then server=$OUT/users/excServer.c; sheader=$OUT/users/excServer.h; fi\n" +
          "  if [ \"$s\" = clock_reply ]; then sheader=$OUT/include/mach/clock_reply_server.h; fi\n" +
          "  $MIG $BASE -target arm64-apple-macos27.0.0 -user $OUT/users/${s}User.c -header $OUT/users/${s}.h -server $server -sheader $sheader libsyscall/mach/${s}.defs\n" +
          "done\n" +
          "$MIG $BASE -target armv7-apple-ios -user /dev/null -header $OUT/include/servers/netname.h -server /dev/null -sheader /dev/null libsyscall/mach/servers/netname.defs\n" +
          "$MIG $BASE -target arm64-apple-macos27.0.0 -user $OUT/users/netnameUser.c -header $OUT/users/netname.h -server /dev/null -sheader /dev/null libsyscall/mach/servers/netname.defs\n" +
          "for s in " + " ".join(_LIBSYSCALL_MIG_INTERNAL) + "; do\n" +
          "  $MIG $BASE -target armv7-apple-ios -user /dev/null -header $OUT/include/mach/${s}_internal.h -server /dev/null -sheader /dev/null libsyscall/mach/${s}.defs\n" +
          "done\n" +
          "cp osfmk/arm64/asm.h $OUT/include/mach/arm64/asm.h\n" +
          "cp $(location //userspace/libc:libc_features)/arm64/libc-features.h $OUT/include/libc-features.h\n" +
          # Upstream installs pthread/workqueue_private.h as pthread_workqueue.h.
          "cp subprojects/libpthread/private/pthread/workqueue_private.h $OUT/include/pthread_workqueue.h\n" +
          "cp $(location :xnu_codegen)/gen/sys/syscall.h $OUT/include/sys/syscall.h\n" +
          "cp $(location :xnu_codegen)/gen/sys/sysproto.h $OUT/include/sys/sysproto.h\n" +
          "cp $(location //userspace/IOKitUser:IOKitLibHeader) $OUT/include/IOKit/IOKitLib.h\n" +
          "cp $(location //userspace/IOKitUser:IOCFPlugInHeader) $OUT/include/IOKit/IOCFPlugIn.h\n" +
          _USERSPACE_SYMBOL_ALIASING_CMD +
          "mkdir -p $OUT/include/skywalk\n" +
          "cp bsd/skywalk/*.h $OUT/include/skywalk/ 2>/dev/null || true\n" +
          "for d in core channel packet nexus mem lib namespace; do cp bsd/skywalk/$d/*.h $OUT/include/skywalk/ 2>/dev/null || true; done\n" +
          "sh bsd/sys/make_posix_availability.sh $OUT/include/sys/_posix_availability.h\n",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

# XNU installs its bsd/sys and osfmk/machine headers into
# System.framework/PrivateHeaders, which is the layout <System/sys/fsctl.h>
# (libc/gen/sync_volume_np.c), <System/sys/csr.h> and
# <System/machine/cpu_capabilities.h> (libc/libdarwin/variant.c) resolve
# through. libsystem's create_system_framework.sh only links the dylib and the
# Versions skeleton; the header tree comes from these projects.
genrule(
    name = "system_framework_headers",
    srcs = glob(["bsd/sys/**"], exclude = ["**/Makefile"]) + glob(["osfmk/machine/**"]) + ["osfmk/mach/dyld_pager.h", "libsyscall/os/thread_self_restrict.h", "//userspace/libc:atexit_header"],
    out = "system_framework_headers",
    cmd = "set -e\nmkdir -p $OUT/System\n" +
          "cp -RL bsd/sys $OUT/System/sys\n" +
          "cp -RL osfmk/machine $OUT/System/machine\n" +
          "mkdir -p $OUT/System/mach\n" +
          "cp osfmk/mach/dyld_pager.h $OUT/System/mach/dyld_pager.h\n" +
          # libc installs its internal atexit.h as System/atexit.h.
          "cp $(location //userspace/libc:atexit_header) $OUT/System/atexit.h\n" +
          # <os/thread_self_restrict.h>: the port TPRO/rwx stand-in (libsyscall/os).
          "mkdir -p $OUT/os\n" +
          "cp libsyscall/os/thread_self_restrict.h $OUT/os/thread_self_restrict.h\n",
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# ---------------------------------------------------------------------------
# Generation only: create-syscalls.pl's stubs.list for ARCHS=arm64, MacOSX.
# Keep this manifest synchronized with syscalls.master/custom/platform maps.
# Buck, not the generator, compiles every declared .s and archives the result.
# ---------------------------------------------------------------------------
_LIBSYSCALL_SYSCALL_SOURCES = [
    "_____sigwait_nocancel.s", "___abort_with_payload.s", "___accept.s", "___accept_nocancel.s",
    "___access_extended.s", "___aio_suspend_nocancel.s", "___bind.s", "___bsdthread_create.s",
    "___bsdthread_ctl.s", "___bsdthread_register.s", "___bsdthread_terminate.s", "___channel_get_info.s",
    "___channel_get_opt.s", "___channel_open.s", "___channel_set_opt.s", "___channel_sync.s",
    "___chmod.s", "___chmod_extended.s", "___close_nocancel.s", "___coalition.s",
    "___coalition_info.s", "___coalition_ledger.s", "___connect.s", "___connect_nocancel.s",
    "___copyfile.s", "___crossarch_trap.s", "___csrctl.s", "___debug_syscall_reject.s",
    "___debug_syscall_reject_config.s", "___delete.s", "___disable_threadsignal.s", "___execve.s",
    "___exit.s", "___fchmod.s", "___fchmod_extended.s", "___fcntl.s",
    "___fcntl_nocancel.s", "___fork.s", "___fs_snapshot.s", "___fstat64_extended.s",
    "___fstat_extended.s", "___fsync_nocancel.s", "___getattrlist.s", "___getdirentries64.s",
    "___gethostuuid.s", "___getlogin.s", "___getpeername.s", "___getpid.s",
    "___getrlimit.s", "___getsgroups.s", "___getsockname.s", "___gettid.s",
    "___gettimeofday.s", "___getwgroups.s", "___guarded_open_dprotected_np.s", "___guarded_open_np.s",
    "___identitysvc.s", "___initgroups.s", "___ioctl.s", "___iopolicysys.s",
    "___kdebug_trace.s", "___kdebug_trace64.s", "___kdebug_trace_string.s", "___kdebug_typefilter.s",
    "___kill.s", "___kqueue_workloop_ctl.s", "___lchown.s", "___listen.s",
    "___log_data.s", "___lseek.s", "___lstat64_extended.s", "___lstat_extended.s",
    "___mac_execve.s", "___mac_get_fd.s", "___mac_get_file.s", "___mac_get_link.s",
    "___mac_get_mount.s", "___mac_get_pid.s", "___mac_get_proc.s", "___mac_getfsstat.s",
    "___mac_mount.s", "___mac_set_fd.s", "___mac_set_file.s", "___mac_set_link.s",
    "___mac_set_proc.s", "___mac_syscall.s", "___mach_bridge_remote_time.s", "___mach_eventlink_signal.s",
    "___mach_eventlink_signal_wait_until.s", "___mach_eventlink_wait_until.s", "___map_with_linking_np.s", "___memorystatus_available_memory.s",
    "___microstackshot.s", "___mkdir_extended.s", "___mkfifo_extended.s", "___mmap.s",
    "___mprotect.s", "___msgctl.s", "___msgrcv_nocancel.s", "___msgsnd_nocancel.s",
    "___msgsys.s", "___msync.s", "___msync_nocancel.s", "___munmap.s",
    "___nexus_create.s", "___nexus_deregister.s", "___nexus_destroy.s", "___nexus_get_opt.s",
    "___nexus_open.s", "___nexus_register.s", "___nexus_set_opt.s", "___open.s",
    "___open_dprotected_np.s", "___open_extended.s", "___open_nocancel.s", "___openat.s",
    "___openat_dprotected_np.s", "___openat_nocancel.s", "___oslog_coproc.s", "___oslog_coproc_reg.s",
    "___persona.s", "___pipe.s", "___poll_nocancel.s", "___posix_spawn.s",
    "___pread_nocancel.s", "___preadv_nocancel.s", "___proc_info.s", "___proc_info_extended_id.s",
    "___process_policy.s", "___pselect.s", "___pselect_nocancel.s", "___psynch_cvbroad.s",
    "___psynch_cvclrprepost.s", "___psynch_cvsignal.s", "___psynch_cvwait.s", "___psynch_mutexdrop.s",
    "___psynch_mutexwait.s", "___psynch_rw_downgrade.s", "___psynch_rw_longrdlock.s", "___psynch_rw_rdlock.s",
    "___psynch_rw_unlock.s", "___psynch_rw_unlock2.s", "___psynch_rw_upgrade.s", "___psynch_rw_wrlock.s",
    "___psynch_rw_yieldwrlock.s", "___pthread_canceled.s", "___pthread_chdir.s", "___pthread_fchdir.s",
    "___pthread_kill.s", "___pthread_markcancel.s", "___pthread_sigmask.s", "___ptrace.s",
    "___pwrite_nocancel.s", "___pwritev_nocancel.s", "___read_nocancel.s", "___readv_nocancel.s",
    "___reboot.s", "___record_system_event.s", "___recvfrom.s", "___recvfrom_nocancel.s",
    "___recvmsg.s", "___recvmsg_nocancel.s", "___rename.s", "___renameat.s",
    "___renameatx_np.s", "___rmdir.s", "___select.s", "___select_nocancel.s",
    "___sem_open.s", "___sem_wait_nocancel.s", "___semctl.s", "___semsys.s",
    "___semwait_signal.s", "___semwait_signal_nocancel.s", "___sendmsg.s", "___sendmsg_nocancel.s",
    "___sendto.s", "___sendto_nocancel.s", "___setattrlist.s", "___setlogin.s",
    "___setpriority.s", "___setregid.s", "___setreuid.s", "___setrlimit.s",
    "___setsgroups.s", "___settid.s", "___settid_with_pid.s", "___settimeofday.s",
    "___setwgroups.s", "___sfi_ctl.s", "___sfi_pidctl.s", "___shared_region_check_np.s",
    "___shared_region_map_and_slide_2_np.s", "___shm_open.s", "___shmctl.s", "___shmsys.s",
    "___sigaction.s", "___sigaltstack.s", "___sigreturn.s", "___sigsuspend.s",
    "___sigsuspend_nocancel.s", "___sigwait.s", "___socketpair.s", "___stack_snapshot_with_config.s",
    "___stat64_extended.s", "___stat_extended.s", "___syscall.s", "___sysctl.s",
    "___sysctlbyname.s", "___telemetry.s", "___terminate_with_payload.s", "___thread_selfid.s",
    "___thread_selfusage.s", "___ulock_wait.s", "___ulock_wait2.s", "___ulock_wake.s",
    "___umask_extended.s", "___unlink.s", "___unlinkat.s", "___vfork.s",
    "___wait4.s", "___wait4_nocancel.s", "___waitid_nocancel.s", "___work_interval_ctl.s",
    "___workq_kernreturn.s", "___workq_open.s", "___write_nocancel.s", "___writev_nocancel.s",
    "_access.s", "_acct.s", "_adjtime.s", "_aio_cancel.s",
    "_aio_error.s", "_aio_fsync.s", "_aio_read.s", "_aio_return.s",
    "_aio_suspend.s", "_aio_write.s", "_audit.s", "_audit_session_join.s",
    "_audit_session_port.s", "_audit_session_self.s", "_auditctl.s", "_auditon.s",
    "_change_fdguard_np.s", "_chdir.s", "_chflags.s", "_chown.s",
    "_chroot.s", "_clonefileat.s", "_close.s", "_coalition_policy_get.s",
    "_coalition_policy_set.s", "_connectx.s", "_csops.s", "_csops_audittoken.s",
    "_disconnectx.s", "_dup.s", "_dup2.s", "_exchangedata.s",
    "_faccessat.s", "_fchdir.s", "_fchflags.s", "_fchmodat.s",
    "_fchown.s", "_fchownat.s", "_fclonefileat.s", "_fdatasync.s",
    "_ffsctl.s", "_fgetattrlist.s", "_fgetxattr.s", "_fhopen.s",
    "_fileport_makefd.s", "_fileport_makeport.s", "_flistxattr.s", "_flock.s",
    "_fmount.s", "_fpathconf.s", "_freadlink.s", "_fremovexattr.s",
    "_fsctl.s", "_fsetattrlist.s", "_fsetxattr.s", "_fsgetpath.s",
    "_fsgetpath_ext.s", "_fstat.s", "_fstat64.s", "_fstatat.s",
    "_fstatat64.s", "_fstatfs.s", "_fstatfs64.s", "_fsync.s",
    "_ftruncate.s", "_funmount.s", "_futimes.s", "_getattrlistat.s",
    "_getattrlistbulk.s", "_getaudit_addr.s", "_getauid.s", "_getdirentries.s",
    "_getdirentriesattr.s", "_getdtablesize.s", "_getegid.s", "_getentropy.s",
    "_geteuid.s", "_getfh.s", "_getfsstat.s", "_getfsstat64.s",
    "_getgid.s", "_getgroups.s", "_getitimer.s", "_getpgid.s",
    "_getpgrp.s", "_getppid.s", "_getpriority.s", "_getrusage.s",
    "_getsid.s", "_getsockopt.s", "_getuid.s", "_getxattr.s",
    "_grab_pgo_data.s", "_graftdmg.s", "_guarded_close_np.s", "_guarded_kqueue_np.s",
    "_guarded_pwrite_np.s", "_guarded_write_np.s", "_guarded_writev_np.s", "_issetugid.s",
    "_kas_info.s", "_kevent.s", "_kevent64.s", "_kevent_id.s",
    "_kevent_qos.s", "_kqueue.s", "_ledger.s", "_link.s",
    "_linkat.s", "_lio_listio.s", "_listxattr.s", "_lstat.s",
    "_lstat64.s", "_madvise.s", "_memorystatus_control.s", "_memorystatus_get_level.s",
    "_mincore.s", "_minherit.s", "_mkdir.s", "_mkdirat.s",
    "_mkfifo.s", "_mkfifoat.s", "_mknod.s", "_mknodat.s",
    "_mlock.s", "_mlockall.s", "_mount.s", "_mremap_encrypted.s",
    "_msgget.s", "_msgrcv.s", "_msgsnd.s", "_munlock.s",
    "_munlockall.s", "_necp_client_action.s", "_necp_match_policy.s", "_necp_open.s",
    "_necp_session_action.s", "_necp_session_open.s", "_net_qos_guideline.s", "_netagent_trigger.s",
    "_nfssvc.s", "_ntp_adjtime.s", "_ntp_gettime.s", "_objc_bp_assist_cfg_np.s",
    "_openbyid_np.s", "_os_fault_with_payload.s", "_panic_with_data.s", "_pathconf.s",
    "_peeloff.s", "_pid_hibernate.s", "_pid_resume.s", "_pid_shutdown_sockets.s",
    "_pid_suspend.s", "_pivot_root.s", "_poll.s", "_pread.s",
    "_preadv.s", "_proc_rlimit_control.s", "_proc_trace_log.s", "_proc_uuid_policy.s",
    "_pwrite.s", "_pwritev.s", "_quotactl.s", "_read.s",
    "_readlink.s", "_readlinkat.s", "_readv.s", "_recvmsg_x.s",
    "_removexattr.s", "_revoke.s", "_searchfs.s", "_sem_close.s",
    "_sem_post.s", "_sem_trywait.s", "_sem_unlink.s", "_sem_wait.s",
    "_semget.s", "_semop.s", "_sendfile.s", "_sendmsg_x.s",
    "_setattrlistat.s", "_setaudit_addr.s", "_setauid.s", "_setegid.s",
    "_seteuid.s", "_setgid.s", "_setgroups.s", "_setitimer.s",
    "_setpgid.s", "_setprivexec.s", "_setsid.s", "_setsockopt.s",
    "_setuid.s", "_setxattr.s", "_shm_unlink.s", "_shmat.s",
    "_shmdt.s", "_shmget.s", "_shutdown.s", "_sigpending.s",
    "_sigprocmask.s", "_socket.s", "_socket_delegate.s", "_stat.s",
    "_stat64.s", "_statfs.s", "_statfs64.s", "_swapon.s",
    "_symlink.s", "_symlinkat.s", "_sync.s", "_system_override.s",
    "_task_inspect_for_pid.s", "_task_read_for_pid.s", "_thread_selfcounts.s", "_tracker_action.s",
    "_truncate.s", "_umask.s", "_undelete.s", "_ungraftdmg.s",
    "_unmount.s", "_usrctl.s", "_utimes.s", "_vfs_purge.s",
    "_vm_pressure_monitor.s", "_waitid.s", "_write.s", "_writev.s",
    "custom.s",
]

genrule(
    name = "libsyscall_syscalls",
    srcs = glob([
        "libsyscall/custom/**",
        "libsyscall/Platforms/**",
    ], exclude = ["**/Makefile"]) + [
        "bsd/kern/syscalls.master",
        "libsyscall/xcodescripts/create-syscalls.pl",
    ],
    outs = {
        "all": _LIBSYSCALL_SYSCALL_SOURCES + ["SYS.h", "stubs.list"],
        "sources": _LIBSYSCALL_SYSCALL_SOURCES,
        "headers": ["SYS.h"],
    },
    cmd = "set -e\n" +
          "mkdir -p $OUT\n" +
          "ARCHS=arm64 perl libsyscall/xcodescripts/create-syscalls.pl bsd/kern/syscalls.master libsyscall/custom libsyscall/Platforms MacOSX $OUT\n",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

cxx_library(
    name = "libsyscalls",
    srcs = [":libsyscall_syscalls[sources]"],
    deps = [":libsyscall_syscalls", ":userspace_generated"],
    preferred_linkage = "static",
    link_style = "static_pic",
    link_whole = True,
    compiler_flags = [
        "-target", target_triple(),
        "-nostdlibinc",
        "-DPRIVATE",
        "-DNO_SYSCALL_LEGACY",
        "-I$(location :libsyscall_syscalls)",
        "-I$(location :userspace_generated)/include",
        "-IEXTERNAL_HEADERS",
        "-Iosfmk",
        "-Ibsd",
    ],
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# ---------------------------------------------------------------------------
# Kernel libraries. All compiled for //platforms:aarch64-darwin (freestanding).
# Source lists come from xnu/sources.bzl, generated off the meson.build lists.
# ---------------------------------------------------------------------------
cxx_library(**kernel_library_args(
    name = "xnu_osfmk",
    subsys = "osfmk",
    srcs_var = "osfmk_c_sources",
    codegen_groups = ["mig_c", "osfmk_gen"],
    # meson adds these to `osfmk_cflags` only; this target alone is affected.
    extra_cflags = [
        "-Wno-implicit-function-declaration",
        "-Wno-int-conversion",
    ],
))

cxx_library(**kernel_library_args(
    name = "xnu_osfmk_vm",
    subsys = "osfmk",
    srcs_var = "osfmk_vm_sources",
    extra_cflags = ["-DVM_UNSAFE_TYPES"],
))

cxx_library(**kernel_library_args(
    name = "xnu_osfmk_asm",
    subsys = "osfmk",
    srcs_var = "osfmk_s_sources",
    asm = True,
))

cxx_library(**kernel_library_args(
    name = "xnu_bsd",
    subsys = "bsd",
    srcs_var = "bsd_c_sources",
    extra_srcs_vars = ["bsd_cpp_sources", "bsd_cross_srcs"],
    codegen_groups = ["bsd_gen"],
))

cxx_library(**kernel_library_args(
    name = "xnu_bsd_vm",
    subsys = "bsd",
    srcs_var = "bsd_vm_sources",
    extra_cflags = ["-DVM_UNSAFE_TYPES"],
))

cxx_library(**kernel_library_args(
    name = "xnu_bsd_mman",
    subsys = "bsd",
    srcs_var = "bsd_mman_sources",
    extra_cflags = ["-DVM_UNSAFE_TYPES"],
))

cxx_library(**kernel_library_args(
    name = "xnu_bsd_asm",
    subsys = "bsd",
    srcs_var = "bsd_s_sources",
    asm = True,
))

cxx_library(**kernel_library_args(
    name = "xnu_libkern",
    subsys = "libkern",
    srcs_var = "libkern_c_sources",
    extra_srcs_vars = ["libkern_cpp_sources"],
))

cxx_library(**kernel_library_args(
    name = "xnu_iokit",
    subsys = "iokit",
    srcs_var = "iokit_c_sources",
    extra_srcs_vars = ["iokit_cpp_sources"],
))

cxx_library(**kernel_library_args(
    name = "xnu_iokit_driverkit",
    subsys = "iokit",
    codegen_groups = ["iig_driverkit_cpp"],
    extra_cflags = [
        "-DDRIVER_PRIVATE",
        "-DIOKIT_KERNEL_PRIVATE",
        "-DDRIVERKIT_PRIVATE=1",
    ],
))

cxx_library(**kernel_library_args(
    name = "xnu_libsa",
    subsys = "libsa",
    srcs_var = "libsa_cpp_sources",
))

cxx_library(**kernel_library_args(
    name = "xnu_pexpert",
    subsys = "pexpert",
    srcs_var = "pexpert_c_sources",
    extra_srcs = ["pexpert/" + BOARDS[board()]["icu"]],
))

cxx_library(**kernel_library_args(
    name = "xnu_security",
    subsys = "security",
    srcs_var = "security_c_sources",
))

cxx_library(**kernel_library_args(
    name = "xnu_san",
    subsys = "san",
))

cxx_library(**kernel_library_args(
    name = "xnu_lastkernelconstructor",
    subsys = "libsa",
    extra_srcs = ["libsa/lastkernelconstructor.c"],
))

# ---------------------------------------------------------------------------
# Kernel Subprojects (subprojects/*)
# ---------------------------------------------------------------------------
load("//xnu:subproject_defs.bzl", "subproject_library_args")

cxx_library(**subproject_library_args(
    name = "xnu_iostorage",
    subproject = "iostorage",
    lang = "cpp",
    extra_srcs = [":xnu_codegen[iig_iostorage_cpp]"],
    extra_includes = [
        "-Isubprojects/IOStorageFamily",
        "-I$(location :xnu_codegen)/gen/export/IOKit/storage",
        "-I$(location :xnu_codegen)/gen/export/DriverKit",
    ],
    extra_defines = [
        "-DDRIVER_PRIVATE",
        "-DIOKIT_KERNEL_PRIVATE",
        "-DDRIVERKIT_PRIVATE=1",
        "-DIOMATCHDEBUG=1",
        "-DIOALLOCDEBUG=1",
        "-DPRIVATE_WIFI_ONLY=1",
        "-DIOASSERT=1",
    ],
))

cxx_library(**subproject_library_args(
    name = "xnu_msdosfs",
    subproject = "msdosfs",
    lang = "c",
    extra_includes = [
        "-Isubprojects/msdosfs/msdosfs.kextproj/msdosfs.kmodproj",
        "-Isubprojects/msdosfs",
    ],
    extra_defines = [
        "-DDRIVER_PRIVATE",
        "-D_KERNEL_BUILD",
        "-DKERNEL_BUILD",
        "-DMACH_KERNEL",
        "-DBSD_BUILD",
        "-DBSD_KERNEL_PRIVATE",
        "-DABSOLUTETIME_SCALAR_TYPE",
        "-DNEEDS_SCHED_CALL_T",
        "-D__PTHREAD_EXPOSE_INTERNALS__",
        "-DPTHREAD_INTERNAL",
        "-Dpthread_kern=pthread_kext_kern",
        "-Dcurrent_uthread=pthread_kext_current_uthread",
        "-Wno-int-conversion",
        "-include", "subprojects/libpthread/overlay/pthread_kext_compat.h",
        "-DMSDOSFS_AUTO_UNLOAD=0",
        "-DDEBUG=0",
        "-Wno-implicit-function-declaration",
    ],
))

cxx_library(**subproject_library_args(
    name = "xnu_libpthread",
    subproject = "libpthread",
    lang = "c",
    extra_includes = [
        "-Isubprojects/libpthread/overlay",
        "-Isubprojects/libpthread",
        "-Isubprojects/libpthread/include",
        "-Isubprojects/libpthread/private",
    ],
    extra_defines = [
        "-D_PTHREAD_BUILD",
        "-D_PTHREAD_KERNEL",
        "-DDRIVER_PRIVATE",
        "-D_KERNEL_BUILD",
        "-DKERNEL_BUILD",
        "-DMACH_KERNEL",
        "-DBSD_BUILD",
        "-DBSD_KERNEL_PRIVATE",
        "-DABSOLUTETIME_SCALAR_TYPE",
        "-DNEEDS_SCHED_CALL_T",
        "-D__PTHREAD_EXPOSE_INTERNALS__",
        "-DPTHREAD_INTERNAL",
        "-Dpthread_kern=pthread_kext_kern",
        "-Dcurrent_uthread=pthread_kext_current_uthread",
        "-Wno-int-conversion",
        "-include", "subprojects/libpthread/overlay/pthread_kext_compat.h",
    ],
))

cxx_library(**subproject_library_args(
    name = "xnu_compiler_rt",
    subproject = "compiler_rt",
    lang = "c",
    extra_includes = [
        "-Isubprojects/llvm-project/compiler-rt/lib/profile",
        "-Isubprojects/llvm-project/compiler-rt/include",
        "-Ilibkern",
    ],
    extra_defines = [
        "-DCOMPILER_RT_PROFILE_BAREMETAL=1",
        "-DCOMPILER_RT_HAS_ATOMICS=1",
        "-Wno-error",
    ],
))

cxx_library(**subproject_library_args(
    name = "xnu_libdispatch",
    subproject = "libdispatch",
    lang = "c",
    extra_includes = [
        "-Isubprojects/libdispatch/src/firehose",
        "-Ilibkern/firehose",
    ],
    extra_defines = [
        "-DKERNEL=1",
        "-Wno-visibility",
    ],
))

# Libsyscall_static and Libsyscall_dynamic Sources phases, resolved through
# their PBXGroups. Architecture/platform guards in these upstream files select
# the arm64 implementation; helper/base files absent from the phases stay out.
_KERNEL_SRCS = [
        "libsyscall/custom/errno.c",
        "libsyscall/mach/clock_sleep.c",
        "libsyscall/mach/error_codes.c",
        "libsyscall/mach/exc_catcher.c",
        "libsyscall/mach/exc_catcher_state.c",
        "libsyscall/mach/exc_catcher_state_identity.c",
        "libsyscall/mach/fprintf_stderr.c",
        "libsyscall/mach/host.c",
        "libsyscall/mach/mach_error.c",
        "libsyscall/mach/mach_error_string.c",
        "libsyscall/mach/mach_eventlink.c",
        "libsyscall/mach/mach_init.c",
        "libsyscall/mach/mach_legacy.c",
        "libsyscall/mach/mach_msg.c",
        "libsyscall/mach/mach_port.c",
        "libsyscall/mach/mach_right.c",
        "libsyscall/mach/mach_traps.s",
        "libsyscall/mach/mach_vm.c",
        "libsyscall/mach/mig_allocate.c",
        "libsyscall/mach/mig_deallocate.c",
        "libsyscall/mach/mig_reply_port.c",
        "libsyscall/mach/mig_reply_setup.c",
        "libsyscall/mach/mig_strncpy.c",
        "libsyscall/mach/ms_thread_switch.c",
        "libsyscall/mach/panic.c",
        "libsyscall/mach/port_descriptions.c",
        "libsyscall/mach/port_obj.c",
        "libsyscall/mach/semaphore.c",
        "libsyscall/mach/slot_name.c",
        "libsyscall/mach/string.c",
        "libsyscall/mach/task.c",
        "libsyscall/mach/thread_act.c",
        "libsyscall/mach/vm_reclaim.c",
        "libsyscall/os/alloc_once.c",
        "libsyscall/os/log_data.c",
        "libsyscall/os/os_log_coprocessor.c",
        "libsyscall/os/x18.c",
        "libsyscall/wrappers/__commpage_gettimeofday.c",
        "libsyscall/wrappers/__get_cpu_capabilities.s",
        # OSS clang uses ordinary callbacks here, without Apple's typed-memory
        # lowering; prevent builtin folding of these callback implementations.
        ("libsyscall/wrappers/_libc_funcptr.c", ["-fno-builtin"]),
        "libsyscall/wrappers/_libc_weak_funcptr.c",
        "libsyscall/wrappers/_libkernel_init.c",
        "libsyscall/wrappers/cancelable/fcntl-cancel.c",
        "libsyscall/wrappers/cancelable/fcntl.c",
        "libsyscall/wrappers/cancelable/open.c",
        "libsyscall/wrappers/cancelable/pselect-darwinext-cancel.c",
        "libsyscall/wrappers/cancelable/pselect-darwinext.c",
        "libsyscall/wrappers/cancelable/select-cancel.c",
        "libsyscall/wrappers/cancelable/select.c",
        "libsyscall/wrappers/cancelable/sigsuspend-cancel.c",
        "libsyscall/wrappers/cancelable/sigsuspend.c",
        "libsyscall/wrappers/carbon_delete.c",
        "libsyscall/wrappers/clonefile.c",
        "libsyscall/wrappers/coalition.c",
        "libsyscall/wrappers/csr.c",
        "libsyscall/wrappers/event_wrappers.c",
        "libsyscall/wrappers/exclaves.c",
        "libsyscall/wrappers/fs_snapshot.c",
        "libsyscall/wrappers/gethostuuid.c",
        "libsyscall/wrappers/getiopolicy_np.c",
        "libsyscall/wrappers/guarded_open_dprotected_np.c",
        "libsyscall/wrappers/guarded_open_np.c",
        "libsyscall/wrappers/init_cpu_capabilities.c",
        "libsyscall/wrappers/ioctl.c",
        "libsyscall/wrappers/kdebug_trace.c",
        "libsyscall/wrappers/kern_debug.c",
        "libsyscall/wrappers/kill.c",
        "libsyscall/wrappers/legacy/accept.c",
        "libsyscall/wrappers/legacy/bind.c",
        "libsyscall/wrappers/legacy/connect.c",
        "libsyscall/wrappers/legacy/getattrlist.c",
        "libsyscall/wrappers/legacy/getaudit.c",
        "libsyscall/wrappers/legacy/getpeername.c",
        "libsyscall/wrappers/legacy/getsockname.c",
        "libsyscall/wrappers/legacy/kill.c",
        "libsyscall/wrappers/legacy/lchown.c",
        "libsyscall/wrappers/legacy/listen.c",
        "libsyscall/wrappers/legacy/mprotect.c",
        "libsyscall/wrappers/legacy/msync.c",
        "libsyscall/wrappers/legacy/munmap.c",
        "libsyscall/wrappers/legacy/recvfrom.c",
        "libsyscall/wrappers/legacy/recvmsg.c",
        "libsyscall/wrappers/legacy/select-pre1050.c",
        "libsyscall/wrappers/legacy/select.c",
        "libsyscall/wrappers/legacy/sendmsg.c",
        "libsyscall/wrappers/legacy/sendto.c",
        "libsyscall/wrappers/legacy/setattrlist.c",
        "libsyscall/wrappers/legacy/sigsuspend.c",
        "libsyscall/wrappers/legacy/socketpair.c",
        "libsyscall/wrappers/libproc/libproc.c",
        "libsyscall/wrappers/libproc/proc_listpidspath.c",
        "libsyscall/wrappers/mach_absolute_time.s",
        "libsyscall/wrappers/mach_approximate_time.c",
        "libsyscall/wrappers/mach_approximate_time.s",
        "libsyscall/wrappers/mach_boottime.c",
        "libsyscall/wrappers/mach_bridge_remote_time.c",
        "libsyscall/wrappers/mach_continuous_time.c",
        "libsyscall/wrappers/mach_get_times.c",
        "libsyscall/wrappers/mach_timebase_info.c",
        "libsyscall/wrappers/nfsclnt.c",
        "libsyscall/wrappers/open-base.c",
        "libsyscall/wrappers/open_dprotected_np.c",
        "libsyscall/wrappers/persona.c",
        "libsyscall/wrappers/pid_shutdown_networking.c",
        "libsyscall/wrappers/posix_sem_obsolete.c",
        "libsyscall/wrappers/proc.c",
        "libsyscall/wrappers/quota_obsolete.c",
        "libsyscall/wrappers/reboot.c",
        "libsyscall/wrappers/remove-counter.c",
        "libsyscall/wrappers/rename.c",
        "libsyscall/wrappers/renameat.c",
        "libsyscall/wrappers/renamex.c",
        "libsyscall/wrappers/rmdir.c",
        "libsyscall/wrappers/setpriority.c",
        "libsyscall/wrappers/sfi.c",
        "libsyscall/wrappers/skywalk/cpu_copy_in_cksum.s",
        ("libsyscall/wrappers/skywalk/cpu_copy_in_cksum_gen.c", ["-fno-builtin"]),
        "libsyscall/wrappers/skywalk/cpu_in_cksum.s",
        ("libsyscall/wrappers/skywalk/cpu_in_cksum_gen.c", ["-fno-builtin"]),
        ("libsyscall/wrappers/skywalk/os_channel.c", ["-fno-builtin"]),
        ("libsyscall/wrappers/skywalk/os_channel_event.c", ["-fno-builtin"]),
        ("libsyscall/wrappers/skywalk/os_nexus.c", ["-fno-builtin"]),
        ("libsyscall/wrappers/skywalk/os_packet.c", ["-fno-builtin"]),
        "libsyscall/wrappers/spawn/posix_spawn.c",
        "libsyscall/wrappers/spawn/posix_spawn_filtering.c",
        "libsyscall/wrappers/stackshot.c",
        "libsyscall/wrappers/statfs_ext.c",
        "libsyscall/wrappers/string/index.c",
        "libsyscall/wrappers/string/memcpy.c",
        ("libsyscall/wrappers/string/memset.c", ["-fno-builtin"]),
        "libsyscall/wrappers/string/strcmp.c",
        "libsyscall/wrappers/string/strcpy.c",
        "libsyscall/wrappers/string/strlcpy.c",
        "libsyscall/wrappers/string/strlen.c",
        "libsyscall/wrappers/string/strsep.c",
        "libsyscall/wrappers/system-version-compat-support.c",
        "libsyscall/wrappers/system-version-compat.c",
        "libsyscall/wrappers/terminate_with_reason.c",
        "libsyscall/wrappers/thread_register_state.c",
        "libsyscall/wrappers/unix03/chmod.c",
        "libsyscall/wrappers/unix03/fchmod.c",
        "libsyscall/wrappers/unix03/getrlimit.c",
        "libsyscall/wrappers/unix03/mmap.c",
        "libsyscall/wrappers/unix03/munmap.c",
        "libsyscall/wrappers/unix03/setrlimit.c",
        "libsyscall/wrappers/unlink.c",
        "libsyscall/wrappers/unlinkat.c",
        "libsyscall/wrappers/utimensat.c",
        "libsyscall/wrappers/varargs_wrappers.s",
        "libsyscall/wrappers/work_interval.c",
        ":userspace_generated[users]",
]

_KERNEL_FLAGS = [
        "-target", target_triple(),
        "-nostdlibinc",
        "-fno-common",
        "-fno-stack-protector",
        "-fno-stack-check",
        "-fno-builtin-calloc",
        "-DPRIVATE",
        "-DLIBSYSCALL_INTERFACE",
        "-D__DARWIN_VERS_1050=1",
        "-DNO_SYSCALL_LEGACY",
        "-DCF_OPEN_SOURCE",
        "-DCF_EXCLUDE_CSTD_HEADERS",
        "-DDEBUG",
        "-D_FORTIFY_SOURCE=0",
        "-D_LIBC_NO_FEATURE_VERIFICATION=1",
        # Single modern macOS ABI: no $UNIX2003/$INODE64 legacy symbol suffixes.
        "-D__DARWIN_ONLY_VERS_1050=1",
        "-D__DARWIN_ONLY_UNIX_CONFORMANCE=1",
        "-D__DARWIN_ONLY_64_BIT_INO_T=1",
        # Upstream libsyscall compiles these sources with clang's default
        # warning level; newer clang promotes int-conversion and
        # incompatible-pointer-types to errors in C, so restore warning level.
        "-Wno-error=int-conversion",
        "-Wno-int-conversion",
        "-Wno-error=incompatible-pointer-types",
        "-Wno-incompatible-pointer-types",
        "-I$(location :userspace_generated)/include",
        "-Isubprojects/libdispatch",
        "-Iuserspace/libclosure",
        "-Ilibsyscall/mach",
        "-include", "EXTERNAL_HEADERS/xros_availability_aliases.h",
        "-Ilibsyscall/os",
        "-Ilibsyscall/wrappers",
        "-Ilibsyscall/wrappers/spawn",
        "-Isubprojects/libpthread/include/pthread",
        "-Ilibsyscall/wrappers/string",
        "-Ilibsyscall/wrappers/libproc",
        "-Ilibsyscall/wrappers/spawn",
        "-Ilibsyscall",
        "-Iuserspace/libc/include",
        "-IEXTERNAL_HEADERS",
        "-Iuserspace/libmalloc/include",
        "-Iuserspace/libmalloc/private",
        "-Iuserspace/libplatform/include",
        "-Iuserspace/libplatform/private",
        "-Iuserspace/CoreFoundation/include",
        "-Iuserspace/IOUSBFamily/include",
        "-Iuserspace/IOFireWireFamily/include",
        "-Iuserspace/CarbonHeaders/include",
        "-Isubprojects/libpthread/include",
        "-Iosfmk",
        "-Ibsd",
        "-Ilibkern",
        "-Iiokit",
        "-Ipexpert",
]

_KERNEL_LANG_FLAGS = {"c": ["-std=gnu11", "-fblocks"]}

cxx_library(
    name = "libsystem_kernel",
    srcs = _KERNEL_SRCS,
    deps = [
        ":userspace_generated",
        ":libsyscalls",
    ],
    preferred_linkage = "shared",
    link_style = "static_pic",
    soname = "libsystem_kernel.dylib",
    compiler_flags = _KERNEL_FLAGS,
    lang_compiler_flags = _KERNEL_LANG_FLAGS,
    # Deliberately no undefined/dynamic_lookup escape: outstanding dependencies
    # must be linked to their real userspace providers.
    linker_flags = ["-nostdlib"],
    post_linker_flags = [
        "-Wl,-install_name,/usr/lib/system/libsystem_kernel.dylib",
    ],
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# Sources in the Libsyscall_dynamic phase but not Libsyscall_static: the libc
# function-pointer trampolines and string wrappers that stand in for libc inside
# the dylib. A static link has the real libc/libplatform/pthread, so they collide.
_KERNEL_DYLIB_ONLY = [
    "libsyscall/wrappers/_libkernel_init.c",
    "libsyscall/wrappers/_libc_funcptr.c",
    "libsyscall/wrappers/spawn/posix_spawn_filtering.c",
    "libsyscall/wrappers/system-version-compat.c",
    "libsyscall/wrappers/string/index.c",
    "libsyscall/wrappers/string/memcpy.c",
    "libsyscall/wrappers/string/memset.c",
    "libsyscall/wrappers/string/strcmp.c",
    "libsyscall/wrappers/string/strcpy.c",
    "libsyscall/wrappers/string/strlcpy.c",
    "libsyscall/wrappers/string/strlen.c",
    "libsyscall/wrappers/string/strsep.c",
]

# The libc/libplatform function-pointer glue from the dylib-only set, for the
# umbrella (libSystem) link: __libkernel_platform_init and __dlsym come from
# here. The glue's upcalls (_libc_funcptr.c's _libkernel_generic_string_functions)
# name the _libkernel_* string wrappers, which are hidden and not exported by
# libplatform (it exports _platform_*), so the umbrella needs them too. strsep
# is not one of them, and it is left out.
cxx_library(
    name = "libsystem_kernel_glue",
    srcs = [
        "libsyscall/wrappers/_libc_funcptr.c",
        "libsyscall/wrappers/_libkernel_init.c",
        "libsyscall/wrappers/system-version-compat.c",
        "libsyscall/wrappers/spawn/posix_spawn_filtering.c",
        "libsyscall/wrappers/string/index.c",
        "libsyscall/wrappers/string/memcpy.c",
        ("libsyscall/wrappers/string/memset.c", ["-fno-builtin"]),
        "libsyscall/wrappers/string/strcmp.c",
        "libsyscall/wrappers/string/strcpy.c",
        "libsyscall/wrappers/string/strlcpy.c",
        "libsyscall/wrappers/string/strlen.c",
    ],
    deps = [
        ":userspace_generated",
        ":libsyscalls",
    ],
    preferred_linkage = "static",
    link_style = "static_pic",
    link_whole = True,
    compiler_flags = _KERNEL_FLAGS,
    lang_compiler_flags = _KERNEL_LANG_FLAGS,
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# Same sources as the dylib, as a static archive for the dyld bootstrap link
# (dyld cannot depend on a shared libsystem_kernel).
cxx_library(
    name = "libsystem_kernel_static",
    srcs = [src for src in _KERNEL_SRCS if (src[0] if type(src) == "tuple" else src) not in _KERNEL_DYLIB_ONLY],
    deps = [
        ":userspace_generated",
        ":libsyscalls",
    ],
    preferred_linkage = "static",
    link_style = "static_pic",
    link_whole = True,
    compiler_flags = _KERNEL_FLAGS,
    lang_compiler_flags = _KERNEL_LANG_FLAGS,
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# Shared pthread sources/flags: the dylib (for libSystem) and the static archive
# dyld links during bootstrap.
_PTHREAD_SRCS = [
        "subprojects/libpthread/src/resolver/resolver.c",
        "subprojects/libpthread/src/pthread.c",
        "subprojects/libpthread/src/pthread_cancelable.c",
        "subprojects/libpthread/src/pthread_cond.c",
        "subprojects/libpthread/src/pthread_mutex.c",
        "subprojects/libpthread/src/qos.c",
        "subprojects/libpthread/src/pthread_rwlock.c",
        "subprojects/libpthread/src/pthread_cwd.c",
        "subprojects/libpthread/src/pthread_tsd.c",
        "subprojects/libpthread/src/variants/pthread_cancelable_cancel.c",
        "subprojects/libpthread/src/pthread_atfork.c",
        "subprojects/libpthread/src/pthread_dependency.c",
        "subprojects/libpthread/src/pthread_asm.s",
]

_PTHREAD_FLAGS = [
        "-target", target_triple(),
        "-nostdlibinc",
        "-fno-common",
        "-fno-stack-protector",
        "-D__DARWIN_ONLY_VERS_1050=1",
        "-D__DARWIN_ONLY_UNIX_CONFORMANCE=1",
        "-D__DARWIN_ONLY_64_BIT_INO_T=1",
        # Upstream pthread.xcconfig BASE_PREPROCESSOR_MACROS. __POSIX_LIB__ selects
        # the full struct sched_param (with `quantum`) in pthread/posix_sched.h.
        "-D__LIBC__",
        "-D__POSIX_LIB__",
        "-D__PTHREAD_BUILDING_PTHREAD__=1",
        "-D_PTHREAD_BUILD",
        "-D__PTHREAD_EXPOSE_INTERNALS__",
        "-DPTHREAD_INTERNAL",
        # libpthread must not see libc's private feature header; it selects
        # PLOCKSTAT, which belongs to the introspection variant only.
        "-D_LIBC_NO_FEATURE_VERIFICATION=1",
        "-Wno-error=int-conversion",
        "-Wno-int-conversion",
        "-Wno-error=incompatible-pointer-types",
        "-Wno-incompatible-pointer-types",
        "-DTARGET_OS_EXCLAVECORE=0",
        "-DTARGET_OS_EXCLAVEKIT=0",
        "-Isubprojects/libpthread",
        "-Wno-nullability-completeness",
        "-Isubprojects/libpthread/include",
        "-Isubprojects/libpthread/src",
        "-Isubprojects/libpthread/src/include",
        "-Isubprojects/libpthread/src/resolver",
        "-Isubprojects/libpthread/src/private",
        "-Isubprojects/libpthread/private",
        "-Iuserspace/libplatform/include",
        "-Iuserspace/libplatform/private",
        "-Iuserspace/libc/include",
        "-Iuserspace/dyld/include",
        "-Iuserspace/libmalloc/include",
        "-Iuserspace/libmalloc/private",
        "-I$(location //userspace:system_headers)",
        "-I$(location :userspace_generated)/include",
        "-I$(location :xnu_codegen)/mig",
        "-IEXTERNAL_HEADERS",
        "-Iosfmk",
        "-Isubprojects/libdispatch",
        "-Ibsd",
        "-Ilibkern",
        "-Ilibsyscall",
        "-Ilibsyscall/mach",
        "-Ilibsyscall/os",
        "-Ilibsyscall/wrappers",
        "-Ilibsyscall/wrappers/spawn",
        "-Isubprojects/libpthread/include/pthread",
]

_PTHREAD_LANG_FLAGS = {
        "c": [
            # PRIVATE exposes the SPIs (e.g. sys/ulock.h flags); only C/C++.
            "-DPRIVATE",
            "-include", "$(location //userspace/AvailabilityVersions:headers)/Availability.h",
            "-include", "EXTERNAL_HEADERS/xros_availability_aliases.h",
            "-include", "osfmk/mach/thread_policy_private.h",
        ],
        "cxx": [
            "-DPRIVATE",
            "-include", "$(location //userspace/AvailabilityVersions:headers)/Availability.h",
            "-include", "EXTERNAL_HEADERS/xros_availability_aliases.h",
            "-include", "osfmk/mach/thread_policy_private.h",
        ],
}

cxx_library(
    name = "libsystem_pthread",
    srcs = _PTHREAD_SRCS,
    deps = [
        "//userspace:system_headers",
        "//userspace/AvailabilityVersions:headers",
        ":xnu_codegen",
        ":userspace_generated",
        ":libsystem_kernel",
    ],
    preferred_linkage = "shared",
    soname = "libsystem_pthread.dylib",
    compiler_flags = _PTHREAD_FLAGS,
    lang_compiler_flags = _PTHREAD_LANG_FLAGS,
    linker_flags = ["-nostdlib"],
    post_linker_flags = [
        "-Wl,-install_name,/usr/lib/system/libsystem_pthread.dylib",
    ],
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# Static dyld variant for the bootstrap link (dyld cannot depend on the dylib).
cxx_library(
    name = "libsystem_pthread_dyld",
    srcs = _PTHREAD_SRCS,
    deps = [
        "//userspace:system_headers",
        "//userspace/AvailabilityVersions:headers",
        ":xnu_codegen",
        ":userspace_generated",
        ":libsystem_kernel_static",
        "//userspace/libplatform:libsystem_platform_dyld",
    ],
    preferred_linkage = "static",
    link_style = "static_pic",
    link_whole = True,
    # The dyld variant (upstream VARIANT_DYLD): static main thread, no malloc hooks,
    # and no JIT write-protect allowlist, which needs the unsupported rwx mechanism.
    compiler_flags = _PTHREAD_FLAGS + ["-DVARIANT_DYLD=1", "-DVARIANT_STATIC=1"],
    lang_compiler_flags = _PTHREAD_LANG_FLAGS,
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# Normal (non-dyld) static archive of libpthread, for the merged libSystem.
cxx_library(
    name = "libsystem_pthread_objects",
    srcs = _PTHREAD_SRCS,
    deps = [
        "//userspace:system_headers",
        "//userspace/AvailabilityVersions:headers",
        ":xnu_codegen",
        ":userspace_generated",
    ],
    preferred_linkage = "static",
    link_style = "static_pic",
    link_whole = True,
    compiler_flags = _PTHREAD_FLAGS,
    lang_compiler_flags = _PTHREAD_LANG_FLAGS,
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# ---------------------------------------------------------------------------
# Final Kernel Link (mach_kernel) & Kernelcache
# ---------------------------------------------------------------------------
load("//xnu:kernel.bzl", "kc_layout_args", "kernel_ldflags", "kext_ldflags")

KERNEL_LIBS = [
    ":xnu_osfmk",
    ":xnu_osfmk_vm",
    ":xnu_osfmk_asm",
    ":xnu_bsd",
    ":xnu_bsd_vm",
    ":xnu_bsd_mman",
    ":xnu_bsd_asm",
    ":xnu_libkern",
    ":xnu_iokit",
    ":xnu_iokit_driverkit",
    ":xnu_libsa",
    ":xnu_pexpert",
    ":xnu_security",
    ":xnu_san",
    ":xnu_iostorage",
    ":xnu_msdosfs",
    ":xnu_libpthread",
    ":xnu_compiler_rt",
    ":xnu_libdispatch",
    ":xnu_lastkernelconstructor",
]

cxx_binary(
    name = "mach_kernel",
    srcs = ["libsa/lastkerneldataconst.c"],
    compiler_flags = c_flags("libsa"),
    linker_flags = kernel_ldflags(),
    link_style = "static",
    deps = KERNEL_LIBS + ["//rust:xnu-rs"],
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# Kexts of the kernelcache. Each is compiled with the kernel's flags for its
# subsystem and linked, by mold, at its slot of the regions the kernel reserves
# (kext_ldflags); tools/buck/kernelcache.py links it into the collection.
cxx_library(**kernel_library_args(
    name = "sandbox_kext_objects",
    subsys = "security",
    extra_srcs = ["security/sandbox_kext/sandbox_kext.c"],
))

cxx_binary(
    name = "sandbox_kext",
    deps = [":sandbox_kext_objects"],
    linker_flags = kext_ldflags(0),
    link_style = "static",
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# AppleMobileFileIntegrity: static trust cache and platform marking (slot 1).
cxx_library(**kernel_library_args(
    name = "amfi_kext_objects",
    subsys = "security",
    extra_srcs = ["security/amfi_kext/amfi_kext.c"],
))

cxx_binary(
    name = "amfi_kext",
    deps = [":amfi_kext_objects"],
    linker_flags = kext_ldflags(1),
    link_style = "static",
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

genrule(
    name = "kernelcache",
    srcs = [
        "tools/buck/kernelcache.py",
    ],
    out = "kernelcache",
    cmd = "python3 tools/buck/kernelcache.py $(location :mach_kernel) -o $OUT " +
          "--kext com.apple.security.sandbox=$(location :sandbox_kext) " +
          "--kext com.apple.driver.AppleMobileFileIntegrity=$(location :amfi_kext) " +
          " ".join(kc_layout_args()),
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# ---------------------------------------------------------------------------
# Top-level Convenience Aliases
# ---------------------------------------------------------------------------
alias(
    name = "config",
    actual = "//SETUP/config:config",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

alias(
    name = "migcom",
    actual = "//tools/migcom:migcom",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

alias(
    name = "mig",
    actual = "//tools/migcom:mig",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

alias(
    name = "iig",
    actual = "//tools/iig:iig",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

alias(
    name = "qemu-boot",
    actual = "//tools/qemu-boot:qemu-boot.elf",
    default_target_platform = "//platforms:aarch64-none",
    visibility = ["PUBLIC"],
)

alias(
    name = "rust",
    actual = "//rust:xnu-rs",
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# ---------------------------------------------------------------------------
# QEMU runner: `buck2 run //:qemu -- --rootfs root.apfs --bootargs rd=disk0`
#
# Runs tools/qemu.py (a host tool) on the kernelcache and the loader, which are
# built for other platforms; the wrappers below transition them there, so one
# `buck2 run` builds everything it runs. Further arguments go to tools/qemu.py.
# ---------------------------------------------------------------------------
load("//xnu:platform.bzl", "bare_metal_artifact", "darwin_artifact")

darwin_artifact(
    name = "kernelcache_for_qemu",
    actual = ":kernelcache",
)

bare_metal_artifact(
    name = "qemu_boot_for_qemu",
    actual = ":qemu-boot",
)

python_bootstrap_binary(
    name = "qemu_py",
    main = "tools/qemu.py",
    default_target_platform = "//platforms:host",
)

command_alias(
    name = "qemu",
    exe = ":qemu_py",
    args = [
        "--kernel",
        "$(location :kernelcache_for_qemu)",
        "--bootloader",
        "$(location :qemu_boot_for_qemu)",
    ],
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

# libc++'s default <__assertion_handler> template (CMakeLists.txt:97 default),
# exported so userspace/dyld can install it. Lives under subprojects/, which the
# root package owns.
export_file(
    name = "libcxx_default_assertion_handler",
    src = "subprojects/llvm-project/libcxx/vendor/llvm/default_assertion_handler.in",
    visibility = ["PUBLIC"],
)

export_file(
    name = "libcxx_functional_src",
    src = "subprojects/llvm-project/libcxx/src/functional.cpp",
    out = "functional.cpp",
    visibility = ["PUBLIC"],
)

# Apple's osfmk/mach tree (incl. mach/machine/*.defs) as an include root for
# userspace/BUCK's liblaunch MIG run: std_types.defs pulls in
# <mach/machine/machine_types.defs> and mach_types.defs <mach/machine/thread_state.h>,
# which an export of the two top-level .defs alone cannot provide. Declared via
# glob, so MIG inputs are tracked. Output is the directory: $OUT/mach/...
genrule(
    name = "launchd_mig_mach_defs",
    srcs = glob(["osfmk/mach/**"], exclude = ["**/Makefile"]),
    out = "launchd_mig_mach_defs",
    cmd = "mkdir -p $OUT/mach && cp -RL osfmk/mach/. $OUT/mach/",
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)

# ---------------------------------------------------------------------------
# libdispatch (Darwin configuration) for the userspace umbrella. Sources follow
# the Xcode "libdispatch" target's Sources phase (libdispatch.xcodeproj), minus:
#   - src/introspection.c, src/shims.c: not in that phase (introspection variant
#     and CMake-only respectively);
#   - src/event/workqueue.c: not in that phase; the Darwin build uses the
#     kernel pthread workqueue (libpthread), DISPATCH_USE_INTERNAL_WORKQUEUE=0;
#   - object.m, data.m, client_callout.mm: ObjC; built with HAVE_OBJC=0 (no
#     objc headers or libobjc in the tree), so OS_OBJECT_HAVE_OBJC1=0.
# MIG (protocol.defs, firehose.defs, firehose_reply.defs) outputs are generated
# here, as the Xcode "Mig Headers" phase and sourcecode.mig build rule do
# (protocol: Client+Server; firehose: Client; firehose_reply: Server).
# DTrace USDT probes are disabled (DISPATCH_USE_DTRACE=0): tools/dtrace cannot
# yet parse provider.d (multi-line probe declarations; typedef'd argument types
# need CTF encoding). The MIG invocations mirror userspace_generated's rules.
# ---------------------------------------------------------------------------
genrule(
    name = "libdispatch_gen",
    srcs = glob(["osfmk/mach/**", "osfmk/machine/**", "EXTERNAL_HEADERS/**"]) + [
        "subprojects/libdispatch/src/protocol.defs",
        "subprojects/libdispatch/config/config.h",
        "subprojects/libdispatch/src/firehose/firehose.defs",
        "subprojects/libdispatch/src/firehose/firehose_reply.defs",
        "subprojects/libdispatch/src/firehose/firehose_types.defs",
    ],
    outs = {
        "srcs": [
            "protocolUser.c",
            "protocolServer.c",
            "firehoseUser.c",
            "firehose_replyServer.c",
        ],
        "all": [
            "config/config.h",
            "protocolUser.c",
            "protocolServer.c",
            "firehoseUser.c",
            "firehose_replyServer.c",
            "protocol.h",
            "protocolServer.h",
            "firehose.h",
            "firehoseServer.h",
            "firehose_reply.h",
            "firehose_replyServer.h",
        ],
    },
    cmd = "set -e\n" +
          "MIG=$(exe //tools/migcom:mig)\n" +
          "D=subprojects/libdispatch/src\n" +
          "BASE=\"-I$D -I$D/firehose -Iosfmk -Ibsd -IEXTERNAL_HEADERS -Ilibsyscall/mach\"\n" +
          "$MIG $BASE -target arm64-apple-macos27.0.0 -user $OUT/protocolUser.c -header $OUT/protocol.h -server $OUT/protocolServer.c -sheader $OUT/protocolServer.h $D/protocol.defs\n" +
          "$MIG $BASE -target arm64-apple-macos27.0.0 -user $OUT/firehoseUser.c -header $OUT/firehose.h -server /dev/null -sheader $OUT/firehoseServer.h $D/firehose/firehose.defs\n" +
          "$MIG $BASE -target arm64-apple-macos27.0.0 -user /dev/null -header $OUT/firehose_reply.h -server $OUT/firehose_replyServer.c -sheader $OUT/firehose_replyServer.h $D/firehose/firehose_reply.defs\n" +
          "mkdir -p $OUT/config\n" +
          # Upstream config.h defines HAVE_OBJC 1 (no objc4 headers or libobjc in
          # this tree) and HAVE_PTHREAD_MACHDEP_H 1 (pthread_machdep.h is not in the
          # tree; direct TSD declarations come from libpthread's private/pthread/).
          "sed -e 's/^#define HAVE_OBJC 1$/#define HAVE_OBJC 0/' -e 's/^#define HAVE_PTHREAD_MACHDEP_H 1$/#define HAVE_PTHREAD_MACHDEP_H 0/' subprojects/libdispatch/config/config.h > $OUT/config/config.h\n",
    default_target_platform = "//platforms:host",
    visibility = ["PUBLIC"],
)

cxx_library(
    name = "libdispatch_objects",
    srcs = [
        "subprojects/libdispatch/resolver/resolver.c",
        "subprojects/libdispatch/src/init.c",
        "subprojects/libdispatch/src/object.c",
        "subprojects/libdispatch/src/block.cpp",
        "subprojects/libdispatch/src/shims/lock.c",
        "subprojects/libdispatch/src/shims/yield.c",
        "subprojects/libdispatch/src/semaphore.c",
        "subprojects/libdispatch/src/once.c",
        "subprojects/libdispatch/src/eventlink.c",
        "subprojects/libdispatch/src/queue.c",
        "subprojects/libdispatch/src/apply.c",
        "subprojects/libdispatch/src/source.c",
        "subprojects/libdispatch/src/workgroup.c",
        "subprojects/libdispatch/src/mach.c",
        "subprojects/libdispatch/src/event/event.c",
        "subprojects/libdispatch/src/event/event_kevent.c",
        "subprojects/libdispatch/src/event/event_epoll.c",
        "subprojects/libdispatch/src/voucher.c",
        "subprojects/libdispatch/src/firehose/firehose_buffer.c",
        "subprojects/libdispatch/src/io.c",
        "subprojects/libdispatch/src/data.c",
        "subprojects/libdispatch/src/transform.c",
        "subprojects/libdispatch/src/time.c",
        "subprojects/libdispatch/src/allocator.c",
        "subprojects/libdispatch/src/benchmark.c",
        ":libdispatch_gen[srcs]",
    ],
    deps = [
        "//:userspace_generated",
        "//:system_framework_headers",
        "//userspace:system_headers",
        "//userspace/AvailabilityVersions:headers",
        "//userspace/libc:libc_features",
        "//userspace/libplatform:headers",
        "//userspace/libmalloc:headers",
        "//userspace/dyld:libcxx_headers",
    ],
    compiler_flags = [
        "-target", target_triple(),
        "-nostdlibinc",
        "-O2",
        "-fblocks",
        "-fno-common",
        "-fno-stack-protector",
        "-momit-leaf-frame-pointer",
        "-include", "EXTERNAL_HEADERS/xros_availability_aliases.h",
        "-DPRIVATE",
        "-D__APPLE_API_PRIVATE",
        "-D__DARWIN_ONLY_VERS_1050=1",
        "-D__DARWIN_ONLY_UNIX_CONFORMANCE=1",
        "-D__DARWIN_ONLY_64_BIT_INO_T=1",
        "-D__LIBC__",
        "-D_LIBC_NO_FEATURE_VERIFICATION=1",
        "-D_FORTIFY_SOURCE=0",
        "-DTARGET_OS_EXCLAVECORE=0",
        "-DTARGET_OS_EXCLAVEKIT=0",
        "-DDISPATCH_USE_DTRACE=0",
        "-DOS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY=1",
        # internal.h has no default for this; upstream derives it from the
        # deployment target (>= macOS 13 on arm64), which this target is.
        "-DDISPATCH_SEND_ACTIVITY_IN_MSGV=1",
        "-DNDEBUG",
        "-I$(location :libdispatch_gen)",
        "-I$(location //:userspace_generated)/include",
        "-I$(location //userspace:system_headers)",
        "-I$(location //userspace/AvailabilityVersions:headers)",
        "-I$(location //userspace/libc:libc_features)/arm64",
        "-I$(location //:system_framework_headers)",
        "-Isubprojects/libdispatch",
        "-Isubprojects/libdispatch/src",
        "-Isubprojects/libdispatch/src/event",
        "-Isubprojects/libdispatch/src/firehose",
        "-Ilibsyscall/wrappers/libproc",
        "-Isubprojects/libdispatch/private",
        "-Iuserspace/libclosure",
        "-Iuserspace/libc/include",
        "-Iuserspace/libc",
        "-Iuserspace/libc/darwin",
        "-Iuserspace/libplatform/include",
        "-Iuserspace/libplatform/private",
        "-Iuserspace/libmalloc/include",
        "-Iuserspace/libmalloc/private",
        "-Isubprojects/libpthread/include",
        "-Isubprojects/libpthread/private",
        "-IEXTERNAL_HEADERS",
        "-Ilibsyscall/mach",
        "-Ilibsyscall",
        "-Ilibsyscall/wrappers",
        "-Iosfmk",
        "-Ibsd",
        "-Ilibkern",
        "-Isubprojects/libpthread/include/pthread",
    ],
    lang_compiler_flags = {
        "c": [
            "-std=gnu11",
            "-include", "$(location //userspace/AvailabilityVersions:headers)/Availability.h",
        ],
        "cxx": [
            "-std=c++20",
            "-fno-exceptions",
            "-fno-rtti",
            "-include", "$(location //userspace/AvailabilityVersions:headers)/Availability.h",
        ],
    },
    preferred_linkage = "static",
    link_style = "static_pic",
    link_whole = True,
    default_target_platform = "//platforms:aarch64-darwin",
    visibility = ["PUBLIC"],
)
