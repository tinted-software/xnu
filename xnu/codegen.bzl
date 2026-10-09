"""Configure-time code generation: job tables and the files they produce.

`tools/buck/gen_tree.py` runs these jobs into one output tree (the
`:xnu_codegen` rule in BUCK). The tables live here, the only place that names
them: BUCK passes them to gen_tree.py as JSON (`jobs_json()`) and derives the
rule's declared outputs from them (`codegen_outs()`), so the two cannot drift.
"""

load("//xnu:flags.bzl", "MIG_SUBDIRS")

# MIG jobs: (defs path under osfmk/, kind, output basename). The kind selects
# the flag set and what is written: `server`/`user` stubs and their headers,
# `*_plain` ones without the kernel-server defines, and `uuhdr`/`ushdr` header-only.
MIG_JOBS = [
    ("mach/clock.defs", "server", "clock_server.c"),
    ("mach/clock_reply.defs", "user", "clock_reply_user.c"),
    ("mach/exc.defs", "user", "exc_user.c"),
    ("mach/exc.defs", "server", "exc_server.c"),
    ("mach/mach_eventlink.defs", "server", "mach_eventlink_server.c"),
    ("mach/host_priv.defs", "server", "host_priv_server.c"),
    ("mach/host_notify_reply.defs", "user", "host_notify_reply_user.c"),
    ("mach/ktrace_background.defs", "user", "ktrace_background_user.c"),
    ("mach/mach_exc.defs", "user", "mach_exc_user.c"),
    ("mach/mach_exc.defs", "server", "mach_exc_server.c"),
    ("mach/mach_host.defs", "server", "mach_host_server.c"),
    ("mach/notify.defs", "user", "mach_notify_user.c"),
    ("mach/mach_port.defs", "server", "mach_port_server.c"),
    ("mach/mach_vm.defs", "server", "mach_vm_server.c"),
    ("mach/mach_voucher.defs", "server", "mach_voucher_server.c"),
    ("mach/memory_entry.defs", "server", "memory_entry_server.c"),
    ("mach/resource_notify.defs", "user", "resource_notify_user.c"),
    ("mach/restartable.defs", "server", "restartable_server.c"),
    ("mach/audit_triggers.defs", "user", "audit_triggers_user.c"),
    ("mach/task_access.defs", "user", "task_access_user.c"),
    ("mach/telemetry_notification.defs", "user", "telemetry_notification_user.c"),
    ("mach/coalition_notification.defs", "user", "coalition_notification_user.c"),
    ("mach/sysdiagnose_notification.defs", "user", "sysdiagnose_notification_user.c"),
    ("mach/vfs_nspace.defs", "user", "vfs_nspace_user.c"),
    ("mach/fairplayd_notification.defs", "user", "fairplayd_notification_user.c"),
    ("mach/arcade_upcall.defs", "user", "arcade_upcall_user.c"),
    ("mach/arcade_register.defs", "server", "arcade_register_server.c"),
    ("mach/memory_error_notification.defs", "user", "memory_error_notification_user.c"),
    ("mach/doubleagent_mig.defs", "user", "doubleagent_mig_user.c"),
    ("mach/iocompressionstats_notification.defs", "user", "iocompressionstats_notification_user.c"),
    ("mach/processor.defs", "server", "processor_server.c"),
    ("mach/processor_set.defs", "server", "processor_set_server.c"),
    ("mach/task.defs", "server", "task_server.c"),
    ("mach/thread_act.defs", "server", "thread_act_server.c"),
    ("mach/vm32_map.defs", "server", "vm32_map_server.c"),
    ("mach/vm_map.defs", "server", "vm_map_server.c"),
    ("mach/upl.defs", "server", "upl_server.c"),
    ("mach/mach_test_upcall.defs", "user", "mach_test_upcall_user.c"),
    ("device/device.defs", "server", "device_server.c"),
    ("UserNotification/UNDRequest.defs", "user_plain", "UNDRequest.c"),
    ("UserNotification/UNDReply.defs", "server_plain", "UNDReplyServer.c"),
    ("gssd/gssd_mach.defs", "user_plain", "gssd_mach.c"),
    ("lockd/lockd_mach.defs", "user_plain", "lockd_mach.c"),
    ("kextd/kextd_mach.defs", "user_plain", "kextd_mach.c"),
    ("mach/clock.defs", "uuhdr", "clock.h"),
    ("mach/clock_priv.defs", "uuhdr", "clock_priv.h"),
    ("mach/host_priv.defs", "uuhdr", "host_priv.h"),
    ("mach/host_security.defs", "uuhdr", "host_security.h"),
    ("mach/mach_host.defs", "uuhdr", "mach_host.h"),
    ("mach/mach_port.defs", "uuhdr", "mach_port.h"),
    ("mach/mach_vm.defs", "uuhdr", "mach_vm.h"),
    ("mach/mach_voucher.defs", "uuhdr", "mach_voucher.h"),
    ("mach/mach_voucher_attr_control.defs", "uuhdr", "mach_voucher_attr_control.h"),
    ("mach/memory_entry.defs", "uuhdr", "memory_entry.h"),
    ("mach/processor.defs", "uuhdr", "processor.h"),
    ("mach/processor_set.defs", "uuhdr", "processor_set.h"),
    ("mach/task.defs", "uuhdr", "task.h"),
    ("mach/thread_act.defs", "uuhdr", "thread_act.h"),
    ("mach/upl.defs", "uuhdr", "upl.h"),
    ("mach/vm_map.defs", "uuhdr", "vm_map.h"),
    ("mach/audit_triggers.defs", "ushdr", "audit_triggers_server.h"),
    ("mach/clock_reply.defs", "ushdr", "clock_reply_server.h"),
    ("mach/coalition_notification.defs", "ushdr", "coalition_notification_server.h"),
    ("mach/doubleagent_mig.defs", "ushdr", "doubleagent_mig_server.h"),
    ("mach/exc.defs", "ushdr", "exc_server.h"),
    ("mach/fairplayd_notification.defs", "ushdr", "fairplayd_notification_server.h"),
    ("mach/arcade_upcall.defs", "ushdr", "arcade_upcall_server.h"),
    ("mach/memory_error_notification.defs", "ushdr", "memory_error_notification_server.h"),
    ("mach/mach_exc.defs", "ushdr", "mach_exc_server.h"),
    ("mach/notify.defs", "ushdr", "notify_server.h"),
    ("mach/task_access.defs", "ushdr", "task_access_server.h"),
    ("mach/telemetry_notification.defs", "ushdr", "telemetry_notification_server.h"),
    ("mach/sysdiagnose_notification.defs", "ushdr", "sysdiagnose_notification_server.h"),
    ("mach/iocompressionstats_notification.defs", "ushdr", "iocompressionstats_notification_server.h"),
    ("mach/vfs_nspace.defs", "ushdr", "vfs_nspace_server.h"),
]

# DriverKit IIG jobs, one `iokit/DriverKit/<name>.iig` each.
IIG_DEFS = [
    "OSObject",
    "OSAction",
    "IOService",
    "IOExtensiblePaniclog",
    "IOUserClient",
    "IOMemoryDescriptor",
    "IOBufferMemoryDescriptor",
    "IOMemoryMap",
    "IODispatchSource",
    "IODispatchQueue",
    "IOInterruptDispatchSource",
    "IODataQueueDispatchSource",
    "IOServiceNotificationDispatchSource",
    "IOServiceStateNotificationDispatchSource",
    "IOEventLink",
    "IOWorkGroup",
    "IOUserServer",
    "IODMACommand",
]

# Files written by gen_tree.py that are only reached through `-I`, listed so
# the whole tree materialises on a cache hit.
_BASE = [
    "manifest.txt",
    "gen/manifest.json",
    "gen/master_config.h",
    "gen/meta_features.h",
    "gen/version.c",
    "gen/export/osfmk/string.h",
]

# Translation units of the bsd library that gen_tree.py writes.
_BSD_GEN = [
    "gen/ioconf.c",
    "gen/init_sysent.c",
    "gen/syscalls.c",
    "gen/audit_kevents.c",
    "gen/systrace_args.c",
]

# The syscall headers, reached through `-I`, not `srcs`.
_BSD_HDRS = [
    "gen/syscall.h",
    "gen/sysproto.h",
    "gen/sys/syscall.h",
    "gen/sys/sysproto.h",
]


def _stem(outc):
    return outc[:-2] if outc.endswith(".c") else outc


def _mig_outputs():
    """(stub translation units, headers) of every MIG job.

    Stubs are written to srv/ (off every include path) so the quoted
    `#include "<name>.h"` they emit resolves through `-I` to the intended
    header; see tools/buck/gen_tree.py.
    """
    mig_c = []
    mig_h = []
    for defs, kind, outc in MIG_JOBS:
        sub = defs.split("/")[0]
        stem = _stem(outc)
        if kind in ("server", "server_plain"):
            mig_c.append("srv/%s/%s" % (sub, outc))
            mig_h.append("mig/ks/%s/%s.h" % (sub, stem))
        elif kind == "user":
            mig_c.append("srv/%s/%s" % (sub, outc))
            mig_h.append("mig/%s/%s" % (sub, outc.replace("_user.c", ".h")))
        elif kind == "user_plain":
            mig_c.append("srv/%s/%s" % (sub, outc))
            mig_h.append("mig/%s/%s.h" % (sub, stem))
        elif kind in ("uuhdr", "ushdr"):
            mig_h.append("mig/%s/%s" % (sub, outc))
    return mig_c, mig_h


def codegen_outs(iostorage_headers):
    """Outputs of `:xnu_codegen`, grouped by the library that compiles them.

    `iostorage_headers` is the glob of IOStorageFamily's `*.h`. `all` lists
    every produced file (so the artifact is fully declared); the other groups
    are consumed as `srcs` by one library each.
    """
    mig_c, mig_h = _mig_outputs()
    iig_driverkit = ["iig/%s.iig.cpp" % n for n in IIG_DEFS]
    iig_iostorage = ["iig/IOUserBlockStorageDevice.iig.cpp"]
    iig_h = ["gen/export/DriverKit/%s.h" % n for n in IIG_DEFS]
    iostorage_h = sorted(["gen/export/IOKit/storage/" + p.split("/")[-1] for p in iostorage_headers])
    if iostorage_h:
        iig_h = iig_h + ["gen/export/DriverKit/IOUserBlockStorageDevice.h"]
    return {
        "all": _BASE + _BSD_GEN + _BSD_HDRS + mig_c + mig_h + iig_driverkit + iig_iostorage + iig_h + iostorage_h,
        "mig_c": mig_c,
        "iig_driverkit_cpp": iig_driverkit,
        "iig_iostorage_cpp": iig_iostorage,
        "bsd_gen": _BSD_GEN,
        "osfmk_gen": ["gen/version.c"],
    }


def jobs_json():
    """The job tables as a single-quoted shell word, for gen_tree.py's `--jobs`."""
    return "'" + json.encode({"mig_jobs": MIG_JOBS, "iig_defs": IIG_DEFS}).replace("'", "'\\''") + "'"
