#!/usr/bin/env python3
"""Run XNU's configure-time code generation into a single output tree.

Runs the configure-time generators: master_config.h/meta_features.h and the
option headers, ioconf.c, the MIG stubs/headers, the IIG DriverKit sources, the
syscall tables, and version.c. The MIG and IIG job tables come from the BUCK
rule (`--jobs`, rendered from //xnu:codegen.bzl), which also derives the rule's
declared outputs from them.

Everything lands under `--outdir`, so the include flags translate one-to-one:

    <out>/gen/...            -I gen
    <out>/gen/export/...     -I gen/export
    <out>/gen/sys/...        -I gen (for <sys/syscall.h>)
    <out>/mig/...            -I mig, -I mig/<sub>
    <out>/mig/ks/...         -I mig/ks, -I mig/ks/<sub>
    <out>/iig/...            -I iig
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Job tables, filled from `--jobs` in main(): MIG jobs are (defs path under
# osfmk/, kind, output basename); IIG jobs are `iokit/DriverKit/<name>.iig`.
MIG_JOBS: list = []
IIG_DEFS: list = []

MIG_BASE_DEFINES = [
    "-DAPPLE",
    "-DKERNEL",
    "-DKERNEL_PRIVATE",
    "-DXNU_KERNEL_PRIVATE",
    "-DPRIVATE",
    "-DMACH_KERNEL_PRIVATE",
    "-DXNU_TARGET_OS_OSX",
]

# Flags per MIG job kind, mirroring the `if kind == ...` ladder in meson.build.
KERNEL_SERVER = ["-DMACH_KERNEL_PRIVATE", "-DKERNEL_SERVER=1", "-mach_msg2"]
KERNEL_USER = [
    "-DMACH_KERNEL_PRIVATE",
    "-DKERNEL_USER=1",
    "-DEXC_SERVER_AUDITTOKEN=1",
    "-DMACH_EXC_SERVER_AUDITTOKEN=1",
    "-maxonstack",
    "1024",
]

# DriverKit IIG flags, from meson.build's `iig_cflags`.
IIG_CFLAGS = [
    "-x",
    "c++",
    "-std=gnu++2c",
    "-D__IIG=1",
    "-DDRIVERKIT_PRIVATE=1",
    "-DPRIVATE_WIFI_ONLY=1",
]


def run(cmd: list[str], **kw) -> None:
    subprocess.check_call([str(c) for c in cmd], **kw)


def gen_config(args, out: Path) -> None:
    """master_config.h, meta_features.h, option headers, ioconf.c, exports."""
    run(
        [
            sys.executable,
            REPO / "tools" / "buck" / "xnu_config.py",
            "--srcroot",
            args.srcroot,
            "--kernel-config",
            args.kernel_config,
            "--board",
            args.board,
            "--format",
            "json",
            "--outdir",
            out / "gen",
        ]
    )
    # Export_hdrs/export symlink dirs are materialised by xnu_config.


def mig_config_defines(args) -> list[str]:
    """-D flags MIG needs, from xnu_config's mig-defines format."""
    out = subprocess.check_output(
        [
            sys.executable,
            REPO / "tools" / "buck" / "xnu_config.py",
            "--srcroot",
            args.srcroot,
            "--kernel-config",
            args.kernel_config,
            "--board",
            args.board,
            "--format",
            "mig-defines",
        ]
    )
    return [d for d in out.decode().split("\n") if d.strip()]


def gen_mig(args, out: Path) -> None:
    gen = out / "gen"
    mig_dir = out / "mig"
    ks_dir = mig_dir / "ks"
    # meson writes every stub to the build root, which is *not* an include
    # directory; `#include "exc_server.h"` therefore resolves through the
    # `-I` chain (mig/ks ahead of mig for osfmk) rather than hitting a
    # same-directory sibling. Reproduce that by keeping stubs off the path.
    srv_dir = out / "srv"
    defines = mig_config_defines(args)
    base = [
        args.mig,
        "-novouchers",
        "-migcom",
        args.mig,
        *MIG_BASE_DEFINES,
        "-target",
        args.triple,
        "-I" + str(args.srcroot / "osfmk"),
        "-I" + str(args.srcroot / "bsd"),
        "-I" + str(args.srcroot / "EXTERNAL_HEADERS"),
        "-I" + str(gen),
        *defines,
    ]

    for defs, kind, outc in MIG_JOBS:
        sub = defs.split("/")[0]
        out_dir = mig_dir / sub
        stem = outc.replace(".c", "")
        out_dir.mkdir(parents=True, exist_ok=True)
        (ks_dir / sub).mkdir(parents=True, exist_ok=True)
        (srv_dir / sub).mkdir(parents=True, exist_ok=True)

        if kind == "server":
            extra = KERNEL_SERVER + [
                "-user", "/dev/null",
                "-header", "/dev/null",
                "-server", str(srv_dir / sub / outc),
                "-sheader", str(ks_dir / sub / (stem + ".h")),
                str(args.srcroot / "osfmk" / defs),
            ]
        elif kind == "user":
            extra = KERNEL_USER + [
                "-user", str(srv_dir / sub / outc),
                "-header", str(out_dir / outc.replace("_user.c", ".h")),
                "-server", "/dev/null",
                "-sheader", "/dev/null",
                str(args.srcroot / "osfmk" / defs),
            ]
        elif kind == "user_plain":
            extra = KERNEL_USER + [
                "-user", str(srv_dir / sub / outc),
                "-header", str(out_dir / (stem + ".h")),
                "-server", "/dev/null",
                "-sheader", "/dev/null",
                str(args.srcroot / "osfmk" / defs),
            ]
        elif kind == "server_plain":
            extra = KERNEL_SERVER + [
                "-user", "/dev/null",
                "-header", "/dev/null",
                "-server", str(srv_dir / sub / outc),
                "-sheader", str(out_dir / (stem + ".h")),
                str(args.srcroot / "osfmk" / defs),
            ]
        elif kind == "uuhdr":
            extra = [
                "-user", "/dev/null",
                "-header", str(out_dir / outc),
                "-server", "/dev/null",
                "-sheader", "/dev/null",
                str(args.srcroot / "osfmk" / defs),
            ]
        elif kind == "ushdr":
            extra = [
                "-user", "/dev/null",
                "-header", "/dev/null",
                "-server", "/dev/null",
                "-sheader", str(out_dir / outc),
                str(args.srcroot / "osfmk" / defs),
            ]
        else:
            raise SystemExit(f"unknown mig job kind: {kind}")
        run(base + extra)

    # MIG's own common .defs are inputs, not outputs; nothing to do.


def gen_syscalls(args, out: Path) -> None:
    """init_sysent.c, syscalls.c, audit_kevents.c, systrace_args.c, syscall.h."""
    gen = out / "gen"
    gen.mkdir(parents=True, exist_ok=True)
    run(
        [
            "sh",
            REPO / "tools" / "buck" / "run_makesyscalls.sh",
            str(gen),
            str(args.srcroot / "bsd/kern/syscalls.master"),
            str(args.srcroot / "bsd/kern/makesyscalls.sh"),
            str(gen),
        ]
    )
    # run_makesyscalls.sh copies syscall.h/sysproto.h into <incdest>/sys for
    # includes spelled <sys/syscall.h>.
    (gen / "sys").mkdir(parents=True, exist_ok=True)


def gen_ioconf(args, out: Path) -> None:
    """xnu_config already wrote gen/ioconf.c; nothing further."""
    src = out / "gen" / "ioconf.c"
    if not src.is_file():
        raise SystemExit(f"expected {src} from xnu_config")


def gen_version(args, out: Path) -> None:
    gen = out / "gen"
    run(
        [
            sys.executable,
            REPO / "tools" / "buck" / "stamp_version.py",
            "--template",
            str(args.srcroot / "config" / "version.c.template"),
            "--output",
            str(gen / "version.c"),
            "--config",
            args.kernel_config,
            "--version",
            args.version,
            "--objroot",
            str(out),
        ]
    )


def gen_iostorage(args, out: Path) -> None:
    """Export IOStorageFamily headers and build its DriverKit IIG.

    Mirrors subprojects/packagefiles/iostorage/meson.build: the family's
    headers are published as <IOKit/storage/...>, and
    IOUserBlockStorageDevice.iig produces one more IIG translation unit.
    """
    src = args.srcroot / "subprojects" / "IOStorageFamily"
    if not src.is_dir():
        return
    gen = out / "gen"
    for dest in (gen / "export" / "IOKit" / "storage", gen / "IOKit" / "storage"):
        dest.mkdir(parents=True, exist_ok=True)
        for h in sorted(src.glob("*.h")):
            shutil.copy2(h, dest / h.name)

    defs = src / "BlockStorageDeviceDriverKit" / "IOUserBlockStorageDevice.iig"
    if not defs.is_file():
        return
    hdr_dir = gen / "export" / "DriverKit"
    hdr_dir.mkdir(parents=True, exist_ok=True)
    iig_dir = out / "iig"
    iig_dir.mkdir(parents=True, exist_ok=True)
    flags = IIG_CFLAGS + [
        "-I" + str(src),
        "-I" + str(args.srcroot / "iokit"),
        "-I" + str(args.srcroot / "osfmk"),
        "-I" + str(args.srcroot / "bsd"),
        "-I" + str(args.srcroot / "EXTERNAL_HEADERS"),
        "-I" + str(gen),
        "-I" + str(gen / "export"),
        "-I" + str(gen / "sys"),
    ]
    run(
        [
            args.iig,
            "--def", str(defs),
            "--header", str(hdr_dir / "IOUserBlockStorageDevice.h"),
            "--impl", str(iig_dir / "IOUserBlockStorageDevice.iig.cpp"),
            "--framework-name", "DriverKit",
            "--",
            *flags,
        ]
    )


def gen_iig(args, out: Path) -> None:
    iig_dir = out / "iig"
    hdr_dir = out / "gen" / "export" / "DriverKit"
    iig_dir.mkdir(parents=True, exist_ok=True)
    hdr_dir.mkdir(parents=True, exist_ok=True)
    srcroot = args.srcroot
    flags = IIG_CFLAGS + [
        "-I" + str(srcroot / "iokit"),
        "-I" + str(srcroot / "osfmk"),
        "-I" + str(srcroot / "bsd"),
        "-I" + str(srcroot / "EXTERNAL_HEADERS"),
        "-I" + str(out / "gen"),
        "-I" + str(out / "gen" / "export"),
        "-I" + str(out / "gen" / "sys"),
    ]
    for name in IIG_DEFS:
        impl = iig_dir / f"{name}.iig.cpp"
        hdr = hdr_dir / f"{name}.h"
        run(
            [
                args.iig,
                "--def", str(srcroot / "iokit" / "DriverKit" / f"{name}.iig"),
                "--header", str(hdr),
                "--impl", str(impl),
                "--framework-name", "DriverKit",
                "--",
                *flags,
            ]
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", type=Path, required=True)
    ap.add_argument("--srcroot", type=Path, default=REPO)
    ap.add_argument("--mig", required=True)
    ap.add_argument("--iig", required=True)
    ap.add_argument("--jobs", required=True, help="JSON: MIG and IIG job tables")
    ap.add_argument("--board", default="qemu")
    ap.add_argument("--kernel-config", default="DEVELOPMENT")
    ap.add_argument("--page-size", choices=("4k", "16k"), default="4k")
    ap.add_argument("--triple", required=True)
    ap.add_argument("--version", default="27.0.0")
    args = ap.parse_args()

    jobs = json.loads(args.jobs)
    MIG_JOBS[:] = [tuple(j) for j in jobs["mig_jobs"]]
    IIG_DEFS[:] = jobs["iig_defs"]

    out = args.outdir.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    gen_config(args, out)
    gen_mig(args, out)
    gen_syscalls(args, out)
    gen_ioconf(args, out)
    gen_version(args, out)
    gen_iig(args, out)
    gen_iostorage(args, out)

    # Provenance marker so the tree is self-describing.
    (out / "manifest.txt").write_text(
        f"board={args.board}\nkernel_config={args.kernel_config}\n"
        f"page_size={args.page_size}\ntriple={args.triple}\nversion={args.version}\n"
    )
    print(f"generated {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
