#!/usr/bin/env python3
"""Run a built XNU kernelcache under QEMU's `virt` machine.

Takes the artifacts of a Buck2 build explicitly (see doc/BUCK2.md):

    K=$(buck2 build //:kernelcache --show-full-output | awk '{print $2}')
    B=$(buck2 build //:qemu-boot  --show-full-output | awk '{print $2}')
    python3 tools/qemu.py --kernel $K --bootloader $B \\
        --rootfs root.apfs --bootargs 'rd=disk0'

The bootloader (tools/qemu-boot) is loaded with `-kernel`; the kernelcache, an
optional trust cache and the extra boot-args are placed at the physical
addresses it reads them from, and the root image is attached as a read-only
virtio-blk disk.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Physical addresses tools/qemu-boot reads its inputs from.
KERNELCACHE_PHYS = 0x48000000
TRUST_CACHE_PHYS = 0x4FE00000  # tools/qemu-boot TRUST_CACHE_PHYS
EXTRA_ARGS_PHYS = 0x4FF00000  # tools/qemu-boot EXTRA_ARGS_PHYS

# arm64e needs pointer authentication, and the kernel and user code sign with
# QEMU's implementation-defined algorithm, which is the fast one.
DEFAULT_CPU = "max,pauth=on,pauth-impdef=on"


def find_qemu_bin(override: str | None) -> str:
    """Find the qemu-system-aarch64 executable."""
    for cand in (override, os.environ.get("QEMU"), "qemu-system-aarch64"):
        if cand and (shutil.which(cand) or os.path.exists(cand)):
            return cand
    raise FileNotFoundError("qemu-system-aarch64 not found; pass --qemu-bin or set $QEMU")


def qemu_command(args: argparse.Namespace, extra: list[str]) -> list[str]:
    """The qemu-system-aarch64 command line for `args`."""
    for name in ("kernel", "bootloader", "rootfs", "trustcache"):
        path = getattr(args, name)
        if path and not Path(path).is_file():
            raise FileNotFoundError(f"--{name}: {path} does not exist")

    cmd = [
        find_qemu_bin(args.qemu_bin),
        "-M", "virt",
        "-cpu", args.cpu,
        "-m", str(args.memory),
        "-smp", str(args.smp),
        "-nographic",
        "-kernel", str(Path(args.bootloader).resolve()),
        "-device", f"loader,force-raw=on,addr={KERNELCACHE_PHYS:#x},file={Path(args.kernel).resolve()}",
    ]

    if args.rootfs:
        # IOVirtioBlk speaks virtio-mmio v2 (modern); QEMU defaults to legacy v1.
        cmd += [
            "-global", "virtio-mmio.force-legacy=false",
            "-drive", f"file={Path(args.rootfs).resolve()},if=none,format=raw,id=hd0,readonly=on",
            "-device", "virtio-blk-device,drive=hd0",
        ]

    if args.trustcache:
        cmd += ["-device", f"loader,force-raw=on,addr={TRUST_CACHE_PHYS:#x},file={Path(args.trustcache).resolve()}"]

    if args.bootargs is not None:
        blob = tempfile.NamedTemporaryFile(prefix="xnu-bootargs-", delete=False)
        blob.write(b"XNUARGS\0" + args.bootargs.encode() + b"\0")
        blob.close()
        cmd += ["-device", f"loader,force-raw=on,addr={EXTRA_ARGS_PHYS:#x},file={blob.name}"]

    if args.gdb or args.gdb_wait:
        cmd.append("-s")
    if args.gdb_wait:
        cmd.append("-S")

    return cmd + extra


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("-k", "--kernel", required=True, help="kernelcache (//:kernelcache)")
    parser.add_argument("-b", "--bootloader", required=True, help="qemu-boot ELF (//:qemu-boot)")
    parser.add_argument("-r", "--rootfs", help="APFS root image, attached as virtio-blk (boot with rd=disk0)")
    parser.add_argument("--bootargs", help="boot-args appended to the loader's defaults, e.g. 'rd=disk0 -s'")
    parser.add_argument("--trustcache", help="trust_cache_offsets_t blob (tools/trustcache wrap)")
    parser.add_argument("--cpu", default=DEFAULT_CPU, help=f"QEMU CPU model (default: {DEFAULT_CPU})")
    parser.add_argument("-m", "--memory", type=int, default=1024, help="guest RAM in MB (default: 1024)")
    parser.add_argument("-c", "--smp", type=int, default=2, help="guest cores (default: 2)")
    parser.add_argument("-s", "--gdb", action="store_true", help="GDB server on TCP port 1234")
    parser.add_argument("-S", "--gdb-wait", action="store_true", help="GDB server, CPU frozen at startup")
    parser.add_argument("--qemu-bin", help="qemu-system-aarch64 to run (default: $QEMU or PATH)")
    args, extra = parser.parse_known_args()

    cmd = qemu_command(args, extra)
    print("==> " + " ".join(cmd), file=sys.stderr)
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
