#!/usr/bin/env python3
"""Generate the cdhash golden set from an Apple restore image.

Inputs (extracted from an IPSW, unencrypted images only):
  --trustcache  Firmware/<image>.dmg.trustcache (IM4P-wrapped trust cache)
  --root        directory tree of the extracted image

For every thin Mach-O with an embedded CodeDirectory, the cdhash is the first
20 bytes of SHA-256(CodeDirectory). Apple's trust cache must list each one; the
script checks that and writes "cdhash  path" lines, plus a count of trust cache
entries that no binary in --root produced.

Trust cache payload (version 1): u32 version, 16-byte uuid, u32 count, then
count entries of 22 bytes: cdhash[20], hash_type, flags.
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys


def trust_cache_hashes(path):
    der = open(path, "rb").read()
    # The IM4P wrapper's payload is the single OCTET STRING; openssl extracts it.
    out = subprocess.run(
        ["openssl", "asn1parse", "-inform", "DER", "-in", path],
        capture_output=True, text=True, check=True,
    ).stdout
    hexs = None
    for line in out.splitlines():
        if "OCTET STRING" in line and "[HEX DUMP]" in line:
            hexs = line.split(":")[-1].strip()
    if hexs is None:
        raise SystemExit(f"{path}: no IM4P payload found")
    pay = bytes.fromhex(hexs)
    version, = struct.unpack_from("<I", pay, 0)
    if version != 1:
        raise SystemExit(f"{path}: unsupported trust cache version {version}")
    count, = struct.unpack_from("<I", pay, 20)
    if 24 + 22 * count != len(pay):
        raise SystemExit(f"{path}: payload length does not match entry count")
    return {pay[24 + 22 * i:24 + 22 * i + 20].hex() for i in range(count)}, count


def cdhash(path):
    d = open(path, "rb").read()
    if d[:4] != b"\xcf\xfa\xed\xfe":  # 64-bit little-endian thin Mach-O
        return None
    ncmds, = struct.unpack_from("<I", d, 16)
    off = 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", d, off)
        if cmd == 0x1D:  # LC_CODE_SIGNATURE
            dataoff, datasz = struct.unpack_from("<II", d, off + 8)
            sb = d[dataoff:dataoff + datasz]
            if struct.unpack_from(">I", sb, 0)[0] != 0xFADE0CC0:
                return None
            for i in range(struct.unpack_from(">I", sb, 8)[0]):
                stype, soff = struct.unpack_from(">II", sb, 12 + 8 * i)
                if stype == 0:  # CSSLOT_CODEDIRECTORY
                    cdlen, = struct.unpack_from(">I", sb, soff + 4)
                    return hashlib.sha256(sb[soff:soff + cdlen]).digest()[:20].hex()
            return None
        off += cs
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trustcache", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    trust, count = trust_cache_hashes(args.trustcache)
    rows = []
    for dirpath, _, files in os.walk(args.root):
        for name in files:
            p = os.path.join(dirpath, name)
            if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p) < 32:
                continue
            h = cdhash(p)
            if h is None:
                continue
            if h not in trust:
                print(f"NOT IN TRUST CACHE: {h} {p}", file=sys.stderr)
                return 1
            rows.append((h, os.path.relpath(p, args.root)))

    produced = {h for h, _ in rows}
    rows.sort()
    with open(args.out, "w") as f:
        f.write("# cdhash (SHA-256 of CodeDirectory, first 20 bytes)  path\n")
        for h, rel in rows:
            f.write(f"{h}  {rel}\n")
    print(f"binaries {len(rows)}, distinct cdhashes {len(produced)}, "
          f"trust cache entries {count}, entries without a binary {len(trust - produced)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
