#!/usr/bin/env bash
# Builds an APFS image with mkapfs and checks it with the hadris CLI oracle
# (the reference reader: `hadris apfs info|ls|stat|cat|extract`).
#
# Usage: tools/mkapfs/verify.sh [source-dir]
#   source-dir  tree to pack; default: a generated rootfs-shaped tree
#               (sbin/launchd, dev/, usr/lib/... with a symlink, an empty file)
#
# Environment:
#   HADRIS=/path/to/hadris   oracle binary (default: hadris on PATH)
#   MKAPFS=/path/to/mkapfs   skip the Buck build and use this binary
#   SIZE=16M                 container size
#   KEEP=1                   keep the work directory
#
#   cargo install hadris-cli --version 3.0.0-rc.1
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
hadris=${HADRIS:-hadris}
size=${SIZE:-16M}

work=$(mktemp -d)
if [ -z "${KEEP:-}" ]; then trap 'rm -rf "$work"' EXIT; else echo "work dir: $work"; fi

if [ -z "${MKAPFS:-}" ]; then
    (cd "$root" && buck2 build //tools/mkapfs:mkapfs >&2)
    MKAPFS=$root/$(cd "$root" && buck2 build //tools/mkapfs:mkapfs --show-output 2>/dev/null | awk '{print $2}')
fi

if [ "$#" -ge 1 ]; then
    src=$1
else
    src=$work/src
    mkdir -p "$src/sbin" "$src/dev" "$src/usr/lib/system" "$src/etc"
    head -c 190000 /dev/urandom > "$src/sbin/launchd";                    chmod 755 "$src/sbin/launchd"
    head -c 5000   /dev/urandom > "$src/usr/lib/libSystem.B.dylib";       chmod 755 "$src/usr/lib/libSystem.B.dylib"
    head -c 655000 /dev/urandom > "$src/usr/lib/system/libsystem_kernel.dylib"
    ln -s libSystem.B.dylib "$src/usr/lib/libSystem.dylib"
    : > "$src/etc/empty"
    printf 'hello\n' > "$src/etc/motd"; chmod 600 "$src/etc/motd"
    for i in $(seq 1 150); do printf 'file %s\n' "$i" > "$src/etc/entry-$i-$(printf 'n%.0s' $(seq 1 $((i % 40))))"; done
fi

img=$work/rootfs.apfs
"$MKAPFS" --size "$size" --label rootfs -o "$img" "$src"

echo "== info"
"$hadris" apfs info "$img" | tee "$work/info.txt"
grep -q '^Block size: 4096$' "$work/info.txt"
grep -q 'Volume 0: rootfs' "$work/info.txt"
grep -q '0 snapshots' "$work/info.txt"

echo "== ls /"
"$hadris" apfs ls "$img" / | sort > "$work/ls-root.txt"
(cd "$src" && ls -A | sort) | diff - "$work/ls-root.txt"

echo "== stat / cat"
for f in $(cd "$src" && find . -type f -size +0 | sed 's|^\./|/|'); do
    "$hadris" apfs stat "$img" "$f" > /dev/null
    "$hadris" apfs cat "$img" "$f" | cmp - "$src$f"
done
while IFS= read -r l; do
    "$hadris" apfs stat "$img" "${l#"$src"}" | grep -q 'file_type: Symlink'
done < <(find "$src" -type l)

echo "== extract"
mkdir "$work/out"
"$hadris" apfs extract "$img" -o "$work/out" 2> "$work/extract.err" || { cat "$work/extract.err"; exit 1; }
diff -r "$src" "$work/out"
tree() { (cd "$1" && find . -printf '%P\t%y\t%m\t%l\n' | sort); }
diff <(tree "$src") <(tree "$work/out")

echo "== layout: every non-empty file is one contiguous extent"
# Reported allocation == size rounded up to the 4096-byte block, i.e. a single
# extent record covers the whole file (checked structurally by the round-trip
# test; here we check what the oracle can see).
for f in $(cd "$src" && find . -type f -size +0 | sed 's|^\./|/|'); do
    len=$(stat -c %s "$src$f")
    want=$(( (len + 4095) / 4096 * 4096 ))
    got=$("$hadris" apfs stat "$img" "$f" | awk '/allocated:/ {gsub(",","",$2); print $2}')
    [ "$got" = "$want" ] || { echo "$f: allocated $got, want $want" >&2; exit 1; }
done

echo "OK"
