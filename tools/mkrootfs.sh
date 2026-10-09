#!/usr/bin/env bash
# Stages the userspace sysroot and init into one tree and packs it into a
# read-only APFS container with tools/mkapfs.
#
# Usage: tools/mkrootfs.sh <mkapfs> <sysroot-dir> <init-binary> <output.img> [size]
#   mkapfs: path to the built //tools/mkapfs:mkapfs binary
#   size:   container size (default 16M; the boot RAM disk window is 16 MiB)
set -euo pipefail

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 <mkapfs> <sysroot-dir> <init-binary> <output.img> [size]" >&2
    exit 2
fi

mkapfs=$1
sysroot=$2
init=$3
out=$4
size=${5:-16M}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

cp -R "$sysroot"/. "$stage"/
mkdir -p "$stage/sbin" "$stage/dev"
cp "$init" "$stage/sbin/launchd"
chmod 755 "$stage/sbin/launchd"

"$mkapfs" --size "$size" --label rootfs -o "$out" "$stage"
