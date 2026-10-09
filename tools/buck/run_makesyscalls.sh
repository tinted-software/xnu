#!/bin/sh
# $1 = @OUTDIR@  $2 = syscalls.master  $3 = makesyscalls.sh  $4 = include dest (gen/)
set -e
outdir="$1"
master="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
script="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
incdest="${4:-}"
if [ -n "$incdest" ]; then
  mkdir -p "$incdest"
  incdest="$(cd "$incdest" && pwd)"
fi
mkdir -p "$outdir"
cd "$outdir"
sh "$script" "$master" table
sh "$script" "$master" names
sh "$script" "$master" audit
sh "$script" "$master" systrace
sh "$script" "$master" header
sh "$script" "$master" proto
if [ -n "$incdest" ]; then
  mkdir -p "$incdest/sys"
  for f in syscall.h sysproto.h; do
    if [ ! -f "$incdest/sys/$f" ] || ! cmp -s "$f" "$incdest/sys/$f"; then
      cp -f "$f" "$incdest/sys/"
    fi
  done
fi
