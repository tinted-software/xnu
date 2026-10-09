#!/usr/bin/env bash
args=()
for arg in "$@"; do
    case "$arg" in
        -fuse-ld=*) ;;
        *) args+=("$arg") ;;
    esac
done
exec lld "${args[@]}"
