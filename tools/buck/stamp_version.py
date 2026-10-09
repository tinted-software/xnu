#!/usr/bin/env python3
"""Stamp config/version.c.template → version.c (subset of config/newvers.pl)."""

from __future__ import annotations

import argparse
import getpass
import time
from pathlib import Path


def stamp(
    template: Path, output: Path, *, config: str, version: str, objroot: str
) -> None:
    text = template.read_text()
    major, minor, rev = (version.split(".") + ["0", "0", "0"])[:3]
    repl = {
        "###KERNEL_VERSION_LONG###": version,
        "###KERNEL_VERSION_SHORT###": version,
        "###KERNEL_VERSION_MAJOR###": major,
        "###KERNEL_VERSION_MINOR###": minor,
        "###KERNEL_VERSION_VARIANT###": rev,
        "###KERNEL_VERSION_REVISION###": rev,
        "###KERNEL_VERSION_STAGE###": "VERSION_STAGE_DEV",
        "###KERNEL_VERSION_PRERELEASE_LEVEL###": "0",
        "###KERNEL_BUILD_CONFIG###": config.lower(),
        "###KERNEL_BUILDER###": getpass.getuser(),
        "###KERNEL_BUILD_OBJROOT###": objroot,
        "###KERNEL_BUILD_DATE###": time.strftime("%a %b %d %H:%M:%S %Z %Y"),
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--config", default="development")
    ap.add_argument("--version", default="99.0.0")
    ap.add_argument("--objroot", default="meson-build")
    args = ap.parse_args()
    stamp(
        args.template,
        args.output,
        config=args.config,
        version=args.version,
        objroot=args.objroot,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
