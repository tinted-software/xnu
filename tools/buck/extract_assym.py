#!/usr/bin/env python3
"""Turn clang -S output of genassym.c into assym.s #defines (Makefile sed)."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def extract(asm: str) -> str:
    pat = re.compile(
        r"DEFINITION__define__([A-Za-z0-9_]+):\s*"
        r"(?:\n[ \t]*)?"
        r'\.ascii[ \t]+"[\$#]*([-0-9#]+)"',
        re.M,
    )
    lines: list[str] = []
    for name, val in pat.findall(asm):
        lines.append(f"#define {name} {val}")
        num = val.replace("#", "").replace("$", "")
        if re.fullmatch(r"-?[0-9]+", num):
            lines.append(f"#define {name}_NUM {num}")
    return "\n".join(lines) + ("\n" if lines else "")


def main() -> int:
    text = extract(Path(sys.argv[1]).read_text())
    out_path = Path(sys.argv[2])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text)
    if len(sys.argv) > 3:
        dest = Path(sys.argv[3])
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
