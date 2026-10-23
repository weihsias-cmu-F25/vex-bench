"""Repair macOS hidden flags on this project's editable-install .pth files.

CPython skips .pth files with UF_HIDDEN. Reinstalling with a cache that carries
this flag can reproduce the issue. This changes flags only, never contents.
"""

import os
import stat
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for package_dir in (root / ".venv/lib").glob("python*/site-packages"):
    for pattern in ("__editable__.vex_bench-*.pth", "_virtualenv.pth"):
        for file in package_dir.glob(pattern):
            flags = getattr(file.stat(), "st_flags", 0)
            hidden = getattr(stat, "UF_HIDDEN", 0)
            if hidden and flags & hidden:
                os.chflags(file, flags & ~hidden)
                print(f"Cleared hidden flag: {file.relative_to(root)}")
            else:
                print(f"No hidden flag: {file.relative_to(root)}")
