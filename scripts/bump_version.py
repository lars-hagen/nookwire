#!/usr/bin/env python3
"""Bump the Nookwire version.

Usage: uv run scripts/bump_version.py 1.7.0

``src/nookwire_ssh/__init__.py`` is the single source of truth: ``pyproject.toml``
reads it as a dynamic attribute and the CLI reads it back through
importlib.metadata. ``install.sh`` is the one artifact that cannot import it,
because it runs before the package exists, so it carries the release tag as a
literal and has to be rewritten here as well.
"""

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def replace(path: Path, pattern: re.Pattern, replacement: str) -> None:
    text = path.read_text()
    new, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise SystemExit(
            f"Expected exactly one match for {pattern.pattern!r} in "
            f"{path.relative_to(ROOT)}, found {count}"
        )
    path.write_text(new)


def main() -> None:
    ap = argparse.ArgumentParser(description="Bump the Nookwire version")
    ap.add_argument("version", help="new version, e.g. 1.7.0")
    args = ap.parse_args()

    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        ap.error(f"version must look like 1.2.3, got {args.version!r}")

    targets = [
        (
            ROOT / "src" / "nookwire_ssh" / "__init__.py",
            re.compile(r'(^__version__ = ")[^"]+(")', re.M),
        ),
        (
            ROOT / "install.sh",
            re.compile(r"(NOOKWIRE_SSH_VERSION:-)[0-9.]+(\})"),
        ),
    ]
    for path, pattern in targets:
        replace(path, pattern, rf"\g<1>{args.version}\g<2>")

    subprocess.run(["uv", "lock"], cwd=ROOT, check=True)
    print(f"Updated to {args.version}:")
    for path, _ in targets:
        print(f"  {path.relative_to(ROOT)}")
    print("  uv.lock (regenerated)")


if __name__ == "__main__":
    main()
