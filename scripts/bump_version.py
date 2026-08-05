#!/usr/bin/env python3
"""Bump the nookwire-ssh version from a single source of truth.

Usage: uv run scripts/bump_version.py 1.5.0

``pyproject.toml`` is authoritative. The launcher, installer, and Python server
are standalone artifacts that cannot import it, so each embeds its own VERSION;
this script rewrites all of them plus the uv lockfile so a release is one
command from one place.
"""

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def replace(path: Path, pattern: re.Pattern, replacement: str) -> bool:
    text = path.read_text()
    new, count = pattern.subn(replacement, text, count=1)
    rel = path.relative_to(ROOT)
    if count != 1:
        raise SystemExit(
            f"Expected exactly one match for {pattern.pattern!r} in {rel}, found {count}"
        )
    if new != text:
        path.write_text(new)
        return True
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description="Bump the nookwire-ssh version")
    ap.add_argument("version", help="new version, e.g. 1.5.0")
    args = ap.parse_args()

    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        ap.error(f"version must look like 1.2.3, got {args.version!r}")
    version = args.version

    targets = [
        (
            ROOT / "pyproject.toml",
            re.compile(r'(^version = ")[^"]+(")', re.M),
            f'\\g<1>{version}\\g<2>',
        ),
        (
            ROOT / "nookwire_ssh.py",
            re.compile(r'(^VERSION = ")[^"]+(")', re.M),
            f'\\g<1>{version}\\g<2>',
        ),
        (
            ROOT / "install.sh",
            re.compile(r"(NOOKWIRE_SSH_VERSION:-)[0-9.]+(\})"),
            f"\\g<1>{version}\\g<2>",
        ),
        (
            ROOT / "nookwire-ssh",
            re.compile(r'(^VERSION=")[^"]+(")', re.M),
            f'\\g<1>{version}\\g<2>',
        ),
    ]

    updated = []
    for rel, pattern, replacement in targets:
        if replace(rel, pattern, replacement):
            updated.append(rel.name)

    subprocess.run(["uv", "lock"], cwd=ROOT, check=True)
    updated.append("uv.lock (regenerated)")

    print("Updated:")
    for name in updated:
        print(f"  {name}")


if __name__ == "__main__":
    main()
