"""The srv.us ssh-config block.

``ssh-config`` prints the ``Host *.srv.us`` block so a plain ``ssh USER@HOST``
works over TLS on the connecting machine. ``--write`` appends it to
~/.ssh/config (never prepends, which would drag any leading global keywords
under the new Host block), is idempotent, chmods the file to 0600, and then runs
``ssh -G`` to confirm the block actually took effect.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

BLOCK = """\
Host *.srv.us
  ProxyCommand openssl s_client -quiet -no_ign_eof -verify_return_error -verify_hostname %h -connect %h:443 -servername %h 2>/dev/null
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR"""


def config_path() -> Path:
    return Path(os.path.expanduser("~/.ssh/config"))


def print_block() -> None:
    print(BLOCK)


def write() -> int:
    config = config_path()
    ssh_dir = config.parent
    try:
        ssh_dir.mkdir(parents=True, exist_ok=True)
        ssh_dir.chmod(0o700)
    except OSError:
        _error(f"Unable to prepare {ssh_dir}")
        return 1

    try:
        present = config.is_file() and any(
            line.strip().startswith("Host *.srv.us")
            for line in config.read_text().splitlines()
        )
    except OSError:
        present = False
    if present:
        print(f"Already present in {config}")
    else:
        # Appending never changes the meaning of existing lines, unlike
        # prepending, which would pull any leading global keywords under this
        # Host block.
        try:
            with open(config, "a") as handle:
                if config.exists() and config.stat().st_size > 0:
                    handle.write("\n")
                handle.write(BLOCK + "\n")
            config.chmod(0o600)
        except OSError as error:
            _error(f"Unable to write {config}: {error}")
            return 1
        print(f"Added the srv.us block to {config}")

    # ssh takes the first value it finds for each keyword, so an earlier
    # matching block wins. Ask ssh what it will actually do rather than assuming.
    ssh = shutil.which("ssh")
    if ssh:
        try:
            resolved = subprocess.run(
                [ssh, "-G", "example.srv.us"],
                capture_output=True,
                text=True,
                timeout=15,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return 0
        proxycommand = next(
            (
                line.split(" ", 1)[1].strip()
                for line in resolved.splitlines()
                if line.lower().startswith("proxycommand ")
            ),
            "",
        )
        if "s_client" not in proxycommand:
            _error(
                f"Warning: an earlier block in {config} overrides it; move the "
                'srv.us block above any "Host *" block.'
            )
    return 0


def _error(message: str) -> None:
    print(message, file=sys.stderr)
