"""The ssh-config block for Nookwire SSH.

``ssh-config`` prints a ``Host`` block so plain ``ssh USER@HOST`` works on the
connecting machine. With no HOST it prints the default ``Host *.srv.us`` block
for the srv.us backend; with a HOST it prints a block for that host using the
currently configured backend's ProxyCommand. ``--write`` appends it to
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

SRVUS_PROXY_COMMAND = (
    "openssl s_client -quiet -no_ign_eof -verify_return_error "
    "-verify_hostname %h -connect %h:443 -servername %h 2>/dev/null"
)
DEFAULT_HOST = "*.srv.us"


def block(host: str, proxy_command: str) -> str:
    """Build the ssh-config block for a host and ProxyCommand."""
    return (
        f"Host {host}\n"
        f"  ProxyCommand {proxy_command}\n"
        "  StrictHostKeyChecking no\n"
        "  UserKnownHostsFile /dev/null\n"
        "  LogLevel ERROR"
    )


def config_path() -> Path:
    return Path(os.path.expanduser("~/.ssh/config"))


def print_block(
    host: str = DEFAULT_HOST, proxy_command: str = SRVUS_PROXY_COMMAND
) -> None:
    print(block(host, proxy_command))


def write(
    host: str = DEFAULT_HOST, proxy_command: str = SRVUS_PROXY_COMMAND
) -> int:
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
            line.strip().startswith("Host " + host)
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
                handle.write(block(host, proxy_command) + "\n")
            config.chmod(0o600)
        except OSError as error:
            _error(f"Unable to write {config}: {error}")
            return 1
        print(f"Added the {host} block to {config}")

    # ssh takes the first value it finds for each keyword, so an earlier
    # matching block wins. Ask ssh what it will actually do rather than assuming.
    ssh = shutil.which("ssh")
    if ssh:
        probe = host.replace("*", "example")
        try:
            resolved = subprocess.run(
                [ssh, "-G", probe],
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
        marker = proxy_command.split()[0]
        if marker not in proxycommand:
            _error(
                f"Warning: an earlier block in {config} overrides it; move the "
                f'{host} block above any "Host *" block.'
            )
    return 0


def _error(message: str) -> None:
    print(message, file=sys.stderr)
