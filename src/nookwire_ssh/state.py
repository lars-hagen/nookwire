"""Runtime state for the Nookwire SSH CLI.

Owns the state directory, PID files (with process-identity protection against
recycled PIDs), the password and meta files, the stable session id, and the key
permission repair for the srv.us tunnel. Porting these one-for-one from the
shell launcher: the printed strings and the file layout are preserved so
existing installs and the test assertions keep working.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

SRVUS_HOST_RE = re.compile(r"https://([A-Za-z0-9.-]+\.srv\.us)/?")


def state_dir() -> Path:
    default = os.environ.get(
        "XDG_STATE_HOME",
        os.path.join(os.path.expanduser("~"), ".local", "state"),
    )
    base = os.environ.get(
        "NOOKWIRE_STATE_DIR",
        os.environ.get("NOOKWIRE_SSH_STATE_DIR", default),
    )
    return Path(base) / "nookwire-ssh"


def tunnel_key_path(state: Path | None = None) -> Path:
    """Return the authoritative key path for tunnel authentication.

    For backwards compatibility:
    1. If a dedicated key already exists at state_dir/tunnel_id_ed25519, use it.
    2. If a legacy key exists at ~/.ssh/id_ed25519, preserve and use it.
    3. Otherwise, use the dedicated key path under state_dir for newly generated keys.
    """
    st_dir = state if state is not None else state_dir()
    dedicated = st_dir / "tunnel_id_ed25519"
    if dedicated.is_file():
        return dedicated
    legacy = Path(os.path.expanduser("~/.ssh/id_ed25519"))
    if legacy.is_file():
        return legacy
    return dedicated


def setup_state() -> Path:
    """Create the state directory with owner-only access."""
    directory = state_dir()
    os.umask(0o077)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    return directory


def process_identity(pid: int) -> str | None:
    """Hash an origin for ``pid`` so a recycled pid is never mistaken for ours.

    Uses /proc/PID/stat field 20 (starttime) when available, else the ps start
    time, exactly as the shell launcher did. Returns None when the pid cannot
    be inspected.
    """
    proc_stat = Path("/proc") / str(pid) / "stat"
    try:
        if proc_stat.is_file():
            data = proc_stat.read_text().rsplit(")", 1)[1].split()[19]
        else:
            data = subprocess.check_output(
                ["ps", "-p", str(pid), "-o", "lstart="], text=True
            ).strip()
    except (OSError, IndexError, subprocess.SubprocessError):
        return None
    if not data:
        return None
    return hashlib.sha256(data.encode()).hexdigest()


def read_pid(pid_file: Path) -> int | None:
    """Return the pid recorded in ``pid_file``, or None if malformed/absent."""
    with contextlib.suppress(OSError):
        fields = pid_file.read_text().split()
        if fields and fields[0].isdigit():
            return int(fields[0])
    return None


def _identity_of(pid_file: Path) -> str | None:
    with contextlib.suppress(OSError):
        fields = pid_file.read_text().split()
        if len(fields) == 2:
            return fields[1]
    return None


def is_running(pid_file: Path) -> bool:
    """True when the recorded pid is alive and still matches its identity."""
    pid = read_pid(pid_file)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    identity = process_identity(pid)
    return identity is not None and identity == _identity_of(pid_file)


def write_pid(pid_file: Path, pid: int) -> bool:
    """Record ``pid IDENTITY``; fails rather than track an unidentifiable pid."""
    identity = process_identity(pid)
    if identity is None:
        return False
    try:
        pid_file.write_text(f"{pid} {identity}\n")
    except OSError:
        return False
    return True


def kill_untracked(pid: int) -> None:
    """Stop a background process we cannot track via a pid file."""
    with contextlib.suppress(OSError):
        os.kill(pid, 15)
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.1)
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, 9)


def stop_one(pid_file: Path) -> None:
    """Stop the process recorded in ``pid_file``, guarding against recycled pids."""
    pid = read_pid(pid_file)
    if pid is None:
        pid_file.unlink(missing_ok=True)
        return
    if is_running(pid_file):
        with contextlib.suppress(OSError):
            os.kill(pid, 15)
        for _ in range(50):
            if not is_running(pid_file):
                break
            time.sleep(0.1)
        else:
            with contextlib.suppress(OSError):
                os.kill(pid, 9)
    pid_file.unlink(missing_ok=True)


def port_open(port: int) -> bool:
    with contextlib.suppress(OSError):
        connection = socket.create_connection(("127.0.0.1", port), 0.2)
        connection.close()
        return True
    return False


def extract_host(tunnel_log: Path) -> str:
    """Return the last srv.us https host the tunnel log announced, if any."""
    try:
        text = tunnel_log.read_text(errors="replace")
    except OSError:
        return ""
    hosts = SRVUS_HOST_RE.findall(text)
    return hosts[-1] if hosts else ""


def generate_password() -> str:
    return secrets.token_urlsafe(32)


def get_or_create_session() -> str:
    """Reuse the persisted session id so the tunnel URL is stable across restarts."""
    session_file = state_dir() / "session"
    try:
        persisted = session_file.read_text().strip()
        if persisted:
            return persisted
    except OSError:
        pass
    session = secrets.token_urlsafe(24)
    session_file.write_text(session + "\n")
    return session


def meta_get(key: str) -> str:
    """Read a single ``key=value`` line from the meta file; '' when absent."""
    try:
        for line in (state_dir() / "meta").read_text().splitlines():
            if line.startswith(key + "="):
                return line[len(key) + 1 :]
    except OSError:
        pass
    return ""


def write_meta(entries: dict[str, str]) -> None:
    content = "".join(f"{key}={value}\n" for key, value in entries.items())
    (state_dir() / "meta").write_text(content)


def read_config() -> dict[str, str]:
    """Return the settings saved by the last successful start.

    Unlike ``meta``, this survives ``stop`` so a later bare ``start`` can reuse
    the backend, hostname and token without retyping them.
    """
    settings: dict[str, str] = {}
    try:
        for line in (state_dir() / "config").read_text().splitlines():
            key, separator, value = line.partition("=")
            if separator and value:
                settings[key] = value
    except OSError:
        pass
    return settings


def write_config(entries: dict[str, str]) -> None:
    """Persist start settings owner-readable only; this file holds the token."""
    config = state_dir() / "config"
    content = "".join(f"{key}={value}\n" for key, value in entries.items() if value)
    config.write_text(content)
    with contextlib.suppress(OSError):
        config.chmod(0o600)


def repair_key_permissions(key: Path) -> None:
    """chmod an srv.us tunnel key to 0600, mirroring OpenSSH's restriction.

    The key itself is created by the tunnel, not the CLI; but OpenSSH shares
    this path and refuses a group- or world-readable key, so the mode is still
    repaired here. The printed lines go to stderr exactly as the launcher's did.
    """
    if not key.is_file():
        return
    mode = key.stat().st_mode & 0o777
    if mode == 0o600:
        return
    try:
        key.chmod(0o600)
    except OSError:
        print(
            f"Warning: could not fix permissions on {key} (mode {mode:03o})",
            file=sys.stderr,
        )
        return
    print(
        f"Fixed permissions on {key} (was {mode:03o}, now 600)",
        file=sys.stderr,
    )
