"""Current-account helpers for hosts without a passwd database entry."""

from __future__ import annotations

import getpass
import os


def current_username(default: str = "nookwire") -> str:
    """Return the current username, or a stable fallback for synthetic UIDs."""
    try:
        return getpass.getuser() or default
    except (KeyError, OSError):
        return default


def ensure_username_environment(username: str | None = None) -> str:
    """Populate the account variables required by libraries such as AsyncSSH."""
    resolved = username or current_username()
    for name in ("USER", "LOGNAME"):
        if not os.environ.get(name):
            os.environ[name] = resolved
    return resolved
