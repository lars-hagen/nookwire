"""Deterministic project identity for ephemeral environments.

Derives a stable tunnel identity when no authoritative key or explicit seed
exists, ensuring endpoint continuity across container restarts without
relying on volatile environment variables or filesystem inodes.

Automatic identity provides endpoint continuity, NOT ownership secrecy:
anyone who can construct the same non-secret project selector can recreate
the same tunnel identity. Set NOOKWIRE_IDENTITY_SEED for exclusive control.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

SEED_DOMAIN = b"nookwire-ssh/srv.us/v1\0"
PROJECT_DOMAIN = b"nookwire/project-identity/v1\0"

CI_PROJECT_ENV_VARS = (
    "GITHUB_REPOSITORY",
    "CI_PROJECT_PATH",
    "BITBUCKET_REPO_FULL_NAME",
    "CIRCLE_PROJECT_REPONAME",
    "RENDER_SERVICE_NAME",
    "RAILWAY_PROJECT_NAME",
    "VERCEL_GIT_REPO_SLUG",
)

AUTO_IDENTITY_WARNING = (
    "Automatic identity provides endpoint continuity, not ownership secrecy. "
    "Anyone with access to this repository or project name can derive the same "
    "tunnel identity. Set NOOKWIRE_IDENTITY_SEED for exclusive control."
)


@dataclasses.dataclass(frozen=True)
class IdentityInfo:
    mode: str  # "seeded" | "project" | "host" | "random"
    source: str  # e.g. "NOOKWIRE_IDENTITY_SEED", "git:origin", "env:GITHUB_REPOSITORY", etc.
    fingerprint: str  # short selector fingerprint (12 hex chars) or ""
    derived_bytes: bytes | None  # 32 bytes for Ed25519 private key, or None
    warning: str | None
    scope: str  # "seed" | "project" | "host-local" | "ephemeral"


def normalize_git_remote(url: str) -> str:
    """Normalize equivalent Git remote URLs to credential-free host/path.

    Examples:
      git@github.com:owner/repo.git -> github.com/owner/repo
      https://github.com/owner/repo -> github.com/owner/repo
      ssh://git@github.com/owner/repo.git -> github.com/owner/repo
      https://user:token@github.com/owner/repo.git -> github.com/owner/repo
      git@github.com:owner/repo -> github.com/owner/repo
    """
    url = url.strip()
    if not url:
        return ""

    # Strip scheme if present (e.g. https://, http://, ssh://, git://)
    scheme_match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url)
    had_scheme = bool(scheme_match)
    if scheme_match:
        url = url[scheme_match.end() :]

    # Strip credentials before '@' (e.g. user:pass@ or git@)
    # Ensure '@' is part of user@host, not in the path
    if "@" in url:
        at_pos = url.find("@")
        slash_pos = url.find("/")
        if slash_pos == -1 or at_pos < slash_pos:
            url = url[at_pos + 1 :]

    # Check for scp-like syntax (only when there was no URL scheme): host:path
    first_slash = url.find("/")
    first_colon = url.find(":")
    if not had_scheme and first_colon != -1 and (first_slash == -1 or first_colon < first_slash):
        host, path = url.split(":", 1)
    else:
        parts = url.split("/", 1)
        host = parts[0]
        path = parts[1] if len(parts) > 1 else ""

    host = host.lower().split(":")[0]
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    path = path.strip("/")
    if not host or not path:
        return ""
    return f"{host}/{path}"


def detect_git_origin(root: Path) -> str | None:
    """Detect and normalize Git remote.origin.url for the given root directory."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            normalized = normalize_git_remote(completed.stdout.strip())
            if normalized:
                return normalized
    except (OSError, subprocess.SubprocessError):
        pass

    # Direct fallback if git CLI is unavailable or in a bare/container environment
    cur = root
    while True:
        git_dir = cur / ".git"
        if git_dir.is_file():
            try:
                content = git_dir.read_text().strip()
                if content.startswith("gitdir:"):
                    ptr = content[len("gitdir:") :].strip()
                    git_dir = (cur / ptr).resolve()
            except OSError:
                pass

        config_file = git_dir / "config" if git_dir.is_dir() else None
        if config_file and config_file.is_file():
            try:
                in_origin = False
                for line in config_file.read_text().splitlines():
                    line = line.strip()
                    if line.startswith("[") and line.endswith("]"):
                        in_origin = bool(
                            re.match(r'^\[remote\s+["\']origin["\']\]', line)
                        )
                    elif in_origin and line.startswith("url"):
                        _, sep, val = line.partition("=")
                        if sep:
                            normalized = normalize_git_remote(val.strip())
                            if normalized:
                                return normalized
            except OSError:
                pass
        if cur == cur.parent:
            break
        cur = cur.parent

    return None


def detect_ci_project(env: dict[str, str] | None = None) -> tuple[str, str] | None:
    """Inspect allowlist of stable project-level CI/PaaS environment variables."""
    environ = os.environ if env is None else env
    for var in CI_PROJECT_ENV_VARS:
        val = environ.get(var, "").strip()
        if val:
            return f"env:{var}", val
    return None


def detect_host_id() -> tuple[str, str] | None:
    """Derive a stable host id across Linux, Windows, and macOS."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        p = Path(path)
        try:
            if p.is_file():
                content = p.read_text().strip()
                if content:
                    return "host:machine-id", content
        except OSError:
            pass

    if sys.platform == "win32":
        try:
            import winreg  # type: ignore

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                if guid and guid.strip():
                    return "host:MachineGuid", guid.strip()
        except Exception:
            pass

    node = platform.node().strip()
    if node:
        return "host:node", node

    return None


def resolve_identity(
    root: Path | None = None,
    username: str | None = None,
    env: dict[str, str] | None = None,
) -> IdentityInfo:
    """Resolve project and tunnel identity according to the decision hierarchy.

    Precedence:
    1. Explicit secret seed: NOOKWIRE_IDENTITY_SEED (fallback: NOOKWIRE_SSH_IDENTITY_SEED)
    2. Explicit non-secret identity: NOOKWIRE_IDENTITY (fallback: NOOKWIRE_SSH_IDENTITY)
    3. Normalized Git remote origin of configured root
    4. Allowlisted CI/PaaS project variable
    5. Host-local identity (effective username + host id + resolved root)
    6. Random identity fallback
    """
    environ = os.environ if env is None else env
    user = username or "nookwire"
    resolved_root = (root or Path.cwd()).resolve()

    # 1. Explicit secret seed
    seed = environ.get("NOOKWIRE_IDENTITY_SEED") or environ.get(
        "NOOKWIRE_SSH_IDENTITY_SEED", ""
    )
    if seed:
        source = (
            "NOOKWIRE_IDENTITY_SEED"
            if "NOOKWIRE_IDENTITY_SEED" in environ
            else "NOOKWIRE_SSH_IDENTITY_SEED"
        )
        derived = hashlib.sha256(SEED_DOMAIN + seed.encode("utf-8")).digest()
        fp = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
        return IdentityInfo(
            mode="seeded",
            source=source,
            fingerprint=fp,
            derived_bytes=derived,
            warning=None,
            scope="seed",
        )

    # 2. Explicit non-secret identity
    ident = environ.get("NOOKWIRE_IDENTITY") or environ.get(
        "NOOKWIRE_SSH_IDENTITY", ""
    )
    if ident:
        source = (
            "env:NOOKWIRE_IDENTITY"
            if "NOOKWIRE_IDENTITY" in environ
            else "env:NOOKWIRE_SSH_IDENTITY"
        )
        raw_selector = f"{user}@{ident}"
        derived = hashlib.sha256(
            PROJECT_DOMAIN + raw_selector.encode("utf-8")
        ).digest()
        fp = hashlib.sha256(raw_selector.encode("utf-8")).hexdigest()[:12]
        return IdentityInfo(
            mode="project",
            source=source,
            fingerprint=fp,
            derived_bytes=derived,
            warning=AUTO_IDENTITY_WARNING,
            scope="project",
        )

    # 3. Normalized Git origin
    origin = detect_git_origin(resolved_root)
    if origin:
        raw_selector = f"{user}@{origin}"
        derived = hashlib.sha256(
            PROJECT_DOMAIN + raw_selector.encode("utf-8")
        ).digest()
        fp = hashlib.sha256(raw_selector.encode("utf-8")).hexdigest()[:12]
        return IdentityInfo(
            mode="project",
            source="git:origin",
            fingerprint=fp,
            derived_bytes=derived,
            warning=AUTO_IDENTITY_WARNING,
            scope="project",
        )

    # 4. CI / PaaS project variable
    ci = detect_ci_project(environ)
    if ci:
        source_name, ci_val = ci
        raw_selector = f"{user}@{ci_val}"
        derived = hashlib.sha256(
            PROJECT_DOMAIN + raw_selector.encode("utf-8")
        ).digest()
        fp = hashlib.sha256(raw_selector.encode("utf-8")).hexdigest()[:12]
        return IdentityInfo(
            mode="project",
            source=source_name,
            fingerprint=fp,
            derived_bytes=derived,
            warning=AUTO_IDENTITY_WARNING,
            scope="project",
        )

    # 5. Host-local identity
    host_info = detect_host_id()
    if host_info:
        source_name, host_id = host_info
        raw_selector = f"{user}@{host_id}:{resolved_root}"
        derived = hashlib.sha256(
            PROJECT_DOMAIN + raw_selector.encode("utf-8")
        ).digest()
        fp = hashlib.sha256(raw_selector.encode("utf-8")).hexdigest()[:12]
        return IdentityInfo(
            mode="host",
            source=source_name,
            fingerprint=fp,
            derived_bytes=derived,
            warning=AUTO_IDENTITY_WARNING,
            scope="host-local",
        )

    # 6. Random fallback
    return IdentityInfo(
        mode="random",
        source="random",
        fingerprint="",
        derived_bytes=None,
        warning=None,
        scope="ephemeral",
    )
