"""Command-line interface for Nookwire.

Port of the original shell launcher to Python. Background server and tunnel
processes are launched as ``[sys.executable, "-m", "nookwire_ssh.server|tunnel"]``
so uv disappears from the runtime path entirely.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import asyncssh

from nookwire_ssh import __version__, relay, server, sshconfig, tunnel, upterm
from nookwire_ssh.identity import current_username, ensure_username_environment
from nookwire_ssh.project_identity import resolve_identity
import nookwire_ssh.state as st

CLI_NAME = "nookwire"
DEFAULT_BACKEND = "srvus"
DEFAULT_PORT = 8022
DEFAULT_SLOT = 1
GITHUB_HTTPS = "https://github.com/lars-hagen/nookwire"
# uv needs the git+ scheme to treat this as a VCS checkout rather than a URL to
# a distribution file.
GITHUB_PACKAGE = f"git+{GITHUB_HTTPS}"
INSTALLER_URL = "https://raw.githubusercontent.com/lars-hagen/nookwire"
# Put the package source on PYTHONPATH so ``sys.executable -m nookwire_ssh.*``
# subprocesses can import the package even before it is pip-installed.
_PKG_SRC = str(Path(__file__).resolve().parent.parent)


def _version() -> str:
    for pkg in ("nookwire", "nookwire-ssh"):
        try:
            return importlib.metadata.version(pkg)
        except Exception:
            pass
    return __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nookwire",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=_version())
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    start = sub.add_parser(
        "start", description="Start AsyncSSH plus a public tunnel in the background."
    )
    start.add_argument("positional", nargs="*", help="DIR [PORT] [SLOT]")
    start.add_argument("--port", "-p")
    start.add_argument("--slot", "-s")
    start.add_argument("--backend", default=None)
    start.add_argument("--endpoint")
    start.add_argument("--hostname")
    start.add_argument("--token")
    start.add_argument("--accept", action="store_true")
    start.add_argument("--allow-tcp-forwarding", action="store_true")
    start.add_argument(
        "--batch",
        action="store_true",
        help="Noninteractive batch mode; suppress key prompts and tty access.",
    )

    status = sub.add_parser(
        "status", description="Print processes, credentials, and connect command."
    )
    status.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON status."
    )

    logs = sub.add_parser("logs", description="Show the last 100 log lines; add -f to follow.")
    logs.add_argument("target", nargs="?", default="all", choices=["all", "server", "tunnel"])
    logs.add_argument("-f", action="store_true")

    sub.add_parser("stop", description="Terminate both background processes.")

    restart = sub.add_parser(
        "restart", description="Stop, then start again with the saved settings."
    )
    restart.add_argument(
        "--batch",
        action="store_true",
        help="Noninteractive batch mode; suppress key prompts.",
    )

    connect = sub.add_parser(
        "connect", description="Print the commands to run on the connecting machine."
    )
    connect.add_argument(
        "--batch",
        action="store_true",
        help="Print a single self-contained SSH command with BatchMode suitable for substitution.",
    )
    connect.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON connection details."
    )

    identity = sub.add_parser(
        "identity", description="Print project and tunnel identity information."
    )
    identity.add_argument("positional", nargs="*", help="[DIR]")
    identity.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON identity."
    )

    proxy = sub.add_parser("proxy", description="Bridge stdin/stdout to the cloudflare relay.")
    proxy.add_argument("url")

    upterm_proxy = sub.add_parser(
        "upterm-proxy", description="Bridge stdin/stdout to an Upterm WSS session."
    )
    upterm_proxy.add_argument("url")

    sshconfig = sub.add_parser("ssh-config", description="Print or append an ssh block.")
    sshconfig.add_argument("--write", action="store_true")
    sshconfig.add_argument("host", nargs="?", default=None)

    upgrade = sub.add_parser("upgrade", description="Re-run the installer to update in place.")
    upgrade.add_argument("ref", nargs="?", default="main")

    return parser


def die(message: str) -> None:
    raise SystemExit(message)


def _resolve_positional(start, saved: dict[str, str] | None = None) -> tuple[Path, int, int]:
    saved = saved or {}
    args = start.positional
    if len(args) > 3:
        die(f"Too many arguments: {' '.join(args[3:])}")
    root_arg = args[0] if len(args) >= 1 else (saved.get("root") or ".")
    port_arg = args[1] if len(args) >= 2 else (start.port or saved.get("port") or DEFAULT_PORT)
    slot_arg = args[2] if len(args) >= 3 else (start.slot or saved.get("slot") or DEFAULT_SLOT)

    port_text = str(port_arg)
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        die("PORT must contain only ASCII digits and be from 1 to 65535")
    port = int(port_text)

    if not str(slot_arg).isdigit() or int(slot_arg) < 1:
        die("SLOT must be a positive integer")
    slot = int(slot_arg)

    try:
        root = Path(root_arg).expanduser().resolve(strict=True)
    except OSError:
        die(f"REMOTE_ROOT is not a directory: {root_arg}")

    return root, port, slot


def prompt_authorized_key(batch: bool = False) -> None:
    """Offer to paste a key when none exists, reading from a real terminal.

    With ``curl ... | sh`` the process stdin is the piped script, so fall back
    to the controlling terminal at /dev/tty, and skip silently when neither is
    available. Batch mode suppresses this prompt unconditionally.
    """
    if (
        batch
        or os.environ.get("NOOKWIRE_BATCH") == "1"
        or os.environ.get("NOOKWIRE_SSH_BATCH") == "1"
    ):
        return

    keys = Path(os.path.expanduser("~/.ssh/authorized_keys"))
    if keys.is_file() and keys.stat().st_size > 0:
        return
    source = None
    if not sys.stdin.isatty():
        try:
            source = open("/dev/tty", "r")
        except OSError:
            return
    print("No keys in ~/.ssh/authorized_keys.", file=sys.stderr)
    print(
        "Paste an SSH public key to enable key auth, or press Enter to skip: ",
        file=sys.stderr,
        end="",
        flush=True,
    )
    pasted = (source or sys.stdin).readline().strip()
    if source is not None:
        source.close()
    if not pasted:
        print("Skipped; password auth only.", file=sys.stderr)
        return
    ssh_dir = Path(os.path.expanduser("~/.ssh"))
    if not _prepare_ssh_dir(ssh_dir):
        print(f"Unable to prepare {ssh_dir}; skipped.", file=sys.stderr)
        return
    with tempfile.NamedTemporaryFile(
        prefix="nookwire-key.", dir=str(ssh_dir), mode="w"
    ) as temp:
        temp.write(pasted + "\n")
        temp.flush()
        if _key_is_valid(Path(temp.name)):
            with open(keys, "ab") as output:
                output.write(pasted.encode() + b"\n")
            keys.chmod(0o600)
            print(f"Key added to {keys}.", file=sys.stderr)
        else:
            print("Not a valid SSH public key; skipped.", file=sys.stderr)


def _prepare_ssh_dir(ssh_dir: Path) -> bool:
    try:
        ssh_dir.mkdir(parents=True, exist_ok=True)
        ssh_dir.chmod(0o700)
        return True
    except OSError:
        return False


def _key_is_valid(path: Path) -> bool:
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen:
        try:
            return (
                subprocess.run(
                    [ssh_keygen, "-l", "-f", str(path)],
                    capture_output=True,
                ).returncode
                == 0
            )
        except OSError:
            return False

    try:
        import base64
        import struct

        parts = path.read_text().split()
        if len(parts) < 2:
            return False
        blob = base64.b64decode(parts[1], validate=True)
        size = struct.unpack(">I", blob[:4])[0]
        return blob[4 : 4 + size].decode() == parts[0]
    except Exception:
        return False


def _backend_proxy_command() -> str:
    """ProxyCommand for the currently configured backend (used for HOST blocks)."""
    backend = st.meta_get("backend") or DEFAULT_BACKEND
    if backend == "cloudflared":
        return "cloudflared access ssh --hostname %h"
    if backend == "cloudflare":
        endpoint = st.meta_get("endpoint")
        session = st.meta_get("session")
        if endpoint and session:
            wss = normalize_endpoint(endpoint, "wss") or endpoint
            return f"nookwire proxy {wss}/tunnel/{session}"
    if backend == "upterm":
        session = upterm.read_session(st.state_dir() / "upterm.json")
        if session:
            return "nookwire upterm-proxy " + upterm.ssh_proxy_url(session)
    return sshconfig.SRVUS_PROXY_COMMAND


def cmd_ssh_config(args) -> int:
    if args.host:
        proxy = _backend_proxy_command()
        if args.write:
            return sshconfig.write(host=args.host, proxy_command=proxy)
        sshconfig.print_block(host=args.host, proxy_command=proxy)
        return 0
    if args.write:
        return sshconfig.write()
    sshconfig.print_block()
    return 0


def cmd_proxy(args) -> int:
    return relay.main(["client", args.url])


def cmd_upterm_proxy(args) -> int:
    return upterm.main(["client", args.url])


def prepare_ssh_dir() -> None:
    ssh_dir = Path(os.path.expanduser("~/.ssh"))
    if not _prepare_ssh_dir(ssh_dir):
        st.stop_one(st.state_dir() / "server.pid")
        die(f"Unable to prepare {ssh_dir}")


def _spawn(command: list[str], environment: dict[str, str], log: Path) -> subprocess.Popen:
    pythonpath = _PKG_SRC
    if environment.get("PYTHONPATH"):
        pythonpath = f"{_PKG_SRC}{os.pathsep}{environment['PYTHONPATH']}"
    environment = {**environment, "PYTHONPATH": pythonpath}
    with open(log, "ab") as output:
        return subprocess.Popen(
            command,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )


def launch_server(args, root: Path, port: int, password: str, state: Path) -> subprocess.Popen:
    username = ensure_username_environment()
    server_flags = []
    if args.accept:
        server_flags.append("--accept")
    if args.allow_tcp_forwarding:
        server_flags.append("--allow-tcp-forwarding")
    if args.backend == "upterm":
        server_flags.extend(
            ["--no-password", "--upterm-ca-keys", str(state / "upterm-ca-keys")]
        )
    command = [
        sys.executable,
        "-m",
        "nookwire_ssh.server",
        "--root",
        str(root),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--username",
        username,
        *server_flags,
    ]
    environment = {
        **os.environ,
        "NOOKWIRE_SSH_PASSWORD": password,
        "USER": username,
        "LOGNAME": username,
    }
    return _spawn(command, environment, state / "server.log")


def normalize_endpoint(value: str, scheme: str) -> str | None:
    stripped = value.strip().rstrip("/")
    for prefix in ("https://", "http://", "wss://", "ws://"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix) :]
            break
    if not stripped:
        return None
    return f"{scheme}://{stripped}"


def launch_tunnel_srvus(
    args, root: Path, port: int, slot: int, state: Path
) -> subprocess.Popen:
    prepare_ssh_dir()
    key = st.tunnel_key_path(state)
    st.repair_key_permissions(key)
    host = os.environ.get("NOOKWIRE_TUNNEL_HOST", "srv.us")
    try:
        port_text = os.environ.get("NOOKWIRE_TUNNEL_PORT", "22")
        sink_port = int(port_text)
    except ValueError:
        sink_port = 22
    username = _ssh_user()
    command = [
        sys.executable,
        "-m",
        "nookwire_ssh.tunnel",
        "--host",
        host,
        "--port",
        str(sink_port),
        "--local-port",
        str(port),
        "--slot",
        str(slot),
        "--key",
        str(key),
        "--username",
        username,
        "--root",
        str(root),
    ]
    return _spawn(command, os.environ, state / "tunnel.log")


def launch_tunnel_cloudflare(args, port: int, session: str, state: Path) -> subprocess.Popen:
    if not args.endpoint:
        st.stop_one(state / "server.pid")
        die("--endpoint is required for the cloudflare backend")
    wss = normalize_endpoint(args.endpoint, "wss")
    if wss is None:
        st.stop_one(state / "server.pid")
        die(f"Invalid --endpoint: {args.endpoint}")
    base_url = f"{wss}/tunnel/{session}"
    command = [
        sys.executable,
        "-m",
        "nookwire_ssh.relay",
        "origin",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        base_url,
    ]
    return _spawn(command, os.environ, state / "tunnel.log")


def launch_tunnel_cloudflared(args, state: Path) -> subprocess.Popen:
    if not shutil.which("cloudflared"):
        st.stop_one(state / "server.pid")
        die("cloudflared is required for the cloudflared backend")
    if not args.hostname:
        st.stop_one(state / "server.pid")
        die("--hostname is required for the cloudflared backend")
    token = (
        args.token
        or os.environ.get("NOOKWIRE_CLOUDFLARED_TOKEN")
        or os.environ.get("NOOKWIRE_SSH_CLOUDFLARED_TOKEN", "")
    )
    if not token:
        st.stop_one(state / "server.pid")
        die("--token or NOOKWIRE_CLOUDFLARED_TOKEN is required for the cloudflared backend")
    environment = {**os.environ, "TUNNEL_TOKEN": token}
    return _spawn(["cloudflared", "tunnel", "run"], environment, state / "tunnel.log")


def launch_tunnel_upterm(args, port: int, state: Path) -> subprocess.Popen:
    prepare_ssh_dir()
    key = st.tunnel_key_path(state)
    st.repair_key_permissions(key)
    endpoint = normalize_endpoint(args.endpoint or upterm.DEFAULT_ENDPOINT, "wss")
    if endpoint is None:
        st.stop_one(state / "server.pid")
        die(f"Invalid --endpoint: {args.endpoint}")
    command = [
        sys.executable,
        "-m",
        "nookwire_ssh.upterm",
        "origin",
        "--endpoint",
        endpoint,
        "--local-port",
        str(port),
        "--username",
        ensure_username_environment(),
        "--key",
        str(key),
        "--host-key",
        str(server.DEFAULT_HOST_KEY),
        "--authorized-keys",
        os.path.expanduser("~/.ssh/authorized_keys"),
        "--ca-keys",
        str(state / "upterm-ca-keys"),
        "--session-file",
        str(state / "upterm.json"),
    ]
    if args.accept:
        command.append("--accept")
    return _spawn(command, os.environ, state / "tunnel.log")


def backend_launch_tunnel(args, root: Path, port: int, slot: int, session: str, state: Path):
    if args.backend == "srvus":
        return launch_tunnel_srvus(args, root, port, slot, state)
    if args.backend == "cloudflare":
        return launch_tunnel_cloudflare(args, port, session, state)
    if args.backend == "cloudflared":
        return launch_tunnel_cloudflared(args, state)
    return launch_tunnel_upterm(args, port, state)


def wait_for_srvus_host(tunnel_pid_file: Path, tunnel_log: Path) -> None:
    for _ in range(40):
        if not st.is_running(tunnel_pid_file):
            return
        if st.extract_host(tunnel_log):
            return
        time.sleep(0.5)


def wait_for_upterm_session(tunnel_pid_file: Path, session_file: Path):
    for _ in range(40):
        if not st.is_running(tunnel_pid_file):
            return None
        session = upterm.read_session(session_file)
        if session:
            return session
        time.sleep(0.5)
    return None


def cmd_start(args) -> int:
    saved = st.read_config()
    batch = bool(
        getattr(args, "batch", False)
        or os.environ.get("NOOKWIRE_BATCH") == "1"
        or os.environ.get("NOOKWIRE_SSH_BATCH") == "1"
        or saved.get("batch") == "1"
    )

    if args.backend is None:
        args.backend = saved.get("backend") or DEFAULT_BACKEND
    if args.backend not in ("srvus", "cloudflare", "cloudflared", "upterm"):
        die(
            f"Unknown backend: {args.backend} "
            "(use srvus, cloudflare, cloudflared, or upterm)"
        )
    if not args.hostname:
        args.hostname = saved.get("hostname") or ""
    if not args.endpoint:
        args.endpoint = saved.get("endpoint") or ""
    if not args.token:
        args.token = (
            os.environ.get("NOOKWIRE_CLOUDFLARED_TOKEN")
            or os.environ.get("NOOKWIRE_SSH_CLOUDFLARED_TOKEN")
            or saved.get("token")
            or ""
        )
    root, port, slot = _resolve_positional(args, saved)
    state = st.setup_state()
    server_pid_file = state / "server.pid"
    tunnel_pid_file = state / "tunnel.pid"
    server_log = state / "server.log"
    tunnel_log = state / "tunnel.log"

    server_running = st.is_running(server_pid_file)
    tunnel_running = st.is_running(tunnel_pid_file)
    if server_running and tunnel_running:
        _show_status()
        return 0
    if server_running:
        pid = st.read_pid(server_pid_file)
        pid_str = f" (pid {pid})" if pid else ""
        die(f"Server is running{pid_str} but tunnel is stopped; run '{CLI_NAME} stop' before starting")
    if tunnel_running:
        pid = st.read_pid(tunnel_pid_file)
        pid_str = f" (pid {pid})" if pid else ""
        die(f"Tunnel is running{pid_str} but server is stopped; run '{CLI_NAME} stop' before starting")

    for pid_file in (server_pid_file, tunnel_pid_file):
        if not pid_file.is_dir():
            pid_file.unlink(missing_ok=True)
    if st.port_open(port):
        die(f"Port {port} is already in use")

    if args.accept:
        (state / "password").unlink(missing_ok=True)
        password = ""
    elif args.backend == "upterm":
        if not batch:
            prompt_authorized_key(batch=batch)
        keys = Path(os.path.expanduser("~/.ssh/authorized_keys"))
        if not keys.is_file() or not keys.stat().st_size:
            die("The upterm backend requires an authorized key or --accept")
        (state / "password").unlink(missing_ok=True)
        password = ""
    else:
        if not batch:
            prompt_authorized_key(batch=batch)
        password = st.generate_password()
        (state / "password").write_text(password)

    session = st.get_or_create_session()
    server_log.write_text("")
    tunnel_log.write_text("")

    server_process = launch_server(args, root, port, password, state)
    if not st.write_pid(server_pid_file, server_process.pid):
        st.kill_untracked(server_process.pid)
        die("Unable to track server process")

    try:
        ready = False
        for _ in range(120):
            if not st.is_running(server_pid_file):
                break
            if st.port_open(port):
                ready = True
                break
            time.sleep(0.5)
        if not ready:
            st.stop_one(server_pid_file)
            print("Server failed to start. Log:", file=sys.stderr)
            _tail_stderr(server_log, 100)
            return 1

        tunnel_process = backend_launch_tunnel(args, root, port, slot, session, state)
        if not st.write_pid(tunnel_pid_file, tunnel_process.pid):
            st.kill_untracked(tunnel_process.pid)
            st.stop_one(server_pid_file)
            die("Unable to track tunnel process")

        time.sleep(2)
        if not st.is_running(tunnel_pid_file):
            st.stop_one(server_pid_file)
            tunnel_pid_file.unlink(missing_ok=True)
            print("Tunnel failed to start. Log:", file=sys.stderr)
            _tail_stderr(tunnel_log, 100)
            return 1

        if args.backend == "srvus":
            wait_for_srvus_host(tunnel_pid_file, tunnel_log)
        if args.backend == "upterm":
            if not wait_for_upterm_session(tunnel_pid_file, state / "upterm.json"):
                st.stop_one(tunnel_pid_file)
                st.stop_one(server_pid_file)
                print("Upterm session failed to start. Log:", file=sys.stderr)
                _tail_stderr(tunnel_log, 100)
                return 1

        key_path = st.tunnel_key_path(state)
        legacy_key = Path(os.path.expanduser("~/.ssh/id_ed25519"))
        if key_path == legacy_key and legacy_key.is_file():
            ident_mode = "key"
            ident_source = str(legacy_key)
            ident_fp = ""
            try:
                k = asyncssh.read_private_key(legacy_key)
                ident_fp = k.get_fingerprint()
            except Exception:
                pass
        else:
            info = resolve_identity(root=root, username=_ssh_user())
            ident_mode = info.mode
            ident_source = info.source
            ident_fp = info.fingerprint

        meta = {
            "backend": args.backend,
            "port": str(port),
            "accept": "1" if args.accept else "0",
            "allow_tcp_forwarding": "1" if args.allow_tcp_forwarding else "0",
            "identity_mode": ident_mode,
            "identity_source": ident_source,
            "identity_fingerprint": ident_fp,
            "key_path": str(key_path),
        }
        if args.backend == "cloudflare":
            meta["endpoint"] = args.endpoint or ""
            meta["session"] = session
        if args.backend == "cloudflared":
            meta["hostname"] = args.hostname or ""
        if args.backend == "upterm":
            meta["endpoint"] = args.endpoint or upterm.DEFAULT_ENDPOINT
        st.write_meta(meta)
        st.write_config(
            {
                "backend": args.backend,
                "root": str(root),
                "port": str(port),
                "slot": str(slot),
                "hostname": args.hostname or "",
                "endpoint": args.endpoint or "",
                "token": args.token or "",
                "batch": "1" if batch else "0",
            }
        )
    except BaseException:
        st.stop_one(tunnel_pid_file)
        st.stop_one(server_pid_file)
        raise

    _show_status()
    return 0


def _tail_stderr(path: Path, count: int) -> None:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return
    for line in lines[-count:]:
        print(line, file=sys.stderr)


def _ssh_user() -> str:
    return current_username()


class _Color:
    def __init__(self, enabled: bool) -> None:
        self._on = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self._on else text

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)


def _colorizer() -> _Color:
    return _Color(sys.stdout.isatty())


def _proc_row(color: _Color, running: bool, pid: int | None) -> str:
    if running:
        return color.green(f"running   pid {pid}")
    return color.red("stopped")


def _print_url_row(color: _Color, known: bool, url: str) -> None:
    del color
    if known:
        print(f"  url       {url}")
    else:
        print("  url       pending   " + _Color(sys.stdout.isatty()).dim("(nookwire logs tunnel -f)"))


def _print_auth_rows(color: _Color, state: Path) -> None:
    accept = st.meta_get("accept")
    allow = st.meta_get("allow_tcp_forwarding")
    if accept == "1":
        print("  auth      none " + color.dim("(--accept); anyone can connect"))
    else:
        password_file = state / "password"
        if password_file.is_file():
            print(f"  auth      {_ssh_user()} / {password_file.read_text()}")
        keys = Path(os.path.expanduser("~/.ssh/authorized_keys"))
        if keys.is_file() and keys.stat().st_size > 0:
            print("  keys      enabled")
        else:
            print("  keys      disabled " + color.dim("(add keys to ~/.ssh/authorized_keys)"))
    if allow == "1":
        print("  forward   enabled")
    else:
        print("  forward   disabled " + color.dim("(--allow-tcp-forwarding)"))


def _setup_line(host: str, proxy_command: str) -> str:
    lines = [
        "Host " + host,
        "  ProxyCommand " + proxy_command,
        "  StrictHostKeyChecking no",
        "  UserKnownHostsFile /dev/null",
        "  LogLevel ERROR",
    ]
    printed = " ".join(f"'{line}'" for line in lines)
    if "*" in host:
        grep_pattern = "^Host " + host.replace("*", "\\*")
    else:
        grep_pattern = f"^Host {host}$"
    return (
        f"grep -qs '{grep_pattern}' ~/.ssh/config || "
        f"printf '%s\\n' {printed} >> ~/.ssh/config"
    )


def _fallback_line(ssh_user: str, host: str, proxy_command: str) -> str:
    return (
        f"ssh {ssh_user}@{host} -o 'ProxyCommand={proxy_command}' "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o LogLevel=ERROR"
    )


class _Target:
    def __init__(
        self,
        host: str,
        proxy_command: str,
        setup_host: str,
        url: str,
        note: str = "",
        user: str = "",
    ):
        self.host = host
        self.proxy_command = proxy_command
        self.setup_host = setup_host
        self.url = url
        self.note = note
        self.user = user


def connect_target(backend: str, state: Path) -> _Target | None:
    if backend == "cloudflare":
        endpoint = st.meta_get("endpoint")
        session = st.meta_get("session")
        if not (endpoint and session):
            return None
        https = normalize_endpoint(endpoint, "https") or endpoint
        wss = normalize_endpoint(endpoint, "wss") or endpoint
        return _Target(
            "nookwire",
            f"nookwire proxy {wss}/tunnel/{session}",
            "nookwire",
            f"{https}/tunnel/{session}",
            "nookwire must be installed on the connecting machine.",
        )
    if backend == "cloudflared":
        hostname = st.meta_get("hostname")
        if not hostname:
            return None
        return _Target(
            hostname,
            "cloudflared access ssh --hostname %h",
            hostname,
            f"ssh://{hostname}",
            "cloudflared must be installed on the connecting machine.",
        )
    if backend == "upterm":
        session = upterm.read_session(state / "upterm.json")
        if not session:
            return None
        endpoint = session["endpoint"]
        host = upterm.endpoint_host(endpoint)
        proxy_url = upterm.ssh_proxy_url(session)
        return _Target(
            host,
            f"nookwire upterm-proxy {proxy_url}",
            host,
            f"ssh://{session['ssh_user']}@{host}:443",
            "nookwire must be installed on the connecting machine.",
            session["ssh_user"],
        )
    host = st.extract_host(state / "tunnel.log")
    if not host:
        return None
    return _Target(host, sshconfig.SRVUS_PROXY_COMMAND, "*.srv.us", f"https://{host}/")


def _show_status() -> int:
    color = _colorizer()
    state = st.state_dir()
    server_pid_file = state / "server.pid"
    tunnel_pid_file = state / "tunnel.pid"
    server_running = st.is_running(server_pid_file)
    tunnel_running = st.is_running(tunnel_pid_file)
    backend = st.meta_get("backend") or DEFAULT_BACKEND
    target = connect_target(backend, state)

    print(f"nookwire {_version()} · {backend}")
    print()
    print(f"  server    {_proc_row(color, server_running, st.read_pid(server_pid_file))}")
    print(f"  tunnel    {_proc_row(color, tunnel_running, st.read_pid(tunnel_pid_file))}")
    _print_url_row(color, target is not None, target.url if target else "")
    _print_auth_rows(color, state)
    ident_mode = st.meta_get("identity_mode") or "random"
    ident_fp = st.meta_get("identity_fingerprint") or ""
    if ident_fp:
        print(f"  identity  {ident_mode} ({ident_fp})")
    else:
        print(f"  identity  {ident_mode}")
    if target is not None:
        print()
        print("  connect   " + color.bold(f"ssh {target.user or _ssh_user()}@{target.host}"))
        print("            " + color.dim("first time here: nookwire connect"))
    return 0 if (server_running and tunnel_running) else 1


def _show_status_json() -> int:
    state = st.state_dir()
    server_pid_file = state / "server.pid"
    tunnel_pid_file = state / "tunnel.pid"
    server_running = st.is_running(server_pid_file)
    tunnel_running = st.is_running(tunnel_pid_file)
    backend = st.meta_get("backend") or DEFAULT_BACKEND
    target = connect_target(backend, state)

    server_pid = st.read_pid(server_pid_file) if server_running else None
    tunnel_pid = st.read_pid(tunnel_pid_file) if tunnel_running else None
    ssh_user = target.user if (target and target.user) else _ssh_user()

    accept = st.meta_get("accept") == "1"
    forwarding = st.meta_get("allow_tcp_forwarding") == "1"
    password_file = state / "password"
    if accept:
        auth_mode = "none"
    elif password_file.is_file():
        auth_mode = "password"
    elif backend == "upterm":
        auth_mode = "keys"
    else:
        auth_mode = "password"

    ident_mode = st.meta_get("identity_mode") or "random"
    ident_source = st.meta_get("identity_source") or "random"
    ident_fp = st.meta_get("identity_fingerprint") or ""

    connect_command = None
    if target is not None:
        connect_command = _fallback_line(ssh_user, target.host, target.proxy_command)

    data = {
        "version": _version(),
        "backend": backend,
        "server_state": "running" if server_running else "stopped",
        "server_pid": server_pid,
        "tunnel_state": "running" if tunnel_running else "stopped",
        "tunnel_pid": tunnel_pid,
        "url": target.url if target else None,
        "host": target.host if target else None,
        "ssh_username": ssh_user,
        "auth_mode": auth_mode,
        "forwarding": forwarding,
        "identity_mode": ident_mode,
        "identity_source": ident_source,
        "identity_fingerprint": ident_fp,
        "connect_command": connect_command,
        "server": {
            "state": "running" if server_running else "stopped",
            "running": server_running,
            "pid": server_pid,
        },
        "tunnel": {
            "state": "running" if tunnel_running else "stopped",
            "running": tunnel_running,
            "pid": tunnel_pid,
        },
        "identity": {
            "mode": ident_mode,
            "source": ident_source,
            "fingerprint": ident_fp,
        },
    }
    sys.stdout.write(json.dumps(data, indent=2) + "\n")
    return 0 if (server_running and tunnel_running) else 1


def cmd_connect(args) -> int:
    st.setup_state()
    state = st.state_dir()
    backend = st.meta_get("backend") or DEFAULT_BACKEND
    target = connect_target(backend, state)
    if target is None:
        die("No published address yet; check nookwire status.")

    ssh_user = target.user or _ssh_user()
    batch_command = (
        f"ssh {ssh_user}@{target.host} -T -o BatchMode=yes "
        f"-o 'ProxyCommand={target.proxy_command}' "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o LogLevel=ERROR"
    )

    if getattr(args, "batch", False):
        sys.stdout.write(batch_command + "\n")
        return 0

    if getattr(args, "json", False):
        data = {
            "host": target.host,
            "ssh_username": ssh_user,
            "setup_host": target.setup_host,
            "proxy_command": target.proxy_command,
            "url": target.url,
            "note": target.note,
            "command": _fallback_line(ssh_user, target.host, target.proxy_command),
            "connect_command": _fallback_line(ssh_user, target.host, target.proxy_command),
            "batch_command": batch_command,
        }
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        return 0

    color = _colorizer()
    print("Run once on the machine you are connecting from:")
    print()
    print("  " + _setup_line(target.setup_host, target.proxy_command))
    print()
    print("Then, from now on:")
    print()
    print("  " + color.bold(f"ssh {ssh_user}@{target.host}"))
    print()
    print("Or, without changing any config:")
    print()
    print("  " + _fallback_line(ssh_user, target.host, target.proxy_command))
    if target.note:
        print()
        print(color.dim(target.note))
    return 0


def cmd_identity(args) -> int:
    st.setup_state()
    state = st.state_dir()
    pos = getattr(args, "positional", [])
    root = Path(pos[0]).expanduser().resolve() if pos else Path.cwd().resolve()
    user = _ssh_user()

    key_path = st.tunnel_key_path(state)
    legacy_key = Path(os.path.expanduser("~/.ssh/id_ed25519"))
    dedicated_key = state / "tunnel_id_ed25519"

    if key_path == legacy_key and legacy_key.is_file():
        mode = "key"
        source = str(legacy_key)
        selector_fp = ""
        warning = None
        key_exists = True
        key_fp = None
        try:
            k = asyncssh.read_private_key(legacy_key)
            key_fp = k.get_fingerprint()
        except Exception:
            key_fp = None
    elif dedicated_key.is_file():
        key_path = dedicated_key
        key_exists = True
        mode = st.meta_get("identity_mode") or "dedicated"
        source = st.meta_get("identity_source") or "dedicated"
        selector_fp = st.meta_get("identity_fingerprint") or ""
        warning = None
        key_fp = None
        try:
            k = asyncssh.read_private_key(dedicated_key)
            key_fp = k.get_fingerprint()
        except Exception:
            key_fp = None
    else:
        info = resolve_identity(root=root, username=user)
        mode = info.mode
        source = info.source
        selector_fp = info.fingerprint
        warning = info.warning
        key_exists = False
        key_fp = None
        if info.derived_bytes is not None:
            try:
                priv = Ed25519PrivateKey.from_private_bytes(info.derived_bytes)
                pem = priv.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
                k = asyncssh.import_private_key(pem)
                key_fp = k.get_fingerprint()
            except Exception:
                key_fp = None

    if getattr(args, "json", False):
        data = {
            "mode": mode,
            "source": source,
            "fingerprint": selector_fp,
            "selector_fingerprint": selector_fp,
            "key_path": str(key_path),
            "key_exists": key_exists,
            "key_fingerprint": key_fp,
            "warning": warning,
        }
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        return 0

    print(f"identity mode:        {mode}")
    print(f"identity source:      {source}")
    print(f"selector fingerprint: {selector_fp or 'none'}")
    print(f"key path:             {key_path}")
    print(f"key exists:           {'yes' if key_exists else 'no'}")
    print(f"key fingerprint:      {key_fp or 'none'}")
    if warning:
        print()
        print(f"Warning: {warning}")
    return 0


def cmd_status(args) -> int:
    st.setup_state()
    if getattr(args, "json", False):
        return _show_status_json()
    return _show_status()


def cmd_logs(args) -> int:
    st.setup_state()
    state = st.state_dir()
    server_log = state / "server.log"
    tunnel_log = state / "tunnel.log"
    for log in (server_log, tunnel_log):
        if not log.is_file():
            log.write_text("")
    if args.target == "all":
        _tail_file(server_log, follow=args.f)
        _tail_file(tunnel_log, follow=args.f)
    elif args.target == "server":
        _tail_file(server_log, follow=args.f)
    else:
        _tail_file(tunnel_log, follow=args.f)
    return 0


def _tail_file(path: Path, follow: bool) -> None:
    if not follow:
        try:
            lines = path.read_text(errors="replace").splitlines()[-100:]
        except OSError:
            lines = []
        for line in lines:
            print(line)
        return
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        try:
            while True:
                line = handle.readline()
                if line:
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                else:
                    time.sleep(0.2)
        except KeyboardInterrupt:
            return


def cmd_stop(args) -> int:
    del args
    st.setup_state()
    state = st.state_dir()
    st.stop_one(state / "tunnel.pid")
    st.stop_one(state / "server.pid")
    (state / "meta").unlink(missing_ok=True)
    print("Nookwire stopped.")
    return 0


def cmd_restart(args) -> int:
    st.setup_state()
    saved = st.read_config()
    if not saved:
        die("Nothing saved to restart; run start with its options once first.")
    batch = getattr(args, "batch", False) or (saved.get("batch") == "1")
    cmd_stop(args)
    return cmd_start(
        argparse.Namespace(
            positional=[],
            port=None,
            slot=None,
            backend=None,
            endpoint=None,
            hostname=None,
            token=None,
            accept=False,
            allow_tcp_forwarding=False,
            batch=batch,
        )
    )


def install_spec(ref: str) -> str:
    version = os.environ.get("NOOKWIRE_VERSION") or os.environ.get("NOOKWIRE_SSH_VERSION")
    if version:
        target = f"v{version}" if version[0].isdigit() else version
    else:
        target = ref
    base = (
        os.environ.get("NOOKWIRE_BASE_URL")
        or os.environ.get("NOOKWIRE_SSH_BASE_URL")
        or GITHUB_PACKAGE
    )
    if "@" in base:
        return base
    return f"{base}@{target}"


def cmd_upgrade(args) -> int:
    if not shutil.which("uv"):
        die("uv is required; install it and re-run `nookwire upgrade`")
    if shutil.which("curl") is None:
        die("curl is required to upgrade")

    ref = args.ref
    version = (
        os.environ.get("NOOKWIRE_VERSION")
        or os.environ.get("NOOKWIRE_SSH_VERSION")
        or __version__
    )
    base_install_url = (
        os.environ.get("NOOKWIRE_INSTALL_URL")
        or os.environ.get("NOOKWIRE_SSH_INSTALL_URL")
        or INSTALLER_URL
    )
    install_url = f"{base_install_url}/{ref}/install.sh"
    base_url = (
        os.environ.get("NOOKWIRE_BASE_URL")
        or os.environ.get("NOOKWIRE_SSH_BASE_URL")
        or f"{GITHUB_PACKAGE}@{ref}"
    )
    headers = ["-H", "Cache-Control: no-cache", "-H", "Pragma: no-cache"]
    try:
        installer = subprocess.run(
            ["curl", "-fsSL", *headers, install_url],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return die(f"Failed to fetch installer from {install_url}")
    print(f"nookwire {version} upgrading from {base_url}")
    completed = subprocess.run(
        ["sh"],
        input=installer.stdout,
        env={**os.environ, "NOOKWIRE_BASE_URL": base_url, "NOOKWIRE_SSH_BASE_URL": base_url},
    )
    return completed.returncode


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return {
        "start": cmd_start,
        "status": cmd_status,
        "logs": cmd_logs,
        "stop": cmd_stop,
        "restart": cmd_restart,
        "connect": cmd_connect,
        "identity": cmd_identity,
        "proxy": cmd_proxy,
        "upterm-proxy": cmd_upterm_proxy,
        "ssh-config": cmd_ssh_config,
        "upgrade": cmd_upgrade,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
