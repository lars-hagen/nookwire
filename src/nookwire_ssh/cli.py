"""Command-line interface for Nookwire SSH.

Port of the original shell launcher to Python. Each subcommand, flag, printed
string, and the state layout are preserved so existing installs and the test
assertions keep working. Background server and tunnel processes are launched as
``[sys.executable, "-m", "nookwire_ssh.server|tunnel"]`` so uv disappears from
the runtime path entirely.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.metadata
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from nookwire_ssh import __version__, relay, server, sshconfig, tunnel, upterm
from nookwire_ssh.identity import current_username, ensure_username_environment
import nookwire_ssh.state as st

DEFAULT_BACKEND = "srvus"
DEFAULT_PORT = 8022
DEFAULT_SLOT = 1
GITHUB_HTTPS = "https://github.com/lars-hagen/nookwire-ssh"
# uv needs the git+ scheme to treat this as a VCS checkout rather than a URL to
# a distribution file.
GITHUB_PACKAGE = f"git+{GITHUB_HTTPS}"
INSTALLER_URL = "https://raw.githubusercontent.com/lars-hagen/nookwire-ssh"
# Put the package source on PYTHONPATH so ``sys.executable -m nookwire_ssh.*``
# subprocesses can import the package even before it is pip-installed.
_PKG_SRC = str(Path(__file__).resolve().parent.parent)


def _version() -> str:
    try:
        return importlib.metadata.version("nookwire-ssh")
    except Exception:
        return __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nookwire-ssh",
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

    sub.add_parser("status", description="Print processes, credentials, and connect command.")

    logs = sub.add_parser("logs", description="Show the last 100 log lines; add -f to follow.")
    logs.add_argument("target", nargs="?", default="all", choices=["all", "server", "tunnel"])
    logs.add_argument("-f", action="store_true")

    sub.add_parser("stop", description="Terminate both background processes.")

    sub.add_parser("restart", description="Stop, then start again with the saved settings.")

    sub.add_parser("connect", description="Print the commands to run on the connecting machine.")

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
    # SystemExit(message) prints the text to stderr and exits 1. Raising
    # (rather than returning) guarantees execution stops at the call site
    # instead of continuing past a fatal condition.
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


def prompt_authorized_key() -> None:
    """Offer to paste a key when none exists, reading from a real terminal.

    With ``curl ... | sh`` the process stdin is the piped script, so fall back
    to the controlling terminal at /dev/tty, and skip silently when neither is
    available.
    """
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
    # No OpenSSH here; no backend needs it anymore. Check the wire format:
    # "TYPE BASE64[ COMMENT]" whose base64 blob names that same type.
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
            return f"nookwire-ssh proxy {wss}/tunnel/{session}"
    if backend == "upterm":
        session = upterm.read_session(st.state_dir() / "upterm.json")
        if session:
            return "nookwire-ssh upterm-proxy " + upterm.ssh_proxy_url(session)
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


def launch_server(args, root: Path, port: int, password: str, state) -> subprocess.Popen:
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


def launch_tunnel_srvus(args, port: int, slot: int, state) -> subprocess.Popen:
    prepare_ssh_dir()
    key = Path(os.path.expanduser("~/.ssh/id_ed25519"))
    st.repair_key_permissions(key)
    host = os.environ.get("NOOKWIRE_TUNNEL_HOST", "srv.us")
    try:
        port_text = os.environ.get("NOOKWIRE_TUNNEL_PORT", "22")
        sink_port = int(port_text)
    except ValueError:
        sink_port = 22
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
    ]
    return _spawn(command, os.environ, state / "tunnel.log")


def launch_tunnel_cloudflare(args, port: int, session: str, state) -> subprocess.Popen:
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


def launch_tunnel_cloudflared(args, state) -> subprocess.Popen:
    if not shutil.which("cloudflared"):
        st.stop_one(state / "server.pid")
        die("cloudflared is required for the cloudflared backend")
    if not args.hostname:
        st.stop_one(state / "server.pid")
        die("--hostname is required for the cloudflared backend")
    token = args.token or os.environ.get("NOOKWIRE_CLOUDFLARED_TOKEN", "")
    if not token:
        st.stop_one(state / "server.pid")
        die("--token or NOOKWIRE_CLOUDFLARED_TOKEN is required for the cloudflared backend")
    # Pass the token via the environment, not argv, so it is not exposed in
    # process listings to other local users.
    environment = {**os.environ, "TUNNEL_TOKEN": token}
    return _spawn(["cloudflared", "tunnel", "run"], environment, state / "tunnel.log")


def launch_tunnel_upterm(args, port: int, state) -> subprocess.Popen:
    prepare_ssh_dir()
    key = Path(os.path.expanduser("~/.ssh/id_ed25519"))
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


def backend_launch_tunnel(args, port: int, slot: int, session: str, state):
    if args.backend == "srvus":
        return launch_tunnel_srvus(args, port, slot, state)
    if args.backend == "cloudflare":
        return launch_tunnel_cloudflare(args, port, session, state)
    if args.backend == "cloudflared":
        return launch_tunnel_cloudflared(args, state)
    return launch_tunnel_upterm(args, port, state)


def wait_for_srvus_host(tunnel_pid_file: Path, tunnel_log: Path) -> None:
    """Wait for srv.us to report the hostname so start can print the connect command."""
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
    # Anything not given explicitly falls back to the last successful start, so
    # a repeat run on the same box needs no arguments. --accept and
    # --allow-tcp-forwarding are deliberately never restored: silently
    # reinstating a no-auth session would be a nasty surprise.
    saved = st.read_config()
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
        args.token = os.environ.get("NOOKWIRE_CLOUDFLARED_TOKEN") or saved.get("token") or ""
    root, port, slot = _resolve_positional(args, saved)
    state = st.setup_state()
    server_pid_file = state / "server.pid"
    tunnel_pid_file = state / "tunnel.pid"
    server_log = state / "server.log"
    tunnel_log = state / "tunnel.log"

    if st.is_running(server_pid_file):
        die("Server is already running")
    if st.is_running(tunnel_pid_file):
        die("Tunnel is already running")
    for pid_file in (server_pid_file, tunnel_pid_file):
        # Clear a stale regular pid file; leave a directory in place so a
        # write_pid against it fails cleanly (the untrackable-process path).
        if not pid_file.is_dir():
            pid_file.unlink(missing_ok=True)
    if st.port_open(port):
        die(f"Port {port} is already in use")

    if args.accept:
        (state / "password").unlink(missing_ok=True)
        password = ""
    elif args.backend == "upterm":
        prompt_authorized_key()
        keys = Path(os.path.expanduser("~/.ssh/authorized_keys"))
        if not keys.is_file() or not keys.stat().st_size:
            die("The upterm backend requires an authorized key or --accept")
        (state / "password").unlink(missing_ok=True)
        password = ""
    else:
        prompt_authorized_key()
        password = st.generate_password()
        (state / "password").write_text(password)

    session = st.get_or_create_session()
    server_log.write_text("")
    tunnel_log.write_text("")

    server_process = launch_server(args, root, port, password, state)
    if not st.write_pid(server_pid_file, server_process.pid):
        st.kill_untracked(server_process.pid)
        die("Unable to track server process")

    # Every failure below stops what it started before returning or dying.
    # An *unexpected* exception has no such handler, and the server is a
    # daemon whose pid file is the only handle on it: one that escapes here
    # keeps running, unreachable by `stop`, until the box reboots. Both
    # stop_one calls are idempotent, so unwinding a path that already
    # cleaned up is harmless.
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

        tunnel_process = backend_launch_tunnel(args, port, slot, session, state)
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

        meta = {
            "backend": args.backend,
            "port": str(port),
            "accept": "1" if args.accept else "0",
            "allow_tcp_forwarding": "1" if args.allow_tcp_forwarding else "0",
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
    """Tiny ANSI helper; emits nothing when output is not a terminal."""

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
        print("  url       pending   " + _Color(sys.stdout.isatty()).dim("(nookwire-ssh logs tunnel -f)"))


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
    """One self-contained, idempotent line to add the block to ~/.ssh/config."""
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
    """Everything needed to build a connect command, once a tunnel is up."""

    def __init__(self, host: str, proxy_command: str, setup_host: str, url: str, note: str = "", user: str = ""):
        self.host = host
        self.proxy_command = proxy_command
        self.setup_host = setup_host
        self.url = url
        self.note = note
        self.user = user


def connect_target(backend: str, state: Path) -> _Target | None:
    """Resolve the published address, or None while the tunnel is still coming up."""
    if backend == "cloudflare":
        endpoint = st.meta_get("endpoint")
        session = st.meta_get("session")
        if not (endpoint and session):
            return None
        https = normalize_endpoint(endpoint, "https") or endpoint
        wss = normalize_endpoint(endpoint, "wss") or endpoint
        return _Target(
            "nookwire",
            f"nookwire-ssh proxy {wss}/tunnel/{session}",
            "nookwire",
            f"{https}/tunnel/{session}",
            "nookwire-ssh must be installed on the connecting machine.",
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
            f"nookwire-ssh upterm-proxy {proxy_url}",
            host,
            f"ssh://{session['ssh_user']}@{host}:443",
            "nookwire-ssh must be installed on the connecting machine.",
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

    print(f"nookwire-ssh {_version()} · {backend}")
    print()
    print(f"  server    {_proc_row(color, server_running, st.read_pid(server_pid_file))}")
    print(f"  tunnel    {_proc_row(color, tunnel_running, st.read_pid(tunnel_pid_file))}")
    _print_url_row(color, target is not None, target.url if target else "")
    _print_auth_rows(color, state)
    # The two pasteable commands are long enough to wrap badly, and they are
    # needed once per connecting machine, not on every status. `connect` prints
    # them; this stays scannable.
    if target is not None:
        print()
        print("  connect   " + color.bold(f"ssh {target.user or _ssh_user()}@{target.host}"))
        print("            " + color.dim("first time here: nookwire-ssh connect"))
    return 0 if (server_running and tunnel_running) else 1


def cmd_connect(args) -> int:
    del args
    st.setup_state()
    state = st.state_dir()
    backend = st.meta_get("backend") or DEFAULT_BACKEND
    target = connect_target(backend, state)
    if target is None:
        die("No published address yet; check nookwire-ssh status.")
    color = _colorizer()
    ssh_user = target.user or _ssh_user()
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


def cmd_status(args) -> int:
    del args
    st.setup_state()
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
    print("Nookwire SSH stopped.")
    return 0


def cmd_restart(args) -> int:
    st.setup_state()
    if not st.read_config():
        die("Nothing saved to restart; run start with its options once first.")
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
        )
    )


def install_spec(ref: str) -> str:
    """Return the package spec for ``uv tool install``.

    NOOKWIRE_SSH_BASE_URL overrides the source (normally the GitHub checkout),
    and NOOKWIRE_SSH_VERSION pins a specific release tag when set.
    """
    version = os.environ.get("NOOKWIRE_SSH_VERSION")
    if version:
        target = f"v{version}" if version[0].isdigit() else version
    else:
        target = ref
    base = os.environ.get("NOOKWIRE_SSH_BASE_URL") or GITHUB_PACKAGE
    if "@" in base:
        return base
    return f"{base}@{target}"


def cmd_upgrade(args) -> int:
    if not shutil.which("uv"):
        die("uv is required; install it and re-run `nookwire-ssh upgrade`")
    if shutil.which("curl") is None:
        die("curl is required to upgrade")

    ref = args.ref
    version = os.environ.get("NOOKWIRE_SSH_VERSION") or __version__
    install_url = (
        f"{os.environ.get('NOOKWIRE_SSH_INSTALL_URL') or INSTALLER_URL}/{ref}/install.sh"
    )
    # Reinstall from the same ref, not the installer's pinned default, so
    # "upgrade main" actually installs main's package.
    base_url = os.environ.get("NOOKWIRE_SSH_BASE_URL") or f"{GITHUB_PACKAGE}@{ref}"
    # A proxy or HTTP cache can serve a stale copy of the installer. Ask it not
    # to with request headers only; raw.githubusercontent rejects query strings,
    # which would otherwise be the usual cache-busting trick.
    headers = ["-H", "Cache-Control: no-cache", "-H", "Pragma: no-cache"]
    try:
        installer = subprocess.run(
            ["curl", "-fsSL", *headers, install_url],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return die(f"Failed to fetch installer from {install_url}")
    print(f"nookwire-ssh {version} upgrading from {base_url}")
    completed = subprocess.run(
        ["sh"],
        input=installer.stdout,
        env={**os.environ, "NOOKWIRE_SSH_BASE_URL": base_url},
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
        "proxy": cmd_proxy,
        "upterm-proxy": cmd_upterm_proxy,
        "ssh-config": cmd_ssh_config,
        "upgrade": cmd_upgrade,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
