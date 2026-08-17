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
import getpass
import importlib.metadata
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from nookwire_ssh import __version__, relay, server, sshconfig, tunnel
import nookwire_ssh.state as st

DEFAULT_BACKEND = "srvus"
DEFAULT_PORT = 8022
DEFAULT_SLOT = 1
GITHUB_HTTPS = "https://github.com/lars-hagen/nookwire-ssh"
INSTALLER_URL = "https://raw.githubusercontent.com/lars-hagen/nookwire-ssh"
SRVUS_PROXY_COMMAND = (
    "openssl s_client -quiet -no_ign_eof -verify_return_error "
    "-verify_hostname %h -connect %h:443 -servername %h 2>/dev/null"
)
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
    start.add_argument("--backend", default=DEFAULT_BACKEND)
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

    proxy = sub.add_parser("proxy", description="Bridge stdin/stdout to the cloudflare relay.")
    proxy.add_argument("url")

    sshconfig = sub.add_parser("ssh-config", description="Print or append the srv.us ssh block.")
    sshconfig.add_argument("--write", action="store_true")

    upgrade = sub.add_parser("upgrade", description="Re-run the installer to update in place.")
    upgrade.add_argument("ref", nargs="?", default="main")

    return parser


def die(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _resolve_positional(start) -> tuple[Path, int, int]:
    args = start.positional
    if len(args) > 3:
        die(f"Too many arguments: {' '.join(args[3:])}")
    root_arg = args[0] if len(args) >= 1 else "."
    port_arg = args[1] if len(args) >= 2 else (start.port or DEFAULT_PORT)
    slot_arg = args[2] if len(args) >= 3 else (start.slot or DEFAULT_SLOT)

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


def cmd_ssh_config(args) -> int:
    if args.write:
        return sshconfig.write()
    sshconfig.print_block()
    return 0


def cmd_proxy(args) -> int:
    return relay.main(["client", args.url])


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
    server_flags = []
    if args.accept:
        server_flags.append("--accept")
    if args.allow_tcp_forwarding:
        server_flags.append("--allow-tcp-forwarding")
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
        getpass.getuser(),
        *server_flags,
    ]
    environment = {**os.environ, "NOOKWIRE_SSH_PASSWORD": password}
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


def backend_launch_tunnel(args, port: int, slot: int, session: str, state):
    if args.backend == "srvus":
        return launch_tunnel_srvus(args, port, slot, state)
    if args.backend == "cloudflare":
        return launch_tunnel_cloudflare(args, port, session, state)
    return launch_tunnel_cloudflared(args, state)


def wait_for_srvus_host(tunnel_pid_file: Path, tunnel_log: Path) -> None:
    """Wait for srv.us to report the hostname so start can print the connect command."""
    for _ in range(40):
        if not st.is_running(tunnel_pid_file):
            return
        if st.extract_host(tunnel_log):
            return
        time.sleep(0.5)


def cmd_start(args) -> int:
    if args.backend not in ("srvus", "cloudflare", "cloudflared"):
        die(f"Unknown backend: {args.backend} (use srvus, cloudflare, or cloudflared)")
    root, port, slot = _resolve_positional(args)
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
    st.write_meta(meta)

    print("Nookwire SSH started in the background.")
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
    try:
        return getpass.getuser()
    except Exception:
        return "nookwire"


def render_srvus_connect(ssh_user: str, state: Path) -> None:
    host = st.extract_host(state / "tunnel.log")
    if not host:
        print("url: pending; run nookwire-ssh logs tunnel -f")
        return
    print(f"url: https://{host}/")
    print(f"connect: ssh {ssh_user}@{host}")
    print('  needs "nookwire-ssh ssh-config --write" once on the connecting machine')
    print("connect without that setup:")
    print(f"ssh {ssh_user}@{host} \\")
    print(f"  -o 'ProxyCommand={SRVUS_PROXY_COMMAND}' \\")
    print("  -o StrictHostKeyChecking=no \\")
    print("  -o UserKnownHostsFile=/dev/null \\")
    print("  -o LogLevel=ERROR")


def render_cloudflare_connect(ssh_user: str, state: Path) -> None:
    del state
    endpoint = st.meta_get("endpoint")
    session = st.meta_get("session")
    if not endpoint or not session:
        print("url: pending; run nookwire-ssh logs tunnel -f")
        return
    wss = normalize_endpoint(endpoint, "wss") or endpoint
    https = normalize_endpoint(endpoint, "https") or endpoint
    print(f"url: {https}/tunnel/{session}")
    print("connect:")
    print(f"ssh {ssh_user}@nookwire \\")
    print(f"  -o 'ProxyCommand=nookwire-ssh proxy {wss}/tunnel/{session}' \\")
    print("  -o StrictHostKeyChecking=no \\")
    print("  -o UserKnownHostsFile=/dev/null \\")
    print("  -o LogLevel=ERROR")
    print("note: on the connecting machine, install nookwire-ssh (needs uv on PATH).")


def render_cloudflared_connect(ssh_user: str, state: Path) -> None:
    del state
    hostname = st.meta_get("hostname")
    if not hostname:
        print("url: pending; run nookwire-ssh logs tunnel -f")
        return
    print(f"url: ssh://{hostname} (via cloudflared)")
    print("connect:")
    print(f"ssh {ssh_user}@{hostname} \\")
    print("  -o 'ProxyCommand=cloudflared access ssh --hostname %h' \\")
    print("  -o StrictHostKeyChecking=no \\")
    print("  -o UserKnownHostsFile=/dev/null \\")
    print("  -o LogLevel=ERROR")
    print("note: the connecting machine needs cloudflared installed.")


def _show_status() -> int:
    print(f"nookwire-ssh {_version()}")
    state = st.state_dir()
    server_pid_file = state / "server.pid"
    tunnel_pid_file = state / "tunnel.pid"
    server_running = st.is_running(server_pid_file)
    tunnel_running = st.is_running(tunnel_pid_file)
    if server_running:
        print(f"server: running (pid {st.read_pid(server_pid_file)})")
    else:
        print("server: stopped")
    if tunnel_running:
        print(f"tunnel: running (pid {st.read_pid(tunnel_pid_file)})")
    else:
        print("tunnel: stopped")

    ssh_user = _ssh_user()
    accept = st.meta_get("accept")
    allow = st.meta_get("allow_tcp_forwarding")
    if accept == "1":
        print("auth: none (--accept); anyone can connect")
    else:
        password_file = state / "password"
        if password_file.is_file():
            print(f"username: {ssh_user}")
            print(f"password: {password_file.read_text()}")
        keys = Path(os.path.expanduser("~/.ssh/authorized_keys"))
        if keys.is_file() and keys.stat().st_size > 0:
            print("key auth: enabled")
        else:
            print("key auth: disabled; add keys to ~/.ssh/authorized_keys")
    if allow == "1":
        print("tcp forwarding: enabled; clients may use ssh -L through this session")
    else:
        print("tcp forwarding: disabled; use --allow-tcp-forwarding")

    backend = st.meta_get("backend") or DEFAULT_BACKEND
    if backend == "cloudflare":
        render_cloudflare_connect(ssh_user, state)
    elif backend == "cloudflared":
        render_cloudflared_connect(ssh_user, state)
    else:
        render_srvus_connect(ssh_user, state)
    return 0 if (server_running and tunnel_running) else 1


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
    base = os.environ.get("NOOKWIRE_SSH_BASE_URL") or GITHUB_HTTPS
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
    base_url = os.environ.get("NOOKWIRE_SSH_BASE_URL") or f"{GITHUB_HTTPS}@{ref}"
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
        "proxy": cmd_proxy,
        "ssh-config": cmd_ssh_config,
        "upgrade": cmd_upgrade,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
