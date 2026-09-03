#!/usr/bin/env python3
"""srv.us reverse tunnel for the Nookwire SSH srvus backend.

Holds one AsyncSSH connection to srv.us with a remote port forward pointing back
at the local SSH server. AsyncSSH is already required by the server, so speaking
SSH in-process here removes the OpenSSH client and ssh-keygen from the host's
requirements; the tunnel then works on stripped images that ship neither.

Launch with asyncssh available, e.g.:
  python -m nookwire_ssh.tunnel --local-port 8022 --slot 1
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import signal
import sys
from pathlib import Path

import asyncssh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nookwire_ssh.identity import current_username, ensure_username_environment
from nookwire_ssh.project_identity import resolve_identity


class TunnelClient(asyncssh.SSHClient):
    """Surface srv.us protocol messages in the tunnel log.

    srv.us reports the assigned https URL over the session channel, and reports
    errors as SSH debug messages or an auth banner. The launcher scrapes the log
    for that URL, so all three have to land on stdout.
    """

    def debug_msg_received(self, msg: str, lang: str, always_display: bool) -> None:
        del lang, always_display
        print(msg, flush=True)

    def auth_banner_received(self, msg: str, lang: str) -> None:
        del lang
        print(msg, flush=True)


def ensure_key(
    path: Path, root: Path | None = None, username: str | None = None
) -> None:
    """Create the tunnel key when missing; reuse it for a stable hostname.

    srv.us derives the hostname from this key, so it is written once and kept.
    Automatic project identity derives a deterministic key from project metadata
    when no explicit seed or existing key is present.
    """
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Tunnel key must be a regular file: {path}")
        return

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = resolve_identity(root=root, username=username)
    if info.derived_bytes is not None:
        private = Ed25519PrivateKey.from_private_bytes(info.derived_bytes)
        encoded = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key = asyncssh.import_private_key(encoded)
    else:
        key = asyncssh.generate_private_key("ssh-ed25519")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(key.export_private_key())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
    source = info.source if info.mode != "random" else "random identity"
    print(f"nookwire-tunnel: created {path} from {source}", flush=True)


async def pump(reader: asyncssh.SSHReader, writer) -> None:
    while True:
        data = await reader.read(4096)
        if not data:
            return
        writer.write(data)
        writer.flush()


async def run(
    host: str,
    port: int,
    local_host: str,
    local_port: int,
    slot: int,
    key: Path,
    username: str,
    root: Path | None = None,
) -> int:
    ensure_username_environment(username)
    ensure_key(key, root=root, username=username)

    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, stopped.set)

    # known_hosts=None matches the connect commands this project prints: the
    # ingress is disposable and only carries bytes, so it is not authenticated.
    connection = await asyncssh.connect(
        host,
        port=port,
        username=username,
        client_keys=[str(key)],
        known_hosts=None,
        client_factory=TunnelClient,
        keepalive_interval=30,
        keepalive_count_max=3,
    )

    process = None
    listener = None
    tasks: list[asyncio.Task] = []
    try:
        # srv.us withholds its tcpip-forward reply until a session channel
        # exists, so open the shell first and keep reading it.
        process = await connection.create_process(request_pty=False)
        tasks = [
            asyncio.create_task(pump(process.stdout, sys.stdout)),
            asyncio.create_task(pump(process.stderr, sys.stderr)),
        ]
        with contextlib.suppress(ConnectionError, BrokenPipeError, asyncssh.Error):
            process.stdin.write_eof()
            await process.stdin.drain()

        listener = await connection.forward_remote_port(
            "", slot, local_host, local_port
        )
        print(
            f"remote forward ready on slot {listener.get_port()} "
            f"-> {local_host}:{local_port}",
            flush=True,
        )

        closed = asyncio.create_task(connection.wait_closed())
        requested = asyncio.create_task(stopped.wait())
        tasks.extend((closed, requested))
        await asyncio.wait((closed, requested), return_when=asyncio.FIRST_COMPLETED)
        if requested.done():
            return 0
        print("nookwire-tunnel: connection closed by the server", flush=True)
        return 1
    finally:
        if listener is not None:
            listener.close()
        if process is not None:
            process.stdin.close()
        connection.close()
        await connection.wait_closed()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="srv.us", help="tunnel host")
    parser.add_argument("--port", type=int, default=22, help="tunnel host port")
    parser.add_argument("--local-host", default="127.0.0.1", help="forward destination")
    parser.add_argument("--local-port", type=int, required=True, help="local SSH port")
    parser.add_argument("--slot", type=int, required=True, help="srv.us slot")
    parser.add_argument("--key", required=True, help="tunnel private key path")
    parser.add_argument("--username", default=None, help="tunnel username")
    parser.add_argument("--root", default=None, help="project root directory")
    args = parser.parse_args(argv)

    try:
        root_path = Path(args.root).resolve() if args.root else None
        return asyncio.run(
            run(
                args.host,
                args.port,
                args.local_host,
                args.local_port,
                args.slot,
                Path(args.key).expanduser(),
                args.username or current_username(),
                root=root_path,
            )
        )
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    except (OSError, ValueError, asyncssh.Error) as error:
        print(f"nookwire-tunnel: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
