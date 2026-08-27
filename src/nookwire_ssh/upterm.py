#!/usr/bin/env python3
"""Upterm WSS ingress for Nookwire's local AsyncSSH server."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
import os
import shlex
import signal
import socket
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import asyncssh
from asyncssh.constants import MSG_REQUEST_SUCCESS
import websockets

from nookwire_ssh.identity import current_username, ensure_username_environment
from nookwire_ssh.tunnel import ensure_key

HOST_CLIENT_VERSION = "SSH-2.0-upterm-host-client"
CLIENT_CLIENT_VERSION = "SSH-2.0-upterm-client-client"
SESSION_REQUEST = b"upterm-create-session@upterm.dev"
DEFAULT_ENDPOINT = "wss://uptermd.upterm.dev"
CHUNK = 65536
WS_OPTIONS = dict(max_size=None, ping_interval=20, ping_timeout=20, close_timeout=5)


def log(message: str) -> None:
    print(f"nookwire-upterm: {message}", flush=True)


def _varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("protobuf varint must be non-negative")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _field(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def encode_create_session(
    host_user: str, host_public_keys: list[bytes], client_authorized_keys: list[bytes]
) -> bytes:
    output = [_field(1, host_user.encode())]
    output.extend(_field(2, key) for key in host_public_keys)
    output.extend(_field(3, key) for key in client_authorized_keys)
    return b"".join(output)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("invalid protobuf varint")


def decode_create_session_response(data: bytes) -> dict[str, str]:
    values: dict[int, bytes] = {}
    offset = 0
    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        if tag & 7 != 2:
            raise ValueError("unsupported Upterm protobuf field")
        size, offset = _read_varint(data, offset)
        end = offset + size
        if end > len(data):
            raise ValueError("truncated Upterm session response")
        values[tag >> 3] = data[offset:end]
        offset = end
    try:
        result = {
            "session_id": values[1].decode(),
            "node_addr": values[2].decode(),
            "ssh_user": values[3].decode(),
        }
    except (KeyError, UnicodeDecodeError) as error:
        raise ValueError("invalid Upterm session response") from error
    if not all(result.values()):
        raise ValueError("incomplete Upterm session response")
    return result


def _clean_websocket_url(url: str) -> tuple[str, str, str]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("ws", "wss") or not parsed.hostname:
        raise ValueError(f"Invalid Upterm WebSocket URL: {url}")
    username = parsed.username or ""
    password = parsed.password or ""
    host = parsed.hostname
    if parsed.port:
        host += f":{parsed.port}"
    clean = urlunsplit((parsed.scheme, host, parsed.path or "/", parsed.query, ""))
    return clean, username, password


def websocket_headers(username: str, password: str, *, client: bool) -> dict[str, str]:
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {credentials}",
        "Upterm-Client-Version": (
            CLIENT_CLIENT_VERSION if client else HOST_CLIENT_VERSION
        ),
    }


def client_proxy_url(endpoint: str, session_id: str, node_addr: str) -> str:
    clean, _, _ = _clean_websocket_url(endpoint)
    parsed = urlsplit(clean)
    encoded_node = base64.urlsafe_b64encode(node_addr.encode()).decode()
    userinfo = f"{quote(session_id, safe='')}:{quote(encoded_node, safe='')}@"
    return urlunsplit(
        (parsed.scheme, userinfo + parsed.netloc, parsed.path, parsed.query, "")
    )


def endpoint_host(endpoint: str) -> str:
    clean, _, _ = _clean_websocket_url(endpoint)
    return urlsplit(clean).hostname or "uptermd.upterm.dev"


def session_proxy_url(session: dict[str, str]) -> str:
    return client_proxy_url(
        session["endpoint"], session["session_id"], session["node_addr"]
    )


def ssh_proxy_url(session: dict[str, str]) -> str:
    """Escape an Upterm URL for OpenSSH ProxyCommand percent expansion."""
    return session_proxy_url(session).replace("%", "%%")


def read_session(path: Path) -> dict[str, str] | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    required = ("session_id", "node_addr", "ssh_user", "endpoint")
    if not all(isinstance(value.get(key), str) and value[key] for key in required):
        return None
    return value


def _write_json_atomic(path: Path, value: dict[str, str]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, separators=(",", ":")) + "\n")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _write_bytes_atomic(path: Path, value: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(value)
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _authorized_public_keys(path: Path) -> list[bytes]:
    if not path.is_file():
        return []
    keys: list[bytes] = []
    for raw_line in path.read_text(errors="replace").splitlines():
        try:
            fields = shlex.split(raw_line, comments=True)
        except ValueError:
            continue
        for index in range(max(0, len(fields) - 1)):
            try:
                key = asyncssh.import_public_key(
                    f"{fields[index]} {fields[index + 1]}"
                )
            except (asyncssh.KeyImportError, ValueError):
                continue
            keys.append(key.export_public_key())
            break
    return keys


class WebSocketSocketBridge:
    """Expose a WebSocket byte stream as one side of a socketpair."""

    def __init__(self, websocket, ssh_socket: socket.socket, pump_socket: socket.socket):
        self.websocket = websocket
        self.ssh_socket = ssh_socket
        self.pump_socket = pump_socket
        self.tasks: list[asyncio.Task] = []

    @classmethod
    async def open(cls, url: str, headers: dict[str, str]) -> "WebSocketSocketBridge":
        websocket = await websockets.connect(
            url, additional_headers=headers, **WS_OPTIONS
        )
        ssh_socket, pump_socket = socket.socketpair()
        ssh_socket.setblocking(False)
        pump_socket.setblocking(False)
        bridge = cls(websocket, ssh_socket, pump_socket)
        bridge.tasks = [
            asyncio.create_task(bridge._socket_to_websocket()),
            asyncio.create_task(bridge._websocket_to_socket()),
        ]
        return bridge

    async def _socket_to_websocket(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            while data := await loop.sock_recv(self.pump_socket, CHUNK):
                await self.websocket.send(data)
        except (OSError, websockets.ConnectionClosed):
            pass
        finally:
            with contextlib.suppress(Exception):
                await self.websocket.close()

    async def _websocket_to_socket(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            async for message in self.websocket:
                if isinstance(message, str):
                    message = message.encode()
                await loop.sock_sendall(self.pump_socket, message)
        except (OSError, websockets.ConnectionClosed):
            pass
        finally:
            with contextlib.suppress(OSError):
                self.pump_socket.shutdown(socket.SHUT_RDWR)

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            await self.websocket.close()
        for sock in (self.ssh_socket, self.pump_socket):
            with contextlib.suppress(OSError):
                sock.close()
        for task in self.tasks:
            task.cancel()
        for task in self.tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


async def request_session(connection, payload: bytes) -> dict[str, str]:
    method = getattr(connection, "_make_global_request", None)
    if method is None:
        raise RuntimeError("AsyncSSH no longer supports Upterm global requests")
    packet_type, packet = await method(SESSION_REQUEST, payload)
    if packet_type != MSG_REQUEST_SUCCESS:
        raise RuntimeError("Upterm rejected the session request")
    return decode_create_session_response(packet.get_remaining_payload())


async def run_origin_once(args: argparse.Namespace) -> bool:
    endpoint, _, _ = _clean_websocket_url(args.endpoint)
    ensure_username_environment(args.username)
    ensure_key(args.key)
    control_key = asyncssh.read_private_key(str(args.key))
    host_key = asyncssh.read_private_key(str(args.host_key))
    client_keys = [] if args.accept else _authorized_public_keys(args.authorized_keys)
    if not args.accept and not client_keys:
        raise ValueError("Upterm requires an authorized key unless --accept is set")

    bridge = await WebSocketSocketBridge.open(
        endpoint, websocket_headers(args.username, "", client=False)
    )
    connection = None
    listener = None
    try:
        connection = await asyncssh.connect(
            endpoint_host(endpoint),
            sock=bridge.ssh_socket,
            username=args.username,
            client_keys=[control_key],
            known_hosts=None,
            client_version="upterm-host-client",
            keepalive_interval=10,
            keepalive_count_max=3,
            login_timeout=20,
        )
        relay_key = connection.get_server_host_key()
        if relay_key is None:
            raise RuntimeError("Upterm relay did not present an SSH host key")
        _write_bytes_atomic(args.ca_keys, relay_key.export_public_key())

        payload = encode_create_session(
            args.username,
            [host_key.export_public_key()],
            client_keys,
        )
        session = await request_session(connection, payload)
        listener = await connection.forward_remote_path_to_port(
            session["session_id"], args.local_host, args.local_port
        )
        published = {**session, "endpoint": endpoint}
        _write_json_atomic(args.session_file, published)
        proxy = session_proxy_url(published)
        log(f"session ready: ssh {session['ssh_user']}@{endpoint_host(endpoint)}")
        log(f"client proxy: nookwire-ssh upterm-proxy {proxy}")
        await connection.wait_closed()
        return True
    finally:
        args.session_file.unlink(missing_ok=True)
        if listener is not None:
            listener.close()
            await listener.wait_closed()
        if connection is not None:
            connection.close()
            await connection.wait_closed()
        await bridge.close()


async def run_origin(args: argparse.Namespace) -> None:
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, stopped.set)
    delay = 1
    args.session_file.unlink(missing_ok=True)
    while not stopped.is_set():
        origin = asyncio.create_task(run_origin_once(args))
        stopping = asyncio.create_task(stopped.wait())
        try:
            done, _ = await asyncio.wait(
                (origin, stopping), return_when=asyncio.FIRST_COMPLETED
            )
            if stopping in done:
                origin.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await origin
                break
            stopping.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stopping
            if not await origin:
                raise RuntimeError("Upterm connection ended before publishing a session")
            delay = 1
        except asyncio.CancelledError:
            origin.cancel()
            stopping.cancel()
            raise
        except Exception as error:  # noqa: BLE001 - tunnel supervisor
            stopping.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stopping
            log(f"connection ended: {error!r}; retrying in {delay}s")
            try:
                await asyncio.wait_for(stopped.wait(), timeout=delay)
            except TimeoutError:
                pass
            delay = min(delay * 2, 30)


async def run_client(url: str) -> None:
    endpoint, session_id, encoded_node = _clean_websocket_url(url)
    if not session_id:
        raise ValueError("Upterm proxy URL is missing its session ID")
    async with websockets.connect(
        endpoint,
        additional_headers=websocket_headers(session_id, encoded_node, client=True),
        **WS_OPTIONS,
    ) as websocket:
        loop = asyncio.get_running_loop()

        async def stdin_to_websocket() -> None:
            try:
                while data := await loop.run_in_executor(None, os.read, 0, CHUNK):
                    await websocket.send(data)
            except websockets.ConnectionClosed:
                pass

        async def websocket_to_stdout() -> None:
            try:
                async for message in websocket:
                    if isinstance(message, str):
                        message = message.encode()
                    view = memoryview(message)
                    while view:
                        view = view[os.write(1, view) :]
            except (websockets.ConnectionClosed, BrokenPipeError):
                pass

        tasks = [
            asyncio.create_task(stdin_to_websocket()),
            asyncio.create_task(websocket_to_stdout()),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for task in done:
            with contextlib.suppress(websockets.ConnectionClosed, BrokenPipeError):
                task.result()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    origin = sub.add_parser("origin")
    origin.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    origin.add_argument("--local-host", default="127.0.0.1")
    origin.add_argument("--local-port", type=int, required=True)
    origin.add_argument("--username", default=current_username())
    origin.add_argument("--key", type=Path, required=True)
    origin.add_argument("--host-key", type=Path, required=True)
    origin.add_argument("--authorized-keys", type=Path, required=True)
    origin.add_argument("--ca-keys", type=Path, required=True)
    origin.add_argument("--session-file", type=Path, required=True)
    origin.add_argument("--accept", action="store_true")
    client = sub.add_parser("client")
    client.add_argument("url")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.mode == "origin":
            asyncio.run(run_origin(args))
        else:
            asyncio.run(run_client(args.url))
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    except (OSError, ValueError, RuntimeError, asyncssh.Error) as error:
        print(f"nookwire-upterm: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
