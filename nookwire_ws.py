#!/usr/bin/env python3
"""Stdio/TCP <-> WebSocket bridge for the Nookwire SSH cloudflare backend.

Two modes pump a raw byte stream across a WebSocket relay (a Cloudflare Worker):

  origin  Connects out to the relay and, on the first inbound byte, dials the
          local SSH server, splicing the two. Loops to serve many sessions.
  client  Connects out to the relay and splices it to stdin/stdout, so it can be
          used as an ssh ProxyCommand.

The relay pairs one "origin" and one "client" socket per tunnel id. Roles are
selected by appending role=origin|client to the base URL passed in.

Launch with the websockets package available, e.g.:
  uv run --with websockets python nookwire_ws.py client wss://host/tunnel/ID
"""

import argparse
import asyncio
import os
import sys

try:
    import websockets
except ImportError:  # pragma: no cover - environment guard
    sys.stderr.write("nookwire_ws: the 'websockets' package is required\n")
    sys.exit(1)

CHUNK = 65536
CONNECT_KWARGS = dict(max_size=None, ping_interval=20, ping_timeout=20, close_timeout=5)


def log(message):
    sys.stderr.write("nookwire_ws: " + message + "\n")
    sys.stderr.flush()


def role_url(base, role):
    joiner = "&" if "?" in base else "?"
    return base + joiner + "role=" + role


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


async def _await_first_completed(*coros):
    tasks = [asyncio.ensure_future(coro) for coro in coros]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    for task in pending:
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001 - draining only
            pass
    for task in done:
        exc = task.exception()
        if exc is not None:
            raise exc


async def run_client(base):
    url = role_url(base, "client")
    async with websockets.connect(url, **CONNECT_KWARGS) as ws:
        loop = asyncio.get_event_loop()
        stdin_fd = sys.stdin.fileno()

        async def stdin_to_ws():
            while True:
                data = await loop.run_in_executor(None, os.read, stdin_fd, CHUNK)
                if not data:
                    break
                await ws.send(data)

        async def ws_to_stdout():
            async for message in ws:
                if isinstance(message, str):
                    message = message.encode()
                _write_all(1, message)

        await _await_first_completed(stdin_to_ws(), ws_to_stdout())


async def run_origin_once(base, host, port):
    url = role_url(base, "origin")
    async with websockets.connect(url, **CONNECT_KWARGS) as ws:
        # Wait for the client's first byte before dialing the local server, so
        # the server's SSH banner is never emitted into a peerless relay.
        try:
            first = await ws.recv()
        except websockets.ConnectionClosed:
            return
        if isinstance(first, str):
            first = first.encode()
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(first)
        await writer.drain()

        async def tcp_to_ws():
            while True:
                data = await reader.read(CHUNK)
                if not data:
                    break
                await ws.send(data)

        async def ws_to_tcp():
            async for message in ws:
                if isinstance(message, str):
                    message = message.encode()
                writer.write(message)
                await writer.drain()

        try:
            await _await_first_completed(tcp_to_ws(), ws_to_tcp())
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass


async def run_origin(base, host, port):
    delay = 1
    while True:
        try:
            await run_origin_once(base, host, port)
            delay = 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep the tunnel alive
            log("origin session ended: " + repr(exc))
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)
            continue
        await asyncio.sleep(0.5)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nookwire SSH WebSocket bridge")
    sub = parser.add_subparsers(dest="mode", required=True)

    client = sub.add_parser("client", help="stdio <-> relay (ssh ProxyCommand)")
    client.add_argument("url", help="base relay URL, e.g. wss://host/tunnel/ID")

    origin = sub.add_parser("origin", help="local SSH server <-> relay")
    origin.add_argument("url", help="base relay URL, e.g. wss://host/tunnel/ID")
    origin.add_argument("--host", default="127.0.0.1")
    origin.add_argument("--port", type=int, required=True)

    args = parser.parse_args(argv)
    try:
        if args.mode == "client":
            asyncio.run(run_client(args.url))
        else:
            asyncio.run(run_origin(args.url, args.host, args.port))
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
