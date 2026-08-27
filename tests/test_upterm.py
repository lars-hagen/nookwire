import base64
import asyncio
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import asyncssh
from asyncssh.constants import MSG_REQUEST_SUCCESS
from asyncssh.packet import SSHPacket
from websockets.frames import Close

from nookwire_ssh import upterm


class UptermProtocolTests(unittest.IsolatedAsyncioTestCase):
    def test_headers_and_proxy_url_match_upterm_protocol(self):
        headers = upterm.websocket_headers("session", "node", client=True)
        self.assertEqual(headers["Upterm-Client-Version"], upterm.CLIENT_CLIENT_VERSION)
        self.assertEqual(
            base64.b64decode(headers["Authorization"].split()[1]), b"session:node"
        )
        url = upterm.client_proxy_url(
            "wss://uptermd.upterm.dev", "session", "node.example:22"
        )
        clean, username, encoded_node = upterm._clean_websocket_url(url)
        self.assertEqual(clean, "wss://uptermd.upterm.dev/")
        self.assertEqual(username, "session")
        self.assertEqual(base64.urlsafe_b64decode(encoded_node), b"node.example:22")
        session = {
            "endpoint": "wss://uptermd.upterm.dev",
            "session_id": "session",
            "node_addr": "node",
        }
        self.assertIn("%%3D", upterm.ssh_proxy_url(session))

    def test_create_session_wire_format_and_response(self):
        request = upterm.encode_create_session("nookwire", [b"host"], [b"client"])
        self.assertEqual(
            request,
            b"\x0a\x08nookwire\x12\x04host\x1a\x06client",
        )
        response = b"\x0a\x03sid\x12\x04node\x1a\x04user"
        self.assertEqual(
            upterm.decode_create_session_response(response),
            {"session_id": "sid", "node_addr": "node", "ssh_user": "user"},
        )
        with self.assertRaises(ValueError):
            upterm.decode_create_session_response(response[:-1])

    async def test_custom_global_request_is_isolated(self):
        response = b"\x0a\x03sid\x12\x04node\x1a\x04user"
        connection = mock.Mock()
        connection._make_global_request = mock.AsyncMock(
            return_value=(MSG_REQUEST_SUCCESS, SSHPacket(response))
        )
        result = await upterm.request_session(connection, b"request")
        self.assertEqual(result["session_id"], "sid")
        connection._make_global_request.assert_awaited_once_with(
            upterm.SESSION_REQUEST, b"request"
        )

    def test_session_file_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "upterm.json"
            path.write_text(
                json.dumps(
                    {
                        "session_id": "sid",
                        "node_addr": "node",
                        "ssh_user": "user",
                        "endpoint": upterm.DEFAULT_ENDPOINT,
                    }
                )
            )
            self.assertEqual(upterm.read_session(path)["ssh_user"], "user")
            path.write_text("{}")
            self.assertIsNone(upterm.read_session(path))

    def test_invalid_websocket_url_is_rejected(self):
        with self.assertRaises(ValueError):
            upterm._clean_websocket_url("https://uptermd.upterm.dev")

    async def test_websocket_socket_bridge_pumps_and_closes(self):
        class FakeWebSocket:
            def __init__(self):
                self.incoming = asyncio.Queue()
                self.sent = []
                self.closed = False

            async def send(self, data):
                self.sent.append(data)

            async def close(self):
                self.closed = True

            def __aiter__(self):
                return self

            async def __anext__(self):
                value = await self.incoming.get()
                if value is None:
                    raise StopAsyncIteration
                return value

        websocket = FakeWebSocket()
        ssh_socket, pump_socket = socket.socketpair()
        ssh_socket.setblocking(False)
        pump_socket.setblocking(False)
        bridge = upterm.WebSocketSocketBridge(websocket, ssh_socket, pump_socket)
        bridge.tasks = [
            asyncio.create_task(bridge._socket_to_websocket()),
            asyncio.create_task(bridge._websocket_to_socket()),
        ]
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendall(ssh_socket, b"to-websocket")
            for _ in range(20):
                if websocket.sent:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(websocket.sent, [b"to-websocket"])

            await websocket.incoming.put(b"to-socket")
            self.assertEqual(await loop.sock_recv(ssh_socket, 9), b"to-socket")
        finally:
            await bridge.close()
        self.assertTrue(websocket.closed)
        self.assertTrue(all(task.done() for task in bridge.tasks))

    def test_authorized_keys_support_options(self):
        key = asyncssh.generate_private_key("ssh-ed25519").export_public_key()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "authorized_keys"
            path.write_bytes(b'command="restricted shell" ' + key)
            self.assertEqual(upterm._authorized_public_keys(path), [key])

    async def test_client_proxy_handles_clean_websocket_close(self):
        class ClosedWebSocket:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def __aiter__(self):
                return self

            async def __anext__(self):
                close = Close(1000, "")
                raise upterm.websockets.ConnectionClosedOK(close, close, True)

            async def send(self, _data):
                return None

        url = upterm.client_proxy_url(upterm.DEFAULT_ENDPOINT, "session", "node")
        with mock.patch.object(upterm.websockets, "connect", return_value=ClosedWebSocket()), mock.patch.object(
            upterm.os, "read", return_value=b""
        ):
            await upterm.run_client(url)


if __name__ == "__main__":
    unittest.main()
