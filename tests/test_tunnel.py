import asyncio
import contextlib
import os
import re
import tempfile
import unittest
from pathlib import Path

import asyncssh

PROJECT = Path(__file__).resolve().parents[1]
SRC = str(PROJECT / "src")


class ForwardingSSHServer(asyncssh.SSHServer):
    """Minimal stand-in for srv.us: no auth, remote port forwarding allowed."""

    def begin_auth(self, username):
        del username
        return False

    def server_requested(self, listen_host, listen_port):
        del listen_host, listen_port
        return True


class TunnelTests(unittest.TestCase):
    def test_tunnel_creates_key_and_forwards_to_local_port(self):
        with tempfile.TemporaryDirectory() as temp:
            asyncio.run(self.check_tunnel_forwarding(Path(temp)))

    async def check_tunnel_forwarding(self, temporary):
        async def echo(reader, writer):
            writer.write(await reader.read(64))
            await writer.drain()
            writer.close()

        local = await asyncio.start_server(echo, "127.0.0.1", 0)
        local_port = local.sockets[0].getsockname()[1]

        host_key = temporary / "relay_host_key"
        host_key.write_bytes(
            asyncssh.generate_private_key("ssh-ed25519").export_private_key()
        )
        relay = await asyncssh.create_server(
            ForwardingSSHServer,
            "127.0.0.1",
            0,
            server_host_keys=[str(host_key)],
            process_factory=lambda process: process.exit(0),
        )

        # The key path does not exist yet: the tunnel has to create it, which is
        # what replaces ssh-keygen for the srvus backend.
        key_path = temporary / "tunnel-keys" / "id_ed25519"
        tunnel = await asyncio.create_subprocess_exec(
            os.sys.executable,
            "-m",
            "nookwire_ssh.tunnel",
            "--host", "127.0.0.1",
            "--port", str(relay.get_port()),
            "--local-port", str(local_port),
            "--slot", "0",
            "--key", str(key_path),
            env={**os.environ, "PYTHONPATH": SRC},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            slot = None
            while slot is None:
                line = await asyncio.wait_for(tunnel.stdout.readline(), 30)
                if not line:
                    self.fail("tunnel exited before the forward was ready")
                match = re.search(rb"remote forward ready on slot (\d+)", line)
                if match:
                    slot = int(match.group(1))

            reader, writer = await asyncio.open_connection("127.0.0.1", slot)
            writer.write(b"ping")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(4), 10), b"ping")
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        finally:
            tunnel.terminate()
            await tunnel.wait()
            relay.close()
            await relay.wait_closed()
            local.close()
            await local.wait_closed()


if __name__ == "__main__":
    unittest.main()
