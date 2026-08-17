import asyncio
import contextlib
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import asyncssh

from nookwire_ssh import cli, state as state_mod

PROJECT = Path(__file__).resolve().parents[1]
SRC = str(PROJECT / "src")

SRVUS_HOST = "cli-smoke.srv.us"


class _RelayServer(asyncssh.SSHServer):
    """Stand-in for srv.us: no auth, accepts remote port forwards."""

    def begin_auth(self, username):
        del username
        return False

    def server_requested(self, listen_host, listen_port):
        del listen_host, listen_port
        return True


def _relay_announce(process):
    """Emit the srv.us URL on the client command so the CLI can scrape it."""

    async def go():
        process.stdout.write(f"nookwire relay: https://{SRVUS_HOST}/\n")
        await process.stdout.drain()

    return go()


def run_relay(relay_port, ready):
    async def main():
        key = asyncssh.generate_private_key("ssh-ed25519")
        fd, path = tempfile.mkstemp()
        os.write(fd, key.export_private_key())
        os.close(fd)
        await asyncssh.create_server(
            _RelayServer,
            "127.0.0.1",
            relay_port,
            server_host_keys=[path],
            process_factory=_relay_announce,
        )
        ready.set()
        while True:
            await asyncio.sleep(60)

    asyncio.run(main())


def start_relay(relay_port):
    ready = threading.Event()
    thread = threading.Thread(target=run_relay, args=(relay_port, ready), daemon=True)
    thread.start()
    ready.wait(timeout=10)
    return thread


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_cli(argv, env=None):
    stdout, stderr = io.StringIO(), io.StringIO()
    saved = dict(os.environ)
    if env is not None:
        os.environ.clear()
        os.environ.update(env)
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    return code, stdout.getvalue(), stderr.getvalue()


def make_env(home, state_base):
    # Point the tunnel at a dead local port by default so a tunnel that is
    # spawned without a real relay fails locally instead of touching srv.us.
    dead = free_port()
    return {
        **os.environ,
        "PYTHONPATH": SRC,
        "HOME": str(home),
        "NOOKWIRE_SSH_STATE_DIR": str(state_base),
        "NOOKWIRE_TUNNEL_HOST": "127.0.0.1",
        "NOOKWIRE_TUNNEL_PORT": str(dead),
    }


def state_dir(state_base):
    return state_base / "nookwire-ssh"


class CLILifecycleTests(unittest.TestCase):
    def test_background_start_status_logs_and_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            key_dir = home / ".ssh"
            key_dir.mkdir()
            key = key_dir / "id_ed25519"
            # A real key: the srv.us tunnel reuses it, and 0600 mode is
            # repaired locally so OpenSSH and the tunnel both accept it.
            key.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
            key.chmod(0o660)  # not 0600 -> must be repaired and reported
            (key_dir / "authorized_keys").write_text("")
            state_base = temp / "state"
            state = state_dir(state_base)
            root = temp / "root"
            root.mkdir()

            relay_port = free_port()
            relay_forward = free_port()
            ssh_port = free_port()
            env = make_env(home, state_base)
            env["NOOKWIRE_TUNNEL_PORT"] = str(relay_port)
            start_relay(relay_port)
            try:
                code, out, err = run_cli(
                    ["start", str(root), str(ssh_port), str(relay_forward)], env=env
                )
                self.assertEqual(code, 0, err)
                self.assertIn("Nookwire SSH started in the background.", out)
                self.assertIn("Fixed permissions on", err)
                self.assertIn("(was 660, now 600)", err)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                self.assertTrue((state / "password").is_file())

                code, out, err = run_cli(["status"], env=env)
                self.assertEqual(code, 0)
                self.assertIn("server: running (pid", out)
                self.assertIn("tunnel: running (pid", out)
                self.assertIn(f"url: https://{SRVUS_HOST}/", out)
                self.assertIn("openssl s_client", out)
                self.assertIn("-quiet", out)
                self.assertIn("-no_ign_eof", out)
                self.assertIn("key auth: disabled", out)
                self.assertNotIn("logs tunnel -f", out)

                code, out, err = run_cli(["logs", "tunnel"], env=env)
                self.assertEqual(code, 0)
                self.assertIn("remote forward ready", out)

                code, out, err = run_cli(["stop"], env=env)
                self.assertEqual(code, 0)
                self.assertIn("Nookwire SSH stopped.", out)
            finally:
                for name in ("server.pid", "tunnel.pid"):
                    pid = state_mod.read_pid(state / name)
                    if pid:
                        with contextlib.suppress(OSError):
                            os.kill(pid, 9)

            code, out, err = run_cli(["status"], env=env)
            self.assertEqual(code, 1)
            self.assertIn("server: stopped", out)
            self.assertIn("tunnel: stopped", out)

    def test_stop_refuses_mismatched_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            env = make_env(home, state_base)
            victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            try:
                (state / "server.pid").write_text(
                    f"{victim.pid} deliberately-wrong-identity\n"
                )
                code, out, err = run_cli(["stop"], env=env)
                self.assertEqual(code, 0)
                self.assertEqual(victim.poll(), None, "unrelated process was killed")
            finally:
                victim.terminate()
                victim.wait()

    @mock.patch("nookwire_ssh.state.process_identity", return_value=None)
    def test_start_refuses_untrackable_server(self, _mock_id):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            root = temp / "root"
            root.mkdir()
            env = make_env(home, state_base)
            ssh_port = free_port()
            code, out, err = run_cli(
                ["start", str(root), str(ssh_port), "1", "--accept"], env=env
            )
            self.assertNotEqual(code, 0)
            self.assertIn("Unable to track server process", err)

    def test_start_refuses_untrackable_tunnel(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            root = temp / "root"
            root.mkdir()
            env = make_env(home, state_base)
            ssh_port = free_port()

            # The server is launched and tracked, but write_pid refuses the
            # tunnel pid file just as it would when the pid is unidentifiable.
            import nookwire_ssh.state as st

            orig_write = st.write_pid

            def write_pid(pid_file, pid):
                if pid_file.name == "tunnel.pid":
                    return False
                return orig_write(pid_file, pid)

            st.write_pid = write_pid
            try:
                code, out, err = run_cli(
                    ["start", str(root), str(ssh_port), "1", "--accept"], env=env
                )
            finally:
                st.write_pid = orig_write
            self.assertNotEqual(code, 0)
            self.assertIn("Unable to track tunnel process", err)
            self.assertFalse((state / "password").exists())

    def test_accept_removes_password_and_skips_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            root = temp / "root"
            root.mkdir()
            (state / "password").write_text("stale-password")
            env = make_env(home, state_base)
            ssh_port = free_port()
            # Force the tunnel step to fail after the server has started so the
            # --accept password-clearing path runs against a real server.
            import nookwire_ssh.state as st

            orig_write = st.write_pid

            def write_pid(pid_file, pid):
                if pid_file.name == "tunnel.pid":
                    return False
                return orig_write(pid_file, pid)

            st.write_pid = write_pid
            try:
                code, out, err = run_cli(
                    ["start", str(root), str(ssh_port), "1", "--accept"], env=env
                )
            finally:
                st.write_pid = orig_write
            self.assertNotEqual(code, 0)
            self.assertFalse((state / "password").exists())

            (state / "meta").write_text("accept=1\nallow_tcp_forwarding=0\nbackend=srvus\n")
            code, out, err = run_cli(["status"], env=env)
            self.assertIn("auth: none (--accept); anyone can connect", out)


class SSHConfigTests(unittest.TestCase):
    def test_ssh_config_print_and_idempotent_write(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            config = home / ".ssh" / "config"
            env = {**os.environ, "HOME": str(home)}

            code, out, err = run_cli(["ssh-config"], env=env)
            self.assertEqual(code, 0)
            self.assertIn("Host *.srv.us", out)
            self.assertIn("openssl s_client", out)

            code, out, err = run_cli(["ssh-config", "--write"], env=env)
            self.assertEqual(code, 0)
            self.assertIn("Added the srv.us block to", out)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(config.read_text().count("Host *.srv.us"), 1)

            code, out, err = run_cli(["ssh-config", "--write"], env=env)
            self.assertEqual(code, 0)
            self.assertIn("Already present in", out)
            self.assertEqual(config.read_text().count("Host *.srv.us"), 1)


class StateUnitTests(unittest.TestCase):
    def test_repair_key_permissions(self):
        import nookwire_ssh.state as st

        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "id_ed25519"
            key.write_bytes(b"key")
            key.chmod(0o660)
            buffer = io.StringIO()
            with contextlib.redirect_stderr(buffer):
                st.repair_key_permissions(key)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertIn("Fixed permissions on", buffer.getvalue())

    def test_extract_host(self):
        import nookwire_ssh.state as st

        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "tunnel.log"
            log.write_text(
                "https://not-a-host.example ignored\nremote forward ready on slot 1\n"
                "https://cli.srv.us/\n"
            )
            self.assertEqual(st.extract_host(log), "cli.srv.us")


if __name__ == "__main__":
    unittest.main()
