import asyncio
import contextlib
import getpass
import io
import json
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
            try:
                code = cli.main(argv)
            except SystemExit as exc:
                # die() raises SystemExit(message); the interpreter prints a
                # string code to stderr before exiting 1, so simulate that.
                if isinstance(exc.code, str):
                    stderr.write(exc.code + "\n")
                    code = 1
                elif exc.code is None:
                    code = 0
                else:
                    code = exc.code
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
    @mock.patch("nookwire_ssh.cli.time.sleep")
    @mock.patch("nookwire_ssh.cli.upterm.read_session", return_value=None)
    @mock.patch("nookwire_ssh.cli.st.is_running", return_value=True)
    def test_upterm_session_wait_times_out(self, _running, _session, sleep):
        result = cli.wait_for_upterm_session(Path("tunnel.pid"), Path("upterm.json"))
        self.assertIsNone(result)
        self.assertEqual(sleep.call_count, 40)

    @mock.patch("nookwire_ssh.cli._spawn")
    @mock.patch("nookwire_ssh.cli.ensure_username_environment", return_value="nookwire")
    def test_launch_server_supports_uid_without_passwd_entry(self, _username, spawn):
        args = mock.Mock(accept=False, allow_tcp_forwarding=False)
        cli.launch_server(args, Path("/workspace"), 8022, "password", Path("/state"))
        command = spawn.call_args.args[0]
        self.assertEqual(command[command.index("--username") + 1], "nookwire")

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
                self.assertIn("  server    running", out)
                self.assertIn("Fixed permissions on", err)
                self.assertIn("(was 660, now 600)", err)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                self.assertTrue((state / "password").is_file())

                code, out, err = run_cli(["status"], env=env)
                self.assertEqual(code, 0)
                self.assertIn("server    running   pid", out)
                self.assertIn("tunnel    running   pid", out)
                self.assertIn(f"url       https://{SRVUS_HOST}/", out)
                self.assertNotIn("\x1b[", out)
                self.assertIn(f"connect   ssh {getpass.getuser()}@{SRVUS_HOST}", out)
                self.assertIn("keys      disabled", out)
                self.assertNotIn("logs tunnel -f", out)

                code, out, err = run_cli(["connect"], env=env)
                self.assertEqual(code, 0, err)
                self.assertIn("openssl s_client", out)
                self.assertIn("-quiet", out)
                self.assertIn("-no_ign_eof", out)
                self.assertIn("Host *.srv.us", out)

                code, out, err = run_cli(["logs", "tunnel"], env=env)
                self.assertEqual(code, 0)
                self.assertIn("remote forward ready", out)

                code, out, err = run_cli(["stop"], env=env)
                self.assertEqual(code, 0)
                self.assertIn("Nookwire stopped.", out)
            finally:
                for name in ("server.pid", "tunnel.pid"):
                    pid = state_mod.read_pid(state / name)
                    if pid:
                        with contextlib.suppress(OSError):
                            os.kill(pid, 9)

            code, out, err = run_cli(["status"], env=env)
            self.assertEqual(code, 1)
            self.assertIn("server    stopped", out)
            self.assertIn("tunnel    stopped", out)

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
            self.assertIn("auth      none (--accept); anyone can connect", out)

    def test_start_refuses_occupied_port(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            root = temp / "root"
            root.mkdir()
            env = make_env(home, state_base)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                sock.listen(1)
                port = sock.getsockname()[1]
                code, out, err = run_cli(
                    ["start", str(root), str(port), "1", "--accept"], env=env
                )
            self.assertNotEqual(code, 0, err)
            self.assertIn(f"Port {port} is already in use", err)
            self.assertFalse((state / "server.pid").exists())
            self.assertFalse((state / "tunnel.pid").exists())

    def test_saved_settings_are_reused_by_a_bare_start(self):
        """A repeat start on the same box needs no arguments."""
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
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                sock.listen(1)
                port = sock.getsockname()[1]
                (state / "config").write_text(
                    "backend=cloudflared\n"
                    f"root={root}\n"
                    f"port={port}\n"
                    "slot=1\n"
                    "hostname=glacier.vctx.io\n"
                    "token=saved-token-value\n"
                )
                # No arguments at all: the saved port has to be the one it tries.
                code, out, err = run_cli(["start"], env=env)
            self.assertNotEqual(code, 0, err)
            self.assertIn(f"Port {port} is already in use", err)

    def test_restart_without_saved_settings_refuses(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            env = make_env(home, state_base)
            code, out, err = run_cli(["restart"], env=env)
            self.assertNotEqual(code, 0)
            self.assertIn("Nothing saved to restart", err)

    def test_status_non_tty_has_no_ansi(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            (state / "meta").write_text(
                "accept=0\nallow_tcp_forwarding=0\nbackend=cloudflared\nhostname=glacier.vctx.io\n"
            )
            env = make_env(home, state_base)
            code, out, err = run_cli(["status"], env=env)
            self.assertNotIn("\x1b[", out)
            self.assertIn("url       ssh://glacier.vctx.io", out)
            self.assertIn("first time here: nookwire connect", out)
            code, out, err = run_cli(["connect"], env=env)
            self.assertEqual(code, 0, err)
            self.assertIn("cloudflared must be installed", out)
            self.assertNotIn("\x1b[", out)


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
            self.assertIn("Added the *.srv.us block to", out)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(config.read_text().count("Host *.srv.us"), 1)

            code, out, err = run_cli(["ssh-config", "--write"], env=env)
            self.assertEqual(code, 0)
            self.assertIn("Already present in", out)
            self.assertEqual(config.read_text().count("Host *.srv.us"), 1)

    def test_ssh_config_explicit_host_uses_backend_proxy_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            (state / "meta").write_text("backend=cloudflared\n")
            config = home / ".ssh" / "config"
            env = {**os.environ, "HOME": str(home), "NOOKWIRE_SSH_STATE_DIR": str(state_base)}

            code, out, err = run_cli(["ssh-config", "glacier.vctx.io"], env=env)
            self.assertEqual(code, 0)
            self.assertIn("Host glacier.vctx.io", out)
            self.assertIn("cloudflared access ssh --hostname %h", out)

            code, out, err = run_cli(["ssh-config", "--write", "glacier.vctx.io"], env=env)
            self.assertEqual(code, 0)
            self.assertIn("Added the glacier.vctx.io block to", out)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(config.read_text().count("Host glacier.vctx.io"), 1)

            code, out, err = run_cli(["ssh-config", "--write", "glacier.vctx.io"], env=env)
            self.assertEqual(code, 0)
            self.assertIn("Already present in", out)
            self.assertEqual(config.read_text().count("Host glacier.vctx.io"), 1)


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

    def test_state_dir_and_tunnel_key_path_precedence(self):
        import nookwire_ssh.state as st

        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            st_dir = temp / "state"
            st_dir.mkdir()
            home = temp / "home"
            home.mkdir()
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir()

            # 1. Neither exists -> returns dedicated path under state_dir
            with mock.patch.dict(os.environ, {"HOME": str(home), "NOOKWIRE_STATE_DIR": str(temp / "custom_state")}):
                self.assertEqual(st.state_dir(), temp / "custom_state" / "nookwire-ssh")
                self.assertEqual(st.tunnel_key_path(st_dir), st_dir / "tunnel_id_ed25519")

            # 2. Legacy key exists -> returns legacy key path for backwards compatibility
            legacy_key = ssh_dir / "id_ed25519"
            legacy_key.write_bytes(b"legacy-key")
            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                self.assertEqual(st.tunnel_key_path(st_dir), legacy_key)

            # 3. Dedicated key exists -> dedicated key takes precedence over legacy key
            dedicated_key = st_dir / "tunnel_id_ed25519"
            dedicated_key.write_bytes(b"dedicated-key")
            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                self.assertEqual(st.tunnel_key_path(st_dir), dedicated_key)


class ExtendedCLITests(unittest.TestCase):
    @mock.patch("nookwire_ssh.cli.launch_server")
    @mock.patch("nookwire_ssh.cli.launch_tunnel_srvus")
    @mock.patch("nookwire_ssh.cli.st.is_running", return_value=True)
    def test_idempotent_repeated_start_both_running(
        self, mock_is_running, mock_launch_tunnel, mock_launch_server
    ):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            (state / "server.pid").write_text("123\n")
            (state / "tunnel.pid").write_text("124\n")
            env = make_env(home, state_base)
            code, out, err = run_cli(["start"], env=env)
            self.assertEqual(code, 0, err)
            self.assertIn("server    running", out)
            mock_launch_server.assert_not_called()
            mock_launch_tunnel.assert_not_called()

    @mock.patch("nookwire_ssh.cli.launch_server")
    @mock.patch("nookwire_ssh.cli.launch_tunnel_srvus")
    @mock.patch("nookwire_ssh.cli.st.is_running")
    def test_repeated_start_partial_state_errors(
        self, mock_is_running, mock_launch_tunnel, mock_launch_server
    ):
        # Server running, tunnel stopped
        mock_is_running.side_effect = lambda path: path.name == "server.pid"
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            (state / "server.pid").write_text("123 dummy-ident\n")
            env = make_env(home, state_base)
            code, out, err = run_cli(["start"], env=env)
            self.assertEqual(code, 1)
            self.assertIn("Server is running (pid 123) but tunnel is stopped", err)
            mock_launch_server.assert_not_called()
            mock_launch_tunnel.assert_not_called()

        # Tunnel running, server stopped
        mock_is_running.side_effect = lambda path: path.name == "tunnel.pid"
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            (state / "tunnel.pid").write_text("124 dummy-ident\n")
            env = make_env(home, state_base)
            code, out, err = run_cli(["start"], env=env)
            self.assertEqual(code, 1)
            self.assertIn("Tunnel is running (pid 124) but server is stopped", err)
            mock_launch_server.assert_not_called()
            mock_launch_tunnel.assert_not_called()

    @mock.patch("time.sleep")
    @mock.patch("nookwire_ssh.cli.wait_for_srvus_host")
    @mock.patch("nookwire_ssh.cli.st.write_pid", return_value=True)
    @mock.patch("nookwire_ssh.cli.st.port_open")
    @mock.patch("nookwire_ssh.cli.st.is_running")
    @mock.patch("nookwire_ssh.cli.prompt_authorized_key")
    @mock.patch("nookwire_ssh.cli.launch_server")
    @mock.patch("nookwire_ssh.cli.launch_tunnel_srvus")
    def test_prompt_suppression_and_batch_precedence(
        self,
        mock_tunnel,
        mock_server,
        mock_prompt,
        mock_is_running,
        mock_port_open,
        mock_write_pid,
        mock_wait_srvus,
        mock_sleep,
    ):
        proc_server = mock.MagicMock()
        proc_server.pid = 99999
        proc_tunnel = mock.MagicMock()
        proc_tunnel.pid = 99998

        running = {"server": False, "tunnel": False}

        def fake_launch_server(*a, **kw):
            running["server"] = True
            return proc_server

        def fake_launch_tunnel(*a, **kw):
            running["tunnel"] = True
            return proc_tunnel

        mock_server.side_effect = fake_launch_server
        mock_tunnel.side_effect = fake_launch_tunnel
        mock_is_running.side_effect = lambda p: running["server"] if "server" in p.name else running["tunnel"]
        mock_port_open.side_effect = lambda p: running["server"]

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

            # 1. start --batch flag suppresses prompt and saves batch=1
            running["server"] = False
            running["tunnel"] = False
            code, out, err = run_cli(
                ["start", "--batch", str(root), "8022", "1"], env=env
            )
            self.assertEqual(code, 0, err)
            mock_prompt.assert_not_called()
            config_text = (state / "config").read_text()
            self.assertIn("batch=1", config_text)

            # 2. Repeated start restoring saved batch without --batch flag
            running["server"] = False
            running["tunnel"] = False
            mock_prompt.reset_mock()
            code, out, err = run_cli(["start", str(root), "8022", "1"], env=env)
            self.assertEqual(code, 0, err)
            mock_prompt.assert_not_called()

            # 3. If config batch is 0, prompt is called
            (state / "config").write_text("backend=srvus\nport=8022\nslot=1\nbatch=0\n")
            running["server"] = False
            running["tunnel"] = False
            mock_prompt.reset_mock()
            code, out, err = run_cli(["start", str(root), "8022", "1"], env=env)
            self.assertEqual(code, 0, err)
            mock_prompt.assert_called_once()

            # 4. NOOKWIRE_BATCH=1 suppresses prompt even if config is 0
            running["server"] = False
            running["tunnel"] = False
            mock_prompt.reset_mock()
            env["NOOKWIRE_BATCH"] = "1"
            code, out, err = run_cli(["start", str(root), "8022", "1"], env=env)
            self.assertEqual(code, 0, err)
            mock_prompt.assert_not_called()

            # 5. Legacy NOOKWIRE_SSH_BATCH=1 suppresses prompt
            running["server"] = False
            running["tunnel"] = False
            mock_prompt.reset_mock()
            env.pop("NOOKWIRE_BATCH")
            env["NOOKWIRE_SSH_BATCH"] = "1"
            code, out, err = run_cli(["start", str(root), "8022", "1"], env=env)
            self.assertEqual(code, 0, err)
            mock_prompt.assert_not_called()

    def test_status_json_output(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            (state / "meta").write_text(
                "accept=0\nallow_tcp_forwarding=0\nbackend=srvus\n"
            )
            (state / "tunnel.log").write_text("https://cli-test.srv.us/\n")
            env = make_env(home, state_base)

            code, out, err = run_cli(["status", "--json"], env=env)
            # Both processes are stopped in this test, so status command exits 1
            self.assertEqual(code, 1)
            self.assertEqual(err, "")
            self.assertNotIn("\x1b[", out)
            data = json.loads(out)
            self.assertIn("version", data)
            self.assertEqual(data["backend"], "srvus")
            self.assertEqual(data["server"]["state"], "stopped")
            self.assertIsNone(data["server"]["pid"])
            self.assertEqual(data["tunnel"]["state"], "stopped")
            self.assertIsNone(data["tunnel"]["pid"])
            self.assertEqual(data["url"], "https://cli-test.srv.us/")
            self.assertEqual(data["host"], "cli-test.srv.us")
            self.assertIn("identity", data)
            self.assertIn("mode", data["identity"])
            self.assertIn("connect_command", data)

    def test_connect_batch_exact_single_line_and_json(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            (state / "meta").write_text("backend=srvus\n")
            (state / "tunnel.log").write_text("https://cli-batch.srv.us/\n")
            env = make_env(home, state_base)

            code, out, err = run_cli(["connect", "--batch"], env=env)
            self.assertEqual(code, 0, err)
            self.assertEqual(err, "")
            lines = out.strip().splitlines()
            self.assertEqual(len(lines), 1, f"Expected exactly 1 line, got: {out!r}")
            cmd = lines[0]
            self.assertTrue(cmd.startswith("ssh "))
            self.assertIn("-T", cmd)
            self.assertIn("-o BatchMode=yes", cmd)
            self.assertIn("cli-batch.srv.us", cmd)
            self.assertNotIn("\x1b[", cmd)

            code, out, err = run_cli(["connect", "--json"], env=env)
            self.assertEqual(code, 0, err)
            self.assertEqual(err, "")
            data = json.loads(out)
            self.assertEqual(data["host"], "cli-batch.srv.us")
            self.assertIn("-o BatchMode=yes", data["batch_command"])
            self.assertIn("ssh", data["command"])

    def test_identity_command_cli_and_json(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            secret = "super-secret-key-12345"
            env = make_env(home, state_base)
            env["NOOKWIRE_IDENTITY_SEED"] = secret

            # Text mode
            code, out, err = run_cli(["identity"], env=env)
            self.assertEqual(code, 0, err)
            self.assertIn("mode:        seeded", out)
            self.assertIn("source:      NOOKWIRE_IDENTITY_SEED", out)
            self.assertIn("fingerprint:", out)
            self.assertNotIn(secret, out)
            self.assertNotIn(secret, err)

            # JSON mode
            code, out, err = run_cli(["identity", "--json"], env=env)
            self.assertEqual(code, 0, err)
            self.assertNotIn(secret, out)
            self.assertNotIn("\x1b[", out)
            data = json.loads(out)
            self.assertEqual(data["mode"], "seeded")
            self.assertEqual(data["source"], "NOOKWIRE_IDENTITY_SEED")
            self.assertTrue(len(data["selector_fingerprint"]) > 0)
            self.assertIsNone(data["warning"])

            # Auto identity shows warning
            env.pop("NOOKWIRE_IDENTITY_SEED")
            env["NOOKWIRE_IDENTITY"] = "public-project"
            code, out, err = run_cli(["identity", "--json"], env=env)
            self.assertEqual(code, 0, err)
            data = json.loads(out)
            self.assertEqual(data["mode"], "project")
            self.assertIsNotNone(data["warning"])
            self.assertIn("Automatic identity provides endpoint continuity", data["warning"])
            self.assertEqual(data["key_path"], str(state / "tunnel_id_ed25519"))
            self.assertFalse(data["key_exists"])

    def test_identity_with_authoritative_legacy_key(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir()
            legacy_key = ssh_dir / "id_ed25519"
            legacy_key.write_bytes(
                asyncssh.generate_private_key("ssh-ed25519").export_private_key()
            )
            legacy_key.chmod(0o600)
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            env = make_env(home, state_base)

            # Even with project env set, legacy key is authoritative
            env["NOOKWIRE_IDENTITY"] = "public-project"
            code, out, err = run_cli(["identity", "--json"], env=env)
            self.assertEqual(code, 0, err)
            data = json.loads(out)
            self.assertEqual(data["mode"], "key")
            self.assertEqual(data["source"], str(legacy_key))
            self.assertEqual(data["key_path"], str(legacy_key))
            self.assertTrue(data["key_exists"])
            self.assertIsNotNone(data["key_fingerprint"])
            self.assertIsNone(data["warning"])

    def test_identity_with_existing_dedicated_key(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state_base = temp / "state"
            state = state_dir(state_base)
            state.mkdir(parents=True)
            dedicated_key = state / "tunnel_id_ed25519"
            dedicated_key.write_bytes(
                asyncssh.generate_private_key("ssh-ed25519").export_private_key()
            )
            dedicated_key.chmod(0o600)
            # Write saved metadata representing a seeded project start
            (state / "meta").write_text(
                "identity_mode=seeded\n"
                "identity_source=NOOKWIRE_IDENTITY_SEED\n"
                "identity_fingerprint=SHA256:dummyselectorfingerprint\n"
            )
            env = make_env(home, state_base)
            code, out, err = run_cli(["identity", "--json"], env=env)
            self.assertEqual(code, 0, err)
            data = json.loads(out)
            self.assertEqual(data["mode"], "seeded")
            self.assertEqual(data["source"], "NOOKWIRE_IDENTITY_SEED")
            self.assertEqual(data["selector_fingerprint"], "SHA256:dummyselectorfingerprint")
            self.assertEqual(data["key_path"], str(dedicated_key))
            self.assertTrue(data["key_exists"])
            self.assertIsNotNone(data["key_fingerprint"])

    @mock.patch("nookwire_ssh.cli._spawn")
    def test_launch_tunnel_uses_dedicated_key_when_legacy_missing(self, mock_spawn):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            home = temp / "home"
            home.mkdir()
            state = temp / "state" / "nookwire-ssh"
            state.mkdir(parents=True)
            args = mock.Mock(endpoint=None, accept=False)
            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                cli.launch_tunnel_srvus(args, root=temp, port=8022, slot=1, state=state)
                cmd_srvus = mock_spawn.call_args.args[0]
                key_idx = cmd_srvus.index("--key") + 1
                self.assertEqual(cmd_srvus[key_idx], str(state / "tunnel_id_ed25519"))

                cli.launch_tunnel_upterm(args, port=8022, state=state)
                cmd_upterm = mock_spawn.call_args.args[0]
                key_idx_up = cmd_upterm.index("--key") + 1
                self.assertEqual(cmd_upterm[key_idx_up], str(state / "tunnel_id_ed25519"))


class PackageAndWorkflowTests(unittest.TestCase):
    def test_package_metadata_and_dual_scripts(self):
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        pyproject_path = PROJECT / "pyproject.toml"
        data = tomllib.loads(pyproject_path.read_text())
        project = data["project"]
        self.assertEqual(project["name"], "nookwire")
        self.assertEqual(project["scripts"]["nookwire"], "nookwire_ssh.cli:main")
        self.assertEqual(
            project["scripts"]["nookwire-ssh"],
            "nookwire_ssh.cli:deprecated_main",
        )
        self.assertIn("urls", project)
        self.assertEqual(
            project["urls"]["Repository"], "https://github.com/lars-hagen/nookwire"
        )
        self.assertEqual(
            project["urls"]["Issues"], "https://github.com/lars-hagen/nookwire/issues"
        )
        self.assertEqual(
            project["urls"]["Security"],
            "https://github.com/lars-hagen/nookwire/security",
        )
        self.assertEqual(project["readme"], "README.md")
        self.assertEqual(project["license"], "MIT")
        self.assertTrue(
            any("lars-hagen" in str(a) for a in project.get("authors", []))
        )
        self.assertTrue(len(project.get("classifiers", [])) > 0)
        self.assertTrue(len(project.get("keywords", [])) > 0)

    def test_version_lookup_precedence(self):
        import importlib.metadata

        # 1. Primary distribution name "nookwire" is found
        with mock.patch(
            "importlib.metadata.version",
            side_effect=lambda name: "2.3.1" if name == "nookwire" else "0.0.0",
        ):
            self.assertEqual(cli._version(), "2.3.1")

        # 2. "nookwire" not installed, fallback to "nookwire-ssh"
        def fake_version(name):
            if name == "nookwire":
                raise importlib.metadata.PackageNotFoundError
            if name == "nookwire-ssh":
                return "2.3.1-compat"
            raise importlib.metadata.PackageNotFoundError

        with mock.patch("importlib.metadata.version", side_effect=fake_version):
            self.assertEqual(cli._version(), "2.3.1-compat")

        # 3. Neither installed, fallback to __version__
        with mock.patch(
            "importlib.metadata.version",
            side_effect=importlib.metadata.PackageNotFoundError,
        ):
            self.assertEqual(cli._version(), cli.__version__)

    def test_legacy_command_warns_and_delegates(self):
        stderr = io.StringIO()
        with mock.patch.object(cli, "main", return_value=7) as delegated:
            with contextlib.redirect_stderr(stderr):
                result = cli.deprecated_main(["status"])

        self.assertEqual(result, 7)
        delegated.assert_called_once_with(["status"])
        self.assertEqual(
            stderr.getvalue(),
            "nookwire-ssh is deprecated; use `nookwire` instead.\n",
        )

    def test_publish_workflow_shape(self):
        workflow_path = PROJECT / ".github" / "workflows" / "publish.yml"
        self.assertTrue(workflow_path.is_file())
        content = workflow_path.read_text()
        self.assertIn("types: [published]", content)
        self.assertIn("contents: read", content)
        self.assertIn("id-token: write", content)
        self.assertIn("environment:\n      name: pypi", content)
        self.assertIn("uv publish --trusted-publishing always", content)

    def test_worker_wrangler_config_shape(self):
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        wrangler_path = PROJECT / "worker" / "wrangler.toml"
        self.assertTrue(wrangler_path.is_file())
        data = tomllib.loads(wrangler_path.read_text())
        self.assertEqual(data["name"], "nookwire-relay")
        self.assertEqual(data["main"], "src/index.js")
        self.assertEqual(data["compatibility_date"], "2024-09-23")
        self.assertTrue(data.get("workers_dev", False))
        bindings = data.get("durable_objects", {}).get("bindings", [])
        self.assertTrue(any(b.get("name") == "RELAY" and b.get("class_name") == "Relay" for b in bindings))
        migrations = data.get("migrations", [])
        self.assertTrue(any("Relay" in m.get("new_sqlite_classes", []) for m in migrations))
        self.assertTrue(data.get("observability", {}).get("enabled", False))


if __name__ == "__main__":
    unittest.main()
