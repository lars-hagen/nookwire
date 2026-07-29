import asyncio
import getpass
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import asyncssh

from nookwire_ssh import (
    Config,
    create_acceptor,
    ensure_host_key,
    sanitize_locale_environment,
)


PROJECT = Path(__file__).resolve().parents[1]
LAUNCHER = PROJECT / "nookwire-ssh"


class NookwireSSHTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "root"
        self.root.mkdir()
        self.password = "test-password-long-enough"
        self.config = Config(
            root=self.root,
            host="127.0.0.1",
            port=0,
            username="nookwire",
            password=self.password,
            password_env="NOOKWIRE_SSH_PASSWORD",
            authorized_keys=Path(self.temporary.name) / "authorized_keys",
            host_key=Path(self.temporary.name) / "host_key",
            shell="/bin/sh",
        )
        self.acceptor = await create_acceptor(self.config)
        self.port = self.acceptor.get_port()

    async def asyncTearDown(self):
        self.acceptor.close()
        await self.acceptor.wait_closed()
        self.temporary.cleanup()

    async def connect(self, password=None):
        return await asyncssh.connect(
            "127.0.0.1",
            port=self.port,
            username="nookwire",
            password=password or self.password,
            known_hosts=None,
        )

    async def test_password_auth_and_command_execution(self):
        async with await self.connect() as connection:
            result = await connection.run("pwd; printf 'ok\\n'; printf '%s' \"$NOOKWIRE_SSH_PASSWORD\"", check=True)
        self.assertEqual(result.stdout, f"{self.root}\nok\n")

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect("incorrect-password-long")

    async def test_authorized_keys_authentication(self):
        key = asyncssh.generate_private_key("ssh-ed25519")
        self.config.authorized_keys.write_bytes(key.export_public_key())
        async with await asyncssh.connect(
            "127.0.0.1",
            port=self.port,
            username="nookwire",
            client_keys=[key],
            known_hosts=None,
        ) as connection:
            result = await connection.run("printf public-key", check=True)
        self.assertEqual(result.stdout, "public-key")

        async with await self.connect() as connection:
            result = await connection.run("printf password-fallback", check=True)
        self.assertEqual(result.stdout, "password-fallback")

        with self.assertRaises(asyncssh.PermissionDenied):
            await asyncssh.connect(
                "127.0.0.1",
                port=self.port,
                username="wrong-user",
                client_keys=[key],
                known_hosts=None,
            )

    async def test_pty_allocates_terminal(self):
        async with await self.connect() as connection:
            result = await connection.run(
                'tty; printf "SHELL=%s\\n" "$0"; [ -t 0 ] && echo STDIN_TTY; '
                "[ -t 1 ] && echo STDOUT_TTY",
                term_type="xterm-256color",
                term_size=(80, 24),
                check=True,
            )
        self.assertIn("STDIN_TTY", result.stdout)
        self.assertIn("STDOUT_TTY", result.stdout)
        self.assertTrue(
            "/dev/pts/" in result.stdout or "/dev/tty" in result.stdout,
            result.stdout,
        )

    async def test_pty_forwards_large_input(self):
        payload = "nookwire-pty-line\n" * 6000  # ~108 KB across many lines
        async with await self.connect() as connection:
            result = await connection.run(
                "head -c 100000 | wc -c",
                term_type="xterm-256color",
                term_size=(80, 24),
                input=payload,
                check=True,
            )
        self.assertIn("100000", result.stdout)

    async def test_sftp_is_root_mapped(self):
        (self.root / "source.txt").write_text("hello", encoding="utf-8")
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret", encoding="utf-8")
        (self.root / "outside-link").symlink_to(outside, target_is_directory=True)
        inside = self.root / "inside"
        inside.mkdir()
        (self.root / "inside-link").symlink_to(inside, target_is_directory=True)
        async with await self.connect() as connection:
            async with connection.start_sftp_client() as sftp:
                self.assertEqual(await sftp.getcwd(), "/")
                async with sftp.open("/source.txt", "rb") as source:
                    self.assertEqual(await source.read(), b"hello")
                await sftp.put(str(self.root / "source.txt"), "/nested.txt")
                async with sftp.open("/nested.txt", "rb") as nested:
                    data = await nested.read()
                with self.assertRaises(asyncssh.SFTPPermissionDenied):
                    await sftp.open("/outside-link/secret.txt", "rb")
                attrs = await sftp.lstat("/outside-link")
                self.assertIsNotNone(attrs.permissions)
                with self.assertRaises(asyncssh.SFTPPermissionDenied):
                    await sftp.readlink("/outside-link")
                await sftp.rename("/outside-link", "/renamed-link")
                with self.assertRaises(asyncssh.SFTPPermissionDenied):
                    await sftp.open("/renamed-link/secret.txt", "rb")
                await sftp.remove("/renamed-link")
                with self.assertRaises(asyncssh.SFTPError):
                    await sftp.rmdir("/inside-link")
                await sftp.remove("/inside-link")
        self.assertEqual(data, b"hello")
        self.assertEqual((self.root / "nested.txt").read_text(encoding="utf-8"), "hello")
        self.assertEqual((outside / "secret.txt").read_text(encoding="utf-8"), "secret")
        self.assertFalse((self.root / "renamed-link").exists())
        self.assertTrue(inside.is_dir())

    async def test_asyncssh_scp_round_trip(self):
        local = Path(self.temporary.name) / "local.txt"
        local.write_text("through scp", encoding="utf-8")
        downloaded = Path(self.temporary.name) / "downloaded.txt"
        async with await self.connect() as connection:
            await asyncssh.scp(local, (connection, "/remote.txt"))
            await asyncssh.scp((connection, "/remote.txt"), downloaded)
        self.assertEqual(downloaded.read_text(encoding="utf-8"), "through scp")

    async def test_disconnect_terminates_running_command(self):
        connection = await self.connect()
        process = await connection.create_process("sh -c 'echo $$; exec sleep 60'")
        pid = int((await process.stdout.readline()).strip())
        connection.close()
        await connection.wait_closed()

        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.02)
        else:
            self.fail(f"child process {pid} survived SSH disconnect")

    async def test_system_ssh_and_scp_clients(self):
        if not shutil.which("ssh") or not shutil.which("scp"):
            self.skipTest("OpenSSH clients are unavailable")

        askpass = Path(self.temporary.name) / "askpass.sh"
        askpass.write_text("#!/bin/sh\nprintf '%s\\n' \"$NOOKWIRE_TEST_PASSWORD\"\n", encoding="utf-8")
        askpass.chmod(0o700)
        environment = {
            **os.environ,
            "DISPLAY": "nookwire:0",
            "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force",
            "NOOKWIRE_TEST_PASSWORD": self.password,
        }
        options = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-p", str(self.port),
        ]

        ssh = await asyncio.create_subprocess_exec(
            "ssh", *options, "nookwire@127.0.0.1", "printf system-ssh",
            env=environment, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await ssh.communicate()
        self.assertEqual(ssh.returncode, 0, stderr.decode())
        self.assertEqual(stdout, b"system-ssh")

        source = Path(self.temporary.name) / "system-source.txt"
        source.write_text("system scp", encoding="utf-8")
        scp_options = [
            "-O",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-P", str(self.port),
        ]
        scp = await asyncio.create_subprocess_exec(
            "scp", *scp_options, str(source), "nookwire@127.0.0.1:/system-scp.txt",
            env=environment, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await scp.communicate()
        self.assertEqual(scp.returncode, 0, stderr.decode())
        self.assertEqual((self.root / "system-scp.txt").read_text(encoding="utf-8"), "system scp")


class LauncherTests(unittest.TestCase):
    def test_existing_host_key_requires_private_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "host-key"
            key.write_text("not a key", encoding="utf-8")
            key.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                ensure_host_key(key)

    def test_host_key_parent_requires_private_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "shared"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "group- or world-accessible"):
                ensure_host_key(parent / "host-key")

    def test_host_key_parent_allows_setgid(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "setgid"
            parent.mkdir(mode=0o700)
            parent.chmod(0o2700)
            key = parent / "host-key"
            ensure_host_key(key)
            self.assertTrue(key.is_file())

    def test_background_start_status_logs_and_stop(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            root = temp_path / "root with spaces"
            root.mkdir()
            bin_dir = temp_path / "bin"
            bin_dir.mkdir()
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]

            fake_uv = bin_dir / "uv"
            fake_uv.write_text(
                "#!/bin/sh\n"
                "exec python3 -c 'import socket,time; "
                f"s=socket.socket(); s.bind((\"127.0.0.1\", {port})); "
                "s.listen(); time.sleep(60)'\n",
                encoding="utf-8",
            )
            fake_uv.chmod(0o755)
            fake_keygen = bin_dir / "ssh-keygen"
            fake_keygen.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            fake_keygen.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "HOME": str(temp_path / "home"),
                "NOOKWIRE_SSH_STATE_DIR": str(temp_path / "state with spaces"),
            }
            Path(environment["HOME"]).mkdir()

            fake_python = bin_dir / "python3"
            fake_python.write_text(
                "#!/bin/sh\ncase \"$2\" in *hashlib*) sleep 0.2 ;; esac\n"
                f'exec "{sys.executable}" "$@"\n',
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            fake_uv.write_text(
                "#!/bin/sh\n"
                "mkdir \"$NOOKWIRE_SSH_STATE_DIR/server.pid\"\n"
                f"printf '%s' \"$$\" > '{temp_path / 'server-child'}'\n"
                f'exec "{sys.executable}" -c "import time; time.sleep(60)"\n',
                encoding="utf-8",
            )
            server_pid_failure = subprocess.run(
                [str(LAUNCHER), "start", str(root), str(port), "1"],
                capture_output=True, text=True, env=environment,
            )
            self.assertNotEqual(server_pid_failure.returncode, 0)
            self.assertIn("Unable to track server process", server_pid_failure.stderr)
            server_pid = int((temp_path / "server-child").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(server_pid, 0)
            failed_status = subprocess.run(
                [str(LAUNCHER), "status"], capture_output=True, text=True,
                env=environment,
            )
            self.assertIn("server: stopped", failed_status.stdout)
            (temp_path / "state with spaces" / "server.pid").rmdir()

            fake_uv.write_text(
                "#!/bin/sh\n"
                f'exec "{sys.executable}" -c \'import socket,time; '
                f"s=socket.socket(); s.bind((\"127.0.0.1\", {port})); "
                "s.listen(); time.sleep(60)'\n",
                encoding="utf-8",
            )
            failed = subprocess.run(
                [str(LAUNCHER), "start", str(root), str(port), "1"],
                capture_output=True, text=True, env=environment,
            )
            self.assertNotEqual(failed.returncode, 0)
            failed_status = subprocess.run(
                [str(LAUNCHER), "status"], capture_output=True, text=True,
                env=environment,
            )
            self.assertIn("server: stopped", failed_status.stdout)

            fake_ssh = bin_dir / "ssh"
            fake_ssh.write_text(
                "#!/bin/sh\nmkdir \"$NOOKWIRE_SSH_STATE_DIR/tunnel.pid\"\n"
                f"printf '%s' \"$$\" > '{temp_path / 'tunnel-child'}'\n"
                "printf 'https://example.srv.us/\\n'\n"
                f'exec "{sys.executable}" -c "import time; time.sleep(60)"\n',
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)

            fake_keygen.write_text(
                "#!/bin/sh\nfor arg do key=$arg; done\nprintf key > \"$key\"\n",
                encoding="utf-8",
            )
            tunnel_pid_failure = subprocess.run(
                [str(LAUNCHER), "start", str(root), str(port), "1"],
                capture_output=True, text=True, env=environment,
            )
            self.assertNotEqual(tunnel_pid_failure.returncode, 0)
            self.assertIn("Unable to track tunnel process", tunnel_pid_failure.stderr)
            failed_status = subprocess.run(
                [str(LAUNCHER), "status"], capture_output=True, text=True,
                env=environment,
            )
            self.assertIn("server: stopped", failed_status.stdout)
            self.assertIn("tunnel: stopped", failed_status.stdout)
            tunnel_pid = int((temp_path / "tunnel-child").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(tunnel_pid, 0)
            (temp_path / "state with spaces" / "tunnel.pid").rmdir()

            fake_ssh.write_text(
                "#!/bin/sh\nprintf 'https://example.srv.us/\\n'\n"
                f'exec "{sys.executable}" -c "import time; time.sleep(60)"\n',
                encoding="utf-8",
            )
            try:
                started = subprocess.run(
                    [str(LAUNCHER), "start", str(root), str(port), "1"],
                    check=True, capture_output=True, text=True, env=environment,
                ).stdout
                self.assertIn("started in the background", started)
                status = subprocess.run(
                    [str(LAUNCHER), "status"], check=True, capture_output=True,
                    text=True, env=environment,
                ).stdout
                self.assertIn("server: running", status)
                self.assertIn("tunnel: running", status)
                self.assertIn("url: https://example.srv.us/", status)
                self.assertIn("ProxyCommand=openssl s_client", status)
                self.assertIn(f"{getpass.getuser()}@example.srv.us", status)
                self.assertIn("key auth: disabled", status)
                self.assertNotIn("logs:", started)
                self.assertGreaterEqual(
                    len((temp_path / "state with spaces" / "password").read_text()), 32
                )
                logs = subprocess.run(
                    [str(LAUNCHER), "logs", "tunnel"], check=True,
                    capture_output=True, text=True, env=environment,
                ).stdout
                self.assertIn("https://example.srv.us/", logs)
            finally:
                subprocess.run(
                    [str(LAUNCHER), "stop"], capture_output=True, text=True,
                    env=environment,
                )
            stopped = subprocess.run(
                [str(LAUNCHER), "status"], capture_output=True, text=True,
                env=environment,
            )
            self.assertNotEqual(stopped.returncode, 0)
            self.assertIn("server: stopped", stopped.stdout)
            self.assertIn("tunnel: stopped", stopped.stdout)

            unrelated = subprocess.Popen(["sleep", "60"])
            try:
                state = temp_path / "state with spaces"
                (state / "server.pid").write_text(
                    f"{unrelated.pid} deliberately-wrong-identity\n",
                    encoding="utf-8",
                )
                subprocess.run(
                    [str(LAUNCHER), "stop"], check=True, capture_output=True,
                    text=True, env=environment,
                )
                self.assertIsNone(unrelated.poll())
            finally:
                unrelated.terminate()
                unrelated.wait()

    def test_curl_installer_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp) / "prefix"
            environment = {
                **os.environ,
                "NOOKWIRE_SSH_PREFIX": str(prefix),
                "NOOKWIRE_SSH_BASE_URL": PROJECT.as_uri(),
            }
            subprocess.run(
                ["sh", str(PROJECT / "install.sh")],
                check=True, capture_output=True, text=True, env=environment,
            )
            installed = prefix / "bin" / "nookwire-ssh"
            companion = prefix / "bin" / "nookwire_ssh.py"
            self.assertTrue(os.access(installed, os.X_OK))
            self.assertTrue(companion.is_file())
            subprocess.run([str(installed), "--help"], check=True, capture_output=True)

    def test_installer_rejects_unsafe_destination_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            prefix = temp_path / "prefix"
            bin_dir = prefix / "bin"
            bin_dir.mkdir(parents=True)
            launcher = bin_dir / "nookwire-ssh"
            server = bin_dir / "nookwire_ssh.py"
            launcher.write_text("old launcher", encoding="utf-8")
            server.write_text("old server", encoding="utf-8")

            unsafe = temp_path / "unsafe-prefix" / "bin"
            unsafe.mkdir(parents=True)
            (unsafe / "nookwire-ssh").mkdir()
            base_environment = {
                **os.environ,
                "NOOKWIRE_SSH_BASE_URL": PROJECT.as_uri(),
            }
            rejected = subprocess.run(
                ["sh", str(PROJECT / "install.sh")], capture_output=True, text=True,
                env={**base_environment, "NOOKWIRE_SSH_PREFIX": str(unsafe.parent)},
            )
            self.assertNotEqual(rejected.returncode, 0)

            fake_bin = temp_path / "fake-bin"
            fake_bin.mkdir()
            real_mv = shutil.which("mv")
            self.assertIsNotNone(real_mv)
            (fake_bin / "mv").write_text(
                "#!/bin/sh\n"
                "case \"$1\" in *backup*) ;; *nookwire_ssh.py) exit 1 ;; esac\n"
                f"exec '{real_mv}' \"$@\"\n",
                encoding="utf-8",
            )
            (fake_bin / "mv").chmod(0o755)
            failed = subprocess.run(
                ["sh", str(PROJECT / "install.sh")], capture_output=True, text=True,
                env={
                    **base_environment,
                    "NOOKWIRE_SSH_PREFIX": str(prefix),
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                },
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(launcher.read_text(encoding="utf-8"), "old launcher")
            self.assertEqual(server.read_text(encoding="utf-8"), "old server")


class LocaleSanitizerTests(unittest.TestCase):
    UTF8_HOST = {"c": "C", "c.utf8": "C.utf8", "posix": "POSIX"}
    ASCII_HOST = {"c": "C", "posix": "POSIX"}

    def sanitize(self, environment, available):
        with mock.patch(
            "nookwire_ssh.available_locales", return_value=available
        ):
            sanitize_locale_environment(environment)
        return environment

    def test_missing_locale_falls_back_to_available_utf8(self):
        environment = {"LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "PATH": "/bin"}
        self.sanitize(environment, self.UTF8_HOST)
        self.assertEqual(environment["LANG"], "C.utf8")
        self.assertEqual(environment["LC_ALL"], "C.utf8")
        self.assertEqual(environment["PATH"], "/bin")

    def test_missing_locale_falls_back_to_c_without_utf8(self):
        environment = {"LANG": "en_US.UTF-8"}
        self.sanitize(environment, self.ASCII_HOST)
        self.assertEqual(environment["LANG"], "C")

    def test_available_locale_is_preserved(self):
        environment = {"LANG": "C.UTF-8", "LC_ALL": "C"}
        self.sanitize(environment, self.UTF8_HOST)
        self.assertEqual(environment["LANG"], "C.UTF-8")
        self.assertEqual(environment["LC_ALL"], "C")

    def test_no_locale_variables_are_untouched(self):
        environment = {"PATH": "/bin", "TERM": "xterm-256color"}
        self.sanitize(environment, self.UTF8_HOST)
        self.assertEqual(environment, {"PATH": "/bin", "TERM": "xterm-256color"})

    def test_only_invalid_variables_are_replaced(self):
        environment = {"LANG": "en_US.UTF-8", "LC_CTYPE": "C.utf8"}
        self.sanitize(environment, self.UTF8_HOST)
        self.assertEqual(environment["LANG"], "C.utf8")
        self.assertEqual(environment["LC_CTYPE"], "C.utf8")


if __name__ == "__main__":
    unittest.main()
