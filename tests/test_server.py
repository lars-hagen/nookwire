import asyncio
import contextlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import asyncssh

from nookwire_ssh.server import (
    Config,
    ConfinedSFTPServer,
    HostSFTPServer,
    TokenSSHServer,
    build_child_argv,
    build_child_environment,
    create_acceptor,
    ensure_host_key,
    sanitize_locale_environment,
)


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

    async def connect(self, password=None, port=None):
        return await asyncssh.connect(
            "127.0.0.1",
            port=port or self.port,
            username="nookwire",
            password=password or self.password,
            known_hosts=None,
        )

    async def spawn(self, **overrides):
        kwargs = dict(
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
        kwargs.update(overrides)
        return await create_acceptor(Config(**kwargs))

    async def test_password_auth_and_command_execution(self):
        async with await self.connect() as connection:
            result = await connection.run("pwd; printf 'ok\\n'; printf '%s' \"$NOOKWIRE_SSH_PASSWORD\"", check=True)
        self.assertEqual(result.stdout, f"{self.root}\nok\n")

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect("incorrect-password-long")

    def test_child_environment_supports_uid_without_passwd_entry(self):
        process = mock.Mock(term_type=None)
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("nookwire_ssh.server.pwd.getpwuid", side_effect=KeyError),
            mock.patch("nookwire_ssh.identity.getpass.getuser", side_effect=KeyError),
        ):
            environment = build_child_environment(process, self.config)
        self.assertEqual(environment["USER"], "nookwire")
        self.assertEqual(environment["LOGNAME"], "nookwire")
        self.assertEqual(environment["HOME"], str(self.root))
        self.assertEqual(environment["PS1"], "[nookwire]$ ")

    def test_synthetic_uid_skips_login_profiles(self):
        config = Config(**{**self.config.__dict__, "shell": "/bin/bash"})
        with mock.patch("nookwire_ssh.server.pwd.getpwuid", side_effect=KeyError):
            self.assertEqual(
                build_child_argv("", config),
                ["/bin/bash", "--noprofile", "--norc", "-i"],
            )
            self.assertEqual(
                build_child_argv("printf ok", config),
                ["/bin/bash", "--noprofile", "--norc", "-c", "printf ok"],
            )

        process = mock.Mock(term_type="xterm-256color")
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("nookwire_ssh.server.pwd.getpwuid", side_effect=KeyError),
            mock.patch("nookwire_ssh.identity.getpass.getuser", side_effect=KeyError),
        ):
            environment = build_child_environment(process, config)
        self.assertEqual(environment["PS1"], "[nookwire@\\h \\W]\\$ ")

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

    async def test_password_authentication_can_be_disabled(self):
        key = asyncssh.generate_private_key("ssh-ed25519")
        authorized_keys = Path(self.temporary.name) / "key-only-authorized_keys"
        authorized_keys.write_bytes(key.export_public_key())
        acceptor = await self.spawn(
            authorized_keys=authorized_keys,
            host_key=Path(self.temporary.name) / "key-only-host_key",
            password_auth=False,
        )
        try:
            async with await asyncssh.connect(
                "127.0.0.1",
                port=acceptor.get_port(),
                username="nookwire",
                client_keys=[key],
                known_hosts=None,
            ):
                pass
            with self.assertRaises(asyncssh.PermissionDenied):
                await asyncssh.connect(
                    "127.0.0.1",
                    port=acceptor.get_port(),
                    username="nookwire",
                    password=self.password,
                    known_hosts=None,
                )
        finally:
            acceptor.close()
            await acceptor.wait_closed()

        with self.assertRaises(asyncssh.PermissionDenied):
            await asyncssh.connect(
                "127.0.0.1",
                port=self.port,
                username="wrong-user",
                client_keys=[key],
                known_hosts=None,
            )

    def test_upterm_ca_authentication_mode(self):
        ca_key = asyncssh.generate_private_key("ssh-ed25519")
        ca_keys = Path(self.temporary.name) / "upterm-ca-keys"
        ca_keys.write_bytes(ca_key.export_public_key())
        config = Config(**{**self.config.__dict__, "upterm_ca_keys": ca_keys})
        server = TokenSSHServer(config)
        self.assertTrue(server.begin_auth("relay-generated-user"))
        self.assertTrue(server.public_key_auth_supported())
        self.assertFalse(server.password_auth_supported())
        self.assertTrue(server.validate_ca_key("anything", ca_key))
        self.assertFalse(
            server.validate_ca_key(
                "anything", asyncssh.generate_private_key("ssh-ed25519")
            )
        )

    async def test_accept_skips_authentication(self):
        acceptor = await self.spawn(
            password="",
            accept=True,
            host_key=Path(self.temporary.name) / "host_key_accept",
        )
        try:
            port = acceptor.get_port()
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="whoever", known_hosts=None
            ) as connection:
                result = await connection.run("printf accept-me", check=True)
            self.assertEqual(result.stdout, "accept-me")
        finally:
            acceptor.close()
            await acceptor.wait_closed()

    async def test_tcp_forwarding_respects_flag(self):
        async def echo_handler(reader, writer):
            try:
                while data := await reader.read(1024):
                    writer.write(data)
                    await writer.drain()
            except (ConnectionError, BrokenPipeError):
                pass
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

        server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        echo_port = server.sockets[0].getsockname()[1]

        try:
            acceptor = await self.spawn(
                allow_tcp_forwarding=True,
                host_key=Path(self.temporary.name) / "host_key_fwd",
            )
            try:
                port = acceptor.get_port()
                async with await self.connect(port=port) as connection:
                    listener = await connection.forward_local_port(
                        "127.0.0.1", 0, "127.0.0.1", echo_port
                    )
                    listen_port = listener.get_port()
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", listen_port
                    )
                    writer.write(b"ping")
                    await writer.drain()
                    self.assertEqual(await reader.readexactly(4), b"ping")
                    writer.close()
                    await writer.wait_closed()
                    listener.close()
                    await listener.wait_closed()
            finally:
                acceptor.close()
                await acceptor.wait_closed()

            denied_base = Config(
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
            allowed_base = Config(
                **{**denied_base.__dict__, "allow_tcp_forwarding": True}
            )
            self.assertFalse(TokenSSHServer(denied_base).connection_requested("h", 1, "o", 2))
            self.assertTrue(TokenSSHServer(allowed_base).connection_requested("h", 1, "o", 2))
        finally:
            server.close()
            await server.wait_closed()

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

    async def test_sftp_host_mode_default(self):
        (self.root / "source.txt").write_text("hello", encoding="utf-8")
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret", encoding="utf-8")
        async with await self.connect() as connection:
            async with connection.start_sftp_client() as sftp:
                self.assertEqual(await sftp.getcwd(), str(self.root.resolve()))
                # Relative path resolves inside project root
                async with sftp.open("source.txt", "rb") as source:
                    self.assertEqual(await source.read(), b"hello")
                # Absolute path outside project root is accessible in default host mode
                async with sftp.open(str(outside / "secret.txt"), "rb") as out_file:
                    self.assertEqual(await out_file.read(), b"secret")
                await sftp.put(str(self.root / "source.txt"), "nested.txt")
                async with sftp.open("nested.txt", "rb") as nested:
                    data = await nested.read()
                # Writing absolute path outside project root
                await sftp.put(str(self.root / "source.txt"), str(outside / "from-sftp.txt"))
        self.assertEqual(data, b"hello")
        self.assertEqual((self.root / "nested.txt").read_text(encoding="utf-8"), "hello")
        self.assertEqual((outside / "from-sftp.txt").read_text(encoding="utf-8"), "hello")

    async def test_sftp_confined_mode(self):
        (self.root / "source.txt").write_text("hello", encoding="utf-8")
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret", encoding="utf-8")
        (self.root / "outside-link").symlink_to(outside, target_is_directory=True)
        inside = self.root / "inside"
        inside.mkdir()
        (self.root / "inside-link").symlink_to(inside, target_is_directory=True)
        acceptor = await self.spawn(confine_sftp=True)
        port = acceptor.get_port()
        try:
            async with await self.connect(port=port) as connection:
                async with connection.start_sftp_client() as sftp:
                    self.assertEqual(await sftp.getcwd(), "/")
                    async with sftp.open(str(self.root / "source.txt"), "rb") as source:
                        self.assertEqual(await source.read(), b"hello")
                    await sftp.put(str(self.root / "source.txt"), str(self.root / "nested.txt"))
                    async with sftp.open(str(self.root / "nested.txt"), "rb") as nested:
                        data = await nested.read()
                    with self.assertRaises(asyncssh.SFTPPermissionDenied):
                        await sftp.open(str(self.root / "outside-link" / "secret.txt"), "rb")
                    attrs = await sftp.lstat(str(self.root / "outside-link"))
                    self.assertIsNotNone(attrs.permissions)
                    with self.assertRaises(asyncssh.SFTPPermissionDenied):
                        await sftp.readlink(str(self.root / "outside-link"))
                    await sftp.rename(str(self.root / "outside-link"), str(self.root / "renamed-link"))
                    with self.assertRaises(asyncssh.SFTPPermissionDenied):
                        await sftp.open(str(self.root / "renamed-link" / "secret.txt"), "rb")
                    await sftp.remove(str(self.root / "renamed-link"))
                    with self.assertRaises(asyncssh.SFTPError):
                        await sftp.rmdir(str(self.root / "inside-link"))
                    await sftp.remove(str(self.root / "inside-link"))
        finally:
            acceptor.close()
            await acceptor.wait_closed()
        self.assertEqual(data, b"hello")
        self.assertEqual((self.root / "nested.txt").read_text(encoding="utf-8"), "hello")
        self.assertEqual((outside / "secret.txt").read_text(encoding="utf-8"), "secret")
        self.assertFalse((self.root / "renamed-link").exists())
        self.assertTrue(inside.is_dir())

    async def test_asyncssh_scp_round_trip(self):
        local = Path(self.temporary.name) / "local.txt"
        local.write_text("through scp", encoding="utf-8")
        absolute_download = Path(self.temporary.name) / "absolute-downloaded.txt"
        relative_download = Path(self.temporary.name) / "relative-downloaded.txt"
        async with await self.connect() as connection:
            absolute_remote = str(self.root / "absolute.txt")
            await asyncssh.scp(local, (connection, absolute_remote))
            await asyncssh.scp((connection, absolute_remote), absolute_download)
            await asyncssh.scp(local, (connection, "relative.txt"))
            await asyncssh.scp((connection, "relative.txt"), relative_download)
        self.assertEqual(absolute_download.read_text(encoding="utf-8"), "through scp")
        self.assertEqual(relative_download.read_text(encoding="utf-8"), "through scp")

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
        """Interoperate with the real OpenSSH clients, not just AsyncSSH."""
        if not shutil.which("ssh") or not shutil.which("scp"):
            self.skipTest("OpenSSH clients are unavailable")

        askpass = Path(self.temporary.name) / "askpass.sh"
        askpass.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$NOOKWIRE_TEST_PASSWORD\"\n", encoding="utf-8"
        )
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
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
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
            "scp", *scp_options, str(source),
            f"nookwire@127.0.0.1:{self.root / 'system-absolute.txt'}",
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await scp.communicate()
        self.assertEqual(scp.returncode, 0, stderr.decode())

        relative = await asyncio.create_subprocess_exec(
            "scp", *scp_options, str(source), "nookwire@127.0.0.1:system-relative.txt",
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await relative.communicate()
        self.assertEqual(relative.returncode, 0, stderr.decode())
        self.assertEqual(
            (self.root / "system-absolute.txt").read_text(encoding="utf-8"), "system scp"
        )
        self.assertEqual(
            (self.root / "system-relative.txt").read_text(encoding="utf-8"), "system scp"
        )

    async def _scp_askpass_env(self):
        askpass = Path(self.temporary.name) / "askpass.sh"
        askpass.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$NOOKWIRE_TEST_PASSWORD\"\n", encoding="utf-8"
        )
        askpass.chmod(0o700)
        return {
            **os.environ,
            "DISPLAY": "nookwire:0",
            "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force",
            "NOOKWIRE_TEST_PASSWORD": self.password,
        }

    async def _run_system_scp(self, *extra_args, **kwargs):
        options = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-P", str(self.port),
        ]
        environment = kwargs.pop("env", await self._scp_askpass_env())
        scp = await asyncio.create_subprocess_exec(
            "scp", *options, *extra_args, **kwargs,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await scp.communicate()
        return scp.returncode, stderr.decode()

    async def test_system_scp_modern_protocol_upload_cases(self):
        """Modern OpenSSH scp (SFTP protocol, not -O) uploads reliably.

        Regression coverage for: multiple sources into an existing directory,
        recursive directory upload where the destination child does not yet
        exist, and single-file upload into a fresh name.
        """
        if not shutil.which("scp"):
            self.skipTest("OpenSSH scp is unavailable")

        source_dir = Path(self.temporary.name) / "src"
        docs = source_dir / "docs"
        docs.mkdir(parents=True)
        (docs / "cred.txt").write_text("secret", encoding="utf-8")
        nested = docs / "nested"
        nested.mkdir()
        (nested / "deep.txt").write_text("deep", encoding="utf-8")

        # 1. Multiple source files into an existing directory.
        existing = self.root / "existing"
        existing.mkdir()
        one = Path(self.temporary.name) / "one.txt"
        two = Path(self.temporary.name) / "two.txt"
        one.write_text("one", encoding="utf-8")
        two.write_text("two", encoding="utf-8")
        rc, stderr = await self._run_system_scp(
            str(one), str(two), f"nookwire@127.0.0.1:{existing}"
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual((existing / "one.txt").read_text(encoding="utf-8"), "one")
        self.assertEqual((existing / "two.txt").read_text(encoding="utf-8"), "two")

        # 2. Recursive directory upload where the destination child does not
        #    yet exist.
        target = self.root / "upload-target"
        target.mkdir()
        rc, stderr = await self._run_system_scp(
            "-r", str(source_dir), f"nookwire@127.0.0.1:{target / 'src'}"
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(
            (target / "src" / "docs" / "cred.txt").read_text(encoding="utf-8"),
            "secret",
        )
        self.assertEqual(
            (target / "src" / "docs" / "nested" / "deep.txt").read_text(
                encoding="utf-8"
            ),
            "deep",
        )

        # 3. Single-file upload into a fresh destination name.
        renamed = self.root / "renamed.txt"
        rc, stderr = await self._run_system_scp(
            str(one), f"nookwire@127.0.0.1:{renamed}"
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(renamed.read_text(encoding="utf-8"), "one")

    async def test_system_scp_host_mode_absolute_and_relative(self):
        """In default host mode, relative paths land in project root and absolute paths reach host."""
        if not shutil.which("scp"):
            self.skipTest("OpenSSH scp is unavailable")

        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        local_src = Path(self.temporary.name) / "local-src.txt"
        local_src.write_text("content-42", encoding="utf-8")

        # 1. Relative destination lands in project root
        rc, stderr = await self._run_system_scp(
            str(local_src), "nookwire@127.0.0.1:relative-landing.txt"
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(
            (self.root / "relative-landing.txt").read_text(encoding="utf-8"),
            "content-42",
        )

        # 2. Absolute destination outside project root succeeds
        outside_target = outside / "outside-target.txt"
        rc, stderr = await self._run_system_scp(
            str(local_src), f"nookwire@127.0.0.1:{outside_target}"
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(
            outside_target.read_text(encoding="utf-8"),
            "content-42",
        )

        # 3. Downloading from outside absolute path succeeds
        downloaded_out = Path(self.temporary.name) / "downloaded-out.txt"
        rc, stderr = await self._run_system_scp(
            f"nookwire@127.0.0.1:{outside_target}", str(downloaded_out)
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(downloaded_out.read_text(encoding="utf-8"), "content-42")

        # 4. Downloading from relative path succeeds
        downloaded_rel = Path(self.temporary.name) / "downloaded-rel.txt"
        rc, stderr = await self._run_system_scp(
            "nookwire@127.0.0.1:relative-landing.txt", str(downloaded_rel)
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(downloaded_rel.read_text(encoding="utf-8"), "content-42")

    async def test_system_scp_confined_mode_outside_access_rejected(self):
        """In confined mode, relative lands in root but outside host paths are rejected/not written."""
        if not shutil.which("scp"):
            self.skipTest("OpenSSH scp is unavailable")

        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        local_src = Path(self.temporary.name) / "local-src.txt"
        local_src.write_text("confined-data", encoding="utf-8")

        acceptor = await self.spawn(confine_sftp=True)
        port = acceptor.get_port()
        try:
            saved_port = self.port
            self.port = port
            try:
                # 1. Relative destination lands in root
                rc, stderr = await self._run_system_scp(
                    str(local_src), "nookwire@127.0.0.1:confined-rel.txt"
                )
                self.assertEqual(rc, 0, stderr)
                self.assertEqual(
                    (self.root / "confined-rel.txt").read_text(encoding="utf-8"),
                    "confined-data",
                )

                # 2. Absolute destination outside root does not touch outside filesystem
                outside_target = outside / "should-not-exist.txt"
                rc, stderr = await self._run_system_scp(
                    str(local_src), f"nookwire@127.0.0.1:{outside_target}"
                )
                self.assertNotEqual(rc, 0, stderr)
                self.assertFalse(outside_target.exists())
            finally:
                self.port = saved_port
        finally:
            acceptor.close()
            await acceptor.wait_closed()

    async def test_system_scp_denied_returns_nonzero_and_reports_status(self):
        """A denied transfer returns nonzero and the SFTP status is reported.

        Writing through an in-root symlink that escapes the root is rejected
        at the SFTP layer under confined mode. This must surface as a non-zero scp exit even
        though the server goes on to report a clean channel exit status, so
        the SFTP permission error is never masked as success.
        """
        if not shutil.which("scp"):
            self.skipTest("OpenSSH scp is unavailable")

        source = Path(self.temporary.name) / "deny-source.txt"
        source.write_text("nope", encoding="utf-8")
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        link = self.root / "escaping-link"
        link.symlink_to(outside, target_is_directory=True)

        acceptor = await self.spawn(confine_sftp=True)
        port = acceptor.get_port()
        try:
            saved_port = self.port
            self.port = port
            try:
                rc, stderr = await self._run_system_scp(
                    str(source), f"nookwire@127.0.0.1:{link / 'pwned.txt'}"
                )
            finally:
                self.port = saved_port
        finally:
            acceptor.close()
            await acceptor.wait_closed()

        self.assertNotEqual(rc, 0)
        self.assertIn("Permission denied", stderr)
        self.assertFalse((outside / "pwned.txt").exists())


class SFTPServerExitStatusTests(unittest.TestCase):
    """The SFTP server only reports channel success for sessions it served.

    AsyncSSH calls SFTPServer.exit() on shudown for both clean sessions and
    sessions cut short before serving anything (for example a protocol
    error). A success exit status must not be fabricated for the latter, or
    the SFTP status of a failed/aborted transfer could be masked.
    """

    def _server(self, temp):
        root = Path(temp) / "root"
        root.mkdir()
        channel = mock.Mock()
        return ConfinedSFTPServer(channel, root), channel

    def test_no_exit_status_before_serving(self):
        with tempfile.TemporaryDirectory() as temp:
            server, channel = self._server(temp)
            server.exit()
            channel.exit.assert_not_called()

            host_server = HostSFTPServer(channel, Path(temp) / "root")
            host_server.exit()
            channel.exit.assert_not_called()

    def test_exit_status_zero_after_serving(self):
        with tempfile.TemporaryDirectory() as temp:
            server, channel = self._server(temp)
            server.map_path(os.fsencode("/"))
            server.exit()
            channel.exit.assert_called_once_with(0)

            channel_host = mock.Mock()
            host_server = HostSFTPServer(channel_host, Path(temp) / "root")
            host_server.map_path(os.fsencode("/some/path"))
            host_server.exit()
            channel_host.exit.assert_called_once_with(0)


class HostKeyTests(unittest.TestCase):
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


class LocaleSanitizerTests(unittest.TestCase):
    UTF8_HOST = {"c": "C", "c.utf8": "C.utf8", "posix": "POSIX"}
    ASCII_HOST = {"c": "C", "posix": "POSIX"}

    def sanitize(self, environment, available):
        with mock.patch(
            "nookwire_ssh.server.available_locales", return_value=available
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
