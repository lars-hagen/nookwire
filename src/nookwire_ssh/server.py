#!/usr/bin/env python3
"""Temporary SSH, SFTP, and SCP access to an ephemeral workspace."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import getpass
import hmac
import pwd
import os
import pty
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import termios
from dataclasses import dataclass
from pathlib import Path

import asyncssh


from nookwire_ssh import __version__ as VERSION
DEFAULT_PASSWORD_ENV = "NOOKWIRE_SSH_PASSWORD"
DEFAULT_HOST_KEY = (
    Path(tempfile.gettempdir()) / f"nookwire-ssh-{os.geteuid()}" / "host-key"
)


@dataclass(frozen=True)
class Config:
    root: Path
    host: str
    port: int
    username: str
    password: str
    password_env: str
    authorized_keys: Path
    host_key: Path
    shell: str
    accept: bool = False
    allow_tcp_forwarding: bool = False


class TokenSSHServer(asyncssh.SSHServer):
    """Authenticate one disposable user with authorized keys or a password.

    When ``accept`` is set, no authentication is requested at all and any
    connecting client is admitted, mirroring upterm's wide-open share mode.
    """

    def __init__(self, config: Config):
        self.config = config
        self.connection: asyncssh.SSHServerConnection | None = None

    def connection_made(self, connection: asyncssh.SSHServerConnection) -> None:
        self.connection = connection

    def begin_auth(self, username: str) -> bool:
        if self.config.accept:
            # Return False to signal that no authentication is required, so
            # the handshake succeeds immediately regardless of credentials.
            return False
        valid_user = hmac.compare_digest(
            username.encode("utf-8"), self.config.username.encode("utf-8")
        )
        authorized_keys = self.config.authorized_keys
        if self.connection and valid_user and authorized_keys.is_file():
            self.connection.set_authorized_keys(str(authorized_keys))
        elif self.connection:
            self.connection.set_authorized_keys(None)
        return True

    def public_key_auth_supported(self) -> bool:
        return self.config.authorized_keys.is_file() and not self.config.accept

    def password_auth_supported(self) -> bool:
        return not self.config.accept

    def validate_password(self, username: str, password: str) -> bool:
        return hmac.compare_digest(
            username.encode("utf-8"), self.config.username.encode("utf-8")
        ) and hmac.compare_digest(
            password.encode("utf-8"), self.config.password.encode("utf-8")
        )

    def connection_requested(
        self,
        dest_host: str,
        dest_port: int,
        orig_host: str,
        orig_port: int,
    ) -> bool:
        """Allow SSH local TCP forwarding (ssh -L) when enabled.

        Direct-TCP/IP channel opens reach destinations visible to the host.
        Returning ``True`` makes AsyncSSH connect to ``dest_host:dest_port``
        and splice the bytes, so a client can ``ssh -L`` through the session.
        """
        del dest_host, dest_port, orig_host, orig_port
        return self.config.allow_tcp_forwarding


def ensure_host_key(path: Path) -> None:
    parent = path.parent
    if parent.exists():
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or parent.is_symlink():
            raise ValueError(f"Host key parent must be a directory: {parent}")
        if info.st_uid != os.geteuid():
            raise ValueError(
                f"Host key parent must be owned by uid {os.geteuid()}: {parent}"
            )
        if stat.S_IMODE(info.st_mode) & 0o077:
            # Owner-only access is the security property; tolerate setgid/sticky
            # bits that some filesystems force onto directories (e.g. grpid mounts).
            raise ValueError(
                f"Host key parent must not be group- or world-accessible: {parent}"
            )
    else:
        parent.mkdir(mode=0o700, parents=True)

    if path.exists():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Host key must be a regular file: {path}")
        info = path.stat()
        if info.st_uid != os.geteuid():
            raise ValueError(f"Host key must be owned by uid {os.geteuid()}: {path}")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError(f"Host key must have mode 0600: {path}")
        return

    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    key = asyncssh.generate_private_key("ssh-ed25519")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(key.export_private_key())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


async def terminate_process_group(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return

    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)

    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()


async def pump_ssh_input(process: asyncssh.SSHServerProcess, child: asyncio.subprocess.Process) -> None:
    assert child.stdin is not None
    try:
        while data := await process.stdin.read(64 * 1024):
            if isinstance(data, str):
                data = data.encode()
            child.stdin.write(data)
            await child.stdin.drain()
    except (asyncssh.BreakReceived, ConnectionError, BrokenPipeError):
        pass
    finally:
        child.stdin.close()
        with contextlib.suppress(BrokenPipeError, ConnectionError):
            await child.stdin.wait_closed()


async def pump_child_output(
    source: asyncio.StreamReader, destination: asyncssh.SSHWriter
) -> None:
    try:
        while data := await source.read(64 * 1024):
            destination.write(data)
            await destination.drain()
    except (ConnectionError, BrokenPipeError):
        pass


def build_child_argv(command: str, config: Config) -> list[str]:
    if command:
        return [config.shell, "-lc", command]
    # Interactive session: start a login shell so the usual profile scripts run
    # and construct PS1, PATH, etc., matching a normal OpenSSH login.
    if os.path.basename(config.shell) in ("bash", "zsh"):
        return [config.shell, "-l", "-i"]
    return [config.shell, "-i"]


_LOCALE_ENV_VARS = (
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
)


def _normalize_locale(name: str) -> str:
    return name.strip().casefold().replace("-", "")


def available_locales() -> dict[str, str]:
    """Map normalized locale names to their canonical form from ``locale -a``."""
    try:
        completed = subprocess.run(
            ["locale", "-a"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    result: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        name = line.strip()
        if name:
            result.setdefault(_normalize_locale(name), name)
    return result


def sanitize_locale_environment(environment: dict[str, str]) -> None:
    """Replace locale settings the host cannot provide so shells stop warning.

    Container images often bake in LANG/LC_* values (e.g. en_US.UTF-8) without
    generating the matching locale, so every child shell emits "setlocale:
    cannot change locale" warnings. Fall back to an available UTF-8 locale, or C
    as a last resort, whenever the requested one is missing.
    """
    requested = {
        var: environment[var] for var in _LOCALE_ENV_VARS if environment.get(var)
    }
    if not requested:
        return
    available = available_locales()
    if not available:
        return

    def is_usable(value: str) -> bool:
        normalized = _normalize_locale(value)
        return normalized in ("c", "posix") or normalized in available

    if all(is_usable(value) for value in requested.values()):
        return

    replacement = None
    for preferred in ("C.UTF-8", "C.utf8"):
        replacement = available.get(_normalize_locale(preferred))
        if replacement:
            break
    if replacement is None:
        replacement = next(
            (original for key, original in available.items() if key.endswith("utf8")),
            "C",
        )

    for var, value in requested.items():
        if not is_usable(value):
            environment[var] = replacement


def build_child_environment(
    process: asyncssh.SSHServerProcess, config: Config
) -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop(config.password_env, None)
    account = pwd.getpwuid(os.geteuid())
    environment["USER"] = account.pw_name
    environment["LOGNAME"] = account.pw_name
    environment["SHELL"] = config.shell
    environment.setdefault("HOME", account.pw_dir)
    environment["PWD"] = str(config.root)
    if process.term_type is not None:
        # A pty was requested; the term type may be empty when the client has no
        # TERM set, so fall back to a widely supported value. PS1 and the rest of
        # the prompt are left to the login shell's own startup files.
        environment["TERM"] = process.term_type or "xterm-256color"
    sanitize_locale_environment(environment)
    return environment


def set_terminal_size(fd: int, term_size: tuple[int, int, int, int]) -> None:
    width, height, pixwidth, pixheight = term_size
    if width and height:
        winsize = struct.pack("HHHH", height, width, pixwidth, pixheight)
        with contextlib.suppress(OSError):
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def acquire_controlling_tty() -> None:
    """Give the child its own session and controlling terminal for job control."""
    os.setsid()
    with contextlib.suppress(OSError):
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def forward_signal(child: asyncio.subprocess.Process, name: str) -> None:
    """Deliver an SSH-requested signal to the child's process group."""
    signum = getattr(signal, f"SIG{name}", None) or getattr(signal, name, None)
    if signum is None or child.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError, ValueError):
        os.killpg(child.pid, int(signum))


async def pump_ssh_to_pty(
    process: asyncssh.SSHServerProcess,
    transport: asyncio.WriteTransport,
    master_fd: int,
    child: asyncio.subprocess.Process,
) -> None:
    """Forward client input to the pty, applying resize and signal requests."""
    while True:
        try:
            data = await process.stdin.read(64 * 1024)
        except asyncssh.TerminalSizeChanged as change:
            set_terminal_size(
                master_fd,
                (change.width, change.height, change.pixwidth, change.pixheight),
            )
            continue
        except asyncssh.SignalReceived as received:
            forward_signal(child, received.signal)
            continue
        except (asyncssh.BreakReceived, asyncssh.SoftEOFReceived):
            continue
        except (ConnectionError, BrokenPipeError):
            break
        if not data:
            break
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogateescape")
        try:
            transport.write(data)
        except (ConnectionError, BrokenPipeError):
            break


async def pump_pty_to_ssh(
    reader: asyncio.StreamReader, process: asyncssh.SSHServerProcess
) -> None:
    """Stream pty output back to the client until the pty reaches EOF."""
    while True:
        try:
            data = await reader.read(64 * 1024)
        except OSError:
            break
        if not data:
            break
        try:
            process.stdout.write(data)
            await process.stdout.drain()
        except (ConnectionError, BrokenPipeError):
            break


async def handle_pty_process(
    process: asyncssh.SSHServerProcess,
    config: Config,
    argv: list[str],
    environment: dict[str, str],
) -> None:
    loop = asyncio.get_running_loop()
    master_fd, slave_fd = pty.openpty()
    set_terminal_size(slave_fd, process.term_size)
    read_dup = -1
    slave_open = True
    read_transport: asyncio.ReadTransport | None = None
    write_transport: asyncio.WriteTransport | None = None
    child: asyncio.subprocess.Process | None = None
    try:
        try:
            child = await asyncio.create_subprocess_exec(
                *argv,
                cwd=config.root,
                env=environment,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=acquire_controlling_tty,
            )
        finally:
            os.close(slave_fd)
            slave_open = False

        # Output: read the pty master through a dedicated descriptor.
        read_dup = os.dup(master_fd)
        reader = asyncio.StreamReader()
        read_transport, _ = await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader),
            os.fdopen(read_dup, "rb", 0),
        )
        read_dup = -1  # owned by read_transport now
        # Input: write through a transport so partial writes and EAGAIN on the
        # (now non-blocking) master descriptor are handled by asyncio.
        write_transport, _ = await loop.connect_write_pipe(
            asyncio.Protocol, os.fdopen(master_fd, "wb", 0)
        )

        input_task = asyncio.create_task(
            pump_ssh_to_pty(process, write_transport, master_fd, child)
        )
        output_task = asyncio.create_task(pump_pty_to_ssh(reader, process))
        child_wait = asyncio.create_task(child.wait())
        channel_wait = asyncio.create_task(process.wait_closed())
        disconnected = False
        try:
            done, _ = await asyncio.wait(
                (child_wait, channel_wait), return_when=asyncio.FIRST_COMPLETED
            )
            disconnected = channel_wait in done
            if disconnected and child.returncode is None:
                await terminate_process_group(child)
            returncode = await child_wait
            if not disconnected:
                # Drain buffered pty output before reporting the exit status.
                await output_task
        finally:
            input_task.cancel()
            output_task.cancel()
            channel_wait.cancel()
            if child.returncode is None:
                await terminate_process_group(child)
            await asyncio.gather(
                input_task,
                output_task,
                channel_wait,
                child_wait,
                return_exceptions=True,
            )

        if not disconnected:
            process.exit(returncode if returncode >= 0 else 128 - returncode)
    finally:
        if slave_open:
            with contextlib.suppress(OSError):
                os.close(slave_fd)
        if read_transport is not None:
            read_transport.close()
        elif read_dup >= 0:
            with contextlib.suppress(OSError):
                os.close(read_dup)
        if write_transport is not None:
            write_transport.close()
        else:
            with contextlib.suppress(OSError):
                os.close(master_fd)
        if child is not None and child.returncode is None:
            await terminate_process_group(child)


async def handle_process(process: asyncssh.SSHServerProcess, config: Config) -> None:
    command = process.command
    if isinstance(command, bytes):
        command = command.decode("utf-8", "surrogateescape")

    argv = build_child_argv(command, config)
    environment = build_child_environment(process, config)

    if process.term_type is not None:
        await handle_pty_process(process, config, argv, environment)
        return

    child = await asyncio.create_subprocess_exec(
        *argv,
        cwd=config.root,
        env=environment,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    assert child.stdout is not None and child.stderr is not None

    input_task = asyncio.create_task(pump_ssh_input(process, child))
    output_tasks = [
        asyncio.create_task(pump_child_output(child.stdout, process.stdout)),
        asyncio.create_task(pump_child_output(child.stderr, process.stderr)),
    ]
    child_wait = asyncio.create_task(child.wait())
    channel_wait = asyncio.create_task(process.wait_closed())
    disconnected = False

    try:
        done, _ = await asyncio.wait(
            (child_wait, channel_wait), return_when=asyncio.FIRST_COMPLETED
        )
        disconnected = channel_wait in done
        if disconnected and child.returncode is None:
            await terminate_process_group(child)
        returncode = await child_wait
        if not disconnected:
            await asyncio.gather(*output_tasks)
    finally:
        input_task.cancel()
        channel_wait.cancel()
        for task in output_tasks:
            task.cancel()
        if child.returncode is None:
            await terminate_process_group(child)
        await asyncio.gather(
            input_task, child_wait, channel_wait, *output_tasks, return_exceptions=True
        )

    if not disconnected:
        process.exit(returncode if returncode >= 0 else 128 - returncode)


class ConfinedSFTPServer(asyncssh.SFTPServer):
    """SFTP server which rejects paths resolving outside its virtual root."""

    def __init__(self, channel: asyncssh.SSHServerChannel, root: Path):
        # The resolved root is the chroot boundary AsyncSSH enforces (it
        # realpaths the chroot internally). The configured root is kept
        # separately as the prefix used to recognize client-supplied absolute
        # host paths, because clients address the root by its configured,
        # unresolved spelling (e.g. /var/... which resolves to /private/var
        # on macOS). The authoritative escape guard always uses the resolved
        # root.
        self._root_path = os.fsencode(root.resolve())
        self._root_prefix = os.path.normpath(os.fsencode(root))
        self._channel = channel
        self._served = False
        super().__init__(channel, chroot=self._root_path)

    def _is_confined_by(self, path: bytes, root: bytes) -> bool:
        try:
            return os.path.commonpath((root, path)) == root
        except ValueError:
            return False

    def _is_confined(self, path: bytes) -> bool:
        return self._is_confined_by(path, self._root_path)

    def _require_confined(self, path: bytes) -> None:
        if not self._is_confined(path):
            raise asyncssh.SFTPPermissionDenied("Path resolves outside the SFTP root")

    def _map_requested(self, path: bytes) -> bytes:
        """Map a client path to a host path within the configured root.

        A path that already names a location under the root (absolute host
        paths passed by the asyncssh API or legacy clients, matched against
        the root as it was configured) is kept as that host path; map_path
        and _map_entry then reject any symlink escape. Every other path is
        interpreted relative to the SFTP virtual root ("/"), which is how
        standard SCP clients address the remote namespace after
        canonicalizing it.
        """
        if os.path.isabs(path) and self._is_confined_by(
            os.path.normpath(path), self._root_prefix
        ):
            return os.path.normpath(path)
        return super().map_path(path)

    def map_path(self, path: bytes) -> bytes:
        self._served = True
        mapped = self._map_requested(path)
        resolved = os.path.realpath(mapped)
        self._require_confined(resolved)
        return resolved

    def _map_entry(self, path: bytes) -> bytes:
        """Map a directory entry without following its final symlink."""
        self._served = True
        mapped = self._map_requested(path)
        self._require_confined(os.path.realpath(os.path.dirname(mapped)))
        return mapped

    def exit(self) -> None:
        # OpenSSH scp in SFTP mode reads the channel's exit status and treats
        # a missing one as failure, so report success for a session that
        # actually served requests. A session torn down before serving any
        # request (e.g. by a protocol error) must not be reported as a clean
        # success.
        if self._served:
            with contextlib.suppress(Exception):
                self._channel.exit(0)
        return None

    def lstat(self, path: bytes) -> os.stat_result:
        return os.lstat(self._map_entry(path))

    def remove(self, path: bytes) -> None:
        os.remove(self._map_entry(path))

    def rmdir(self, path: bytes) -> None:
        os.rmdir(self._map_entry(path))

    def rename(self, oldpath: bytes, newpath: bytes) -> None:
        old_mapped = self._map_entry(oldpath)
        new_mapped = self._map_entry(newpath)
        if os.path.lexists(new_mapped):
            raise asyncssh.SFTPFileAlreadyExists("File already exists")
        os.rename(old_mapped, new_mapped)

    def posix_rename(self, oldpath: bytes, newpath: bytes) -> None:
        os.replace(self._map_entry(oldpath), self._map_entry(newpath))

    def readlink(self, path: bytes) -> bytes:
        mapped = self._map_entry(path)
        resolved = os.path.realpath(mapped)
        self._require_confined(resolved)
        return self.reverse_map_path(resolved)

    def symlink(self, oldpath: bytes, newpath: bytes) -> None:
        del oldpath, newpath
        raise asyncssh.SFTPPermissionDenied("Symbolic links are disabled")


async def create_acceptor(config: Config) -> asyncssh.SSHAcceptor:
    ensure_host_key(config.host_key)

    def sftp_factory(channel: asyncssh.SSHServerChannel) -> asyncssh.SFTPServer:
        return ConfinedSFTPServer(channel, config.root)

    return await asyncssh.create_server(
        lambda: TokenSSHServer(config),
        config.host,
        config.port,
        server_host_keys=[str(config.host_key)],
        process_factory=lambda process: handle_process(process, config),
        sftp_factory=sftp_factory,
        allow_scp=True,
        encoding=None,
        line_editor=False,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/marimo", help="SFTP root and command working directory")
    parser.add_argument("--host", default="127.0.0.1", help="listen address")
    parser.add_argument("--port", type=int, default=8022, help="listen port")
    parser.add_argument(
        "--username",
        default=getpass.getuser(),
        help="accepted SSH username (default: current OS user)",
    )
    parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV, help="environment variable containing the password")
    parser.add_argument("--authorized-keys", default="~/.ssh/authorized_keys", help="OpenSSH authorized_keys file")
    parser.add_argument("--host-key", default=str(DEFAULT_HOST_KEY), help="persistent Ed25519 host key path")
    parser.add_argument("--shell", default=None, help="shell used for commands and interactive sessions (default: $SHELL, then bash, then sh)")
    parser.add_argument(
        "--accept",
        action="store_true",
        help="skip all authentication and admit any connecting client",
    )
    parser.add_argument(
        "--allow-tcp-forwarding",
        action="store_true",
        help="allow clients to use local TCP forwarding (ssh -L) through the session",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args(argv)


def resolve_shell(requested: str | None) -> str:
    if requested is not None:
        candidates = [requested]
    else:
        candidates = [os.environ.get("SHELL", ""), "/bin/bash", "/bin/sh"]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            shell = Path(candidate).expanduser().resolve(strict=True)
        except OSError:
            continue
        if shell.is_file() and os.access(shell, os.X_OK):
            return str(shell)
    raise ValueError("No usable shell found; set --shell to an executable")


def build_config(args: argparse.Namespace) -> Config:
    root = Path(args.root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Root is not a directory: {root}")
    if not 1 <= args.port <= 65535:
        raise ValueError("Port must be from 1 to 65535")
    if not args.username or any(character.isspace() for character in args.username):
        raise ValueError("Username must be non-empty and contain no whitespace")

    password = os.environ.get(args.password_env, "")
    if not args.accept and len(password) < 16:
        raise ValueError(f"{args.password_env} must contain at least 16 characters")

    shell = resolve_shell(args.shell)

    return Config(
        root=root,
        host=args.host,
        port=args.port,
        username=args.username,
        password=password,
        password_env=args.password_env,
        authorized_keys=Path(args.authorized_keys).expanduser().resolve(),
        host_key=Path(args.host_key).expanduser().resolve(),
        shell=str(shell),
        accept=args.accept,
        allow_tcp_forwarding=args.allow_tcp_forwarding,
    )


async def serve(config: Config) -> None:
    acceptor = await create_acceptor(config)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, stop.set)

    print(
        f"Nookwire SSH {VERSION} listening on {config.host}:{config.port} "
        f"as {config.username}; SFTP root and command cwd: {config.root}",
        flush=True,
    )
    if config.accept:
        print(
            "nookwire-ssh: --accept set; anyone can connect without "
            "authentication",
            flush=True,
        )
    if config.allow_tcp_forwarding:
        print(
            "nookwire-ssh: --allow-tcp-forwarding set; clients may use "
            "ssh -L through this session",
            flush=True,
        )
    try:
        await stop.wait()
    finally:
        acceptor.close()
        await acceptor.wait_closed()


def main(argv: list[str] | None = None) -> int:
    try:
        config = build_config(parse_args(argv))
        asyncio.run(serve(config))
    except (OSError, ValueError, asyncssh.Error) as error:
        print(f"nookwire-ssh: {error}", file=sys.stderr)
        return 1
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
