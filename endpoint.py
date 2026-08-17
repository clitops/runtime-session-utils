#!/usr/bin/env python3
"""Authenticated temporary SSH endpoint with interactive PTY support."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import getpass
import os
import pty
import pwd
import signal
import struct
import sys
import termios
from dataclasses import dataclass
from pathlib import Path

import asyncssh


@dataclass(frozen=True)
class Config:
    root: Path
    host: str
    port: int
    username: str
    authorized_key: asyncssh.SSHKey
    host_key: Path
    shell: str


class KeyServer(asyncssh.SSHServer):
    def __init__(self, config: Config):
        self.config = config

    def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return False

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return username == self.config.username and key == self.config.authorized_key

    def connection_requested(
        self,
        dest_host: str,
        dest_port: int,
        orig_host: str,
        orig_port: int,
    ) -> bool:
        del dest_host, dest_port, orig_host, orig_port
        return False


def ensure_host_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    if path.exists():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Invalid host key path: {path}")
        path.chmod(0o600)
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


def terminal_size(fd: int, size: tuple[int, int, int, int]) -> None:
    width, height, pixel_width, pixel_height = size
    if width and height:
        packed = struct.pack("HHHH", height, width, pixel_width, pixel_height)
        with contextlib.suppress(OSError):
            fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)


def acquire_terminal() -> None:
    os.setsid()
    with contextlib.suppress(OSError):
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)


async def terminate_group(child: asyncio.subprocess.Process) -> None:
    if child.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(child.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(child.wait(), timeout=5)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)
        await child.wait()


def child_argv(command: str, config: Config) -> list[str]:
    if command:
        return [config.shell, "-lc", command]
    if os.path.basename(config.shell) in ("bash", "zsh"):
        return [config.shell, "-l", "-i"]
    return [config.shell, "-i"]


def child_environment(process: asyncssh.SSHServerProcess, config: Config) -> dict[str, str]:
    environment = os.environ.copy()
    account = pwd.getpwuid(os.geteuid())
    environment.update(
        {
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "SHELL": config.shell,
            "PWD": str(config.root),
        }
    )
    if process.term_type is not None:
        environment["TERM"] = process.term_type or "xterm-256color"
    return environment


async def ssh_to_pty(
    process: asyncssh.SSHServerProcess,
    transport: asyncio.WriteTransport,
    master_fd: int,
    child: asyncio.subprocess.Process,
) -> None:
    while True:
        try:
            data = await process.stdin.read(65536)
        except asyncssh.TerminalSizeChanged as change:
            terminal_size(master_fd, (change.width, change.height, change.pixwidth, change.pixheight))
            continue
        except asyncssh.SignalReceived as received:
            signum = getattr(signal, f"SIG{received.signal}", None)
            if signum and child.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signum)
            continue
        except (asyncssh.BreakReceived, asyncssh.SoftEOFReceived):
            continue
        except (ConnectionError, BrokenPipeError):
            break
        if not data:
            break
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogateescape")
        transport.write(data)


async def pty_to_ssh(reader: asyncio.StreamReader, process: asyncssh.SSHServerProcess) -> None:
    while True:
        try:
            data = await reader.read(65536)
        except OSError:
            break
        if not data:
            break
        try:
            process.stdout.write(data)
            await process.stdout.drain()
        except (ConnectionError, BrokenPipeError):
            break


async def handle_pty(
    process: asyncssh.SSHServerProcess,
    config: Config,
    argv: list[str],
    environment: dict[str, str],
) -> None:
    loop = asyncio.get_running_loop()
    master_fd, slave_fd = pty.openpty()
    if process.term_size:
        terminal_size(slave_fd, process.term_size)
    reader_transport = None
    writer_transport = None
    child = None
    try:
        child = await asyncio.create_subprocess_exec(
            *argv,
            cwd=config.root,
            env=environment,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=acquire_terminal,
        )
        os.close(slave_fd)
        slave_fd = -1

        read_fd = os.dup(master_fd)
        reader = asyncio.StreamReader()
        reader_transport, _ = await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(read_fd, "rb", 0)
        )
        writer_transport, _ = await loop.connect_write_pipe(
            asyncio.Protocol, os.fdopen(master_fd, "wb", 0)
        )

        input_task = asyncio.create_task(ssh_to_pty(process, writer_transport, master_fd, child))
        output_task = asyncio.create_task(pty_to_ssh(reader, process))
        child_wait = asyncio.create_task(child.wait())
        channel_wait = asyncio.create_task(process.wait_closed())
        done, _ = await asyncio.wait((child_wait, channel_wait), return_when=asyncio.FIRST_COMPLETED)
        disconnected = channel_wait in done
        if disconnected and child.returncode is None:
            await terminate_group(child)
        return_code = await child_wait
        if not disconnected:
            await output_task
            process.exit(return_code if return_code >= 0 else 128 - return_code)
        input_task.cancel()
        output_task.cancel()
        channel_wait.cancel()
        await asyncio.gather(input_task, output_task, channel_wait, return_exceptions=True)
    finally:
        if child is not None and child.returncode is None:
            await terminate_group(child)
        if slave_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(slave_fd)
        if reader_transport is not None:
            reader_transport.close()
        if writer_transport is not None:
            writer_transport.close()
        else:
            with contextlib.suppress(OSError):
                os.close(master_fd)


async def stream_input(process: asyncssh.SSHServerProcess, child: asyncio.subprocess.Process) -> None:
    assert child.stdin is not None
    try:
        while data := await process.stdin.read(65536):
            if isinstance(data, str):
                data = data.encode()
            child.stdin.write(data)
            await child.stdin.drain()
    except (ConnectionError, BrokenPipeError):
        pass
    finally:
        child.stdin.close()


async def stream_output(source: asyncio.StreamReader, destination: asyncssh.SSHWriter) -> None:
    try:
        while data := await source.read(65536):
            destination.write(data)
            await destination.drain()
    except (ConnectionError, BrokenPipeError):
        pass


async def handle_process(process: asyncssh.SSHServerProcess, config: Config) -> None:
    command = process.command
    if isinstance(command, bytes):
        command = command.decode("utf-8", "surrogateescape")
    argv = child_argv(command, config)
    environment = child_environment(process, config)
    if process.term_type is not None:
        await handle_pty(process, config, argv, environment)
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
    input_task = asyncio.create_task(stream_input(process, child))
    output_tasks = [
        asyncio.create_task(stream_output(child.stdout, process.stdout)),
        asyncio.create_task(stream_output(child.stderr, process.stderr)),
    ]
    child_wait = asyncio.create_task(child.wait())
    channel_wait = asyncio.create_task(process.wait_closed())
    done, _ = await asyncio.wait((child_wait, channel_wait), return_when=asyncio.FIRST_COMPLETED)
    disconnected = channel_wait in done
    if disconnected and child.returncode is None:
        await terminate_group(child)
    return_code = await child_wait
    if not disconnected:
        await asyncio.gather(*output_tasks)
        process.exit(return_code if return_code >= 0 else 128 - return_code)
    input_task.cancel()
    channel_wait.cancel()
    for task in output_tasks:
        task.cancel()
    await asyncio.gather(input_task, channel_wait, *output_tasks, return_exceptions=True)


def resolve_shell(requested: str | None) -> str:
    for candidate in (requested, os.environ.get("SHELL"), "/bin/bash", "/bin/sh"):
        if not candidate:
            continue
        try:
            path = Path(candidate).expanduser().resolve(strict=True)
        except OSError:
            continue
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise ValueError("No executable shell found")


async def serve(config: Config) -> None:
    ensure_host_key(config.host_key)
    acceptor = await asyncssh.create_server(
        lambda: KeyServer(config),
        config.host,
        config.port,
        server_host_keys=[str(config.host_key)],
        process_factory=lambda process: handle_process(process, config),
        encoding=None,
        line_editor=False,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, stop.set)
    print(f"endpoint ready on {config.host}:{config.port}", flush=True)
    try:
        await stop.wait()
    finally:
        acceptor.close()
        await acceptor.wait_closed()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--username", default=getpass.getuser())
    parser.add_argument("--host-key", required=True)
    parser.add_argument("--authorized-key", required=True)
    parser.add_argument("--shell")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve(strict=True)
    authorized_key_path = Path(args.authorized_key).expanduser().resolve(strict=True)
    if not authorized_key_path.is_file() or authorized_key_path.is_symlink():
        raise SystemExit("Invalid authorized public key path")
    config = Config(
        root=root,
        host=args.host,
        port=args.port,
        username=args.username,
        authorized_key=asyncssh.read_public_key(str(authorized_key_path)),
        host_key=Path(args.host_key).expanduser().resolve(),
        shell=resolve_shell(args.shell),
    )
    try:
        asyncio.run(serve(config))
    except (OSError, ValueError, asyncssh.Error) as error:
        print(f"endpoint error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
