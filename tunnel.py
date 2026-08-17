#!/usr/bin/env python3
"""Keep one srv.us reverse tunnel open using AsyncSSH."""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys

import asyncssh


class TunnelClient(asyncssh.SSHClient):
    """Expose srv.us protocol messages in the runtime tunnel log."""

    def debug_msg_received(self, msg: str, lang: str, always_display: bool) -> None:
        print(msg, flush=True)

    def auth_banner_received(self, msg: str, lang: str) -> None:
        print(msg, flush=True)


async def pump(reader, writer) -> None:
    while True:
        data = await reader.read(4096)
        if not data:
            return
        writer.write(data)
        writer.flush()


async def run(local_port: int, slot: int, key: str, username: str) -> None:
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stopped.set)
        except NotImplementedError:
            pass

    connection = await asyncssh.connect(
        "srv.us",
        username=username,
        client_keys=[key],
        known_hosts=None,
        client_factory=TunnelClient,
        keepalive_interval=30,
        keepalive_count_max=3,
    )
    process = None
    listener = None
    tasks: list[asyncio.Task] = []
    try:
        # srv.us blocks its tcpip-forward reply until a session channel exists.
        # Open the non-PTY shell first and keep its output readers active.
        process = await connection.create_process(request_pty=False)
        tasks = [
            asyncio.create_task(pump(process.stdout, sys.stdout)),
            asyncio.create_task(pump(process.stderr, sys.stderr)),
        ]
        process.stdin.write_eof()
        await process.stdin.drain()

        listener = await connection.forward_remote_port(
            "",
            slot,
            "127.0.0.1",
            local_port,
        )
        print(f"remote forward ready on slot {listener.get_port()}", flush=True)

        connection_closed = asyncio.create_task(connection.wait_closed())
        stop_requested = asyncio.create_task(stopped.wait())
        tasks.extend((connection_closed, stop_requested))
        await asyncio.wait(
            (connection_closed, stop_requested),
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        if listener is not None:
            listener.close()
        if process is not None:
            process.stdin.close()
        connection.close()
        await connection.wait_closed()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-port", type=int, required=True)
    parser.add_argument("--slot", type=int, required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    asyncio.run(run(args.local_port, args.slot, args.key, args.username))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
