#!/usr/bin/env python3
"""Verify that one temporary runtime session left no residue."""

from __future__ import annotations

import argparse
import json
import os
import socket
import tempfile
from pathlib import Path


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    base = Path(args.base).expanduser().resolve()
    temp_root = Path(
        os.environ.get("RUNTIME_SESSION_TEMP_ROOT", tempfile.gettempdir())
    ).expanduser().resolve()
    if base.parent != temp_root or not base.name.startswith("runtime-session-"):
        raise SystemExit(f"Refusing unexpected path: {base}")
    metadata_path = base / "session.json"
    metadata = json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
    pids = [
        pid
        for pid in (
            metadata.get("server_pid"),
            metadata.get("tunnel_pid"),
            metadata.get("watchdog_pid"),
        )
        if isinstance(pid, int)
    ]
    active = [pid for pid in pids if alive(pid)]
    opened = port_open(args.port)
    result = {
        "clean": not base.exists() and not active and not opened,
        "base": str(base),
        "base_exists": base.exists(),
        "active_pids": active,
        "port": args.port,
        "port_open": opened,
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
