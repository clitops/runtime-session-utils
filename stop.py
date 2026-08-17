#!/usr/bin/env python3
"""Stop one temporary runtime session and remove its state."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import tempfile
import time
from pathlib import Path


def safe_base(value: str) -> Path:
    base = Path(value).expanduser().resolve()
    temp_root = Path(
        os.environ.get("RUNTIME_SESSION_TEMP_ROOT", tempfile.gettempdir())
    ).expanduser().resolve()
    if base.parent != temp_root or not base.name.startswith("runtime-session-"):
        raise ValueError(f"Refusing unexpected path: {base}")
    return base


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop(value: str) -> dict[str, object]:
    base = safe_base(value)
    metadata_path = base / "session.json"
    metadata = json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
    pids = [
        pid
        for pid in (
            metadata.get("tunnel_pid"),
            metadata.get("server_pid"),
            metadata.get("watchdog_pid"),
        )
        if isinstance(pid, int)
    ]
    for pid in pids:
        try:
            os.killpg(pid, signal.SIGTERM)
        except OSError:
            pass
    time.sleep(1)
    for pid in pids:
        if alive(pid):
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass
    shutil.rmtree(base, ignore_errors=True)
    residual = [pid for pid in pids if alive(pid)]
    return {
        "clean": not base.exists() and not residual,
        "base": str(base),
        "residual_pids": residual,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    result = stop(parser.parse_args().base)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
