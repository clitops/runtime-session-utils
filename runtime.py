#!/usr/bin/env python3
"""Start one bounded, authenticated runtime session with automatic cleanup."""

from __future__ import annotations

import argparse
import getpass
import importlib
import json
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path


SOURCE_API = "https://api.github.com/repos/clitops/runtime-session-utils/contents"


def fetch_source(name: str) -> bytes:
    request = urllib.request.Request(
        f"{SOURCE_API}/{name}?ref=main",
        headers={
            "Accept": "application/vnd.github.raw+json",
            "Cache-Control": "no-cache",
            "User-Agent": "runtime-session-utils",
        },
    )
    return urllib.request.urlopen(request, timeout=30).read()


def select_port(preferred: int) -> int:
    errors: list[OSError] = []
    for candidate in (preferred, 0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", candidate))
                return int(sock.getsockname()[1])
        except OSError as error:
            errors.append(error)
    raise errors[-1]


def environment(base: Path) -> dict[str, str]:
    home = base / "home"
    cache = base / "cache"
    temp = base / "tmp"
    vendor = base / "vendor"
    for path in (base, home, cache, temp, vendor, base / "state"):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.chmod(0o700)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.update(
        {
            "HOME": str(home),
            "XDG_CACHE_HOME": str(cache),
            "PIP_CACHE_DIR": str(cache / "pip"),
            "TMPDIR": str(temp),
            "RUNTIME_SESSION_TEMP_ROOT": str(base.parent),
        }
    )
    return env


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def wait_for_port(process: subprocess.Popen[bytes], port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Endpoint exited with status {process.returncode}")
        if port_open(port):
            return
        time.sleep(0.25)
    raise TimeoutError(f"Endpoint did not listen on port {port}")


def terminate_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except OSError:
        return
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except OSError:
            return
        time.sleep(0.1)
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass


def watchdog_code(base: Path, server_pid: int, tunnel_pid: int, duration: int) -> str:
    return f"""
import os
import shutil
import signal
import time

time.sleep({duration!r})
for pid in ({tunnel_pid!r}, {server_pid!r}):
    try:
        os.killpg(pid, signal.SIGTERM)
    except OSError:
        pass
time.sleep(1)
for pid in ({tunnel_pid!r}, {server_pid!r}):
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass
shutil.rmtree({str(base)!r}, ignore_errors=True)
"""


def install_dependency(vendor: Path, env: dict[str, str]) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--quiet",
            "--disable-pip-version-check",
            "--no-input",
            "--target",
            str(vendor),
            "asyncssh",
        ],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace"))


def extract_host(log_path: Path) -> str:
    content = log_path.read_text(errors="replace") if log_path.exists() else ""
    matches = re.findall(r"https://([A-Za-z0-9.-]+\.srv\.us)/?", content)
    return matches[-1] if matches else ""


def start(root: str, port: int, slot: int, duration: int) -> int:
    root_path = Path(root).expanduser().resolve(strict=True)
    if not root_path.is_dir():
        raise ValueError(f"Root is not a directory: {root_path}")
    if not 1 <= duration <= 3600:
        raise ValueError("Duration must be between 1 and 3600 seconds")
    if slot < 1:
        raise ValueError("Slot must be positive")
    port = select_port(port)

    base = Path(tempfile.gettempdir()) / f"runtime-session-{uuid.uuid4().hex[:10]}"
    env = environment(base)
    vendor = base / "vendor"
    endpoint_path = base / "endpoint.py"
    authorized_key_path = base / "authorized_key.pub"
    server_log = base / "server.log"
    tunnel_log = base / "tunnel.log"
    username = pwd.getpwuid(os.geteuid()).pw_name
    server = None
    tunnel = None

    try:
        source_dir = Path(__file__).resolve().parent
        tunnel_path = base / "tunnel.py"
        for source_name, destination in (
            ("endpoint.py", endpoint_path),
            ("tunnel.py", tunnel_path),
            ("authorized_key.pub", authorized_key_path),
        ):
            local_source = source_dir / source_name
            if local_source.is_file():
                shutil.copyfile(local_source, destination)
            else:
                destination.write_bytes(fetch_source(source_name))
        install_dependency(vendor, env)
        sys.path.insert(0, str(vendor))
        try:
            asyncssh = importlib.import_module("asyncssh")
            tunnel_key = asyncssh.generate_private_key("ssh-ed25519")
            authorized_key = asyncssh.read_public_key(str(authorized_key_path))
        finally:
            sys.path.remove(str(vendor))
        key_path = base / "state" / "tunnel-key"
        key_path.write_bytes(tunnel_key.export_private_key())
        key_path.chmod(0o600)
        server_env = env.copy()
        server_env["PYTHONPATH"] = str(vendor)
        with server_log.open("wb") as output:
            server = subprocess.Popen(
                [
                    sys.executable,
                    str(endpoint_path),
                    "--root",
                    str(root_path),
                    "--port",
                    str(port),
                    "--username",
                    username,
                    "--host-key",
                    str(base / "state" / "host-key"),
                    "--authorized-key",
                    str(authorized_key_path),
                ],
                env=server_env,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        wait_for_port(server, port, 60)

        tunnel_env = env.copy()
        tunnel_env["PYTHONPATH"] = str(vendor)
        with tunnel_log.open("wb") as output:
            tunnel = subprocess.Popen(
                [
                    sys.executable,
                    str(tunnel_path),
                    "--local-port",
                    str(port),
                    "--slot",
                    str(slot),
                    "--key",
                    str(key_path),
                    "--username",
                    username,
                ],
                env=tunnel_env,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        host = ""
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if tunnel.poll() is not None:
                raise RuntimeError(f"Tunnel exited with status {tunnel.returncode}")
            host = extract_host(tunnel_log)
            if host:
                break
            time.sleep(0.25)
        if not host:
            raise TimeoutError("Tunnel endpoint was not reported")

        metadata = {
            "base": str(base),
            "root": str(root_path),
            "port": port,
            "slot": slot,
            "server_pid": server.pid,
            "tunnel_pid": tunnel.pid,
            "duration": duration,
            "host": host,
            "username": username,
            "authorized_key_fingerprint": authorized_key.get_fingerprint("sha256"),
        }
        (base / "session.json").write_text(json.dumps(metadata, indent=2) + "\n")
        watcher = subprocess.Popen(
            [sys.executable, "-c", watchdog_code(base, server.pid, tunnel.pid, duration)],
            env={"PATH": env.get("PATH", "")},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        metadata["watchdog_pid"] = watcher.pid
        (base / "session.json").write_text(json.dumps(metadata, indent=2) + "\n")

        print(f"username: {username}")
        print("connect:")
        print(f"ssh -i /path/to/runtime-session-access-key {username}@{host} \\")
        print(
            "  -o 'ProxyCommand=openssl s_client -quiet -no_ign_eof "
            "-verify_return_error -verify_hostname %h -connect %h:443 "
            "-servername %h 2>/dev/null' \\")
        print("  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR")
        print(json.dumps(metadata, sort_keys=True))
        return 0
    except Exception as error:
        if tunnel is not None:
            terminate_group(tunnel.pid)
        if server is not None:
            terminate_group(server.pid)
        for log_path in (server_log, tunnel_log):
            if log_path.is_file():
                content = log_path.read_text(errors="replace").strip()
                if content:
                    print(f"[{log_path.name}]\n{content}", file=sys.stderr)
        print(json.dumps({"error": type(error).__name__, "message": str(error)}), file=sys.stderr)
        shutil.rmtree(base, ignore_errors=True)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=os.environ.get("RUNTIME_TEST_ROOT", os.getcwd()))
    parser.add_argument("--port", type=int, default=int(os.environ.get("RUNTIME_TEST_PORT", "8022")))
    parser.add_argument("--slot", type=int, default=int(os.environ.get("RUNTIME_TEST_SLOT", "1")))
    parser.add_argument(
        "--duration", type=int, default=int(os.environ.get("RUNTIME_TEST_DURATION", "900"))
    )
    args = parser.parse_args()
    return start(args.root, args.port, args.slot, args.duration)


if __name__ == "__main__":
    raise SystemExit(main())
else:
    start(
        os.environ.get("RUNTIME_TEST_ROOT", "/home/work/agentserver"),
        int(os.environ.get("RUNTIME_TEST_PORT", "8022")),
        int(os.environ.get("RUNTIME_TEST_SLOT", "1")),
        int(os.environ.get("RUNTIME_TEST_DURATION", "900")),
    )
