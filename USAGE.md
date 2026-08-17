# Runtime session utilities

Small utilities for one owner-authorized, public-key-authenticated temporary SSH
session through srv.us.

## Properties

- Binds the local endpoint to `127.0.0.1`.
- Accepts only the assessment public key in `authorized_key.pub`; password
  authentication is disabled.
- Rejects TCP forwarding.
- Uses AsyncSSH for both the local endpoint and srv.us tunnel, with no system
  SSH client dependency.
- Stores keys, dependencies, logs, and state under one temporary directory.
- Limits the session to at most 3600 seconds.
- Runs a detached watchdog which stops both process groups and removes state.
- Includes explicit early-stop and cleanup-verification utilities.

The endpoint is not an OS sandbox. An authenticated shell has the permissions of
the account running `runtime.py`.

## Local usage

```bash
python3 runtime.py --root "$PWD" --port 8022 --duration 3600
```

Use the matching local private key and printed connection command. To stop early:

```bash
python3 stop.py /tmp/runtime-session-XXXXXXXXXX
python3 check.py /tmp/runtime-session-XXXXXXXXXX --port 8022
```

## Minimal loader

```python
import urllib.request

url = "https://api.github.com/repos/clitops/runtime-session-utils/contents/runtime.py?ref=main"
request = urllib.request.Request(
    url,
    headers={"Accept": "application/vnd.github.raw+json", "User-Agent": "runtime-loader"},
)
source = urllib.request.urlopen(request, timeout=30).read()
exec(compile(source, url, "exec"), globals())
```
