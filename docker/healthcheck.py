"""Container HEALTHCHECK for the app image.

The same image runs three roles. For ``reddysec web`` we ask /healthz. For
``reddysec worker`` and ``reddysec deadman`` there is no HTTP server; a running
process is "healthy" here and real liveness is the heartbeat alert in Log
Analytics (infra/azure/modules/alerts.bicep). Container Apps ignores this and
uses its own probes; docker compose uses it.
"""

from __future__ import annotations

import sys
import urllib.request

PORT = 8000


def role() -> str:
    try:
        with open("/proc/1/cmdline", "rb") as f:
            args = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
    except OSError:
        return "unknown"
    for candidate in ("web", "worker", "deadman"):
        if candidate in args:
            return candidate
    return "unknown"


def main() -> int:
    if role() != "web":
        return 0
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=4) as resp:  # noqa: S310
            return 0 if resp.status == 200 else 1
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
