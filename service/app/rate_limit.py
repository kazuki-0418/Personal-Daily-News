"""Rate-limit plumbing for the service.

slowapi's `@limit` decorator takes a string (or a zero-arg callable). Since
the limit is configured via env at startup, we read the env var once at
import time and pass the literal string to the decorator. Tests that want a
tighter threshold override `CLICK_RATE_LIMIT` before the routes module is
imported (see conftest).
"""

from __future__ import annotations

import os

from fastapi import Request
from slowapi import Limiter


def _remote_ip(request: Request) -> str:
    """Prefer Cloudflare's CF-Connecting-IP, fall back to peer address.

    Behind the Cloudflare Tunnel, request.client.host is the tunnel's
    internal IP, so every real client would share one bucket without this.
    """
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip
    if request.client is not None:
        return request.client.host
    return "0.0.0.0"


CLICK_RATE_LIMIT = os.environ.get("CLICK_RATE_LIMIT", "60/minute")

limiter = Limiter(key_func=_remote_ip)
