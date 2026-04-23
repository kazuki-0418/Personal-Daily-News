"""GET /r/{article_id}?s=<sig> — signed click tracker."""

from __future__ import annotations

import hashlib
import logging

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from .. import db
from ..rate_limit import CLICK_RATE_LIMIT, limiter
from ..settings import Settings
from ..signing import verify

log = logging.getLogger(__name__)

router = APIRouter()

# UA substrings that indicate link prefetching / bot fetch — these requests
# must not be counted as human clicks.
PREFETCH_UA_PATTERNS = (
    "GoogleImageProxy",
    "YahooMailProxy",
    "bingbot",
    "Googlebot",
    "Slackbot",
    "facebookexternalhit",
    "Twitterbot",
    "LinkedInBot",
    "Discordbot",
)


def _hash_ip(ip: str, salt: str) -> str:
    return hashlib.sha256(f"{ip}|{salt}".encode()).hexdigest()[:32]


def _is_prefetch(user_agent: str) -> bool:
    return any(p in user_agent for p in PREFETCH_UA_PATTERNS)


@router.get("/r/{article_id}")
@limiter.limit(CLICK_RATE_LIMIT)
def click(article_id: str, s: str, request: Request) -> RedirectResponse:
    settings: Settings = request.app.state.settings

    article = db.get_article(article_id)
    if article is None:
        return RedirectResponse(settings.missing_redirect_url, status_code=302)

    ua = request.headers.get("user-agent", "")

    if not verify(article_id, s, settings.click_signing_secret):
        # Bad signature — 302 to the real URL anyway so an attacker can't
        # distinguish "signature rejected" from "click logged", but do not
        # record the click.
        log.info("click: bad signature for article_id=%s", article_id)
        return RedirectResponse(article["url"], status_code=302)

    if _is_prefetch(ua):
        log.info("click: prefetch/bot UA skipped logging for article_id=%s", article_id)
        return RedirectResponse(article["url"], status_code=302)

    client_ip = _resolve_client_ip(request)
    try:
        db.log_click(
            article_id=article_id,
            user_id=article["user_id"],
            user_agent=ua[:512],
            ip_hash=_hash_ip(client_ip, settings.ip_salt),
        )
    except Exception:
        # Don't fail the redirect if click logging misbehaves — the UX cost
        # of a broken link far exceeds the analytics cost of a missed row.
        log.exception("click: failed to log click for article_id=%s", article_id)

    return RedirectResponse(article["url"], status_code=302)


def _resolve_client_ip(request: Request) -> str:
    """Prefer Cloudflare's CF-Connecting-IP, fall back to direct peer."""
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip
    if request.client is not None:
        return request.client.host
    return "0.0.0.0"
