"""HMAC signing of article IDs for /r/{article_id}.

Keep in sync with the inline signer in `daily_news.py` — identical secret +
message must produce identical signatures. The golden vector in
`tests/test_signing.py` is the contract both sides honour.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

# ~128 bits of signature strength, URL-safe. Truncation is intentional: we
# trade a few bits of tag space for shorter email URLs, which is an
# acceptable tradeoff for a non-auth context where brute-forcing one link at
# 60/minute takes ~10^30 years.
SIG_LEN = 22


def sign_article(article_id: str, secret: str) -> str:
    digest = hmac.new(secret.encode(), article_id.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode()[:SIG_LEN]


def verify(article_id: str, sig: str, secret: str) -> bool:
    expected = sign_article(article_id, secret)
    return hmac.compare_digest(sig, expected)
