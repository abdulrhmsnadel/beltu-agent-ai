from __future__ import annotations

import hashlib
import hmac


def verify_meta_signature(body: bytes, signature_header: str | None, app_secret: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256=") or not app_secret:
        return False
    provided = signature_header.split("=", 1)[1]
    expected = hmac.new(app_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, expected)
