from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


class ScopeGuard:
    """Compatibility shim for pre-v1.3 callers.

    BELTU v1.3 no longer enforces a configured target scope file. Target
    acceptance is handled by the registered scan target plus the existing
    capability policy, approval, and resource controls. The class remains only
    so older integrations importing ScopeGuard do not break.
    """

    def __init__(self, scope_file: str | Path | None = None) -> None:
        self.scope_file = Path(scope_file) if scope_file is not None else None

    def allowed(self, target: str) -> bool:
        """Return True for every non-empty target; configured scope is disabled."""
        return bool(str(target).strip())

    def allowed_url(self, url: str) -> bool:
        """Return True when the value contains a hostname; URL scope is disabled."""
        value = str(url).strip()
        return bool(value) and bool(urlparse(value).hostname)

    def require_allowed(self, target: str) -> None:
        """Legacy no-op: v1.3 does not block targets using scope.yaml."""
        if not str(target).strip():
            raise ValueError("Target cannot be empty")
