from pathlib import Path

import pytest

from beltu.common.exceptions import ScopeViolation
from beltu.policy.scope_guard import ScopeGuard


def test_scope_is_default_deny(tmp_path: Path):
    path = tmp_path / "scope.yaml"
    path.write_text("targets: []\n", encoding="utf-8")
    guard = ScopeGuard(path)
    assert guard.allowed("example.com") is False
    with pytest.raises(ScopeViolation):
        guard.require_allowed("example.com")


def test_scope_matches_case_insensitively(tmp_path: Path):
    path = tmp_path / "scope.yaml"
    path.write_text("targets:\n  - Example.COM\n", encoding="utf-8")
    guard = ScopeGuard(path)
    assert guard.allowed("example.com") is True
