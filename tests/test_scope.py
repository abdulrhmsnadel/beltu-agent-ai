from beltu.policy.scope_guard import ScopeGuard


def test_configured_scope_no_longer_blocks_targets():
    guard = ScopeGuard("/path/that/does/not/exist/scope.yaml")
    assert guard.allowed("example.com")
    assert guard.allowed("anything.web-security-academy.net")
    guard.require_allowed("example.com")


def test_url_target_is_accepted_without_scope_file():
    guard = ScopeGuard()
    assert guard.allowed_url("https://example.com/some/path")
