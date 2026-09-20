# BELTU Security Notes

BELTU is intended for explicitly authorized security testing.

## Local AI

The default reasoning provider is `freetoken_local` and the configured endpoint is loopback-only (`127.0.0.1:8000`). The provider rejects non-loopback URLs. BELTU does not supply a cloud API key to the FreeToken process.

## Execution

Target scope, action policy, approval records, capability allowlists, and resource limits remain independent of the LLM. The model returns structured proposals; it does not receive direct shell access. High-risk and medium-risk actions continue to require the existing policy/approval path.

## Remote operations

The Remote Operations gateway binds to loopback by default and requires authenticated bearer tokens with scoped permissions. Do not expose the gateway directly to the public internet. Use TLS/WSS and a trusted reverse proxy for non-local deployments.

## Files and artifacts

Per-scan workspaces are contained by path checks. Runtime databases, evidence, local model weights, access tokens, `.env` files, and other operational data must remain outside source control.
