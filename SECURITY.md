# BELTU Security Notes

BELTU is intended for explicitly authorized security testing.

## Context security boundary

Before any target-derived text reaches the reasoning layer, \`ContextBuilder\` passes the assembled context through the mandatory \`ContextSecurityBoundary\`.

That boundary is implemented in:

\`src/beltu/brain/context_security.py\`

It:

- treats target/tool/browser/API output as untrusted evidence
- normalizes Unicode and removes selected invisible/control characters
- redacts common credentials, authorization headers, cookies, tokens, API keys, and private-key material
- bounds individual strings and aggregate reasoning context
- labels target-derived records as \`untrusted_target_data\`
- fails closed if the boundary is disabled

The reasoning prompt separately wraps the context in \`<BELTU_TARGET_DATA>\` and instructs the model never to follow embedded commands or role changes from that data.

Detailed flow and security expectations are documented in [\`docs/security.md\`](docs/security.md).

## Local AI

The default reasoning provider is \`freetoken_local\` and the configured endpoint is loopback-only (\`127.0.0.1:8000\`). The provider rejects non-loopback URLs. BELTU does not supply a cloud API key to the FreeToken process.

## Execution

Target scope, action policy, approval records, capability allowlists, and resource limits remain independent of the LLM. The model returns structured proposals; it does not receive direct shell access. High-risk and medium-risk actions continue to require the existing policy/approval path.

## Remote operations

The Remote Operations gateway binds to loopback by default and requires authenticated bearer tokens with scoped permissions. Do not expose the gateway directly to the public internet. Use TLS/WSS and a trusted reverse proxy for non-local deployments.

## Files and artifacts

Per-scan workspaces are contained by path checks. Runtime databases, evidence, local model weights, access tokens, \`.env\` files, and other operational data must remain outside source control.
