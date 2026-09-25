# BELTU Security Model

- Scope is default-deny and checked at registration and immediately before execution.
- External tools are enabled only when explicitly configured for the deployment; the sample agent configuration may enable bounded low-risk autonomous execution. LLM reasoning remains local by default.
- Process execution uses argument vectors rather than shell commands.
- Approval-gated actions require a current approval tied to the decision action hash.
- Secrets are environment-based; intelligence layers retain metadata/fingerprints rather than raw token values.
- Remote file access is confined to the current scan workspace and preview size is bounded.
- Remote deployments should use TLS/WSS, explicit CORS origins, strong random signing secrets, and restricted network exposure.
