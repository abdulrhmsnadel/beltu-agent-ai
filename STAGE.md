# Stage 22 — Multi-Model Local Brain

BELTU 1.2.0 introduces a context-aware local hybrid reasoning architecture.

- Standard local reasoning remains the default for reconnaissance and tool-output interpretation.
- Altar-1 receives specialized code-review, exploit-proof/reproduction, and authorization-matrix anomaly contexts.
- Router decisions are deterministic and feed the normal reasoning pipeline.
- Altar-1 request activity is exposed through filesystem leases.
- The Resource Governor clamps tool concurrency while Altar-1 is active.
- Coverage includes routing, provider handling, activity leases, and resource mitigation.
