# Stage 24 — Multi-Model Brain and Cloud Co-Pilot

BELTU 1.3.0 extends the local hybrid reasoning architecture with a privacy-bounded Gemini advisory tier.

- Standard local reasoning remains the default for reconnaissance and tool-output interpretation.
- Gemini receives only the sanitized advisory context allowed by the cloud privacy policy.
- Local BELTU state and policy remain the final authority for decisions and execution.
- Altar-1 receives specialized code-review, exploit-proof/reproduction, and authorization-matrix anomaly contexts.
- Router decisions are deterministic and feed the normal reasoning pipeline.
- Altar-1 request activity is exposed through filesystem leases.
- The Resource Governor clamps tool concurrency while Altar-1 is active.
- Coverage includes routing, provider handling, activity leases, and resource mitigation.
