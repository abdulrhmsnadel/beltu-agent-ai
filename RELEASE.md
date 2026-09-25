# BELTU 1.3.0 Release

BELTU 1.3.0 adds the Gemini advisory co-pilot, privacy boundary, deterministic three-tier routing, and hardened local model runtime.

## Included

- Context-aware LLMRouter
- Altar1LocalProvider
- Per-task Altar-1 decoding profiles
- Loopback-only specialist inference
- Altar-1 request activity leases
- VRAM/resource governor mitigation while Altar-1 is active
- Altar-1 start/stop helper scripts
- Stage 22 multi-model tests
- Stage 24 Gemini privacy/routing tests
- Package version 1.3.0
- Updated mobile client metadata (1.3.0+23)

## Deployment note

Gemini is advisory-only and the local BELTU operator remains final authority. The local reasoning path does not require a cloud API key.

The public Altar-1 model card describes a 328 GB INT4/W4A16 build intended for 4× NVIDIA H200 serving. BELTU keeps the specialist disabled by default and does not automatically download model weights.
