# BELTU 1.2.0 Release

BELTU 1.2.0 adds a multi-model local reasoning brain with deterministic routing between the standard local provider and the optional Altar-1 security specialist.

## Included

- Context-aware LLMRouter
- Altar1LocalProvider
- Per-task Altar-1 decoding profiles
- Loopback-only specialist inference
- Altar-1 request activity leases
- VRAM/resource governor mitigation while Altar-1 is active
- Altar-1 start/stop helper scripts
- Stage 22 multi-model tests
- Package version 1.2.0
- Updated mobile client metadata

## Deployment note

The public Altar-1 model card describes a 328 GB INT4/W4A16 build intended for 4× NVIDIA H200 serving. BELTU keeps the specialist disabled by default and does not automatically download model weights.
