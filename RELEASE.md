# BELTU 1.1.0 Release

BELTU 1.1.0 adds local FreeToken reasoning, GPU/VRAM-aware resource governance, simplified CLI commands, and the Flutter Mobile Command Center.

## Included

- `freetoken_local` provider with loopback-only enforcement and streamed OpenAI-compatible token parsing.
- FreeToken install/start/stop automation under `scripts/`.
- CPU/RAM/NVIDIA VRAM telemetry plus FreeToken process telemetry.
- Adaptive concurrency, per-tool thread/concurrency flags, and CPU-affinity throttling for BELTU-managed child processes.
- `beltu target`, `beltu hunt`, `beltu remote`, and richer `beltu status`.
- Mobile Dashboard, Agent Chat, Approvals, Live Activity, Files, and Reports.
- Authenticated report/file download API.
- Updated documentation for local/air-gapped operation.
