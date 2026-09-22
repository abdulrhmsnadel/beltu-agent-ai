# BELTU 1.2.0 — Multi-Model Local Security Agent

BELTU is a local-first agentic security-testing platform for explicitly authorized bug-bounty, lab, and red-team assessments. It maintains persistent scan state, builds context from observations and evidence, reasons over hypotheses, selects capabilities, applies scope/approval/resource gates, executes allowlisted tooling, correlates evidence, validates findings, and generates reports.

## What's new in 1.2.0

BELTU adds a multi-model local reasoning layer.

- **Standard local model:** general reasoning, reconnaissance, mapping, and tool-output interpretation.
- **Altar-1 local model:** optional specialist for code review, exploit-proof/reproduction analysis, and authorization-matrix anomaly verification.
- **Dynamic router:** classifies the current AgentContext and selects the provider for the reasoning cycle.
- **VRAM governor:** detects active Altar-1 work and aggressively reduces external-tool concurrency and threading.
- **Activity leases:** expose Altar-1 request activity to the resource governor even when the serving backend does not provide compatible request statistics.

The models are reasoning components, not unrestricted command runners. Proposed actions still pass through BELTU scope, policy, approval, capability, evidence, and resource controls.

## Agent flow

```text
Authorized target
      |
      v
Persistent scan state
      |
      v
Observe -> Context Build -> Hypothesize -> Plan
      |                              |
      |                              v
      |                       Multi-Model Router
      |                         /           \
      v                        v             v
Evidence / Graph       Standard Local    Altar-1 Local
      |                        |              |
      +------------------------+--------------+
                               |
                               v
                     Structured reasoning result
                               |
                       Scope / Policy / Approval
                               |
                               v
                        Capability execution
                               |
                               v
                       Evidence -> Findings
                               |
                               v
                          Re-evaluate
```

## Routing

The router is deterministic and context-driven.

**Standard route**
- reconnaissance
- asset/service mapping
- endpoint discovery
- normal tool output
- generic scan-cycle reasoning

**Altar-1 route**
- source/code review
- static security analysis
- exploit-proof / proof-of-concept / reproduction analysis
- authorization/access-control/permission matrix anomaly verification

For specialized requests BELTU selects a profile that can adjust temperature, token budget, and `top_p` without changing the serving node.

## Resource protection

While an Altar-1 request is active, BELTU:
- clamps managed tool thread limits to 1
- clamps managed external-tool parallelism to the configured minimum
- can restrict managed child processes to one CPU where Linux affinity is available
- records Altar-1 activity and GPU-memory telemetry where the relevant process information is available

## Altar-1 deployment

Aikido announced Altar on September 21, 2026 as an open-weight security model for sovereign/on-prem security intelligence. The public model card describes the 504B-parameter pruned model at about 328 GB INT4/W4A16 and documents vLLM/SGLang serving on 4× NVIDIA H200.

Model card:
https://huggingface.co/AikidoSec/altar-1

Announcement:
https://www.aikido.dev/blog/aikido-altar-open-weight-ai-sovereign-security

BELTU keeps Altar-1 disabled by default and loopback-only when enabled.

## Configuration

Default:

```yaml
brain:
  llm_enabled: true
  llm:
    provider: freetoken_local
    base_url: http://127.0.0.1:8000/v1
    model: auto
    local_only: true
    routing:
      enabled: true
    altar1:
      enabled: false
      base_url: http://127.0.0.1:8001/v1
      model: aikido/altar-1
      local_only: true
```

Enable only after the local specialist node is available:

```yaml
brain:
  llm:
    altar1:
      enabled: true
```

There is no cloud fallback for Altar-1. Normal deterministic heuristic fallback remains available when configured.

## Running

Standard local engine:

```bash
scripts/start_local_ai.sh
```

Altar-1 specialist:

```bash
scripts/start_altar1.sh
```

Stop:

```bash
scripts/stop_altar1.sh
```

Inspect:

```bash
beltu llm
beltu resources
beltu doctor --strict
```

## Mobile Command Center

The Flutter client connects to the authenticated BELTU Remote Operations gateway and exposes dashboard, agent chat, approvals, activity, files, and reports.

```bash
cd mobile
flutter pub get
flutter run --dart-define=BELTU_BASE_URL=http://10.0.2.2:8765
```

## Safety

Run BELTU only against targets you own or are explicitly authorized to assess. Defaults include:
- default-deny scope
- approval-gated high-risk actions
- external tools disabled until explicitly enabled
- loopback-only local inference
- authenticated loopback remote operations
- runtime secrets, evidence, databases, and model weights excluded from Git

## Version

**1.2.0**
