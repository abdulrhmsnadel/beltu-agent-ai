# BELTU 1.3.0 — Three-Tier Multi-Model Security Agent

BELTU is a **local-first agentic security-testing platform** for explicitly authorized bug-bounty, lab, and red-team assessments. It keeps persistent scan state, builds context from observations and evidence, generates hypotheses, plans next actions, selects capabilities, applies scope/policy/approval/resource gates, executes allowlisted security tooling, correlates evidence, validates findings, and generates reports.

> **Authorized use only.** Run BELTU only against systems you own or have explicit permission to assess. Respect program scope, rate limits, terms, and applicable law.

---

## What BELTU actually does

BELTU is built as a closed feedback loop rather than a fixed scanner pipeline:

```text
Target
  ↓
Scope validation
  ↓
Persistent scan state
  ↓
Observe
  ↓
Build context
  ↓
Hypotheses
  ↓
Reasoning
  ↓
Plan
  ↓
Policy / Approval / Resource gates
  ↓
Capability execution
  ↓
Evidence collection
  ↓
Finding correlation / validation
  ↓
Re-evaluate
  ↓
Re-plan
```

The language model is a **reasoning component**, not an unrestricted shell runner. The model can propose structured hypotheses and actions, but BELTU's scope, policy, approval, capability, and resource layers decide whether an action is allowed to execute.

---

# Installation

## 1. Supported environment

BELTU's core runtime is intended for:

- Kali Linux
- Ubuntu
- Other Linux environments with Python 3.11+

Required base tools:

- Python 3.11+
- Git
- pip / venv
- curl
- unzip

Optional security tools are installed separately when you enable the corresponding capabilities.

---

## 2. Clone BELTU

```bash
git clone https://github.com/abdulrhmsnadel/beltu-agent-ai.git
cd beltu-agent-ai
```

Prebuilt source archives are versioned separately from the Git checkout. For the current GitHub source, use the clone instructions above.

---

## 3. Create the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m ensurepip --upgrade
python -m pip install --upgrade pip setuptools wheel
```

---

## 4. Install BELTU

Recommended editable install for development:

```bash
python -m pip install -e .
```

For an environment where you already installed the required dependencies and want to avoid build isolation/network resolution:

```bash
python -m pip install -e . --no-deps --no-build-isolation
```

Check the CLI:

```bash
beltu --help
beltu status
```

You should see BELTU 1.3.0 in the status output after installation.

---

# First-time configuration

## 5. Run the security/installation audit

```bash
beltu doctor --strict
```

The release is intentionally controlled:

- scope is default-deny
- low-risk external tools may execute autonomously when enabled
- medium/high-risk active testing remains approval-gated
- local inference is loopback-only
- remote operations bind to loopback by default
- secrets, runtime databases, evidence, and model weights are not meant to be committed

Fix any FAIL reported by `doctor --strict` before a real engagement.

---

## 6. Configure the target scope

Edit:

```text
config/scope.yaml
```

Example:

```yaml
targets:
  - your-authorized-domain.example
```

Only place domains/assets that you are explicitly authorized to assess in this file.

You can validate/register a target with:

```bash
beltu target your-authorized-domain.example
```

---

## 7. Configure execution

BELTU 1.3.0 supports autonomous execution for registered low-risk adapters:

```yaml
execution:
  external_tools_enabled: true
```

This does **not** turn BELTU into an unrestricted shell agent. The execution path is:

```text
LLM / planner
    ↓
scope
    ↓
policy
    ↓
approval gate
    ↓
capability registry
    ↓
resource governor
    ↓
allowlisted adapter
    ↓
bounded worker
```

Passive discovery adapters can run autonomously inside the explicit scope. Active HTTP, browser, session, authorization, business-logic, API-manipulation, and race-condition workflows require an approved decision.

---

# Gemini Cloud Co-Pilot

BELTU 1.3.0 adds Gemini as a **cloud advisory co-pilot** beside the standard local operator and optional Altar-1 reviewer.

The roles are deliberately separate:

```text
Local :8000
  primary operator
  owns final reasoning
        │
        ├──► Gemini Cloud
        │      observes sanitized state
        │      diagnoses mistakes
        │      suggests next evidence/capability
        │
        └──► Altar-1 :8001
               deep local security review
               
Gemini never executes BELTU tools.
The local operator is the only component that turns advice into execution.
```

Gemini can receive a minimized snapshot containing:

- current scan/target state
- sanitized tool observations
- asset and endpoint summaries
- API/auth/authorization/workflow metadata
- current hypotheses
- the Local operator's structured draft: summary, hypotheses, action kinds, capability/tool names, rationale, risk and evidence references

Gemini is asked specifically to return:

```text
continue
retry
correct
escalate_to_deep_review
stop_escalation
observe
```

plus a reason, focus, confidence, and an optional recommended capability.

The Local operator then performs a **final local reasoning pass** using that advisory. The recommendation is not executed directly.

## Cloud privacy boundary

Before every Gemini request, BELTU applies a local scrubber that redacts common:

```text
Authorization
Cookie / Set-Cookie
passwords
API keys
client secrets
access/refresh tokens
JWTs
session identifiers
private keys
credentials
```

Final reports, confirmed exploit payloads, PoC code, credentials, and session secrets are excluded from the cloud-visible context.

The scrubber runs **before** the Gemini rate-limit slot is consumed and before the HTTP request is created.

## Gemini fallback

Gemini is not a runtime dependency for the agent loop.

```text
Gemini OK
   ↓
advice
   ↓
Local final pass

Gemini 429 / quota / safety block / timeout / network failure
   ↓
advice omitted
   ↓
Local operator continues
```

The cloud failure is recorded in the router trace; it does not crash the TaskQueue or Orchestrator.

## Gemini configuration

Never place the Gemini key in `config/agent.yaml` or source code.

Set it in the environment:

```bash
export GEMINI_API_KEY="YOUR_KEY"
```

Then configure only the environment-variable name:

```yaml
gemini:
  enabled: true
  api_key_env: GEMINI_API_KEY
  model: gemini-3.8-flash
  requests_per_minute: 15
  fallback_to_standard: true
```

The `15 RPM` value is a conservative BELTU-local limiter. Gemini's actual quota is project/model/tier dependent and should be checked in Google AI Studio.

---

# Basic usage

## A. Register a target

```bash
beltu target your-authorized-domain.example
```

This validates the target against the configured scope and stores it in BELTU's persistent state.

---

## B. Start an autonomous hunt

```bash
beltu hunt your-authorized-domain.example

# Validate scope, DB and local AI readiness without creating a scan
beltu hunt your-authorized-domain.example --check
```

A hunt creates/continues persistent scan state and lets the agent reason over observations, hypotheses, capabilities, and previous scan state.

Use only an explicitly authorized target.

---

## C. Inspect the agent

```bash
beltu status
beltu resources
beltu llm
beltu tools --check
beltu coverage
```

These show the current scan state, resource pressure, local model state, and registered tools.

---

# How the agent works during a hunt

A typical reasoning cycle is:

### 1. Observe

BELTU receives output/observations from enabled capabilities and stored intelligence.

Examples:

```text
Asset discovered
HTTP service detected
Endpoint discovered
API relation identified
Authentication boundary observed
Authorization anomaly observed
Business workflow state observed
```

### 2. Build context

The Context Builder combines current observations with persistent state, hypotheses, attack-surface intelligence, API intelligence, authentication data, authorization data, business-logic data, and existing findings.

### 3. Generate hypotheses

The reasoning layer asks:

```text
What is known?
What is uncertain?
What evidence is missing?
What capability can reduce that uncertainty?
What should be tested next?
```

### 4. Select the next capability

The Capability Registry and Intelligent Capability Selector turn the reasoning result into a candidate structured action.

The action still has to pass:

```text
Scope
 ↓
Policy
 ↓
Approval (when required)
 ↓
Resource Governor
 ↓
Execution
```

### 5. Execute and capture evidence

BELTU records tool output, process state, timing, return codes, observations, and evidence references.

### 6. Re-evaluate

The feedback loop uses the new observations to update hypotheses and generate the next reasoning cycle instead of blindly following a fixed list of steps.

---

# Multi-model brain — v1.3.0

BELTU 1.3.0 adds a deterministic **Multi-Model LLM Router**.

```text
                    AgentContext
                         ↓
                  Dynamic LLM Router
                     /         \
                    /           \
                   ↓             ↓
          Standard local      Altar-1 local
             :8000/v1            :8001/v1
```

## Standard local operator — :8000

The standard local model remains the primary operator. Gemini observes its sanitized state and can advise; the local operator decides and executes.

## Standard local model

The standard local model handles general reasoning such as:

- reconnaissance
- asset/service mapping
- endpoint discovery
- ordinary tool-output parsing
- general scan-cycle reasoning

## Altar-1 local specialist

When enabled, Altar-1 is selected for specialized contexts such as:

- source-code review
- static security analysis
- exploit-proof / reproduction analysis
- authorization/access-control/permission matrix anomaly verification

The router also selects a per-task request profile so decoding parameters can change without changing the model node.

## Important: Altar-1 is optional

The public Altar-1 model is extremely large. Its model card describes a 504B-parameter pruned model at about **328 GB INT4/W4A16**, with a documented vLLM configuration using **4× NVIDIA H200**.

For that reason:

- Altar-1 is disabled by default.
- BELTU does not automatically download its weights.
- The provider is loopback-only when local-only mode is enabled.
- A machine that cannot actually host the checkpoint should not be configured as an Altar-1 node.

Official model card:

https://huggingface.co/AikidoSec/altar-1

---

# Local standard model — FreeToken

BELTU can use a local FreeToken-compatible inference service.

The project configuration expects:

```text
http://127.0.0.1:8000/v1
```

Install the local FreeToken environment with:

```bash
scripts/install_local_ai.sh
```

That script prepares the FreeToken checkout/virtual environment but does **not** download a model for you.

Point BELTU to a local model directory:

```bash
export BELTU_FREETOKEN_MODEL=/absolute/path/to/local/model
```

Then start it:

```bash
scripts/start_local_ai.sh
```

Verify the local service:

```bash
curl http://127.0.0.1:8000/v1/models
```

Inspect BELTU's view of the provider:

```bash
beltu llm
```

The standard provider stays local; BELTU's default configuration does not require an OpenAI/Claude/Gemini API key.

---

# Altar-1 setup

Altar-1 is a separate local specialist node.

Default configuration:

```yaml
brain:
  llm:
    routing:
      enabled: true
    altar1:
      enabled: false
      base_url: http://127.0.0.1:8001/v1
      model: aikido/altar-1
      local_only: true
```

Enable it only after the actual local Altar-1 server is available:

```yaml
brain:
  llm:
    altar1:
      enabled: true
```

Then:

```bash
scripts/start_altar1.sh
```

Stop it with:

```bash
scripts/stop_altar1.sh
```

The included launcher is a local orchestration helper; you still need the Altar-1 serving stack and model weights on the machine. The public model card documents:

```bash
vllm serve aikido/altar-1 --tensor-parallel-size 4 --trust-remote-code --max-model-len 131072
```

citeturn710406search0

---

# VRAM protection

When an Altar-1 request is active, the Resource Governor aggressively reduces the amount of concurrent external work.

```text
Altar-1 ACTIVE
     ↓
Tool thread limit = 1
     ↓
Parallel external processes = minimum
     ↓
Managed child CPU affinity = one CPU when available
```

BELTU also tracks an activity lease under:

```text
data/runtime/altar1.active/
```

This lets the governor detect active specialist work even if the serving backend does not expose compatible request telemetry.

NVIDIA telemetry is used when `nvidia-smi` is available.

---

# Interactive tool execution — v1.2.0

The Tool Execution Layer now contains real bounded workers instead of only reconnaissance adapters.

| Capability | Adapter | Behavior |
|---|---|---|
| Browser automation | `browser` | Playwright-based UI steps: goto/click/fill/press/wait/extract/screenshot; no arbitrary JavaScript |
| Burp-style HTTP workflows | `http-workflow` | Bounded request sequences, variables, response assertions and replay |
| Session replay | `session-replay` | Replays workflows with a local session profile; raw secrets are not copied into observations |
| API manipulation | `api-manipulation` | Bounded query/header/JSON mutations against an identified operation |
| Authorization testing | `authorization-matrix` | Compare explicitly supplied principals on the same operation |
| Business-logic workflows | `business-logic` | Ordered state-aware HTTP steps with assertions |
| Race-condition testing | `race-condition` | Bounded concurrent requests, maximum 20 requests / 8 workers |

All active capabilities are approval-gated. Worker request counts, concurrency, payload size, response size, URL scope, and browser steps are bounded in code.

## Session profiles

Session material is stored only under:

```text
data/runtime/sessions/
```

A simple HTTP session profile can look like:

```json
{
  "headers": {
    "Authorization": "Bearer <local-secret>"
  },
  "cookies": [
    {
      "name": "session",
      "value": "<local-secret>"
    }
  ]
}
```

Use only local profiles you created for the authorized engagement. BELTU redacts common authorization/cookie/token patterns before observations are persisted.

The browser worker can also save a Playwright storage-state profile with `save_session`, which can then be consumed by the session replay workflow.

## Interactive execution examples

The agent/LLM can create declarative payloads such as:

```json
{
  "target": "target.example",
  "requests": [
    {
      "method": "GET",
      "url": "https://target.example/account",
      "assert": {"status": 200}
    },
    {
      "method": "POST",
      "url": "https://target.example/orders",
      "json_body": {"item_id": "{{item_id}}"},
      "extract": {"item_id": {"json_path": "id"}}
    }
  ]
}
```

API mutation payloads use:

```json
{
  "request": {
    "method": "POST",
    "url": "https://target.example/orders",
    "json_body": {"quantity": 1}
  },
  "mutations": [
    {"location": "json", "name": "quantity", "value": 0},
    {"location": "json", "name": "quantity", "value": 2}
  ]
}
```

Race testing is intentionally narrow:

```json
{
  "request": {
    "method": "POST",
    "url": "https://target.example/orders/1/claim",
    "json_body": {"confirm": true}
  },
  "count": 6,
  "concurrency": 6
}
```

The LLM proposes these structures; the control plane still decides whether execution is allowed.

# Tooling

The core package does not require every security tool just to start BELTU.

Registered capability adapters currently include:

| Tool | Main capability |
|---|---|
| Subfinder | passive subdomain discovery |
| Assetfinder | passive asset discovery |
| Amass | passive asset/DNS enrichment |
| HTTPX | HTTP service verification |
| Nmap | service discovery |
| Nuclei | template-based candidate detection |
| Browser | bounded Playwright UI automation |
| HTTP Workflow | bounded request/replay sequences |
| Session Replay | local-profile session replay |
| API Manipulation | bounded parameter mutations |
| Authorization Matrix | interactive principal comparison |
| Business Logic | bounded workflow/state execution |
| Race Condition | bounded concurrent request testing |

Install only the tools you need and keep them within the scope of your authorized engagement.

For example, on Kali/Debian-based systems:

```bash
sudo apt update
sudo apt install -y nmap
```

For ProjectDiscovery and other third-party tools, use their official installation instructions so you receive the correct current binary for your platform.

---

# Useful CLI commands

## Target and scan lifecycle

```bash
beltu target <domain>
beltu targets
beltu hunt <domain>

beltu list
beltu start <target-id>
beltu think <scan-id>
beltu observe <scan-id> --kind <kind> --subject <subject>
beltu replan <scan-id>
beltu cycles <scan-id>
beltu evidence <scan-id>
```

## Findings and validation

```bash
beltu findings <scan-id>
beltu finding-validation <scan-id>
beltu finding-context <scan-id>
```

## Intelligence

```bash
beltu asset-inventory <scan-id>
beltu asset-graph <scan-id>
beltu surface-rank <scan-id>
beltu surface <scan-id>

beltu api-inventory <scan-id>
beltu api-relations <scan-id>
beltu api-context <scan-id>

beltu auth-inventory <scan-id>
beltu auth-boundaries <scan-id>
beltu auth-context <scan-id>

beltu authz-inventory <scan-id>
beltu authz-anomalies <scan-id>
beltu authz-context <scan-id>

beltu business-workflows <scan-id>
beltu business-anomalies <scan-id>
beltu business-context <scan-id>
```

## Capability and decision state

```bash
beltu capability-rank <scan-id>
beltu capability-history <scan-id>
beltu observation-links <scan-id>
beltu decision-execute <decision-id>
```

## Reports

```bash
beltu report <scan-id>
beltu report-list <scan-id>
```

## Approvals

Approval commands are nested under `beltu approval`:

```bash
beltu approval request <decision-id>
beltu approval list
beltu approval approve <approval-id> --token <token>
beltu approval reject <approval-id> --token <token>
```

Optional request parameters:

```bash
beltu approval request <decision-id> --channel cli --ttl 600
```

Use the exact subcommand help for argument details:

```bash
beltu --help
beltu <command> --help
```

---

# Authentication / approvals

High-risk actions require a validated approval record.

This means the LLM or planner cannot directly bypass the approval system.

The control flow is:

```text
Reasoning result
      ↓
Structured decision
      ↓
Approval service
      ↓
Capability dispatcher
      ↓
Resource governor
      ↓
Execution
```

Use:

```bash
beltu approval --help
```

to inspect approval commands in your installed build.

---

# Remote operations

BELTU includes an authenticated Remote Operations gateway for the mobile command center and remote control integrations.

By default it is designed for loopback operation.

Set credentials locally in your shell — do **not** put them in Git:

```bash
export BELTU_REMOTE_USER="your-local-username"

read -s BELTU_REMOTE_PASSWORD
export BELTU_REMOTE_PASSWORD

export BELTU_REMOTE_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

Then validate the configuration:

```bash
beltu remote-doctor
```

Start the gateway:

```bash
beltu remote
```

The gateway listens on the configured local address/port. Do not expose it to the public internet without deliberately designing and securing the deployment.

---

# Mobile Command Center

The mobile application is a Flutter client for the BELTU Remote Operations API.

It is a control surface, not the security engine itself.

```text
Android / iOS client
        ↓
Authenticated Remote Gateway
        ↓
BELTU Agent
        ↓
Brain / Execution / Evidence / Reports
```

## Build on Android

Requirements:

- Flutter SDK
- Android Studio
- Android SDK
- adb
- Android device or emulator

From the repository:

```bash
cd mobile

# The repository stores the Flutter/Dart source. If Android/iOS platform
# folders are not present yet, generate them once with Flutter:
flutter create .

flutter pub get
```

For an Android emulator using a host-side BELTU gateway:

```bash
flutter run --dart-define=BELTU_BASE_URL=http://10.0.2.2:8765
```

For a physical Android device connected over USB, you can use ADB reverse port forwarding after the gateway is running:

```bash
adb reverse tcp:8765 tcp:8765
flutter run --dart-define=BELTU_BASE_URL=http://127.0.0.1:8765
```

---

# Workspace and stored state

BELTU keeps runtime artifacts in the project data tree.

Important locations include:

```text
data/
├── beltu.db
├── evidence/
└── runtime/
    ├── freetoken.pid
    ├── freetoken.log
    └── altar1.active/
```

Do not commit:
- credentials
- access tokens
- model weights
- runtime databases
- evidence from private engagements
- generated reports containing sensitive data

The repository includes Git ignore rules for runtime material.

---

# Typical operator workflow

For a normal authorized engagement:

### Phase 1 — Prepare

```bash
cd beltu-agent-ai
source .venv/bin/activate
beltu doctor --strict
```

### Phase 2 — Scope

Edit `config/scope.yaml` and add only the authorized target. BELTU is default-deny: a target is rejected until it is explicitly in this file.

### Phase 3 — Register

```bash
beltu target target.example
```

### Phase 4 — Start reasoning

```bash
beltu hunt target.example
```

### Phase 5 — Monitor

```bash
beltu status
beltu resources
beltu llm
```

### Phase 6 — Inspect intelligence

Use the asset/API/auth/authz/business-logic commands for the scan ID shown by BELTU.

### Phase 7 — Validate

Inspect findings and run the applicable validation workflow. High-risk execution remains approval-gated.

### Phase 8 — Report

```bash
beltu report <scan-id>
beltu report-list <scan-id>
```

---

# Troubleshooting

## `beltu: command not found`

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Or verify the editable install:

```bash
python -m pip show beltu
```

---

## `FreeToken is unreachable`

Check:

```bash
beltu llm
curl http://127.0.0.1:8000/v1/models
```

Then start:

```bash
scripts/start_local_ai.sh
```

---

## `Altar-1 is unreachable`

Check:

```bash
curl http://127.0.0.1:8001/v1/models
```

Make sure the Altar-1 server is actually running and that:

```yaml
brain:
  llm:
    altar1:
      enabled: true
```

matches the running configuration.

---

## Remote gateway says authentication is not configured

Set the credentials in the same shell that starts the gateway:

```bash
export BELTU_REMOTE_USER="your-local-username"
read -s BELTU_REMOTE_PASSWORD
export BELTU_REMOTE_PASSWORD
export BELTU_REMOTE_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

beltu remote-doctor
beltu remote
```

---

## Doctor reports Git/runtime issues

Run:

```bash
beltu doctor --strict
```

Fix the specific FAIL entries rather than bypassing the audit.

---

# Development and tests

Run the complete Python test suite from the repository root:

```bash
source .venv/bin/activate
python -m pytest -q
```

Run Python syntax compilation:

```bash
python -m compileall -q src
```

The multi-model coverage is under:

```text
tests/stage22/test_stage22_multi_model.py
```

---

# Repository structure

```text
beltu-agent-ai/
├── config/
│   ├── agent.yaml
│   ├── scope.yaml
│   └── tools.yaml
├── docs/
├── mobile/
├── prompts/
├── scripts/
│   ├── install.sh
│   ├── install_local_ai.sh
│   ├── start_local_ai.sh
│   ├── start_altar1.sh
│   ├── stop_altar1.sh
│   └── release.sh
├── src/
│   └── beltu/
│       ├── brain/
│       ├── control/
│       ├── execution/
│       ├── interface/
│       ├── integrations/
│       ├── reporting/
│       └── storage/
└── tests/
```

---

# Security model

BELTU's architectural security boundary is:

```text
LLM
 ↓
Structured reasoning
 ↓
Scope guard
 ↓
Policy
 ↓
Approval gate
 ↓
Capability registry
 ↓
Resource governor
 ↓
Process execution
 ↓
Evidence
```

The model is never the sole authority for execution.

---

# Version

**BELTU 1.3.0**

Standalone successor to the legacy `beltu-agent` repository.
