# BELTU 1.1.0

BELTU is a local-first agentic security-testing platform for **explicitly authorized** assessments. It keeps the reasoning loop, persistent state, evidence, reporting, scope controls, approval gates, and tool execution in separate layers so the system can reason over evidence without turning the language model into an unrestricted command runner.

The 1.1.0 upgrade adds a **local FreeToken inference path** and a product-style mobile Command Center. FreeToken is an edge-native MoE serving engine with OpenAI-compatible APIs and CPU/GPU/host-memory execution strategies. Its documented server command is `ft serve`; the current CLI defaults to port 1919, while BELTU deliberately runs its local instance on `127.0.0.1:8000` to keep the BELTU/FreeToken contract isolated.

## What BELTU does

```text
Authorized Target
      ↓
Persistent Scan State
      ↓
Observe → Hypothesize → Plan → Policy → Act
      ↓
Evidence + Correlation
      ↓
Re-evaluate / Re-plan
      ↓
Findings + Reports
```

BELTU's LLM is a **reasoning component**, not a shell. The model returns structured hypotheses and declarative actions; the scope guard, approval system, capability registry, resource governor, and execution layer decide whether anything can actually run.

## Safety defaults

- Targets are default-deny and must be explicitly present in `config/scope.yaml`.
- High-risk actions require a validated approval record.
- External tools remain policy-controlled and are **disabled by default** in the repository configuration.
- FreeToken reasoning is loopback-only; BELTU rejects a non-loopback FreeToken base URL.
- Remote API binds to `127.0.0.1` by default and requires authentication.
- Runtime databases, evidence, tokens, model weights, and `.env` files are not meant to be committed to Git.

## Requirements

### BELTU

- Linux (Kali/Ubuntu recommended)
- Python 3.11+
- Git
- `venv` support
- The Python dependencies declared in `pyproject.toml`

### Security tools

Install the tools that match the capabilities you intend to enable:

| Tool | Capability | Purpose |
|---|---|---|
| Subfinder | `asset.discovery.subdomains` | passive subdomain discovery |
| Assetfinder | `asset.discovery.subdomains` | passive asset discovery |
| Amass | `asset.discovery.subdomains` | passive DNS/asset enrichment |
| Httpx | `web.verify` | HTTP service verification |
| Nmap | `service.discovery` | service discovery |
| Nuclei | `web.vulnerability_detection` | template-based candidate detection |

BELTU never needs every tool present for the CLI, database, reasoning, reporting, or mobile gateway to start.

### FreeToken

The current official FreeToken documentation lists Linux x86_64, an NVIDIA GPU/driver stack, CUDA 13, and Python >=3.10 as the supported environment for its accelerated path. It recommends `uv` and documents `ft serve --model <path-or-hf-id>` plus OpenAI-compatible `/v1/*` APIs.

On older CPU-only hardware, BELTU can still run with the heuristic fallback, but the local FreeToken engine itself may not be practical. Do not assume a large MoE checkpoint will fit your machine merely because it is supported by the engine.

## Installation

### 1. Enter the checked-out BELTU repository

```bash
cd ~/BELTU
```

### 2. Create the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m ensurepip --upgrade
python -m pip install -U pip setuptools wheel
python -m pip install -e . --no-build-isolation
```

### 3. Install BELTU through the project installer

```bash
scripts/install.sh
```

This runs the editable package installation and the strict static release audit.

### 4. Run the local safety checks

```bash
beltu doctor --strict
beltu status
```

### 5. Configure scope

Edit:

```text
config/scope.yaml
```

and add **only targets you are authorized to test**.

### 6. Install FreeToken

The deployment script clones the official FreeToken repository and creates a separate local environment so FreeToken dependencies do not pollute the BELTU environment.

```bash
chmod +x scripts/install_local_ai.sh scripts/start_local_ai.sh scripts/stop_local_ai.sh
scripts/install_local_ai.sh
```

The script expects a local model path before starting the server:

```bash
export BELTU_FREETOKEN_MODEL=/absolute/path/to/your/local/model
scripts/install_local_ai.sh
scripts/start_local_ai.sh
```

BELTU intentionally passes a **local filesystem model path** to FreeToken. For a truly air-gapped runtime, preload the FreeToken source and model weights before disconnecting the machine; do not give BELTU a remote Hugging Face model id at runtime. FreeToken's `ft serve` can also load FTW checkpoints directly.

The FreeToken documentation describes MoE backends including `offload`, `cpu`, `hybrid`, and `auto`; `auto` may use a cached bandwidth profile to choose an execution strategy.

### 7. Verify FreeToken

```bash
curl http://127.0.0.1:8000/v1/models
beltu llm
beltu resources
```

If the FreeToken server is up and serving a local model, `beltu llm` should report `freetoken_local` and a loopback endpoint.

The one-command installer can also run the local-AI setup after BELTU installation:

```bash
BELTU_INSTALL_LOCAL_AI=1 scripts/install.sh
```

## CLI reference

| Command | Use | Example |
|---|---|---|
| `beltu target <domain>` | validate scope and register a target | `beltu target example.com` |
| `beltu targets` | list registered targets | `beltu targets` |
| `beltu hunt <domain>` | start the persistent BELTU reasoning lifecycle | `beltu hunt example.com` |
| `beltu status` | show scans, resources, policy and local-AI state | `beltu status` |
| `beltu resources` | show CPU/RAM/GPU/FreeToken telemetry and tool limits | `beltu resources` |
| `beltu llm` | show local reasoning configuration | `beltu llm` |
| `beltu tools` | show registered tool adapters and approval metadata | `beltu tools` |
| `beltu remote` | start the authenticated Mobile Command Center gateway | `beltu remote` |
| `beltu remote-doctor` | validate remote environment variables | `beltu remote-doctor` |
| `beltu doctor --strict` | run static release/security checks | `beltu doctor --strict` |
| `beltu scan ...` | advanced scan lifecycle commands | `beltu scan --help` |
| `beltu report <scan-id>` | generate report packages | `beltu report 1` |
| `beltu findings <scan-id>` | show finding candidates | `beltu findings 1` |
| `beltu approval ...` | inspect/resolve persistent approvals | `beltu approval --help` |

The legacy administration commands remain under `beltu target-admin ...` for compatibility with older local workflows.

## Local AI architecture

```text
BELTU Brain
    ↓
FreeTokenLocalProvider
    ↓  loopback only
127.0.0.1:8000/v1/chat/completions
    ↓
FreeToken
 ┌───────────────┐
 │ MoE scheduler │
 │ GPU cache     │
 │ Host RAM      │
 │ CPU execution │
 └───────────────┘
```

BELTU reads the OpenAI-compatible streamed response from FreeToken, aggregates public `content` tokens, and sends the resulting structured JSON through the existing BELTU validator. The provider refuses non-loopback endpoints, so the reasoning path cannot silently fall back to a cloud API.

FreeToken exposes `ft ctl stats`/`GET /v1/stats`, model discovery through `/v1/models`, and OpenAI-compatible `/v1/chat/completions`.

## Resource governance

BELTU now samples:

- BELTU CPU and RSS
- host CPU/RAM pressure
- NVIDIA GPU VRAM and utilization when `nvidia-smi` is available
- FreeToken PID, CPU, RSS, VRAM, served model, and best-effort `/v1/stats` metadata

The governor converts that telemetry into per-tool concurrency limits. For tools that expose concurrency flags (for example Nuclei `-c`, Httpx/Subfinder `-t`, and Nmap parallelism controls), BELTU injects conservative values before process launch. During a run, the governor can also reduce CPU affinity for BELTU-managed child processes when host/VRAM pressure becomes critical. This is intentionally different from pretending that arbitrary third-party tools expose a safe API for changing their internal thread counts at runtime.

## Mobile Command Center

The Flutter client lives in `mobile/` and contains:

- Dashboard with CPU/RAM/GPU/FreeToken telemetry and active scans
- Agent Chat
- Approval queue with explicit Approve/Reject flow
- Live event stream over WebSocket
- Workspace file browser and Markdown/JSON/TXT preview
- Report packages with binary download to the app's private documents directory

Build/run examples:

```bash
cd mobile
flutter pub get
flutter run --dart-define=BELTU_BASE_URL=http://10.0.2.2:8765
```

Use `10.0.2.2` for an Android emulator talking to a host-local gateway. A physical phone needs a trusted reachable server address; never expose the gateway to the public internet without a proper TLS/authentication deployment.

## Remote gateway

Set secure environment variables before starting:

```bash
export BELTU_REMOTE_USER=beltu
export BELTU_REMOTE_PASSWORD='choose-a-strong-password'
export BELTU_REMOTE_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export BELTU_REMOTE_HOST=127.0.0.1
export BELTU_REMOTE_PORT=8765
```

Start:

```bash
beltu remote
```

Health:

```bash
curl http://127.0.0.1:8765/health
```

The app can then authenticate against `/v1/auth/login`, subscribe to `/v1/ws/events`, inspect resources, browse per-scan workspaces, and access reports.

## Workspace layout

Each scan keeps its artifacts under:

```text
data/targets/<target>/scan-<id>/
├── reports/
├── findings/
├── evidence/
├── data/
└── agent/
```

Reports are separated from agent activity, execution history, evidence, structured intelligence, and finding packages so an engagement can be reconstructed later instead of exposing only the final vulnerability report.

## Air-gap model

To run without cloud reasoning:

1. Install BELTU and FreeToken while the machine has connectivity.
2. Preload the FreeToken source and model weights locally.
3. Configure `BELTU_FREETOKEN_MODEL` with a filesystem path.
4. Start FreeToken on `127.0.0.1:8000`.
5. Disconnect the host from the network.
6. BELTU reasoning continues against the local FreeToken endpoint; if FreeToken is unavailable, BELTU can fall back to its deterministic heuristic engine rather than reaching for a cloud API.

FreeToken's documented OpenAI-compatible endpoint and local serving workflow make this architecture possible.

## Release notes

BELTU 1.1.0 keeps the 1.0.0 persistent-agent architecture and adds:

- local FreeToken provider and streamed-token handling
- loopback-only reasoning enforcement
- GPU/VRAM-aware resource telemetry
- adaptive tool concurrency/CPU-affinity governance
- simplified `target`, `hunt`, `remote`, and `status` workflow
- mobile Command Center screens
- report/file download API
- local AI install/start/stop scripts
