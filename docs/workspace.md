# Workspace Layout

Each scan gets an isolated workspace:

```text
data/targets/<target>/scan-<id>/
├── reports/
├── findings/<finding-id>/
├── evidence/
├── data/
└── agent/
```

Reports are separated from agent reasoning, execution history, evidence, and structured intelligence. ZIP packages include hashes/manifests and can be audited against the report database.
