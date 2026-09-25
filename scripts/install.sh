#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  PYTHON_BIN="$(command -v python)"
elif [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
else
  python3 -m venv .venv
  PYTHON_BIN=".venv/bin/python"
fi

"$PYTHON_BIN" -m pip install -e .
"$PYTHON_BIN" -m compileall -q src
"$PYTHON_BIN" -m pip check
"$PYTHON_BIN" -c 'from beltu.release.audit import run_audit; checks=run_audit(); raise SystemExit(2 if any(not c.ok for c in checks) else 0)'

if [[ "${BELTU_INSTALL_LOCAL_AI:-0}" == "1" ]]; then
  scripts/install_local_ai.sh
fi
printf "BELTU installed in %s. Activate with: source .venv/bin/activate\n" "$PYTHON_BIN"
