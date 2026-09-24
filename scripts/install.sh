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
.venv/bin/beltu doctor --strict

if [[ "${BELTU_INSTALL_LOCAL_AI:-0}" == "1" ]]; then
  scripts/install_local_ai.sh
fi
printf "BELTU installed in %s. Activate with: source .venv/bin/activate\n" "$PYTHON_BIN"
