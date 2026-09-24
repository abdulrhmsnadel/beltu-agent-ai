#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$BASH_SOURCE")/.."

ROOT="$PWD"
VENV="$ROOT/.venv"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "[BELTU] Creating project virtual environment at $VENV"
  python3 -m venv "$VENV"
fi

"$VENV/bin/python" -m pip install -U pip setuptools wheel
"$VENV/bin/python" -m pip install -e .

if [[ "${BELTU_INSTALL_LOCAL_AI:-0}" == "1" ]]; then
  scripts/install_local_ai.sh
fi

"$VENV/bin/beltu" doctor --strict
printf "BELTU installed in %s\n" "$VENV"
