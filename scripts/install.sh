#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 -m pip install -e . --no-build-isolation
beltu doctor --strict
if [[ "${BELTU_INSTALL_LOCAL_AI:-0}" == "1" ]]; then
  scripts/install_local_ai.sh
fi
printf "BELTU installed.\n"
