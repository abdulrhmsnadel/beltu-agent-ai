#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT/data/runtime/freetoken.pid"
if [[ ! -f "$PID_FILE" ]]; then echo "FreeToken PID file not found."; exit 0; fi
PID="$(cat "$PID_FILE")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  for _ in {1..20}; do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.2
  done
fi
rm -f "$PID_FILE"
echo "FreeToken stopped."
