#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT/data/runtime/altar1.pid"
if [[ ! -f "$PID_FILE" ]]; then
  echo "Altar-1 is not running."
  exit 0
fi
PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [[ "$PID" =~ ^[0-9]+$ ]] && kill -0 "$PID" 2>/dev/null; then
  kill "$PID" || true
  for _ in {1..20}; do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.25
  done
fi
rm -f "$PID_FILE"
echo "Altar-1 stopped."