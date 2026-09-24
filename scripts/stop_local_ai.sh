#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FT_VENV="${BELTU_FREETOKEN_VENV:-$HOME/.local/share/beltu/freetoken/.venv}"
PID_FILE="$ROOT/data/runtime/freetoken.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "FreeToken is not running (PID file not found)."
  exit 0
fi

PID="$(cat "$PID_FILE" 2>/dev/null || true)"
valid_pid=false
if [[ "$PID" =~ ^[1-9][0-9]*$ ]] && kill -0 "$PID" 2>/dev/null && [[ -r "/proc/$PID/cmdline" ]]; then
  if tr '\0' ' ' <"/proc/$PID/cmdline" 2>/dev/null | grep -F -- "$FT_VENV/bin/ft" >/dev/null; then
    valid_pid=true
  fi
fi

if ! $valid_pid; then
  echo "FreeToken PID file is stale or does not belong to FreeToken; refusing to kill PID $PID."
  rm -f "$PID_FILE"
  exit 0
fi

kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID" 2>/dev/null || true
for _ in {1..150}; do
  kill -0 "$PID" 2>/dev/null || { rm -f "$PID_FILE"; echo "FreeToken stopped."; exit 0; }
  sleep 0.2
done
kill -KILL -- "-$PID" 2>/dev/null || kill -KILL "$PID" 2>/dev/null || true
rm -f "$PID_FILE"
echo "FreeToken stopped."
