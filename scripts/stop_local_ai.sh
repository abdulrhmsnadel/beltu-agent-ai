#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$BASH_SOURCE")/.." && pwd)"
PID_FILE="$ROOT/data/runtime/freetoken.pid"
FT_DIR="${BELTU_FREETOKEN_DIR:-$HOME/.local/share/beltu/freetoken}"
FT_VENV="${BELTU_FREETOKEN_VENV:-$FT_DIR/.venv}"
FT_BIN="$FT_VENV/bin/ft"

if [[ ! -f "$PID_FILE" ]]; then
  echo "FreeToken PID file not found."
  exit 0
fi

PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [[ ! "$PID" =~ ^[1-9][0-9]*$ ]]; then
  rm -f "$PID_FILE"
  echo "FreeToken PID file was invalid; removed stale file."
  exit 0
fi

if ! kill -0 "$PID" 2>/dev/null; then
  rm -f "$PID_FILE"
  echo "FreeToken PID was stale; removed stale file."
  exit 0
fi

CMDLINE="$(tr "\0" " " < "/proc/$PID/cmdline" 2>/dev/null || true)"
if [[ "$CMDLINE" != *"$FT_BIN"* && "$CMDLINE" != *" ft "* && "$CMDLINE" != ft* ]]; then
  rm -f "$PID_FILE"
  echo "FreeToken PID did not belong to the expected ft process; no signal sent." >&2
  exit 4
fi

kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID" 2>/dev/null || true
for _ in {1..120}; do
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.5
done

if kill -0 "$PID" 2>/dev/null; then
  kill -KILL -- "-$PID" 2>/dev/null || kill -KILL "$PID" 2>/dev/null || true
  for _ in {1..20}; do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.25
  done
fi

if kill -0 "$PID" 2>/dev/null; then
  echo "FreeToken process is still running; PID file retained for manual recovery." >&2
  exit 5
fi

rm -f "$PID_FILE"
echo "FreeToken stopped."
