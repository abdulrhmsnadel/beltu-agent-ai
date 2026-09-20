#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FT_DIR="${BELTU_FREETOKEN_DIR:-$HOME/.local/share/beltu/freetoken}"
FT_VENV="${BELTU_FREETOKEN_VENV:-$FT_DIR/.venv}"
MODEL_PATH="${BELTU_FREETOKEN_MODEL:-}"
PORT="${BELTU_FREETOKEN_PORT:-8000}"
HOST="${BELTU_FREETOKEN_HOST:-127.0.0.1}"
MEMORY_RATIO="${BELTU_FREETOKEN_MEMORY_RATIO:-0.80}"
MAX_REQUESTS="${BELTU_FREETOKEN_MAX_RUNNING_REQUESTS:-1}"
MOE_BACKEND="${BELTU_FREETOKEN_MOE_BACKEND:-auto}"
PID_FILE="$ROOT/data/runtime/freetoken.pid"
LOG_FILE="$ROOT/data/runtime/freetoken.log"

[[ -x "$FT_VENV/bin/ft" ]] || { echo "FreeToken is not installed. Run scripts/install_local_ai.sh first." >&2; exit 2; }
[[ -n "$MODEL_PATH" ]] || { echo "BELTU_FREETOKEN_MODEL must point to an existing local model directory." >&2; exit 3; }
[[ -d "$MODEL_PATH" ]] || { echo "Model directory does not exist: $MODEL_PATH" >&2; exit 4; }

mkdir -p "$ROOT/data/runtime"
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; then
  echo "FreeToken already running (pid $(cat "$PID_FILE"))."
  exit 0
fi

CMD=("$FT_VENV/bin/ft" serve --model "$MODEL_PATH" --host "$HOST" --port "$PORT" --moe-strategy "$MOE_BACKEND" --memory-ratio "$MEMORY_RATIO" --max-running-requests "$MAX_REQUESTS" --moe-cache-auto)

nohup "${CMD[@]}" >>"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
chmod 600 "$PID_FILE"

echo "FreeToken started: http://$HOST:$PORT/v1"
echo "PID: $(cat "$PID_FILE")"
echo "Log: $LOG_FILE"
