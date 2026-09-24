#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$BASH_SOURCE")/.." && pwd)"
ENV_FILE="$ROOT/data/runtime/freetoken.env"
if [[ -f "$ENV_FILE" ]]; then
  # This file is created with mode 600 by install_local_ai.sh.
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

FT_DIR="${BELTU_FREETOKEN_DIR:-$HOME/.local/share/beltu/freetoken}"
FT_VENV="${BELTU_FREETOKEN_VENV:-$FT_DIR/.venv}"
MODEL_PATH="${BELTU_FREETOKEN_MODEL:-}"
PORT="${BELTU_FREETOKEN_PORT:-8000}"
HOST="${BELTU_FREETOKEN_HOST:-127.0.0.1}"
MEMORY_RATIO="${BELTU_FREETOKEN_MEMORY_RATIO:-0.45}"
MAX_REQUESTS="${BELTU_FREETOKEN_MAX_RUNNING_REQUESTS:-1}"
CUDA_DEVICES="${BELTU_FREETOKEN_CUDA_VISIBLE_DEVICES:-}"
MOE_BACKEND="${BELTU_FREETOKEN_MOE_BACKEND:-auto}"
PID_FILE="$ROOT/data/runtime/freetoken.pid"
LOG_FILE="$ROOT/data/runtime/freetoken.log"

[[ -x "$FT_VENV/bin/ft" ]] || { echo "FreeToken is not installed. Run scripts/install_local_ai.sh first." >&2; exit 2; }
[[ -n "$MODEL_PATH" && -e "$MODEL_PATH" ]] || { echo "BELTU_FREETOKEN_MODEL must point to an existing local model directory or checkpoint file." >&2; exit 3; }

case "$HOST" in
  127.0.0.1|localhost|::1) ;;
  *) echo "Refusing non-loopback FreeToken host: $HOST" >&2; exit 4 ;;
esac

awk "BEGIN { exit !($MEMORY_RATIO > 0 && $MEMORY_RATIO <= 1) }" || { echo "BELTU_FREETOKEN_MEMORY_RATIO must be in (0,1]." >&2; exit 5; }

mkdir -p "$ROOT/data/runtime"
if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ "$PID" =~ ^[1-9][0-9]*$ ]] && kill -0 "$PID" 2>/dev/null; then
    CMDLINE="$(tr "\0" " " < "/proc/$PID/cmdline" 2>/dev/null || true)"
    if [[ "$CMDLINE" == *"$FT_VENV/bin/ft"* || "$CMDLINE" == *" ft "* || "$CMDLINE" == ft* ]]; then
      echo "FreeToken already running (pid $PID)."
      exit 0
    fi
  fi
  rm -f "$PID_FILE"
fi

if [[ -n "$CUDA_DEVICES" ]]; then
  export CUDA_VISIBLE_DEVICES="$CUDA_DEVICES"
fi

CMD=("$FT_VENV/bin/ft" serve --model "$MODEL_PATH" --host "$HOST" --port "$PORT" --moe-strategy "$MOE_BACKEND" --memory-ratio "$MEMORY_RATIO" --max-running-requests "$MAX_REQUESTS" --moe-cache-auto)

setsid nohup "${CMD[@]}" >>"$LOG_FILE" 2>&1 &
PID="$!"
echo "$PID" > "$PID_FILE"
chmod 600 "$PID_FILE"

ready=0
for _ in {1..60}; do
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "http://$HOST:$PORT/v1/models" >/dev/null 2>&1 && { ready=1; break; }
  else
    python3 - "$HOST" "$PORT" <<'PY' >/dev/null 2>&1 && { ready=1; break; }
import sys
from urllib.request import urlopen
host, port = sys.argv[1], sys.argv[2]
with urlopen(f"http://{host}:{port}/v1/models", timeout=1):
    pass
PY
  fi
  kill -0 "$PID" 2>/dev/null || break
  sleep 1
done

if [[ "$ready" != "1" ]]; then
  echo "FreeToken failed readiness check; inspect $LOG_FILE." >&2
  "$ROOT/scripts/stop_local_ai.sh" || true
  exit 6
fi

echo "FreeToken ready: http://$HOST:$PORT/v1"
echo "PID: $PID"
echo "Log: $LOG_FILE"
