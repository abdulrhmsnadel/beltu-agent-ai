#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FT_DIR="${BELTU_FREETOKEN_DIR:-$HOME/.local/share/beltu/freetoken}"
FT_VENV="${BELTU_FREETOKEN_VENV:-$FT_DIR/.venv}"
MODEL_PATH="${BELTU_FREETOKEN_MODEL:-}"
PORT="${BELTU_FREETOKEN_PORT:-8000}"
HOST="${BELTU_FREETOKEN_HOST:-127.0.0.1}"
MAX_REQUESTS="${BELTU_FREETOKEN_MAX_RUNNING_REQUESTS:-1}"
MOE_BACKEND="${BELTU_FREETOKEN_MOE_BACKEND:-auto}"
READY_TIMEOUT="${BELTU_FREETOKEN_READY_TIMEOUT:-30}"
PID_FILE="$ROOT/data/runtime/freetoken.pid"
LOG_FILE="$ROOT/data/runtime/freetoken.log"

[[ -x "$FT_VENV/bin/ft" ]] || { echo "FreeToken is not installed. Run scripts/install_local_ai.sh first." >&2; exit 2; }
[[ -n "$MODEL_PATH" ]] || { echo "BELTU_FREETOKEN_MODEL must point to an existing local model directory." >&2; exit 3; }
[[ -d "$MODEL_PATH" ]] || { echo "Model directory does not exist: $MODEL_PATH" >&2; exit 4; }

case "$HOST" in
  127.0.0.1|localhost|::1) ;;
  *) echo "FreeToken must bind to loopback only (127.0.0.1/localhost/::1)." >&2; exit 5 ;;
esac

pid_is_freetoken() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -F -- "$FT_VENV/bin/ft" >/dev/null
}

kill_group() {
  local pid="$1"
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  for _ in {1..150}; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  ! kill -0 "$pid" 2>/dev/null
}

mkdir -p "$ROOT/data/runtime"
if [[ -f "$PID_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if pid_is_freetoken "$OLD_PID"; then
    echo "FreeToken already running (pid $OLD_PID)."
    exit 0
  fi
  rm -f "$PID_FILE"
fi

CMD=("$FT_VENV/bin/ft" serve --model "$MODEL_PATH" --host "$HOST" --port "$PORT" --max-running-requests "$MAX_REQUESTS")
if [[ "$MOE_BACKEND" != "auto" ]]; then
  CMD+=(--moe-strategy "$MOE_BACKEND")
fi

umask 077
setsid nohup "${CMD[@]}" >>"$LOG_FILE" 2>&1 &
PID=$!
echo "$PID" >"$PID_FILE"
chmod 600 "$PID_FILE"

ready=0
for ((i=0; i<READY_TIMEOUT*5; i++)); do
  if curl -fsS --max-time 1 "http://$HOST:$PORT/v1/models" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! pid_is_freetoken "$PID"; then
    echo "FreeToken exited during startup. See $LOG_FILE" >&2
    rm -f "$PID_FILE"
    exit 6
  fi
  sleep 0.2
done

if (( ready )); then
  echo "FreeToken ready: http://$HOST:$PORT/v1"
else
  echo "FreeToken process started (pid $PID) but is not ready yet; check $LOG_FILE."
fi
echo "PID: $PID"
echo "Log: $LOG_FILE"
