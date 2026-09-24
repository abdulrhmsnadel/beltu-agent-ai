#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${BELTU_ALTAR1_VENV:-$HOME/.local/share/beltu/altar1/.venv}"
MODEL="${BELTU_ALTAR1_MODEL:-}"
HOST="${BELTU_ALTAR1_HOST:-127.0.0.1}"
PORT="${BELTU_ALTAR1_PORT:-8001}"
TENSOR_PARALLEL="${BELTU_ALTAR1_TENSOR_PARALLEL_SIZE:-4}"
MAX_MODEL_LEN="${BELTU_ALTAR1_MAX_MODEL_LEN:-131072}"
READY_TIMEOUT="${BELTU_ALTAR1_READY_TIMEOUT:-30}"
PID_FILE="$ROOT/data/runtime/altar1.pid"
LOG_FILE="$ROOT/data/runtime/altar1.log"

VLLM_BIN="$VENV_DIR/bin/vllm"
[[ -x "$VLLM_BIN" ]] || {
  echo "vLLM not found at $VLLM_BIN. Install vLLM in the Altar-1 serving environment first." >&2
  exit 2
}
[[ -n "$MODEL" && -d "$MODEL" ]] || {
  echo "BELTU_ALTAR1_MODEL must point to an existing local model directory; remote Hugging Face IDs are disabled." >&2
  exit 3
}

case "$HOST" in
  127.0.0.1|localhost|::1) ;;
  *) echo "Altar-1 must bind to loopback only (127.0.0.1/localhost/::1)." >&2; exit 4 ;;
esac

pid_is_altar() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -F -- "$VLLM_BIN" >/dev/null
}

mkdir -p "$ROOT/data/runtime"
if [[ -f "$PID_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if pid_is_altar "$OLD_PID"; then
    echo "Altar-1 already running (pid $OLD_PID)."
    exit 0
  fi
  rm -f "$PID_FILE"
fi

CMD=(
  "$VLLM_BIN" serve "$MODEL"
  --tensor-parallel-size "$TENSOR_PARALLEL"
  --trust-remote-code
  --max-model-len "$MAX_MODEL_LEN"
  --host "$HOST"
  --port "$PORT"
)

umask 077
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
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
  if ! pid_is_altar "$PID"; then
    echo "Altar-1 exited during startup. See $LOG_FILE" >&2
    rm -f "$PID_FILE"
    exit 5
  fi
  sleep 0.2
done

if (( ready )); then
  echo "Altar-1 ready: http://$HOST:$PORT/v1"
else
  echo "Altar-1 process started (pid $PID) but is not ready yet; check $LOG_FILE."
fi
echo "PID: $PID"
echo "Log: $LOG_FILE"
