#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${BELTU_ALTAR1_VENV:-$HOME/.local/share/beltu/altar1/.venv}"
MODEL="${BELTU_ALTAR1_MODEL:-aikido/altar-1}"
HOST="${BELTU_ALTAR1_HOST:-127.0.0.1}"
PORT="${BELTU_ALTAR1_PORT:-8001}"
TENSOR_PARALLEL="${BELTU_ALTAR1_TENSOR_PARALLEL_SIZE:-4}"
MAX_MODEL_LEN="${BELTU_ALTAR1_MAX_MODEL_LEN:-131072}"
PID_FILE="$ROOT/data/runtime/altar1.pid"
LOG_FILE="$ROOT/data/runtime/altar1.log"

VLLM_BIN="$VENV_DIR/bin/vllm"
[[ -x "$VLLM_BIN" ]] || {
  echo "vLLM not found at $VLLM_BIN. Install vLLM in the Altar-1 serving environment first." >&2
  exit 2
}

mkdir -p "$ROOT/data/runtime"
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; then
  echo "Altar-1 already running (pid $(cat "$PID_FILE"))."
  exit 0
fi

CMD=(
  "$VLLM_BIN" serve "$MODEL"
  --tensor-parallel-size "$TENSOR_PARALLEL"
  --trust-remote-code
  --max-model-len "$MAX_MODEL_LEN"
  --host "$HOST"
  --port "$PORT"
)

nohup "${CMD[@]}" >>"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
chmod 600 "$PID_FILE"

echo "Altar-1 started: http://$HOST:$PORT/v1"
echo "PID: $(cat "$PID_FILE")"
echo "Log: $LOG_FILE"