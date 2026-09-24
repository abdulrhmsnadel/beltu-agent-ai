#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$BASH_SOURCE")/.." && pwd)"
VENV_DIR="${BELTU_ALTAR1_VENV:-$HOME/.local/share/beltu/altar1/.venv}"
MODEL_PATH="${BELTU_ALTAR1_MODEL_PATH:-}"
MODEL_REVISION="${BELTU_ALTAR1_MODEL_REVISION:-}"
HOST="${BELTU_ALTAR1_HOST:-127.0.0.1}"
PORT="${BELTU_ALTAR1_PORT:-8001}"
TENSOR_PARALLEL="${BELTU_ALTAR1_TENSOR_PARALLEL_SIZE:-4}"
MAX_MODEL_LEN="${BELTU_ALTAR1_MAX_MODEL_LEN:-131072}"
GPU_MEMORY_UTIL="${BELTU_ALTAR1_GPU_MEMORY_UTILIZATION:-0.90}"
CUDA_DEVICES="${BELTU_ALTAR1_CUDA_VISIBLE_DEVICES:-}"
PID_FILE="$ROOT/data/runtime/altar1.pid"
LOG_FILE="$ROOT/data/runtime/altar1.log"

VLLM_BIN="$VENV_DIR/bin/vllm"
[[ -x "$VLLM_BIN" ]] || { echo "vLLM not found at $VLLM_BIN. Install the pinned Altar-1 serving environment first." >&2; exit 2; }
[[ -n "$MODEL_PATH" && -e "$MODEL_PATH" ]] || { echo "BELTU_ALTAR1_MODEL_PATH must point to a local Altar-1 model path; remote model IDs are refused." >&2; exit 3; }
[[ "$MODEL_REVISION" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "BELTU_ALTAR1_MODEL_REVISION must be a pinned 40-character model commit SHA." >&2; exit 4; }

case "$HOST" in
  127.0.0.1|localhost|::1) ;;
  *) echo "Refusing non-loopback Altar-1 host: $HOST" >&2; exit 5 ;;
esac

awk "BEGIN { exit !($GPU_MEMORY_UTIL > 0 && $GPU_MEMORY_UTIL <= 1) }" || { echo "BELTU_ALTAR1_GPU_MEMORY_UTILIZATION must be in (0,1]." >&2; exit 6; }

mkdir -p "$ROOT/data/runtime"
if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ "$PID" =~ ^[1-9][0-9]*$ ]] && kill -0 "$PID" 2>/dev/null; then
    CMDLINE="$(tr "\0" " " < "/proc/$PID/cmdline" 2>/dev/null || true)"
    if [[ "$CMDLINE" == *"$VLLM_BIN"* || "$CMDLINE" == *" vllm "* || "$CMDLINE" == vllm* ]]; then
      echo "Altar-1 already running (pid $PID)."
      exit 0
    fi
  fi
  rm -f "$PID_FILE"
fi

CMD=("$VLLM_BIN" serve "$MODEL_PATH" --tensor-parallel-size "$TENSOR_PARALLEL" --trust-remote-code --max-model-len "$MAX_MODEL_LEN" --host "$HOST" --port "$PORT" --gpu-memory-utilization "$GPU_MEMORY_UTIL" --revision "$MODEL_REVISION")

export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
if [[ -n "$CUDA_DEVICES" ]]; then
  export CUDA_VISIBLE_DEVICES="$CUDA_DEVICES"
fi

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
with urlopen(f"http://{host}:{port}/v1/models", timeout=2):
    pass
PY
  fi
  kill -0 "$PID" 2>/dev/null || break
  sleep 1
done

if [[ "$ready" != "1" ]]; then
  echo "Altar-1 failed readiness check; inspect $LOG_FILE." >&2
  "$ROOT/scripts/stop_altar1.sh" || true
  exit 7
fi

echo "Altar-1 ready: http://$HOST:$PORT/v1"
echo "PID: $PID"
echo "Log: $LOG_FILE"
