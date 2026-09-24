#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$BASH_SOURCE")/.." && pwd)"
FT_REPO="${BELTU_FREETOKEN_REPO:-https://github.com/FlashML-org/FreeToken.git}"
FT_COMMIT="${BELTU_FREETOKEN_COMMIT:-}"
FT_DIR="${BELTU_FREETOKEN_DIR:-$HOME/.local/share/beltu/freetoken}"
FT_VENV="${BELTU_FREETOKEN_VENV:-$FT_DIR/.venv}"
MODEL_PATH="${BELTU_FREETOKEN_MODEL:-}"
PORT="${BELTU_FREETOKEN_PORT:-8000}"
HOST="${BELTU_FREETOKEN_HOST:-127.0.0.1}"
PID_FILE="$ROOT/data/runtime/freetoken.pid"
LOG_FILE="$ROOT/data/runtime/freetoken.log"

command -v git >/dev/null || { echo "git is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
[[ "$HOST" == "127.0.0.1" || "$HOST" == "localhost" || "$HOST" == "::1" ]] || { echo "Refusing non-loopback FreeToken host: $HOST" >&2; exit 3; }
[[ "$FT_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "BELTU_FREETOKEN_COMMIT must be a pinned 40-character commit SHA." >&2; exit 4; }

mkdir -p "$ROOT/data/runtime"
mkdir -p "$(dirname "$FT_DIR")"

if [[ ! -d "$FT_DIR/.git" ]]; then
  echo "[BELTU] Cloning official FreeToken repository..."
  git clone "$FT_REPO" "$FT_DIR"
fi

echo "[BELTU] Checking out pinned FreeToken commit: $FT_COMMIT"
git -C "$FT_DIR" fetch --depth 1 origin "$FT_COMMIT"
git -C "$FT_DIR" checkout --detach "$FT_COMMIT"
[[ "$(git -C "$FT_DIR" rev-parse HEAD)" == "$FT_COMMIT" ]] || { echo "FreeToken checkout did not reach the requested commit." >&2; exit 5; }

PYTHON_BIN="$(command -v python3)"
if [[ -x "$FT_VENV/bin/python" ]]; then
  :
elif command -v uv >/dev/null; then
  uv venv --python "$PYTHON_BIN" "$FT_VENV"
else
  "$PYTHON_BIN" -m venv "$FT_VENV"
fi

if command -v uv >/dev/null; then
  uv pip install --python "$FT_VENV/bin/python" -e "$FT_DIR[accel]"
else
  "$FT_VENV/bin/python" -m pip install -U pip setuptools wheel
  "$FT_VENV/bin/python" -m pip install -e "$FT_DIR[accel]"
fi

if ! "$FT_VENV/bin/ft" --version >/dev/null 2>&1; then
  echo "[BELTU] FreeToken installation did not expose the ft CLI." >&2
  exit 6
fi

cat > "$ROOT/data/runtime/freetoken.env" <<EOF
BELTU_FREETOKEN_URL=http://$HOST:$PORT
BELTU_FREETOKEN_MODEL=$MODEL_PATH
BELTU_FREETOKEN_PID_FILE=$PID_FILE
BELTU_FREETOKEN_COMMIT=$FT_COMMIT
EOF
chmod 600 "$ROOT/data/runtime/freetoken.env"

if command -v nvidia-smi >/dev/null 2>&1; then
  echo "[BELTU] NVIDIA GPU detected."
else
  echo "[BELTU] WARNING: nvidia-smi is unavailable; verify the FreeToken backend is usable on this host." >&2
fi

if [[ -z "$MODEL_PATH" ]]; then
  cat <<EOF

FreeToken is installed at the pinned commit, but no local model path was supplied.
Provide an already-downloaded model before starting the server:

  export BELTU_FREETOKEN_MODEL=/absolute/path/to/model
  "$ROOT/scripts/start_local_ai.sh"

The model path may be a local directory or checkpoint file. Do not use a remote
Hugging Face model id when the runtime must remain air-gapped.
EOF
  exit 0
fi

[[ -e "$MODEL_PATH" ]] || { echo "Local model path does not exist: $MODEL_PATH" >&2; exit 7; }
echo "[BELTU] FreeToken engine installed at pinned commit. Start with:"
echo "  BELTU_FREETOKEN_MODEL=$MODEL_PATH BELTU_FREETOKEN_PORT=$PORT $ROOT/scripts/start_local_ai.sh"
