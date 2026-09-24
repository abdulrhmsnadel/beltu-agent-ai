#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
else
  echo "BELTU release requires .venv. Run scripts/install.sh first." >&2
  exit 2
fi

"$PYTHON_BIN" -m pip install -e '.[test]'
"$PYTHON_BIN" -m pytest -q
"$PYTHON_BIN" -m compileall -q src
.venv/bin/beltu doctor --strict

tracked_sensitive="$(git ls-files | grep -E '(^|/)(\.env|.*\.env\..*|data/(beltu\.db|runtime/|targets/|evidence/|reports/))' || true)"
if [[ -n "$tracked_sensitive" ]]; then
  echo "Refusing to release: sensitive/runtime paths are tracked:" >&2
  printf '%s\n' "$tracked_sensitive" >&2
  exit 3
fi

rm -rf dist
mkdir -p dist
"$PYTHON_BIN" -m pip wheel . --no-deps --wheel-dir dist

VERSION="$("$PYTHON_BIN" - <<'PY'
from pathlib import Path
import re
text=Path("src/beltu/version.py").read_text(encoding="utf-8")
match=re.search(r'__version__\s*=\s*"([^"]+)"', text)
if not match:
    raise SystemExit("Could not determine BELTU version")
print(match.group(1))
PY
)"

OUT="dist/BELTU-${VERSION}.zip"
git archive --format=zip --prefix="BELTU-${VERSION}/" HEAD -o "$OUT"
DIGEST="$(sha256sum "$OUT" | awk '{print $1}')"
printf '%s  %s\n' "$DIGEST" "$(basename "$OUT")" > "dist/BELTU-${VERSION}.sha256"
printf '%s\n' "$OUT"
printf '%s\n' "$DIGEST"
