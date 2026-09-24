#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$BASH_SOURCE")/.."

ROOT="$PWD"
VENV="$ROOT/.venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Release venv not found at $VENV. Run scripts/install.sh first." >&2
  exit 2
fi

"$VENV/bin/python" -m pip install -e '.[test]'
"$VENV/bin/python" -m pytest -q
"$VENV/bin/python" -m compileall -q src
"$VENV/bin/beltu" doctor --strict

rm -rf dist
mkdir -p dist
"$VENV/bin/python" -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist

VERSION="$("$VENV/bin/python" -c 'from beltu.version import __version__; print(__version__)')"
ARCHIVE="dist/BELTU-$VERSION.zip"

git archive --format=zip --prefix="BELTU-$VERSION/" -o "$ARCHIVE" HEAD

[[ -s "$ARCHIVE" ]] || { echo "Source archive was not created." >&2; exit 3; }

(
  cd dist
  find . -maxdepth 1 -type f ! -name "SHA256SUMS" -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "Release version: $VERSION"
echo "Artifacts:"
find dist -maxdepth 1 -type f -printf "  %f\n" | sort
printf "\nChecksums:\n"
cat dist/SHA256SUMS
