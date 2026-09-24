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
PYPROJECT_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml | head -n 1)"
MANIFEST_VERSION="$("$VENV/bin/python" -c 'import json; print(json.load(open("RELEASE_MANIFEST.json", encoding="utf-8"))["version"])')"
README_VERSION="$(sed -n '1s/^# BELTU \([^ ]*\).*/\1/p' README.md)"
if [[ "$VERSION" != "$PYPROJECT_VERSION" || "$VERSION" != "$MANIFEST_VERSION" || "$VERSION" != "$README_VERSION" ]]; then
  echo "Version mismatch: version.py=$VERSION pyproject=$PYPROJECT_VERSION manifest=$MANIFEST_VERSION README=$README_VERSION" >&2
  exit 3
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree must be clean before creating a release archive." >&2
  exit 4
fi
ARCHIVE="dist/BELTU-$VERSION.zip"

git archive --format=zip --prefix="BELTU-$VERSION/" -o "$ARCHIVE" HEAD

[[ -s "$ARCHIVE" ]] || { echo "Source archive was not created." >&2; exit 5; }

(
  cd dist
  find . -maxdepth 1 -type f ! -name "SHA256SUMS" -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "Release version: $VERSION"
echo "Artifacts:"
find dist -maxdepth 1 -type f -printf "  %f\n" | sort
printf "\nChecksums:\n"
cat dist/SHA256SUMS
