#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
umask 077

mkdir -p backups
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="backups/beltu-backup-${stamp}.tar.gz"
workdir="$(mktemp -d)"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

DB="data/beltu.db"
if [[ -f "$DB" ]]; then
  python3 - "$DB" "$workdir/beltu.db" <<'PY'
import sqlite3
import sys

src = sqlite3.connect(sys.argv[1])
try:
    dst = sqlite3.connect(sys.argv[2])
    try:
        src.backup(dst)
    finally:
        dst.close()
finally:
    src.close()
PY
fi

for path in targets evidence reports; do
  if [[ -e "data/$path" ]]; then
    cp -a "data/$path" "$workdir/$path"
  fi
done

if [[ ! -e "$workdir/beltu.db" && ! -d "$workdir/targets" && ! -d "$workdir/evidence" && ! -d "$workdir/reports" ]]; then
  echo "Nothing to back up under data/." >&2
  exit 1
fi

tar -C "$workdir" -czf "$archive" .
printf '%s\n' "$archive"
