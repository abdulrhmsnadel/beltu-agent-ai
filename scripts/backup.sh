#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$BASH_SOURCE")/.."
umask 077

command -v sqlite3 >/dev/null || { echo "sqlite3 is required for a consistent live database backup." >&2; exit 2; }

mkdir -p backups
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="backups/beltu-backup-$STAMP.tar.gz"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/data"

if [[ -f data/beltu.db ]]; then
  sqlite3 data/beltu.db ".backup \'$STAGE/data/beltu.db\'"
else
  echo "[BELTU] data/beltu.db not found; creating an empty placeholder." >&2
  : > "$STAGE/data/beltu.db"
fi

for dir in targets evidence reports; do
  if [[ -d "data/$dir" ]]; then
    cp -a "data/$dir" "$STAGE/data/$dir"
  else
    mkdir -p "$STAGE/data/$dir"
  fi
done

tar -C "$STAGE" -czf "$ARCHIVE" data
chmod 600 "$ARCHIVE"
printf "%s\n" "$ARCHIVE"
