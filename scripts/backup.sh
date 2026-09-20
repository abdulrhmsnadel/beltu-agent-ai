#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p backups
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="backups/beltu-backup-${stamp}.tar.gz"
tar -czf "$archive" data/beltu.db data/targets data/evidence data/reports
printf '%s\n' "$archive"
