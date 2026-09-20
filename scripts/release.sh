#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 -m pytest -q
python3 -m compileall -q src
beltu doctor --strict
rm -rf dist
mkdir -p dist
python3 -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python3 - <<'PYRELEASE'
from pathlib import Path
import hashlib, zipfile
root=Path('.')
version=(root/'src/beltu/version.py').read_text().split('=')[-1].strip().strip('\"')
out=root/'dist'/f'BELTU-{version}.zip'
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
    for p in root.rglob('*'):
        if not p.is_file(): continue
        rel=p.relative_to(root).as_posix()
        if rel.startswith(('dist/','.git/','.pytest_cache/','data/targets/','data/evidence/','data/reports/')): continue
        if rel=='data/beltu.db' or rel=='patch2.py' or rel.endswith('.pyc') or '__pycache__/' in rel: continue
        z.write(p,rel)
digest=hashlib.sha256(out.read_bytes()).hexdigest()
(root/'dist'/f'BELTU-{version}.sha256').write_text(digest+'  '+out.name+'\n')
print(out)
print(digest)
PYRELEASE
