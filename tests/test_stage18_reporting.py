from pathlib import Path
import hashlib, json
from typer.testing import CliRunner
from beltu.storage.database import Database
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.evidence_repository import EvidenceRepository
from beltu.reporting.engine import ReportEngine
from beltu.interface.cli.app import app

def seed(tmp_path: Path):
    db=Database(tmp_path/"data"/"beltu.db"); db.initialize()
    target=TargetRepository(db).add("example.com"); scan=ScanRepository(db).create(target.id)
    return db, target, scan

def test_report_generation_creates_complete_workspace(tmp_path):
    db,_,scan=seed(tmp_path)
    obs=ObservationRepository(db).add(scan.id,"api.operation","GET /admin",{"method":"GET","path":"/admin"},"test",0.9)
    captured=tmp_path/"data/evidence/capture.json"; captured.parent.mkdir(parents=True, exist_ok=True); captured.write_text('{"ok":true}',encoding="utf-8")
    EvidenceRepository(db).add(scan.id,obs.id,"tool.output",str(captured),hashlib.sha256(captured.read_bytes()).hexdigest(),captured.stat().st_size,"application/json",{})
    result=ReportEngine(db,tmp_path).generate(scan.id); ws=Path(result.workspace)
    assert (ws/"reports/executive-summary.md").exists()
    assert (ws/"reports/full-engagement.md").exists()
    assert (ws/"evidence/EVD-000001.json").exists()
    assert (ws/"data/observations.json").exists()
    assert (ws/"packages/full-engagement-package.zip").exists()
    manifest=json.loads((ws/"workspace-manifest.json").read_text())
    assert manifest["scan_id"]==scan.id and manifest["file_count"]>0

def test_report_generation_is_idempotent_for_registry(tmp_path):
    db,_,scan=seed(tmp_path); eng=ReportEngine(db,tmp_path)
    eng.generate(scan.id); eng.generate(scan.id)
    rows=db.connect().execute("SELECT * FROM report_packages WHERE scan_id=?",(scan.id,)).fetchall()
    assert len(rows)==9

def test_report_cli(tmp_path,monkeypatch):
    db,_,scan=seed(tmp_path); monkeypatch.chdir(tmp_path); (tmp_path/"config").mkdir(); (tmp_path/"config/scope.yaml").write_text("targets:\n  - example.com\n")
    result=CliRunner().invoke(app,["report",str(scan.id)])
    assert result.exit_code==0, result.stdout


def test_reporter_does_not_copy_evidence_outside_evidence_root(tmp_path):
    db,_,scan=seed(tmp_path)
    obs=ObservationRepository(db).add(scan.id,"test","outside",{},"test",0.5)
    outside=tmp_path/"secret.txt"; outside.write_text("secret",encoding="utf-8")
    EvidenceRepository(db).add(scan.id,obs.id,"bad",str(outside),hashlib.sha256(outside.read_bytes()).hexdigest(),outside.stat().st_size,"text/plain",{})
    result=ReportEngine(db,tmp_path).generate(scan.id)
    assert not list((Path(result.workspace)/"evidence").glob("EVD-*"))
