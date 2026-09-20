from __future__ import annotations
import json
from pathlib import Path
from beltu.analysis.finding_intelligence import FindingIntelligenceService
from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.hypothesis_engine import HeuristicHypothesisEngine
from beltu.brain.llm.prompting import build_user_prompt
from beltu.brain.schemas import AgentContext
from beltu.storage.database import Database
from beltu.storage.repositories.finding_repository import FindingRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository

def setup(tmp_path: Path):
    db=Database(tmp_path/'db.sqlite'); db.initialize()
    targets=TargetRepository(db); target=targets.add('example.com')
    scans=ScanRepository(db); scan=scans.create(target.id)
    return db,target,scan

def test_idempotent_candidate_and_plan(tmp_path):
    db,_,scan=setup(tmp_path); obs=ObservationRepository(db)
    obs.add(scan.id,'finding.candidate','/account',{'category':'authorization','severity':'high','title':'Potential authorization inconsistency'},'fixture',0.85)
    svc=FindingIntelligenceService(db); first=svc.rebuild(scan.id); second=svc.rebuild(scan.id)
    repo=FindingRepository(db)
    assert first.summary['findings']==1 and second.summary['findings']==1
    assert len(repo.list_findings(scan.id))==1
    assert len(repo.list_steps(repo.get_plan(repo.list_findings(scan.id)[0].id).id))==3

def test_cross_layer_sources_are_retained(tmp_path):
    db,_,scan=setup(tmp_path); now='2026-09-20T00:00:00+00:00'
    with db.connect() as c:
        c.execute('INSERT INTO business_workflows(scan_id,workflow_key,label,confidence,source,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(scan.id,'orders','Orders',0.8,'fixture','{}',now,now))
        workflow_id=c.execute('SELECT id FROM business_workflows WHERE scan_id=? AND workflow_key=?',(scan.id,'orders')).fetchone()[0]
        c.execute('INSERT INTO authorization_anomalies(scan_id,kind,severity,entity_type,entity_id,statement,rationale,confidence,basis_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(scan.id,'principal_state_conflict','high','operation',7,'Conflicting access state','fixture',0.8,json.dumps({'evidence_ids':[1]}),now,now))
        c.execute('INSERT INTO business_logic_anomalies(scan_id,workflow_id,kind,severity,statement,rationale,confidence,entity_key,basis_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(scan.id,workflow_id,'sensitive_transition','high','Sensitive transition has inconsistent boundary evidence','fixture',0.78,'operation:7',json.dumps({'evidence_ids':[2]}),'candidate',now,now))
    result=FindingIntelligenceService(db).rebuild(scan.id)
    assert result.summary['findings']==1
    f=FindingRepository(db).list_findings(scan.id)[0]
    sources=FindingRepository(db).list_sources(f.id)
    assert {s.source_type for s in sources}=={'authorization_anomaly','business_logic_anomaly'}
    assert {1,2}.issubset(set(x for s in sources for x in s.evidence_ids))

def test_plan_is_declarative_and_approval_gated(tmp_path):
    db,_,scan=setup(tmp_path); obs=ObservationRepository(db)
    obs.add(scan.id,'finding.candidate','/checkout',{'category':'business-logic','severity':'medium','title':'Candidate workflow issue'},'fixture',0.9)
    FindingIntelligenceService(db).rebuild(scan.id); repo=FindingRepository(db); f=repo.list_findings(scan.id)[0]
    plan=repo.get_plan(f.id); assert plan.requires_approval and plan.status=='draft'
    joined=' '.join(s.instruction.lower() for s in repo.list_steps(plan.id))
    for token in ('curl','wget','subprocess','os.system','bash ','sh '): assert token not in joined
    assert all(s.approval_required is False for s in repo.list_steps(plan.id)[:2])
    assert repo.list_steps(plan.id)[-1].approval_required is True

def test_context_and_llm_prompt_receive_finding_surface(tmp_path):
    db,target,scan=setup(tmp_path); obs=ObservationRepository(db)
    obs.add(scan.id,'finding.candidate','/x',{'category':'authz','severity':'low','title':'Candidate'},'fixture',0.7)
    finding=FindingIntelligenceService(db)
    finding.rebuild(scan.id)
    ctx=ContextBuilder(ScanRepository(db),TargetRepository(db),obs,HypothesisRepository(db),AttackSurfaceGraph(),finding_intelligence=finding).build(scan.id)
    assert ctx.finding_surface['summary']['findings']==1
    prompt=build_user_prompt(Path(tmp_path),'missing.md',ctx,3,3)
    assert 'finding_surface' in prompt and 'Candidate' in prompt

def test_heuristic_generates_validation_hypothesis(tmp_path):
    db,target,scan=setup(tmp_path); obs=ObservationRepository(db)
    obs.add(scan.id,'finding.candidate','/x',{'category':'authz','severity':'medium','title':'Candidate'},'fixture',0.8)
    finding=FindingIntelligenceService(db); finding.rebuild(scan.id)
    ctx=AgentContext(scan.id,target.value,observations=({"id":1,"kind":"finding.candidate","subject":"/x","data":{},"source":"fixture","confidence":0.8},),finding_surface=finding.context_payload(scan.id))
    props=HeuristicHypothesisEngine().generate(ctx)
    assert any('should be validated' in p.statement.lower() for p in props)
