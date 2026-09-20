from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any
from beltu.storage.database import Database
from beltu.storage.models.findings import FindingCandidate, FindingSource, ValidationPlan, ValidationPlanStep

def now() -> str:
    return datetime.now(timezone.utc).isoformat()
def _arr(v: str|None) -> tuple[str,...]:
    try:
        x=json.loads(v or '[]')
        return tuple(str(i) for i in x) if isinstance(x,list) else ()
    except json.JSONDecodeError:
        return ()
def _ids(v: str|None) -> tuple[int,...]:
    out=[]
    for x in _arr(v):
        try: out.append(int(x))
        except ValueError: pass
    return tuple(dict.fromkeys(out))
def _obj(v: str|None)->dict[str,Any]:
    try:
        x=json.loads(v or '{}')
        return x if isinstance(x,dict) else {}
    except json.JSONDecodeError:
        return {}

class FindingRepository:
    def __init__(self, db: Database): self.db=db
    def _f(self,r): return FindingCandidate(r['id'],r['scan_id'],r['fingerprint'],r['title'],r['category'],r['severity'],float(r['confidence']),r['status'],r['subject'],r['entity_type'],r['entity_id'],r['impact_summary'],r['rationale'],r['source_count'],float(r['corroboration_score']),r['created_at'],r['updated_at'])
    def _s(self,r): return FindingSource(r['id'],r['scan_id'],r['finding_id'],r['source_type'],r['source_id'],r['relation'],float(r['confidence']),_ids(r['evidence_ids_json']),_obj(r['metadata_json']),r['created_at'])
    def _p(self,r): return ValidationPlan(r['id'],r['scan_id'],r['finding_id'],r['objective'],r['status'],r['risk_level'],bool(r['requires_approval']),_arr(r['preconditions_json']),_arr(r['expected_evidence_json']),_arr(r['stop_conditions_json']),float(r['confidence']),r['rationale'],r['created_at'],r['updated_at'])
    def _st(self,r): return ValidationPlanStep(r['id'],r['plan_id'],r['ordinal'],r['step_kind'],r['title'],r['instruction'],r['expected_observation_kind'],bool(r['approval_required']),r['risk_level'],r['created_at'])
    def upsert_finding(self, *, scan_id:int, fingerprint:str, title:str, category:str, severity:str, confidence:float, subject:str, entity_type:str|None, entity_id:int|None, impact_summary:str, rationale:str, source_count:int, corroboration_score:float, status:str='candidate') -> FindingCandidate:
        if not 0<=confidence<=1 or not 0<=corroboration_score<=1: raise ValueError('Finding scores must be between 0 and 1')
        ts=now()
        with self.db.connect() as c:
            row=c.execute('SELECT * FROM finding_candidates WHERE scan_id=? AND fingerprint=?',(scan_id,fingerprint)).fetchone()
            if row is None:
                cur=c.execute('''INSERT INTO finding_candidates(scan_id,fingerprint,title,category,severity,confidence,status,subject,entity_type,entity_id,impact_summary,rationale,source_count,corroboration_score,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(scan_id,fingerprint,title[:300],category[:100],severity[:30],confidence,status,subject[:500],entity_type,entity_id,impact_summary[:800],rationale[:1200],int(source_count),corroboration_score,ts,ts))
                row=c.execute('SELECT * FROM finding_candidates WHERE id=?',(cur.lastrowid,)).fetchone()
            else:
                c.execute('''UPDATE finding_candidates SET title=?,category=?,severity=?,confidence=MAX(confidence,?),status=?,subject=?,entity_type=?,entity_id=?,impact_summary=?,rationale=?,source_count=?,corroboration_score=MAX(corroboration_score,?),updated_at=? WHERE id=?''',(title[:300],category[:100],severity[:30],confidence,status,subject[:500],entity_type,entity_id,impact_summary[:800],rationale[:1200],int(source_count),corroboration_score,ts,row['id']))
                row=c.execute('SELECT * FROM finding_candidates WHERE id=?',(row['id'],)).fetchone()
        return self._f(row)
    def add_source(self, *,scan_id:int,finding_id:int,source_type:str,source_id:int,relation:str,confidence:float,evidence_ids:tuple[int,...]=(),metadata:dict[str,Any]|None=None):
        ts=now()
        with self.db.connect() as c:
            row=c.execute('SELECT * FROM finding_sources WHERE finding_id=? AND source_type=? AND source_id=? AND relation=?',(finding_id,source_type,source_id,relation)).fetchone()
            args=(scan_id,finding_id,source_type[:80],source_id,relation[:120],confidence,json.dumps(list(dict.fromkeys(evidence_ids))),json.dumps(metadata or {},sort_keys=True),ts)
            if row is None:
                cur=c.execute('INSERT INTO finding_sources(scan_id,finding_id,source_type,source_id,relation,confidence,evidence_ids_json,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)',args)
                row=c.execute('SELECT * FROM finding_sources WHERE id=?',(cur.lastrowid,)).fetchone()
            else:
                c.execute('UPDATE finding_sources SET confidence=MAX(confidence,?),evidence_ids_json=?,metadata_json=? WHERE id=?',(confidence,args[6],args[7],row['id']))
                row=c.execute('SELECT * FROM finding_sources WHERE id=?',(row['id'],)).fetchone()
        return self._s(row)
    def list_findings(self, scan_id):
        with self.db.connect() as c: rows=c.execute('SELECT * FROM finding_candidates WHERE scan_id=? ORDER BY confidence DESC,id',(scan_id,)).fetchall()
        return [self._f(r) for r in rows]
    def list_sources(self,finding_id):
        with self.db.connect() as c: rows=c.execute('SELECT * FROM finding_sources WHERE finding_id=? ORDER BY id',(finding_id,)).fetchall()
        return [self._s(r) for r in rows]
    def upsert_plan(self, *,scan_id:int,finding_id:int,objective:str,risk_level:str,requires_approval:bool,preconditions:tuple[str,...],expected_evidence:tuple[str,...],stop_conditions:tuple[str,...],confidence:float,rationale:str,status:str='draft'):
        ts=now()
        vals=(scan_id,finding_id,objective,status,risk_level,int(requires_approval),json.dumps(list(preconditions)),json.dumps(list(expected_evidence)),json.dumps(list(stop_conditions)),confidence,rationale,ts,ts)
        with self.db.connect() as c:
            row=c.execute('SELECT * FROM validation_plans WHERE finding_id=?',(finding_id,)).fetchone()
            if row is None:
                cur=c.execute('INSERT INTO validation_plans(scan_id,finding_id,objective,status,risk_level,requires_approval,preconditions_json,expected_evidence_json,stop_conditions_json,confidence,rationale,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',vals)
                row=c.execute('SELECT * FROM validation_plans WHERE id=?',(cur.lastrowid,)).fetchone()
            else:
                c.execute('UPDATE validation_plans SET objective=?,status=?,risk_level=?,requires_approval=?,preconditions_json=?,expected_evidence_json=?,stop_conditions_json=?,confidence=MAX(confidence,?),rationale=?,updated_at=? WHERE id=?',(objective,status,risk_level,int(requires_approval),vals[6],vals[7],vals[8],confidence,rationale,ts,row['id']))
                row=c.execute('SELECT * FROM validation_plans WHERE id=?',(row['id'],)).fetchone()
        return self._p(row)
    def replace_steps(self,plan_id:int,steps:list[dict[str,Any]]):
        ts=now()
        with self.db.connect() as c:
            c.execute('DELETE FROM validation_plan_steps WHERE plan_id=?',(plan_id,))
            for i,st in enumerate(steps,1):
                c.execute('INSERT INTO validation_plan_steps(plan_id,ordinal,step_kind,title,instruction,expected_observation_kind,approval_required,risk_level,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(plan_id,i,st['step_kind'],st['title'],st['instruction'],st.get('expected_observation_kind'),int(st.get('approval_required',True)),st.get('risk_level','medium'),ts))
            rows=c.execute('SELECT * FROM validation_plan_steps WHERE plan_id=? ORDER BY ordinal',(plan_id,)).fetchall()
        return [self._st(r) for r in rows]
    def get_plan(self,finding_id):
        with self.db.connect() as c: row=c.execute('SELECT * FROM validation_plans WHERE finding_id=?',(finding_id,)).fetchone()
        return self._p(row) if row else None
    def list_steps(self,plan_id):
        with self.db.connect() as c: rows=c.execute('SELECT * FROM validation_plan_steps WHERE plan_id=? ORDER BY ordinal',(plan_id,)).fetchall()
        return [self._st(r) for r in rows]
