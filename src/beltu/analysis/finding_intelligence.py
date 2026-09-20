from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass
from typing import Any
from beltu.storage.database import Database
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.finding_repository import FindingRepository

def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")

def _severity(value: str) -> str:
    value=value.lower()
    return value if value in {"critical","high","medium","low","info"} else "medium"

def _fingerprint(category: str, subject: str) -> str:
    raw=f"{category.lower().strip()}|{_norm(subject)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _evidence_ids(data: dict[str, Any]) -> tuple[int,...]:
    raw=data.get("evidence_ids", [])
    if not isinstance(raw,list): return ()
    out=[]
    for x in raw:
        try: out.append(int(x))
        except (TypeError,ValueError): pass
    return tuple(dict.fromkeys(out))

@dataclass(frozen=True, slots=True)
class FindingIntelligenceResult:
    findings: tuple[Any,...]
    plans: tuple[Any,...]
    summary: dict[str,int]

class FindingIntelligenceService:
    """Correlate stored security signals into candidate findings and declarative validation plans.

    Stage 17 is analysis-only: no target traffic, commands, exploitation, or active validation.
    """
    def __init__(self, db: Database) -> None:
        self.db=db
        self.observations=ObservationRepository(db)
        self.findings=FindingRepository(db)

    def _signals(self, scan_id: int) -> list[dict[str,Any]]:
        signals=[]
        for obs in self.observations.list_for_scan(scan_id):
            kind=obs.kind.lower()
            if not ("finding" in kind or kind in {"vulnerability","misconfiguration","access_control","authorization","workflow.anomaly","business_logic"}):
                continue
            data=obs.data if isinstance(obs.data,dict) else {}
            subject=str(data.get("url") or data.get("path") or data.get("resource") or obs.subject)
            category=_norm(str(data.get("category") or data.get("type") or kind)) or "finding"
            signals.append({
                "source_type":"observation","source_id":obs.id,"category":category,
                "severity":_severity(str(data.get("severity") or "medium")),"subject":subject,
                "statement":str(data.get("title") or data.get("description") or obs.subject),
                "confidence":obs.confidence,"evidence_ids":_evidence_ids(data),
            })
        with self.db.connect() as conn:
            for row in conn.execute("SELECT * FROM authorization_anomalies WHERE scan_id=? ORDER BY id",(scan_id,)).fetchall():
                basis=json.loads(row["basis_json"] or "{}")
                signals.append({"source_type":"authorization_anomaly","source_id":row["id"],"category":f"authz_{_norm(row['kind'])}","severity":_severity(row["severity"]),"subject":f"{row['entity_type']}:{row['entity_id']}","statement":row["statement"],"confidence":float(row["confidence"]),"evidence_ids":_evidence_ids(basis)})
            for row in conn.execute("SELECT * FROM business_logic_anomalies WHERE scan_id=? ORDER BY id",(scan_id,)).fetchall():
                basis=json.loads(row["basis_json"] or "{}")
                signals.append({"source_type":"business_logic_anomaly","source_id":row["id"],"category":f"business_{_norm(row['kind'])}","severity":_severity(row["severity"]),"subject":row["entity_key"],"statement":row["statement"],"confidence":float(row["confidence"]),"evidence_ids":_evidence_ids(basis)})
        return signals

    def rebuild(self, scan_id: int) -> FindingIntelligenceResult:
        signals=self._signals(scan_id)
        by_subject: dict[str,list[dict[str,Any]]] = {}
        for signal in signals:
            by_subject.setdefault(_norm(signal["subject"]), []).append(signal)

        groups: list[list[dict[str,Any]]] = []
        for subject_items in by_subject.values():
            layers={x["source_type"] for x in subject_items}
            if len(layers) >= 2:
                groups.append(subject_items)
            else:
                by_category: dict[str,list[dict[str,Any]]] = {}
                for item in subject_items:
                    by_category.setdefault(item["category"], []).append(item)
                groups.extend(by_category.values())

        created=[]; plans=[]
        for items in groups:
            uniq={(x["source_type"],x["source_id"]) for x in items}
            top=max(items,key=lambda x:(x["confidence"],x["source_id"]))
            layers={x["source_type"] for x in items}
            category = top["category"] if len(layers)==1 else "correlated_security_signal"
            fp=_fingerprint(category,top["subject"])
            corroboration=min(1.0,0.30*len(uniq)+0.18*max(0,len(layers)-1))
            confidence=min(0.99,0.55*top["confidence"]+0.45*corroboration)
            rank={"critical":4,"high":3,"medium":2,"low":1,"info":0}
            severity=max((x["severity"] for x in items),key=lambda v:rank[v])
            rationale=(f"Correlated {len(uniq)} unique signal(s) across {len(layers)} source layer(s). "
                       "The result is a candidate, not a confirmed vulnerability.")
            finding=self.findings.upsert_finding(
                scan_id=scan_id,fingerprint=fp,title=top["statement"],category=category,severity=severity,
                confidence=confidence,subject=top["subject"],entity_type=None,entity_id=None,
                impact_summary=f"Potential {severity} impact indicated by stored evidence; exploitability is unconfirmed.",
                rationale=rationale,source_count=len(uniq),corroboration_score=corroboration,status="candidate")
            created.append(finding)
            for source in sorted(uniq):
                item=next(x for x in items if (x["source_type"],x["source_id"])==source)
                self.findings.add_source(
                    scan_id=scan_id,finding_id=finding.id,source_type=item["source_type"],source_id=item["source_id"],
                    relation="supports",confidence=item["confidence"],evidence_ids=item["evidence_ids"],
                    metadata={"category":item["category"],"subject":item["subject"]})
            plan=self.findings.upsert_plan(
                scan_id=scan_id,finding_id=finding.id,
                objective="Determine whether the candidate is reproducible and sufficiently supported by stored evidence.",
                risk_level="medium",requires_approval=True,
                preconditions=("Target remains explicitly scoped.","Linked evidence is available.","No superseding contradiction exists."),
                expected_evidence=("Independent corroborating observation.","Relevant request/response or state evidence when already captured."),
                stop_conditions=("Material contradiction appears.","Target scope changes or expires.","Required evidence is unavailable."),
                confidence=finding.confidence,
                rationale="Start with passive cross-checks. Any active validation requires policy checks and explicit approval.",
                status="draft")
            self.findings.replace_steps(plan.id,[
                {"step_kind":"review_sources","title":"Review correlated source evidence","instruction":"Compare linked sources for subject consistency, scope, and provenance. Do not generate new target traffic.","expected_observation_kind":"finding.correlation_review","approval_required":False,"risk_level":"low"},
                {"step_kind":"check_contradictions","title":"Check contradictory evidence","instruction":"Look for evidence that weakens, supersedes, or invalidates the candidate; record the contradiction before continuing.","expected_observation_kind":"finding.validation_review","approval_required":False,"risk_level":"low"},
                {"step_kind":"request_approval","title":"Request approval for active validation","instruction":"If passive evidence remains insufficient, stop and request explicit approval before any active validation action.","expected_observation_kind":"approval.requested","approval_required":True,"risk_level":"medium"},
            ])
            plans.append(plan)
        return FindingIntelligenceResult(tuple(created),tuple(plans),{"signals":len(signals),"findings":len(self.findings.list_findings(scan_id)),"plans":len(plans)})

    def context_payload(self, scan_id: int, limit: int=100) -> dict[str,Any]:
        findings=self.findings.list_findings(scan_id)[:limit]
        items=[]
        for f in findings:
            plan=self.findings.get_plan(f.id)
            items.append({"id":f.id,"fingerprint":f.fingerprint,"title":f.title,"category":f.category,"severity":f.severity,"confidence":f.confidence,"status":f.status,"subject":f.subject,"impact_summary":f.impact_summary,"rationale":f.rationale,"source_count":f.source_count,"corroboration_score":f.corroboration_score,"sources":[{"type":s.source_type,"id":s.source_id,"relation":s.relation,"confidence":s.confidence,"evidence_ids":list(s.evidence_ids)} for s in self.findings.list_sources(f.id)],"validation_plan_id":plan.id if plan else None,"validation_status":plan.status if plan else None})
        plans=[self.findings.get_plan(f.id) for f in findings]
        return {"summary":{"findings":len(findings),"candidate_findings":sum(f.status=="candidate" for f in findings),"validated_findings":sum(f.status=="validated" for f in findings)},"findings":items,"validation_plans":[{"id":p.id,"finding_id":p.finding_id,"status":p.status,"risk_level":p.risk_level,"requires_approval":p.requires_approval,"steps":[{"ordinal":s.ordinal,"kind":s.step_kind,"title":s.title,"approval_required":s.approval_required,"risk_level":s.risk_level} for s in self.findings.list_steps(p.id)]} for p in plans if p]}
