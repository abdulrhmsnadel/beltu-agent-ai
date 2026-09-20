from __future__ import annotations

import hashlib
import json
import re
import shutil
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beltu.storage.database import Database
from beltu.storage.repositories.report_repository import ReportRepository

@dataclass(frozen=True, slots=True)
class ReportResult:
    scan_id: int
    target: str
    workspace: str
    files: tuple[str, ...]
    packages: tuple[str, ...]
    manifest: str

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def safe_slug(value: str) -> str:
    slug = re.sub(r'[^A-Za-z0-9._-]+', '-', value.strip()).strip('.-_')
    return slug[:90] or 'target'

def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str)

def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in ('token', 'password', 'secret', 'api_key', 'access_key', 'private_key')):
                out[key] = '[REDACTED]'
            else:
                out[key] = redact_sensitive(item)
        return out
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value

def table_md(rows: list[dict[str, Any]], columns: list[tuple[str, str]], limit: int = 200) -> str:
    if not rows:
        return '_None._\n'
    out = ['| ' + ' | '.join(label for label, _ in columns) + ' |', '| ' + ' | '.join('---' for _ in columns) + ' |']
    for row in rows[:limit]:
        values=[]
        for _, key in columns:
            value=row.get(key, '')
            if isinstance(value,(dict,list)):
                value=json.dumps(value, ensure_ascii=False, sort_keys=True)
            values.append(str(value).replace('|','\\|').replace('\n',' '))
        out.append('| ' + ' | '.join(values) + ' |')
    return '\n'.join(out) + '\n'

class ReportEngine:
    REPORT_TYPES = ('executive','technical_findings','reconnaissance','attack_surface','agent_activity','execution_history','evidence_index','full_engagement')
    def __init__(self, db: Database, project_root: str | Path):
        self.db=db
        self.project_root=Path(project_root)
        self.data_root=self.project_root/'data'
        self.targets_root=self.data_root/'targets'
        self.repo=ReportRepository(db)
    def _bundle(self, scan_id: int) -> dict[str, Any]:
        queries={
            'observations':'SELECT * FROM observations WHERE scan_id=? ORDER BY id',
            'hypotheses':'SELECT * FROM hypotheses WHERE scan_id=? ORDER BY id',
            'decisions':'SELECT * FROM decisions WHERE scan_id=? ORDER BY id',
            'tasks':'SELECT * FROM tasks WHERE scan_id=? ORDER BY id',
            'reasoning_cycles':'SELECT * FROM reasoning_cycles WHERE scan_id=? ORDER BY id',
            'llm_runs':'SELECT * FROM llm_runs WHERE scan_id=? ORDER BY id',
            'selections':'SELECT * FROM capability_selections WHERE scan_id=? ORDER BY id',
            'assets':'SELECT * FROM assets WHERE scan_id=? ORDER BY id',
            'services':'SELECT * FROM asset_services WHERE scan_id=? ORDER BY id',
            'endpoints':'SELECT * FROM asset_endpoints WHERE scan_id=? ORDER BY id',
            'technologies':'SELECT * FROM asset_technologies WHERE scan_id=? ORDER BY id',
            'surface':'SELECT * FROM surface_priorities WHERE scan_id=? ORDER BY score DESC,id',
            'api_operations':'SELECT * FROM api_operations WHERE scan_id=? ORDER BY id',
            'api_parameters':'SELECT * FROM api_parameters WHERE scan_id=? ORDER BY id',
            'api_relations':'SELECT * FROM api_relations WHERE scan_id=? ORDER BY id',
            'auth_principals':'SELECT * FROM auth_principals WHERE scan_id=? ORDER BY id',
            'auth_sessions':'SELECT * FROM auth_sessions WHERE scan_id=? ORDER BY id',
            'auth_controls':'SELECT * FROM auth_operation_controls WHERE scan_id=? ORDER BY id',
            'auth_transitions':'SELECT * FROM auth_transitions WHERE scan_id=? ORDER BY id',
            'authorization_matrix':'SELECT * FROM authorization_matrix WHERE scan_id=? ORDER BY id',
            'authorization_anomalies':'SELECT * FROM authorization_anomalies WHERE scan_id=? ORDER BY id',
            'workflows':'SELECT * FROM business_workflows WHERE scan_id=? ORDER BY id',
            'workflow_states':'SELECT * FROM workflow_states WHERE workflow_id IN (SELECT id FROM business_workflows WHERE scan_id=?) ORDER BY id',
            'workflow_transitions':'SELECT * FROM workflow_transitions WHERE scan_id=? ORDER BY id',
            'business_logic_anomalies':'SELECT * FROM business_logic_anomalies WHERE scan_id=? ORDER BY id',
            'findings':'SELECT * FROM finding_candidates WHERE scan_id=? ORDER BY confidence DESC,id',
            'finding_sources':'SELECT * FROM finding_sources WHERE scan_id=? ORDER BY id',
            'validation_plans':'SELECT * FROM validation_plans WHERE scan_id=? ORDER BY id',
            'validation_steps':'SELECT * FROM validation_plan_steps WHERE plan_id IN (SELECT id FROM validation_plans WHERE scan_id=?) ORDER BY plan_id,ordinal',
            'evidence':'SELECT * FROM evidence WHERE scan_id=? ORDER BY id',
            'observation_links':'SELECT * FROM observation_links WHERE scan_id=? ORDER BY id',
            'approvals':'SELECT * FROM approvals WHERE scan_id=? ORDER BY id',
        }
        with self.db.connect() as conn:
            scan=conn.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
            if not scan: raise ValueError(f'Unknown scan: {scan_id}')
            target=conn.execute('SELECT * FROM targets WHERE id=?',(scan['target_id'],)).fetchone()
            if not target: raise ValueError(f'Unknown target for scan: {scan_id}')
            data={}
            for key, sql in queries.items():
                rows=conn.execute(sql,(scan_id,)).fetchall()
                data[key]=[dict(r) for r in rows]
        data['scan']=dict(scan); data['target']=dict(target)
        return data
    def _write_text(self,path:Path,text:str):
        path.parent.mkdir(parents=True,exist_ok=True)
        payload=text.rstrip()+'\n'; path.write_text(payload,encoding='utf-8'); return sha_bytes(payload.encode())
    def _write_json(self,path:Path,obj:Any): return self._write_text(path,json_text(obj))
    def _report_docs(self,b:dict[str,Any],ws:Path):
        target=b['target']['value']; scan=b['scan']; findings=b['findings']
        finding_lines=[]
        for f in findings:
            finding_lines.append(f"### FND-{f['id']:04d} — {f['title']}\n\n- Category: `{f['category']}`\n- Severity: `{f['severity']}`\n- Confidence: `{f['confidence']:.2f}`\n- Status: `{f['status']}`\n- Subject: `{f['subject']}`\n- Impact: {f['impact_summary']}\n- Rationale: {f['rationale']}\n")
        counts={k:len(b[k]) for k in ('observations','hypotheses','decisions','tasks','assets','services','endpoints','technologies','surface','api_operations','auth_principals','auth_sessions','authorization_matrix','workflows','findings','evidence')}
        docs={
            'executive': f"# BELTU Executive Report\n\n**Target:** `{target}`  \n**Scan:** `{scan['id']}`  \n**Status:** `{scan['status']}`  \n**Generated:** `{utc_now()}`\n\n## Scope\n\nThis report reflects persisted BELTU state. Analytical candidates are not presented as confirmed vulnerabilities.\n\n## Snapshot\n\n{table_md([{'metric':k,'value':v} for k,v in counts.items()],[('Metric','metric'),('Value','value')])}\n\n## Findings\n\n{chr(10).join(finding_lines) if finding_lines else '_No finding candidates recorded._'}\n",
            'technical_findings': f"# BELTU Technical Findings\n\n**Target:** `{target}` | **Scan:** `{scan['id']}`\n\n{chr(10).join(finding_lines) if finding_lines else '_No finding candidates recorded._'}\n\n## Sources\n\n{table_md(b['finding_sources'],[('Finding','finding_id'),('Type','source_type'),('Source','source_id'),('Relation','relation'),('Confidence','confidence')])}\n\n## Validation Plans\n\n{table_md(b['validation_plans'],[('Finding','finding_id'),('Status','status'),('Risk','risk_level'),('Approval','requires_approval'),('Confidence','confidence')])}",
            'reconnaissance': f"# BELTU Reconnaissance Report\n\n**Target:** `{target}` | **Scan:** `{scan['id']}`\n\n## Assets\n{table_md(b['assets'],[('ID','id'),('Type','asset_type'),('Value','normalized_value'),('Status','status'),('Source','source'),('Confidence','confidence')])}\n## Services\n{table_md(b['services'],[('Asset','asset_id'),('Transport','transport'),('Port','port'),('State','state'),('Service','service'),('Product','product'),('Version','version')])}\n## Endpoints\n{table_md(b['endpoints'],[('Asset','asset_id'),('Method','method'),('URL','url'),('Type','endpoint_type'),('Auth','auth_hint'),('Source','source')])}\n## Technologies\n{table_md(b['technologies'],[('Asset','asset_id'),('Name','name'),('Version','version'),('Category','category'),('Source','source'),('Confidence','confidence')])}",
            'attack_surface': f"# BELTU Attack Surface Report\n\n**Target:** `{target}` | **Scan:** `{scan['id']}`\n\n## Prioritized Surface\n\n{table_md(b['surface'],[('Priority','priority'),('Type','entity_type'),('Entity','entity_id'),('Value','value'),('Score','score'),('Exposure','exposure'),('Novelty','novelty'),('Sensitivity','sensitivity'),('Confidence','confidence')])}\n## API Surface\n\n{table_md(b['api_operations'],[('ID','id'),('Method','method'),('Path','path'),('Style','api_style'),('Auth','auth_required'),('Operation','operation_id'),('Confidence','confidence')])}\n## Authorization Matrix\n\n{table_md(b['authorization_matrix'],[('Operation','operation_id'),('Principal','principal_label'),('Role','role'),('State','access_state'),('Auth','auth_required'),('Confidence','confidence')])}",
            'agent_activity': f"# BELTU Agent Activity Report\n\n**Target:** `{target}` | **Scan:** `{scan['id']}`\n\n## Reasoning Cycles\n\n{table_md(b['reasoning_cycles'],[('ID','id'),('Trigger','trigger'),('Task','trigger_task_id'),('Status','status'),('Context','context_fingerprint'),('Created','created_at'),('Completed','completed_at')])}\n## Hypotheses\n\n{table_md(b['hypotheses'],[('ID','id'),('Statement','statement'),('Confidence','confidence'),('Status','status'),('Created','created_at')])}\n## Decisions\n\n{table_md(b['decisions'],[('ID','id'),('Hypothesis','hypothesis_id'),('Action','action_kind'),('Risk','risk_level'),('Approval','requires_approval'),('Status','status'),('Rationale','rationale')])}\n## Capability Selection\n\n{table_md(b['selections'],[('Capability','capability'),('Tool','tool'),('Score','score'),('Information Gain','expected_information_gain'),('Cost','cost'),('Risk','risk_level'),('Rationale','rationale')])}\n## LLM Run Metadata\n\n{table_md(b['llm_runs'],[('ID','id'),('Provider','provider'),('Model','model'),('Status','status'),('Latency','latency_ms'),('Prompt SHA','prompt_sha256'),('Response SHA','response_sha256')])}",
            'execution_history': f"# BELTU Execution History\n\n**Target:** `{target}` | **Scan:** `{scan['id']}`\n\n## Tasks\n\n{table_md(b['tasks'],[('ID','id'),('Kind','kind'),('Status','status'),('Attempts','attempts'),('Priority','priority'),('Created','created_at'),('Started','started_at'),('Finished','finished_at'),('Error','error')])}\n## Decisions\n\n{table_md(b['decisions'],[('ID','id'),('Action','action_kind'),('Risk','risk_level'),('Approval','requires_approval'),('Status','status'),('Created','created_at')])}\n## Approvals\n\n{table_md(b['approvals'],[('ID','id'),('Decision','decision_id'),('Action','action_kind'),('Status','status'),('Channel','channel'),('Requested','requested_at'),('Resolved','resolved_at'),('Resolved By','resolved_by')])}",
            'evidence_index': f"# BELTU Evidence Index\n\n**Target:** `{target}` | **Scan:** `{scan['id']}`\n\n{table_md(b['evidence'],[('ID','id'),('Kind','kind'),('Observation','observation_id'),('Original Path','path'),('SHA-256','sha256'),('Bytes','size_bytes'),('MIME','mime_type'),('Created','created_at')])}",
            'full_engagement': f"# BELTU Full Engagement Report\n\n**Target:** `{target}`  \n**Scan:** `{scan['id']}`  \n**Generated:** `{utc_now()}`\n\n## Summary\n\nFindings: **{len(findings)}** | Evidence: **{len(b['evidence'])}** | Reasoning cycles: **{len(b['reasoning_cycles'])}** | Tasks: **{len(b['tasks'])}** | Assets: **{len(b['assets'])}** | API operations: **{len(b['api_operations'])}**\n\n## Findings\n\n{chr(10).join(finding_lines) if finding_lines else '_None._'}\n\n## Surface\n\n{table_md(b['surface'],[('Priority','priority'),('Type','entity_type'),('Value','value'),('Score','score'),('Rationale','rationale')])}\n## Authentication / Authorization\n\nPrincipals: {len(b['auth_principals'])}; sessions: {len(b['auth_sessions'])}; authorization entries: {len(b['authorization_matrix'])}.\n## Business Logic\n\nWorkflows: {len(b['workflows'])}; transitions: {len(b['workflow_transitions'])}; candidate anomalies: {len(b['business_logic_anomalies'])}.\n## Agent Activity\n\nReasoning cycles: {len(b['reasoning_cycles'])}; decisions: {len(b['decisions'])}; selections: {len(b['selections'])}.\n",
        }
        filenames={'executive':'executive-summary.md','technical_findings':'technical-findings.md','reconnaissance':'reconnaissance.md','attack_surface':'attack-surface.md','agent_activity':'agent-activity.md','execution_history':'execution-history.md','evidence_index':'evidence-index.md','full_engagement':'full-engagement.md'}
        result=[]
        for typ,body in docs.items():
            p=ws/'reports'/filenames[typ]; self._write_text(p,body); result.append((typ,p))
        return result
    def _snapshots(self,b,ws):
        out=[]; base=ws/'data'; base.mkdir(parents=True,exist_ok=True)
        for key,value in b.items():
            if key in {'scan','target'} or not isinstance(value,list): continue
            p=base/f'{key}.json'; self._write_json(p,redact_sensitive(value)); out.append(p)
        for key in ('scan','target'):
            p=base/f'{key}.json'; self._write_json(p,redact_sensitive(b[key])); out.append(p)
        return out
    def _copy_evidence(self,b,ws):
        out=[]
        for e in b['evidence']:
            src=Path(e['path']).resolve() if e.get('path') else None
            evidence_root=(self.data_root/'evidence').resolve()
            if src and src.exists() and src.is_file() and (src == evidence_root or evidence_root in src.parents):
                dest=ws/'evidence'/f"EVD-{e['id']:06d}{src.suffix or '.bin'}"
                dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(src,dest); out.append(dest)
        return out
    def _finding_files(self,b,ws):
        out=[]; sources={}
        for s in b['finding_sources']: sources.setdefault(s['finding_id'],[]).append(s)
        plans={p['finding_id']:p for p in b['validation_plans']}; steps={}
        for st in b['validation_steps']: steps.setdefault(st['plan_id'],[]).append(st)
        evidence={e['id']:e for e in b['evidence']}
        for f in b['findings']:
            d=ws/'findings'/f"FND-{f['id']:04d}"; d.mkdir(parents=True,exist_ok=True)
            body=f"# FND-{f['id']:04d} — {f['title']}\n\n- Category: `{f['category']}`\n- Severity: `{f['severity']}`\n- Confidence: `{f['confidence']:.2f}`\n- Status: `{f['status']}`\n- Subject: `{f['subject']}`\n\n## Impact\n\n{f['impact_summary']}\n\n## Rationale\n\n{f['rationale']}\n\n## Sources\n\n"
            for s in sources.get(f['id'],[]): body += f"- `{s['source_type']}:{s['source_id']}` — {s['relation']} — confidence {s['confidence']:.2f}\n"
            p=d/'vulnerability-report.md'; self._write_text(p,body); out.append(p)
            p=d/'finding.json'; self._write_json(p,redact_sensitive(f)); out.append(p)
            srcs=sources.get(f['id'],[]); self._write_json(d/'sources.json',redact_sensitive(srcs)); out.append(d/'sources.json')
            eids=[]
            for s in srcs:
                try: eids.extend(int(x) for x in json.loads(s.get('evidence_ids_json') or '[]'))
                except (TypeError,ValueError,json.JSONDecodeError): pass
            self._write_json(d/'evidence.json',[evidence[i] for i in dict.fromkeys(eids) if i in evidence]); out.append(d/'evidence.json')
            plan=plans.get(f['id'])
            if plan:
                payload=dict(plan); payload['steps']=steps.get(plan['id'],[]); self._write_json(d/'validation-plan.json',redact_sensitive(payload)); out.append(d/'validation-plan.json')
        return out
    def generate(self,scan_id:int)->ReportResult:
        b=self._bundle(scan_id); ws=self.targets_root/safe_slug(b['target']['value'])/f'scan-{scan_id}'; ws.mkdir(parents=True,exist_ok=True)
        report_files=self._report_docs(b,ws); snapshots=self._snapshots(b,ws); evidence=self._copy_evidence(b,ws); finding_files=self._finding_files(b,ws)
        self._write_text(ws/'README.md',f"# BELTU Workspace\n\nTarget: `{b['target']['value']}`\n\nScan: `{scan_id}`\n\nFolders: `reports/`, `findings/`, `evidence/`, `data/`, `packages/`.\n")
        source_files=[p for _,p in report_files]+snapshots+evidence+finding_files+[ws/'README.md']
        manifest_records=[]
        for p in sorted(source_files):
            data=p.read_bytes(); manifest_records.append({'path':p.relative_to(ws).as_posix(),'sha256':sha_bytes(data),'size_bytes':len(data)})
        manifest={'format':'beltu-stage18-workspace-v1','generated_at':utc_now(),'target':b['target']['value'],'scan_id':scan_id,'file_count':len(manifest_records),'files':manifest_records}
        mp=ws/'workspace-manifest.json'; self._write_json(mp,manifest)
        package_dir=ws/'packages'; package_dir.mkdir(exist_ok=True)
        package_paths=[]
        generation_fingerprint=sha_bytes(json.dumps({'scan_id':scan_id,'files':manifest_records},sort_keys=True).encode())
        all_package_inputs=source_files+[mp]
        for typ,p in report_files:
            zp=package_dir/f'{typ}.zip'
            with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
                for item in all_package_inputs: z.write(item,item.relative_to(ws).as_posix())
            package_paths.append(zp)
            pkg=self.repo.upsert_package(scan_id=scan_id,report_type=typ,relative_path=p.relative_to(ws).as_posix(),generation_fingerprint=generation_fingerprint,absolute_path=str(p))
            entries=[]
            for item in [p]+evidence+finding_files+[mp]:
                entries.append({'kind':'report' if item==p else ('manifest' if item==mp else 'artifact'),'relative_path':item.relative_to(ws).as_posix(),'sha256':sha_bytes(item.read_bytes()),'size_bytes':item.stat().st_size,'mime_type':'text/markdown' if item.suffix=='.md' else ('application/json' if item.suffix=='.json' else 'application/octet-stream')})
            self.repo.replace_files(pkg.id,entries)
        full=package_dir/'full-engagement-package.zip'
        with zipfile.ZipFile(full,'w',zipfile.ZIP_DEFLATED) as z:
            for item in all_package_inputs: z.write(item,item.relative_to(ws).as_posix())
        package_paths.append(full)
        self.repo.upsert_package(scan_id=scan_id, report_type='full_package', relative_path=full.relative_to(ws).as_posix(), generation_fingerprint=generation_fingerprint, absolute_path=str(full))
        files=list(source_files)+[mp]+package_paths
        return ReportResult(scan_id,b['target']['value'],str(ws),tuple(p.relative_to(ws).as_posix() for p in sorted(files)),tuple(p.relative_to(ws).as_posix() for p in package_paths),mp.relative_to(ws).as_posix())
