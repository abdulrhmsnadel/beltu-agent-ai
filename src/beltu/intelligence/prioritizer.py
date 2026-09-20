from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse
import re
from beltu.intelligence.service import AssetIntelligenceService
from beltu.storage.database import Database
from beltu.storage.models.asset import Asset, AssetEndpoint, AssetService, AssetTechnology
from beltu.storage.models.surface import SurfacePriority
from beltu.storage.repositories.surface_priority_repository import SurfacePriorityRepository

PATH_HINTS = ("/admin", "/login", "/auth", "/api", "/graphql", "/oauth", "/checkout", "/cart", "/upload", "/webhook", "/internal", "/debug", "/actuator")
SENSITIVE_PORTS = {22, 23, 25, 110, 143, 445, 3389, 3306, 5432, 6379, 9200, 27017}

@dataclass(frozen=True, slots=True)
class SurfaceRankResult:
    priorities: tuple[SurfacePriority, ...]
    summary: dict[str, int]

class SurfacePrioritizer:
    """Derive explainable attack-surface priority from persisted inventory only."""
    def __init__(self, db: Database, inventory: AssetIntelligenceService | None = None) -> None:
        self.db=db
        self.inventory=inventory or AssetIntelligenceService(db)
        self.repo=SurfacePriorityRepository(db)

    @staticmethod
    def _priority(score: float) -> str:
        if score >= 0.85: return "P1"
        if score >= 0.65: return "P2"
        if score >= 0.40: return "P3"
        return "P4"

    @staticmethod
    def _asset_score(asset: Asset, children: int, root: bool=False):
        exposure = 1.0 if asset.asset_type == "ip" else 0.78 if asset.asset_type == "subdomain" else 0.70
        novelty = min(1.0, 0.55 + 0.08 * min(children, 5))
        sensitivity = 0.55 if root else (0.72 if children else 0.45)
        score=min(1.0, 0.42*exposure + 0.20*novelty + 0.28*sensitivity + 0.10*asset.confidence)
        return exposure, novelty, sensitivity, score, {"children":children,"asset_type":asset.asset_type}

    @staticmethod
    def _service_score(service: AssetService, asset: Asset | None):
        exposure = 0.92 if service.state in {"open","listening"} else 0.35
        sensitivity = 0.88 if service.port in SENSITIVE_PORTS else 0.58
        if service.service and service.service.lower() in {"http","https"}: sensitivity=max(sensitivity,0.68)
        novelty=0.70 if service.product or service.version else 0.58
        score=min(1.0,0.44*exposure+0.22*novelty+0.24*sensitivity+0.10*service.confidence)
        return exposure,novelty,sensitivity,score,{"port":service.port,"state":service.state,"service":service.service,"product":service.product,"version":service.version,"host":asset.normalized_value if asset else None}

    @staticmethod
    def _endpoint_score(endpoint: AssetEndpoint, asset: Asset | None):
        parsed=urlparse(endpoint.url if "://" in endpoint.url else "https://"+endpoint.url.lstrip("/"))
        path=(endpoint.path or parsed.path or "/").lower()
        hint=any(h in path for h in PATH_HINTS)
        api=endpoint.endpoint_type in {"api","openapi","graphql"}
        auth=bool(endpoint.auth_hint) or any(x in path for x in ("login","auth","oauth","session"))
        exposure=0.90 if api else 0.82
        sensitivity=min(1.0,0.45+0.20*hint+0.20*auth+0.15*(endpoint.method.upper() not in {"GET","HEAD"}))
        novelty=0.85 if hint or api else 0.62
        score=min(1.0,0.35*exposure+0.25*novelty+0.30*sensitivity+0.10*endpoint.confidence)
        return exposure,novelty,sensitivity,score,{"path_hint":hint,"api":api,"auth_hint":auth,"method":endpoint.method,"host":asset.normalized_value if asset else None}

    def rebuild(self, scan_id: int) -> SurfaceRankResult:
        inventory=self.inventory.rebuild(scan_id)
        assets_by_id={a.id:a for a in inventory.assets}
        rels=self.inventory.assets.relations_for_scan(scan_id)
        children:dict[int,int]={}
        for r in rels: children[r.parent_asset_id]=children.get(r.parent_asset_id,0)+1
        rows:list[SurfacePriority]=[]
        for a in inventory.assets:
            root=(a.asset_type=="domain" and bool(a.metadata.get("registered")))
            e,n,s,score,signals=self._asset_score(a,children.get(a.id,0),root)
            rows.append(self.repo.upsert(scan_id=scan_id,entity_type="asset",entity_id=a.id,value=a.normalized_value,score=score,priority=self._priority(score),exposure=e,novelty=n,sensitivity=s,confidence=a.confidence,rationale=f"Asset exposure={e:.2f}, novelty={n:.2f}, sensitivity={s:.2f}; {a.asset_type} with {children.get(a.id,0)} known child relation(s).",signals=signals))
        for s in self.inventory.assets.list_services(scan_id):
            a=assets_by_id.get(s.asset_id); e,n,se,score,signals=self._service_score(s,a)
            rows.append(self.repo.upsert(scan_id=scan_id,entity_type="service",entity_id=s.id,value=f"{a.normalized_value if a else s.asset_id}:{s.port}/{s.transport}",score=score,priority=self._priority(score),exposure=e,novelty=n,sensitivity=se,confidence=s.confidence,rationale=f"Service state={s.state}, port={s.port}, service={s.service or 'unknown'}; sensitivity={se:.2f}.",signals=signals))
        for ept in self.inventory.assets.list_endpoints(scan_id):
            a=assets_by_id.get(ept.asset_id); e,n,se,score,signals=self._endpoint_score(ept,a)
            rows.append(self.repo.upsert(scan_id=scan_id,entity_type="endpoint",entity_id=ept.id,value=ept.url,score=score,priority=self._priority(score),exposure=e,novelty=n,sensitivity=se,confidence=ept.confidence,rationale=f"Endpoint method={ept.method}, path={ept.path}; API/auth-sensitive signals={signals['api'] or signals['auth_hint']}.",signals=signals))
        rows.sort(key=lambda x:(x.score,x.priority,x.entity_type), reverse=True)
        summary={p:sum(1 for r in rows if r.priority==p) for p in ("P1","P2","P3","P4")}
        summary["total"]=len(rows)
        return SurfaceRankResult(tuple(rows),summary)

    def context_payload(self, scan_id:int, limit:int=20)->dict:
        result=self.rebuild(scan_id)
        return {"summary":result.summary,"priorities":[self._payload(r) for r in result.priorities[:limit]]}

    @staticmethod
    def _payload(r:SurfacePriority)->dict:
        return {"id":r.id,"entity_type":r.entity_type,"entity_id":r.entity_id,"value":r.value,"score":r.score,"priority":r.priority,"exposure":r.exposure,"novelty":r.novelty,"sensitivity":r.sensitivity,"confidence":r.confidence,"rationale":r.rationale,"signals":r.signals}
