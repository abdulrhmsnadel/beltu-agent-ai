from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from beltu.storage.models.asset import Asset, AssetRelation

@dataclass(frozen=True, slots=True)
class AssetGraphSnapshot:
    nodes: tuple[str, ...]
    edges: tuple[tuple[str, str, str], ...]

class AssetGraphBuilder:
    def build(self, assets: Iterable[Asset], relations: Iterable[AssetRelation]) -> AssetGraphSnapshot:
        assets_by_id = {a.id: a for a in assets}
        nodes = {a.normalized_value for a in assets_by_id.values()}
        edges: set[tuple[str,str,str]] = set()
        for rel in relations:
            parent = assets_by_id.get(rel.parent_asset_id)
            child = assets_by_id.get(rel.child_asset_id)
            if parent and child:
                edges.add((parent.normalized_value, child.normalized_value, rel.relation))
        return AssetGraphSnapshot(tuple(sorted(nodes)), tuple(sorted(edges)))
