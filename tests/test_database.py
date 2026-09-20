from pathlib import Path

from beltu.storage.database import Database
from beltu.storage.repositories.target_repository import TargetRepository


def test_database_persists_target(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    repo = TargetRepository(db)
    created = repo.add("example.com")

    db2 = Database(tmp_path / "beltu.db")
    db2.initialize()
    loaded = TargetRepository(db2).get(created.id)

    assert loaded is not None
    assert loaded.value == "example.com"
    assert loaded.status == "new"
