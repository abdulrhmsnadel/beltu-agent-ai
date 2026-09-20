from pathlib import Path

from beltu.common.enums import ScanStatus, TaskStatus
from beltu.storage.database import Database
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository


def test_interrupted_scan_and_task_are_recovered(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    tasks = TaskRepository(db)

    target = targets.add("example.com")
    scan = scans.create(target.id, ScanStatus.RUNNING)
    task = tasks.create(scan.id, "agent.evaluate")
    tasks.mark_running(task.id)

    assert tasks.get(task.id).status == TaskStatus.RUNNING.value
    assert scans.recover_interrupted() == 1
    assert tasks.recover_interrupted() == 1
    assert scans.get(scan.id).status == ScanStatus.PENDING.value
    assert tasks.get(task.id).status == TaskStatus.PENDING.value
