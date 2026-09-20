from beltu.common.enums import ScanStatus, TargetStatus, TaskStatus

_TARGET_ALLOWED: dict[TargetStatus, set[TargetStatus]] = {
    TargetStatus.NEW: {TargetStatus.ACTIVE, TargetStatus.BLOCKED},
    TargetStatus.ACTIVE: {TargetStatus.PAUSED, TargetStatus.COMPLETED, TargetStatus.BLOCKED},
    TargetStatus.PAUSED: {TargetStatus.ACTIVE, TargetStatus.BLOCKED},
    TargetStatus.COMPLETED: set(),
    TargetStatus.BLOCKED: {TargetStatus.NEW},
}

_SCAN_ALLOWED: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.PENDING: {ScanStatus.RUNNING, ScanStatus.CANCELLED},
    ScanStatus.RUNNING: {ScanStatus.PAUSED, ScanStatus.SUCCEEDED, ScanStatus.FAILED, ScanStatus.CANCELLED},
    ScanStatus.PAUSED: {ScanStatus.RUNNING, ScanStatus.CANCELLED},
    ScanStatus.SUCCEEDED: set(),
    ScanStatus.FAILED: {ScanStatus.PENDING, ScanStatus.CANCELLED},
    ScanStatus.CANCELLED: set(),
}

_TASK_ALLOWED: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.PENDING: {TaskStatus.RUNNING, TaskStatus.CANCELLED},
    TaskStatus.RUNNING: {TaskStatus.WAITING_APPROVAL, TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELLED},
    TaskStatus.WAITING_APPROVAL: {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.CANCELLED},
    TaskStatus.FAILED: {TaskStatus.PENDING, TaskStatus.CANCELLED},
    TaskStatus.SUCCEEDED: set(),
    TaskStatus.CANCELLED: set(),
}


def can_transition(current, new) -> bool:
    table = _TARGET_ALLOWED if isinstance(current, TargetStatus) else _SCAN_ALLOWED if isinstance(current, ScanStatus) else _TASK_ALLOWED
    return new in table[current]
