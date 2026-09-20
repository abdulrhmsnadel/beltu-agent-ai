from beltu.common.enums import TargetStatus
from beltu.core.state_machine import can_transition


def test_valid_transitions():
    assert can_transition(TargetStatus.NEW, TargetStatus.ACTIVE)
    assert can_transition(TargetStatus.ACTIVE, TargetStatus.PAUSED)
    assert can_transition(TargetStatus.PAUSED, TargetStatus.ACTIVE)


def test_invalid_transition():
    assert not can_transition(TargetStatus.COMPLETED, TargetStatus.ACTIVE)
