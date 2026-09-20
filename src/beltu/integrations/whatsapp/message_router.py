from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class ApprovalCommand:
    action: Literal["approve", "reject"]
    approval_id: int
    token: str | None


_APPROVE = re.compile(r"^\s*(?:YES|APPROVE)\s+(\d+)\s+([A-Za-z0-9_-]+)\s*$", re.I)
_REJECT = re.compile(r"^\s*(?:NO|REJECT)\s+(\d+)(?:\s+([A-Za-z0-9_-]+))?\s*$", re.I)


def parse_approval_command(text: str) -> ApprovalCommand | None:
    if match := _APPROVE.match(text):
        return ApprovalCommand("approve", int(match.group(1)), match.group(2))
    if match := _REJECT.match(text):
        return ApprovalCommand("reject", int(match.group(1)), match.group(2))
    return None
