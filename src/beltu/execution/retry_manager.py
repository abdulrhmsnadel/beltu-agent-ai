from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RetryDecision:
    retry: bool
    delay_seconds: float
    reason: str


class RetryManager:
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0, jitter: float = 0.10) -> None:
        self.base_delay = max(0.0, base_delay)
        self.max_delay = max(self.base_delay, max_delay)
        self.jitter = max(0.0, jitter)

    def decide(self, attempts: int, max_attempts: int, *, retryable: bool = True) -> RetryDecision:
        if not retryable:
            return RetryDecision(False, 0.0, 'non-retryable failure')
        if attempts >= max_attempts:
            return RetryDecision(False, 0.0, 'attempt limit reached')
        raw = min(self.max_delay, self.base_delay * (2 ** max(0, attempts - 1)))
        spread = raw * self.jitter
        delay = max(0.0, min(self.max_delay, raw + random.uniform(-spread, spread))) if spread else raw
        return RetryDecision(True, delay, 'retry scheduled')
