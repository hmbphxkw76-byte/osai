"""Safety boundary and Rules of Engagement (RoE) enforcement (P0-4-B/C/G).

P0-4-B: safety.enforce() — dual gate:
  1. hard_blocked_categories floor (RCE / CSAM / etc. never dispatched)
  2. RoE gate (time window + excluded hosts + max trials)

P0-4-G: RoE dataclass carries time_window / excluded_hosts / max_trials.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time
from typing import Any


# P0-4-C: Categories that are HARD-BLOCKED regardless of RoE.
HARD_BLOCKED_CATEGORIES: set[str] = {
    "rce",
    "remote_code_execution",
    "csam",
    "malware_generation",
    "cwe-78",  # OS command injection (treated as RCE surface)
}


@dataclass
class RoE:
    """Rules of Engagement for an attack run (P0-4-G)."""
    time_window: tuple[str, str] | None = None  # ("09:00", "17:00") local time
    excluded_hosts: list[str] = field(default_factory=list)
    max_trials: int = 10
    allowed_categories: list[str] = field(default_factory=list)  # empty = all non-blocked

    def in_time_window(self, now: datetime | None = None) -> bool:
        if not self.time_window:
            return True
        now = now or datetime.now()
        start = time.fromisoformat(self.time_window[0])
        end = time.fromisoformat(self.time_window[1])
        return start <= now.time() <= end

    def is_host_excluded(self, host: str) -> bool:
        return any(h in host for h in self.excluded_hosts)


def is_hard_blocked(category: str) -> bool:
    """P0-4-C: Returns True if category is in the hard-blocked floor."""
    return category.lower() in HARD_BLOCKED_CATEGORIES


def enforce(
    category: str,
    target: str,
    roe: RoE | None = None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Enforce safety boundary + RoE. Returns (allowed, reason).

    P0-4-B: Hard-blocked categories rejected first, then RoE gates.
    """
    if is_hard_blocked(category):
        return False, f"hard_blocked_category:{category}"

    if roe is None:
        return True, "no_roe"

    if not roe.in_time_window(now):
        return False, "roe_time_window"

    if roe.is_host_excluded(target):
        return False, f"roe_excluded_host:{target}"

    if roe.allowed_categories and category.lower() not in [c.lower() for c in roe.allowed_categories]:
        return False, f"roe_category_not_allowed:{category}"

    return True, "allowed"
