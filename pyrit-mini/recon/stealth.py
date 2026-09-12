# -*- coding: utf-8 -*-
"""recon.stealth - Stealth/Evasion configuration and policy management.

Compatibility module that provides stealth-related exports.
Actual implementations are in recon.stealth_config and recon.stealth_timing.

Constitution compliance:
    - R-H3: Single responsibility - re-exports from sub-modules
    - C4: Internal compatibility shim
"""

from __future__ import annotations

from recon.stealth_config import (
    StealthLevelManager as StealthConfigManager,
)
from recon.stealth_config import (
    StealthPolicy,
    get_stealth_manager,
)
from recon.stealth_timing import StealthTimer, stealth_delay


def get_stealth_policy(manager: StealthConfigManager | None = None) -> StealthPolicy:
    """Get the current stealth policy.

    Args:
        manager: Optional stealth manager instance. Uses global if None.

    Returns:
        Current StealthPolicy instance
    """
    if manager is None:
        manager = get_stealth_manager()
    return manager.policy


__all__ = [
    "StealthConfigManager",
    "StealthPolicy",
    "StealthTimer",
    "get_stealth_manager",
    "get_stealth_policy",
    "stealth_delay",
]
