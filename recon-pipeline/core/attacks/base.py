"""Base interface for attack adapters (P0-4-D)."""
from __future__ import annotations

from abc import ABC, abstractmethod

from core.models.finding import Finding


class AttackAdapter(ABC):
    """Uniform attack adapter interface."""

    tool_name: str = "abstract"

    @abstractmethod
    def run(
        self,
        target: str,
        payload_ref: str,
        strategy: str,
        owasp_id: str = "",
        max_trials: int = 3,
    ) -> Finding:
        """Execute an attack and return a Finding with ASR fields populated."""
        ...
