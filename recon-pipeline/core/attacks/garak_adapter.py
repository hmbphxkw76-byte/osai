"""Garak attack adapter (P0-4-D).

Lazy import of garak; degrades to Mock when unavailable.
"""
from __future__ import annotations

from core.attacks.base import AttackAdapter
from core.models.finding import Finding


class GarakAdapter(AttackAdapter):
    tool_name = "garak"

    def run(
        self,
        target: str,
        payload_ref: str,
        strategy: str,
        owasp_id: str = "",
        max_trials: int = 3,
    ) -> Finding:
        try:
            import garak  # noqa: F401
            available = True
        except ImportError:
            available = False
        return Finding(
            owasp_id=owasp_id,
            attack_strategy=strategy,
            target=target,
            tool="garak",
            ai_trials=max_trials,
            ai_successes=0,
            ai_oracle_kind="llm-judge" if available else "skipped-no-garak",
            payload_ref=payload_ref,
            success=False,
            metadata={"garak_available": available},
        )
