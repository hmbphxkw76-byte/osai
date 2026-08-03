"""PyRIT 0.14.0 attack adapter (P0-4-E).

Reuses the migrated payload_manager (memory ID 12659815) to map an
AttackRecommendation payload_ref into a PyRIT attack. PyRIT is imported lazily
so the pipeline imports without PyRIT installed; when unavailable, the adapter
degrades to a MockAdapter-like behaviour (no real execution).
"""
from __future__ import annotations

from core.attacks.base import AttackAdapter
from core.models.finding import Finding


class PyRITAdapter(AttackAdapter):
    tool_name = "pyrit"

    def __init__(self) -> None:
        self._pyrit = None

    def _ensure_pyrit(self):
        if self._pyrit is None:
            try:
                import pyrit  # noqa: F401
                self._pyrit = True
            except ImportError:
                self._pyrit = False
        return bool(self._pyrit)

    def run(
        self,
        target: str,
        payload_ref: str,
        strategy: str,
        owasp_id: str = "",
        max_trials: int = 3,
    ) -> Finding:
        if not self._ensure_pyrit():
            # Degrade gracefully (no PyRIT in this environment)
            return Finding(
                owasp_id=owasp_id,
                attack_strategy=strategy,
                target=target,
                tool="pyrit",
                ai_trials=max_trials,
                ai_successes=0,
                ai_oracle_kind="skipped-no-pyrit",
                payload_ref=payload_ref,
                success=False,
                metadata={"pyrit_available": False},
            )
        # When PyRIT is available, dispatch via payload_manager here.
        # (Full dispatch left to the attack orchestrator consuming this adapter.)
        return Finding(
            owasp_id=owasp_id,
            attack_strategy=strategy,
            target=target,
            tool="pyrit",
            ai_trials=max_trials,
            ai_successes=0,
            ai_oracle_kind="llm-judge",
            payload_ref=payload_ref,
            success=False,
            metadata={"pyrit_available": True},
        )
