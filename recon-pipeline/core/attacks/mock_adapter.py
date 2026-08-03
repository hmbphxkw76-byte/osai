"""Mock adapter for tools not yet wired (garak/giskard/promptfoo) (P0-4-D).

Produces a valid Finding without external dependencies so the closed loop
is testable end-to-end. Replace with real adapters when the tool is available.
"""
from __future__ import annotations

from core.attacks.base import AttackAdapter
from core.models.finding import Finding


class MockAdapter(AttackAdapter):
    tool_name = "mock"

    def __init__(self, tool: str = "mock") -> None:
        self.tool_name = tool

    def run(
        self,
        target: str,
        payload_ref: str,
        strategy: str,
        owasp_id: str = "",
        max_trials: int = 3,
    ) -> Finding:
        # Deterministic mock: 1 trial, success=False (no real execution)
        return Finding(
            owasp_id=owasp_id,
            attack_strategy=strategy,
            target=target,
            tool=self.tool_name,
            ai_trials=max_trials,
            ai_successes=0,
            ai_oracle_kind="mock",
            payload_ref=payload_ref,
            success=False,
            metadata={"mock": True},
        )
