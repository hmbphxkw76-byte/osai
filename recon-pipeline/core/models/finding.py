"""Unified Finding model for the recon → attack → ASR closed loop (P0-4-A).

Mirrors RedAmon's normalizer.Finding dataclass:
  - ai_asr: attack success rate (successes / trials)
  - ai_trials: number of attack attempts
  - ai_oracle_kind: how success was judged (e.g. 'llm-judge', 'keyword', 'manual')
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    owasp_id: str = ""
    attack_strategy: str = ""
    target_type: str = ""
    target: str = ""
    tool: str = ""
    # ASR fields
    ai_trials: int = 0
    ai_successes: int = 0
    ai_oracle_kind: str = "keyword"
    # Evidence
    payload_ref: str = ""
    response_excerpt: str = ""
    success: bool = False
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ai_asr(self) -> float:
        """Attack success rate in [0, 1]."""
        if self.ai_trials <= 0:
            return 0.0
        return round(self.ai_successes / self.ai_trials, 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "owasp_id": self.owasp_id,
            "attack_strategy": self.attack_strategy,
            "target_type": self.target_type,
            "target": self.target,
            "tool": self.tool,
            "ai_trials": self.ai_trials,
            "ai_successes": self.ai_successes,
            "ai_asr": self.ai_asr,
            "ai_oracle_kind": self.ai_oracle_kind,
            "payload_ref": self.payload_ref,
            "response_excerpt": self.response_excerpt[:500],
            "success": self.success,
            "error": self.error,
            "metadata": self.metadata,
        }
