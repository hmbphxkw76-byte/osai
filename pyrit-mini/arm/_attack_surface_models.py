"""arm/_attack_surface_models — Data models for attack surface mapping.

Extracted from `arm/attack_surface_mapper.py` (SRP): the vector categories, risk
levels, and the `AttackVector` / `AttackPlan` data contracts are shared by the
mapper and downstream planning code, so they live in their own dependency-free
module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class VectorCategory(Enum):
    """Four attack vector categories (aligned with NIST AI 100-2)."""

    ENTRY = "entry"
    PROCESSING = "processing"
    EXIT = "exit"
    PERSISTENCE = "persistence"


class RiskLevel(Enum):
    """Attack surface risk classification."""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class AttackVector:
    """A single identifiable attack vector in the target system."""

    vector_id: str
    category: VectorCategory
    subcategory: str
    description: str
    target_endpoint: str
    owasp_id: str
    risk_level: RiskLevel
    asr_prior: float = 0.5
    evidence: list[str] = field(default_factory=list)
    exploit_references: list[str] = field(default_factory=list)


@dataclass
class AttackPlan:
    """Prioritized attack plan generated from mapped vectors."""

    entry_vectors: list[AttackVector] = field(default_factory=list)
    processing_vectors: list[AttackVector] = field(default_factory=list)
    exit_vectors: list[AttackVector] = field(default_factory=list)
    persistence_vectors: list[AttackVector] = field(default_factory=list)

    def all_vectors(self) -> list[AttackVector]:
        """Return all vectors sorted by ASR prior descending."""
        all_vecs = (
            self.entry_vectors
            + self.processing_vectors
            + self.exit_vectors
            + self.persistence_vectors
        )
        return sorted(all_vecs, key=lambda v: v.asr_prior, reverse=True)

    def critical_vectors(self) -> list[AttackVector]:
        """Return only CRITICAL risk vectors."""
        return [v for v in self.all_vectors() if v.risk_level == RiskLevel.CRITICAL]

    def summary(self) -> dict[str, int]:
        """Return vector count summary by category."""
        return {
            "entry": len(self.entry_vectors),
            "processing": len(self.processing_vectors),
            "exit": len(self.exit_vectors),
            "persistence": len(self.persistence_vectors),
            "total": len(self.all_vectors()),
        }
