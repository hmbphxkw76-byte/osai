# -*- coding: utf-8 -*-
"""attack_knowledge_base.py — Historical Attack Knowledge Base for Cross-Target Transfer.

Stores and retrieves attack results across targets to enable knowledge transfer.
High-ASR techniques discovered on one target can inform attacks on similar targets.

Academic basis:
    - Chao et al. (arXiv:2310.08419): PAIR — transferable prompts across models
    - Liu et al. (arXiv:2309.00614): Jailbreaking ChatGPT via prompt transfer
    - Zou et al. (arXiv:2307.15043): Transferable adversarial attacks on LLMs

Constitution compliance:
    - R-DECIDE-2: Audit trail for cross-target knowledge transfer
    - R-DATA-2: ASR centrality in decision making

Data Flow:
    Attack Results → knowledge_base.record() → Persistent Storage
    New Target → knowledge_base.query() → Transferable Strategies
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AttackKnowledgeEntry:
    """Single entry in the attack knowledge base."""
    target_id: str
    target_type: str  # e.g., "openai", "anthropic", "azure"
    technique: str
    objective: str
    asr: float
    iterations: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class KnowledgeQuery:
    """Query parameters for knowledge base lookup."""
    target_type: str | None = None
    technique: str | None = None
    min_asr: float = 0.0
    limit: int = 10


class AttackKnowledgeBase:
    """Knowledge base for storing and querying attack results.

    Enables cross-target knowledge transfer by maintaining a history
    of successful attack strategies across different targets.
    """

    def __init__(self, storage_path: Path | str | None = None) -> None:
        """Initialize knowledge base.

        Args:
            storage_path: Path to JSON file for persistent storage.
                         If None, uses in-memory only.
        """
        self.storage_path = Path(storage_path) if storage_path else None
        self.entries: list[AttackKnowledgeEntry] = []
        self._technique_index: dict[str, list[int]] = {}
        self._type_index: dict[str, list[int]] = {}

        # Load existing data if available
        if self.storage_path and self.storage_path.exists():
            self._load()

    def record(self, entry: AttackKnowledgeEntry) -> None:
        """Record a new attack result.

        Args:
            entry: AttackKnowledgeEntry to store.
        """
        idx = len(self.entries)
        self.entries.append(entry)

        # Update indices
        if entry.technique not in self._technique_index:
            self._technique_index[entry.technique] = []
        self._technique_index[entry.technique].append(idx)

        if entry.target_type not in self._type_index:
            self._type_index[entry.target_type] = []
        self._type_index[entry.target_type].append(idx)

        logger.debug(
            "[KnowledgeBase] Recorded: %s/%s (ASR=%.1f%%)",
            entry.target_type, entry.technique, entry.asr * 100,
        )

    def query(self, query: KnowledgeQuery) -> list[AttackKnowledgeEntry]:
        """Query the knowledge base for relevant entries.

        Args:
            query: KnowledgeQuery with filter parameters.

        Returns:
            List of matching AttackKnowledgeEntry, sorted by ASR descending.
        """
        results = []

        for entry in self.entries:
            # Apply filters
            if query.target_type and entry.target_type != query.target_type:
                continue
            if query.technique and entry.technique != query.technique:
                continue
            if entry.asr < query.min_asr:
                continue

            results.append(entry)

        # Sort by ASR descending
        results.sort(key=lambda e: e.asr, reverse=True)

        return results[: query.limit]

    def get_best_techniques(
        self,
        target_type: str,
        min_asr: float = 0.3,
        limit: int = 5,
    ) -> list[tuple[str, float]]:
        """Get best performing techniques for a target type.

        Args:
            target_type: Target model type.
            min_asr: Minimum ASR threshold.
            limit: Maximum number of results.

        Returns:
            List of (technique, avg_asr) tuples, sorted by ASR.
        """
        # Filter by type and min ASR
        type_indices = self._type_index.get(target_type, [])
        filtered = [
            self.entries[i]
            for i in type_indices
            if self.entries[i].asr >= min_asr
        ]

        if not filtered:
            return []

        # Aggregate by technique
        tech_asrs: dict[str, list[float]] = {}
        for entry in filtered:
            if entry.technique not in tech_asrs:
                tech_asrs[entry.technique] = []
            tech_asrs[entry.technique].append(entry.asr)

        # Calculate averages and sort
        avg_asrs = [
            (tech, sum(asrs) / len(asrs))
            for tech, asrs in tech_asrs.items()
        ]
        avg_asrs.sort(key=lambda x: x[1], reverse=True)

        return avg_asrs[:limit]

    def get_transferable_strategies(
        self,
        current_target_type: str,
        current_target_id: str,
    ) -> dict[str, Any]:
        """Get transferable strategies from previous targets.

        Cross-target knowledge transfer: uses data from similar targets
        to bootstrap strategy selection for the current target.

        Args:
            current_target_type: Type of the current target.
            current_target_id: ID of the current target (to exclude).

        Returns:
            Dict with transferable strategies and metadata.
        """
        # Get entries from same type but different target
        type_indices = self._type_index.get(current_target_type, [])
        previous_entries = [
            self.entries[i]
            for i in type_indices
            if self.entries[i].target_id != current_target_id
        ]

        if not previous_entries:
            return {
                "has_transferable_knowledge": False,
                "recommendation": "No previous data for this target type",
            }

        # Get best techniques
        best_techniques = self.get_best_techniques(current_target_type)

        return {
            "has_transferable_knowledge": True,
            "previous_targets": len(set(e.target_id for e in previous_entries)),
            "best_techniques": best_techniques,
            "total_history": len(previous_entries),
        }

    def save(self) -> None:
        """Persist knowledge base to disk."""
        if not self.storage_path:
            logger.debug("[KnowledgeBase] No storage path configured, skipping save")
            return

        try:
            import json
            data = [
                {
                    "target_id": e.target_id,
                    "target_type": e.target_type,
                    "technique": e.technique,
                    "objective": e.objective,
                    "asr": e.asr,
                    "iterations": e.iterations,
                    "metadata": e.metadata,
                }
                for e in self.entries
            ]
            self.storage_path.write_text(json.dumps(data, indent=2))
            logger.info("[KnowledgeBase] Saved %d entries", len(self.entries))
        except Exception as e:
            logger.error("[KnowledgeBase] Save failed: %s", e)

    def _load(self) -> None:
        """Load knowledge base from disk."""
        try:
            import json
            data = json.loads(self.storage_path.read_text())
            self.entries = [
                AttackKnowledgeEntry(
                    target_id=d["target_id"],
                    target_type=d["target_type"],
                    technique=d["technique"],
                    objective=d["objective"],
                    asr=d["asr"],
                    iterations=d.get("iterations", 1),
                    metadata=d.get("metadata", {}),
                )
                for d in data
            ]
            # Rebuild indices
            for idx, entry in enumerate(self.entries):
                if entry.technique not in self._technique_index:
                    self._technique_index[entry.technique] = []
                self._technique_index[entry.technique].append(idx)
                if entry.target_type not in self._type_index:
                    self._type_index[entry.target_type] = []
                self._type_index[entry.target_type].append(idx)
            logger.info("[KnowledgeBase] Loaded %d entries", len(self.entries))
        except Exception as e:
            logger.error("[KnowledgeBase] Load failed: %s", e)
