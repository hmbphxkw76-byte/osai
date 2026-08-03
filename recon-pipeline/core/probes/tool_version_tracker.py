# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Tool Version Tracker — cross-scan tool hash comparison + rug-pull detection.

Aligns with RedAmon agentic/orchestrator_helpers patterns:
  - tool_hash (SHA256) tracking across sessions
  - instructions_hash pin (rug-pull detection)
  - Diff reporting: new tools, removed tools, modified tools

Non-LLM guarantee: pure SHA256 comparison, zero ML dependencies.

Academic basis:
  - OWASP LLM06: tool behavior changes may indicate supply-chain compromise
  - VulnerableMCP: 13 Critical CVEs — rug-pull via tool signature mutation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolVersionRecord:
    """A single tool's version snapshot at a point in time.

    Attributes:
        tool_name: Tool identifier.
        tool_hash: SHA256 fingerprint of tool schema (name+description+inputSchema).
        instructions_hash: SHA256 of MCP server instructions (if available).
        server_url: MCP server or agent endpoint URL.
        first_seen: ISO timestamp of first observation.
        last_seen: ISO timestamp of most recent observation.
        checksum_history: All observed hashes over time (for drift analysis).
    """

    tool_name: str = ""
    tool_hash: str = ""
    instructions_hash: str = ""
    server_url: str = ""
    first_seen: str = ""
    last_seen: str = ""
    checksum_history: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_hash": self.tool_hash,
            "instructions_hash": self.instructions_hash,
            "server_url": self.server_url,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "checksum_count": len(self.checksum_history),
        }


@dataclass
class ToolDiffEntry:
    """A single difference between two tool version snapshots.

    Attributes:
        tool_name: Tool identifier.
        change_type: "added" | "removed" | "modified" | "instructions_changed".
        old_hash: Previous hash (empty for added).
        new_hash: Current hash (empty for removed).
        severity: "info" | "warning" | "critical".
        detail: Human-readable explanation.
    """

    tool_name: str = ""
    change_type: str = ""
    old_hash: str = ""
    new_hash: str = ""
    severity: str = "info"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "change_type": self.change_type,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class ToolVersionDiff:
    """Complete diff between two tool version baselines.

    Attributes:
        baseline_label: Label for the old baseline (e.g. "scan-2026-08-03").
        current_label: Label for the new baseline (e.g. "scan-2026-08-04").
        diffs: All detected changes.
        added_count: New tools not in baseline.
        removed_count: Tools removed since baseline.
        modified_count: Tools with changed hashes.
        rug_pull_alerts: Tools whose instructions_hash changed (rug-pull).
    """

    baseline_label: str = ""
    current_label: str = ""
    diffs: list[ToolDiffEntry] = field(default_factory=list)

    @property
    def added_count(self) -> int:
        return sum(1 for d in self.diffs if d.change_type == "added")

    @property
    def removed_count(self) -> int:
        return sum(1 for d in self.diffs if d.change_type == "removed")

    @property
    def modified_count(self) -> int:
        return sum(1 for d in self.diffs if d.change_type == "modified")

    @property
    def rug_pull_alerts(self) -> list[ToolDiffEntry]:
        return [d for d in self.diffs if d.change_type == "instructions_changed"]

    @property
    def has_changes(self) -> bool:
        return len(self.diffs) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_label": self.baseline_label,
            "current_label": self.current_label,
            "diffs": [d.to_dict() for d in self.diffs],
            "added_count": self.added_count,
            "removed_count": self.removed_count,
            "modified_count": self.modified_count,
            "rug_pull_alert_count": len(self.rug_pull_alerts),
            "has_changes": self.has_changes,
        }

    def summary(self) -> str:
        lines = [
            f"ToolVersionDiff: {self.baseline_label} → {self.current_label}",
            f"  Added: {self.added_count}",
            f"  Removed: {self.removed_count}",
            f"  Modified: {self.modified_count}",
            f"  Rug-pull alerts: {len(self.rug_pull_alerts)}",
        ]
        for d in self.diffs:
            lines.append(f"  [{d.severity:>8}] {d.change_type}: {d.tool_name} — {d.detail}")
        return "\n".join(lines)


class ToolVersionTracker:
    """Cross-scan tool version comparator.

    Tracks tool_hash and instructions_hash across multiple scans,
    producing diffs for supply-chain integrity monitoring.

    Usage::
        tracker = ToolVersionTracker()
        tracker.record_snapshot("scan-01", tools_from_mcp_probe)
        # ... later, after another scan ...
        diff = tracker.diff("scan-01", "scan-02")
        for alert in diff.rug_pull_alerts:
            logger.critical(f"RUG-PULL: {alert.tool_name} instructions changed!")
    """

    def __init__(self) -> None:
        self._snapshots: dict[str, dict[str, ToolVersionRecord]] = {}

    def record_snapshot(
        self,
        label: str,
        tools: list[dict[str, str]],
        timestamp: str = "",
    ) -> dict[str, ToolVersionRecord]:
        """Record a snapshot of tool versions.

        Args:
            label: Unique label for this scan (e.g. "scan-2026-08-03").
            tools: List of tool dicts with keys: tool_name, tool_hash,
                   instructions_hash (optional), server_url.
            timestamp: ISO timestamp for this snapshot.

        Returns:
            Dict of tool_name → ToolVersionRecord for this snapshot.
        """
        snapshot: dict[str, ToolVersionRecord] = {}
        for tool in tools:
            name = tool["tool_name"]
            tool_hash = tool.get("tool_hash", "")
            inst_hash = tool.get("instructions_hash", "")

            snapshot[name] = ToolVersionRecord(
                tool_name=name,
                tool_hash=tool_hash,
                instructions_hash=inst_hash,
                server_url=tool.get("server_url", ""),
                first_seen=timestamp,
                last_seen=timestamp,
                checksum_history=[tool_hash] if tool_hash else [],
            )

        self._snapshots[label] = snapshot
        return snapshot

    def diff(self, baseline_label: str, current_label: str) -> ToolVersionDiff:
        """Compare two snapshots and produce a diff.

        Args:
            baseline_label: Label of the older snapshot.
            current_label: Label of the newer snapshot.

        Returns:
            ToolVersionDiff with all detected changes.

        Raises:
            KeyError: If either label doesn't exist.
        """
        baseline = self._snapshots.get(baseline_label)
        current = self._snapshots.get(current_label)

        if baseline is None:
            raise KeyError(f"Baseline snapshot '{baseline_label}' not found")
        if current is None:
            raise KeyError(f"Current snapshot '{current_label}' not found")

        diff = ToolVersionDiff(
            baseline_label=baseline_label,
            current_label=current_label,
        )

        baseline_names = set(baseline.keys())
        current_names = set(current.keys())

        # Added tools
        for name in current_names - baseline_names:
            cur = current[name]
            diff.diffs.append(ToolDiffEntry(
                tool_name=name,
                change_type="added",
                new_hash=cur.tool_hash,
                severity="info",
                detail=f"New tool discovered at {cur.server_url}",
            ))

        # Removed tools
        for name in baseline_names - current_names:
            base = baseline[name]
            diff.diffs.append(ToolDiffEntry(
                tool_name=name,
                change_type="removed",
                old_hash=base.tool_hash,
                severity="warning",
                detail=f"Tool no longer available at {base.server_url}",
            ))

        # Modified tools (same name, different hash)
        for name in baseline_names & current_names:
            base = baseline[name]
            cur = current[name]

            if base.tool_hash != cur.tool_hash and cur.tool_hash:
                severity = "critical" if base.instructions_hash != cur.instructions_hash else "warning"
                diff.diffs.append(ToolDiffEntry(
                    tool_name=name,
                    change_type="modified",
                    old_hash=base.tool_hash,
                    new_hash=cur.tool_hash,
                    severity=severity,
                    detail=f"Tool schema changed at {cur.server_url}",
                ))

            # Instructions_hash changed = rug-pull alert
            if base.instructions_hash and cur.instructions_hash:
                if base.instructions_hash != cur.instructions_hash:
                    diff.diffs.append(ToolDiffEntry(
                        tool_name=name,
                        change_type="instructions_changed",
                        old_hash=base.instructions_hash,
                        new_hash=cur.instructions_hash,
                        severity="critical",
                        detail=f"RUG-PULL: Server instructions changed for {name} at {cur.server_url}",
                    ))

        return diff

    def get_snapshot(self, label: str) -> dict[str, ToolVersionRecord]:
        """Retrieve a snapshot by label."""
        if label not in self._snapshots:
            raise KeyError(f"Snapshot '{label}' not found")
        return self._snapshots[label]

    @property
    def snapshot_labels(self) -> list[str]:
        return sorted(self._snapshots.keys())
