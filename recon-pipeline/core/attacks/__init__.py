"""Attack execution adapters for the recon → attack → ASR loop (P0-4-D/E).

Adapters wrap external attack tools behind a uniform interface:
    run(target, payload_ref, strategy) -> Finding

P0-4-E: PyRIT 0.14.0 adapter is preferred and reuses the migrated
payload_manager (see memory ID 12659815).
"""
from __future__ import annotations

from .base import AttackAdapter
from .mock_adapter import MockAdapter
from .pyrit_adapter import PyRITAdapter

__all__ = ["AttackAdapter", "MockAdapter", "PyRITAdapter"]


def get_adapter(tool: str) -> AttackAdapter:
    """Return the adapter for a named tool (P0-4-D dispatch)."""
    tool = tool.lower()
    if tool == "pyrit":
        return PyRITAdapter()
    if tool in ("garak", "giskard", "promptfoo"):
        # Pluggable adapters; fall back to Mock when the tool is not importable.
        try:
            if tool == "garak":
                from .garak_adapter import GarakAdapter
                return GarakAdapter()
        except Exception:  # noqa: BLE001
            pass
        return MockAdapter(tool)
    return MockAdapter(tool)
