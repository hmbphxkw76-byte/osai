"""core/phases/technique_blueprint — unified optimal combination selector.

Given an attack object + target fingerprint, produce the ``TechniqueBlueprint``:
the best-practice, ASR-reranked combination of seeds + converters + strike
strategies + scorers, with ``config/components/<obj>.yaml`` as the single
source of truth for the default combo.

Read-only lookup + reranking; contains NO attack execution logic (mirrors
``core.registry.ComponentRegistry``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core.object_taxonomy import component_for_object, normalize_object
from core.registry import get_registry
from core.technique_registry import SCORER_REGISTRY, resolve_converters

logger = logging.getLogger(__name__)


@dataclass
class TechniqueBlueprint:
    """The ASR-reranked optimal combination of the four attack axes."""

    object_key: str
    seed_files: list[Path] = field(default_factory=list)
    converters: list[Any] = field(default_factory=list)
    strike_strategies: list[tuple[int, str, int]] = field(default_factory=list)
    t0_scorer: Callable | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize for logging / reporting."""
        return {
            "object_key": self.object_key,
            "seed_files": [str(p) for p in self.seed_files],
            "converters": [type(c).__name__ for c in self.converters],
            "strike_strategies": self.strike_strategies,
            "t0_scorer": getattr(self.t0_scorer, "__name__", None),
        }


def _resolve_seed_files(seed_sets: list[str]) -> list[Path]:
    """Resolve ``seed_sets`` directory globs to ``.prompt`` file list (deduped)."""
    out: list[Path] = []
    root = Path(__file__).resolve().parent.parent
    seen: set[Path] = set()
    for entry in seed_sets or []:
        dir_path = root / entry.rstrip("*").rstrip("/")
        if dir_path.is_dir():
            for f in sorted(dir_path.glob("*.prompt")):
                if f not in seen:
                    seen.add(f)
                    out.append(f)
    return out


def _resolve_t0_scorer(raw: dict[str, Any]) -> Callable | None:
    """Resolve the component's T0 checker: registered scorer first, else dotted attr."""
    assess = raw.get("assess") or {}
    t0 = assess.get("t0_check") if isinstance(assess, dict) else None
    if not t0:
        return None
    # registered scorers take precedence (plug-in path)
    for ctype, fn in SCORER_REGISTRY.items():
        if ctype and ctype in str(t0):
            return fn
    # fallback: import the dotted ``module:attr`` (existing behavior)
    try:
        module_path, attr = str(t0).split(":", 1)
        import importlib

        mod = importlib.import_module(module_path)
        return getattr(mod, attr)
    except Exception as e:
        logger.warning("[BLUEPRINT] t0_check unresolvable %r: %s", t0, e)
        return None


def _target_type_for(raw: dict[str, Any]) -> str:
    """Best-effort target_type for the l5_optimal fallback."""
    tt = (raw.get("target_type") or "").lower()
    if tt:
        return tt
    if (raw.get("id") or "") == "mcp":
        return "mcp_agent"
    return "unknown"


def _asr_rerank(converters: list[Any], *, ctx: Any) -> list[Any]:
    """Reuse the existing ASR prune/rerank from arm.converter_selector (no new logic)."""
    try:
        from arm.converter_selector import _prune_low_asr_converters

        return _prune_low_asr_converters(converters, ctx=ctx)
    except Exception:
        return converters


def _select_converters(raw: dict[str, Any], *, converter_target: Any, ctx: Any) -> list[Any]:
    """Converters: component YAML ``converter_presets`` -> registry -> ASR rerank.

    W0 fallback: when ``converter_presets`` is empty/unresolved, use the existing
    target-aware ``l5_optimal`` so behavior is byte-for-byte equivalent to today.
    """
    presets = raw.get("converter_presets") or []
    if presets:
        converters = resolve_converters(presets, converter_target=converter_target)
        if converters:
            converters = _asr_rerank(converters, ctx=ctx)
            logger.info("[BLUEPRINT] resolved %d converters from converter_presets", len(converters))
            return converters
        logger.info("[BLUEPRINT] converter_presets empty/unresolved -> fallback l5_optimal")
    try:
        from arm.converter_presets import l5_optimal

        converters = l5_optimal(converter_target, target_type=_target_type_for(raw))
        return _asr_rerank(converters, ctx=ctx)
    except Exception as e:
        logger.warning("[BLUEPRINT] l5_optimal fallback failed: %s", e)
        return []


def _select_strike(norm: str) -> list[tuple[int, str, int]]:
    """Strike strategies: existing per-target TARGET_STRATEGY_MAP (unchanged)."""
    try:
        from strike.common.progressive_strike import TARGET_STRATEGY_MAP

        return TARGET_STRATEGY_MAP.get(norm, TARGET_STRATEGY_MAP.get("model", []))
    except Exception:
        return []


def build_optimal_blueprint(
    object_key: str,
    *,
    fingerprint: dict[str, Any] | None = None,
    converter_target: Any | None = None,
    ctx: Any = None,
) -> TechniqueBlueprint:
    """Build the ASR-reranked optimal combination for an attack object.

    Args:
        object_key: canonical object or component key (e.g. ``"mcp"``).
        fingerprint: optional target fingerprint (reserved for future capability routing).
        converter_target: optional PyRIT target fed to converter builders.
        ctx: optional PipelineContext (used only for ASR rerank history).

    Returns:
        TechniqueBlueprint with seeds / converters / strike / scorer populated.
    """
    norm = normalize_object(object_key) or object_key
    reg = get_registry()
    raw = reg.get(norm) or reg.get(component_for_object(norm) or "")
    if raw is None:
        logger.warning("[BLUEPRINT] No component declaration for %r", object_key)
        return TechniqueBlueprint(object_key=norm)

    return TechniqueBlueprint(
        object_key=norm,
        seed_files=_resolve_seed_files(raw.get("seed_sets") or []),
        converters=_select_converters(raw, converter_target=converter_target, ctx=ctx),
        strike_strategies=_select_strike(norm),
        t0_scorer=_resolve_t0_scorer(raw),
    )
