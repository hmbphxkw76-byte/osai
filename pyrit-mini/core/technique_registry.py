"""core/technique_registry — plug-in extension registry for attack primitives.

Holds three registries (converters / strike strategies / scorers) and the
``@register_*`` decorators so that adding a new primitive is a one-line
declaration instead of editing scattered hardcoded tables.

Design constraints (mirrors ``core.registry.ComponentRegistry``):
  * zero attack logic — this module only reflects / looks up
  * unknown keys -> None / WARNING, never crash (IA-6)
  * W0 compatible: an empty registry is a legal state; callers fall back

Academic basis: PyRIT (arXiv:2407.01232) — native attack / converter classes.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

# name -> builder(converter_target) -> list[Converter]  (PyRIT native instances)
CONVERTER_REGISTRY: dict[str, Callable[..., Any]] = {}
# strategy_name -> PyRIT attack class
STRATEGY_REGISTRY: dict[str, type] = {}
# strategy_name -> params builder(ctx.args) -> dict | None
STRATEGY_PARAMS: dict[str, Callable[[Any], Any]] = {}
# component_type -> t0 checker callable
SCORER_REGISTRY: dict[str, Callable] = {}


def register_converter(name: str) -> Callable[[Callable], Callable]:
    """Decorator: register a converter builder under a canonical name.

    The builder signature is ``builder(converter_target) -> list[Converter]``.
    """

    def _(fn: Callable) -> Callable:
        CONVERTER_REGISTRY[name] = fn
        return fn

    return _


def register_strategy(name: str, attack_cls: type) -> type:
    """Register a PyRIT attack class under a strategy name (plug-in entry)."""
    STRATEGY_REGISTRY[name] = attack_cls
    return attack_cls


def register_strategy_params(name: str, params_fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """Register the params builder for a multi-turn strategy."""
    STRATEGY_PARAMS[name] = params_fn
    return params_fn


def register_scorer(component_type: str) -> Callable[[Callable], Callable]:
    """Decorator: register a T0 checker under its component_type."""

    def _(fn: Callable) -> Callable:
        SCORER_REGISTRY[component_type] = fn
        return fn

    return _


def resolve_converters(names: list[str], converter_target: Any | None = None) -> list[Any]:
    """Resolve converter preset names to flattened converter instances.

    Unknown names are logged and skipped (IA-6); a broken builder never aborts
    the whole blueprint.
    """
    out: list[Any] = []
    for name in names or []:
        builder = CONVERTER_REGISTRY.get(name)
        if builder is None:
            logger.warning("[REGISTRY] Unknown converter preset %r — skipped", name)
            continue
        try:
            built = builder(converter_target)
            if built:
                out.extend(built)
        except Exception as e:  # a broken builder must not abort the blueprint
            logger.warning("[REGISTRY] Converter builder %r failed: %s", name, e)
    return out


def get_scorer(component_type: str) -> Callable | None:
    """Return the registered T0 checker for a component_type, or None."""
    return SCORER_REGISTRY.get(component_type)


def get_strategy_class(name: str) -> type | None:
    """Return the registered PyRIT attack class for a strategy name, or None."""
    return STRATEGY_REGISTRY.get(name)


def get_strategy_params(name: str) -> Callable[[Any], Any] | None:
    """Return the registered params builder for a strategy name, or None."""
    return STRATEGY_PARAMS.get(name)
