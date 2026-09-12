"""Judge Registry  - ScorerRegistry

:
    - _resolve_scoring_endpoint - SCORING_CHAT_* > SCORER_CHAT_* > ADVERSARIAL_CHAT_*
    - _register_judge_to_registry -  ScorerRegistry
    - _get_judge_from_registry -  ScorerRegistry
    - _get_judge_scorer - / fallback
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def _resolve_scoring_endpoint() -> tuple[str, str, str]:
    """Resolve scoring endpoint config.

    Priority: SCORING_CHAT_* > SCORER_CHAT_* > ADVERSARIAL_CHAT_*

    Returns:
        (, , ) triple; (, , ) if unavailable.
    """
    endpoint = (
        os.environ.get("SCORING_CHAT_ENDPOINT", "")
        or os.environ.get("SCORER_CHAT_ENDPOINT", "")
        or os.environ.get("ADVERSARIAL_CHAT_ENDPOINT", "")
    )
    api_key = (
        os.environ.get("SCORING_CHAT_KEY", "")
        or os.environ.get("SCORER_CHAT_KEY", "")
        or os.environ.get("ADVERSARIAL_CHAT_KEY", "")
    )
    model = (
        os.environ.get("SCORING_CHAT_MODEL", "")
        or os.environ.get("SCORER_CHAT_MODEL", "")
        or os.environ.get("ADVERSARIAL_CHAT_MODEL", "")
    )
    return endpoint, api_key, model


def _register_judge_to_registry(scorer: Any, name: str) -> None:
    """L5 v55: Judge scorer PyRIT ScorerRegistry."""
    try:
        from pyrit.registry import ScorerRegistry

        registry = ScorerRegistry.get_registry_singleton()
        registry.instances.register(scorer=scorer, name=name, tags=[{name: {}}])
        logger.debug("L5 v55: Judge '%s' registered to ScorerRegistry", name)
    except Exception as e:
        logger.debug("L5 v55: Failed to register judge '%s': %s", name, e)


def _get_judge_from_registry(name: str) -> Any:
    """L5 v55: imports PyRIT ScorerRegistry Judge scorer."""
    try:
        from pyrit.registry import ScorerRegistry

        registry = ScorerRegistry.get_registry_singleton()
        return registry.get(name)
    except Exception:
        return None


def _get_judge_scorer(primary_name: str, fallback_name: str) -> Any:
    """L5 v57: Get judge scorer wrapper or plain scorer."""
    scorer = _get_judge_from_registry(primary_name)
    if scorer is None:
        scorer = _get_judge_from_registry(fallback_name)
    return scorer


def _resolve_arbiter_endpoint() -> tuple[str, str, str]:
    """Resolve arbiter (3rd judge) endpoint from environment.

    Returns:
        (, , ) triple; (, , ) if unavailable.
    """
    endpoint = os.environ.get("ARBITER_CHAT_ENDPOINT", "")
    key = os.environ.get("ARBITER_CHAT_KEY", "")
    model = os.environ.get("ARBITER_CHAT_MODEL", "")
    return endpoint, key, model
