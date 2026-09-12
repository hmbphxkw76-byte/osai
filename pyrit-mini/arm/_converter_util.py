# -*- coding: utf-8 -*-
"""Shared helper for L5 converter chain builders.

SRP split from `converter_chains.py` (R-DELIVERY-1): this leaf module owns the
single `_conv` helper that resolves a PyRIT Converter class by name. It has no
builder logic of its own, so the text/document chain modules can both depend on
it without creating a cycle.
"""

from __future__ import annotations

import importlib
import logging

logger = logging.getLogger(__name__)


def _conv(name: str) -> type:
    """EURu?PyRIT Converter?

    Args:
        name: Converter ?

    Returns:
        Converter EUR?

    Raises:
        AttributeError: Converter uEUR?
    """
    mod = importlib.import_module("pyrit.converter")
    cls = getattr(mod, name, None)
    if cls is None:
        raise AttributeError(f"PyRIT Converter '{name}' not found")
    return cls
