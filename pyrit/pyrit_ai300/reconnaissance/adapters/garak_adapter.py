# -*- coding: utf-8 -*-
"""Garak Adapter - 向后兼容 shim（已迁移到 garak/ 包）"""

from .garak import GarakAdapter
from .garak.adapter import (
    PROBE_OWASP_MAP,
    PROBES_BY_DEPTH,
    PROBE_DETECTOR_MAP,
    DEFAULT_PROBES,
    GARAK_VENV_DIR,
    GARAK_REQUIREMENTS,
    GARAK_CACHE_DIR,
)

__all__ = [
    "GarakAdapter",
    "PROBE_OWASP_MAP",
    "PROBES_BY_DEPTH",
    "PROBE_DETECTOR_MAP",
    "DEFAULT_PROBES",
    "GARAK_VENV_DIR",
    "GARAK_REQUIREMENTS",
    "GARAK_CACHE_DIR",
]
