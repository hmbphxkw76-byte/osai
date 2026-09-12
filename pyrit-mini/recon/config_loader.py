"""TLS/SSL Load - P2-06: TLS verify (SSOT)

imports config/defaults.yaml  tls_verify , all httpx/aiohttp
SSL

Academic basis:
    - OWASP WSTG-CRYP-01 - Layer
    - NIST SP 800-52 Rev. 2 - TLS

:
    tls_verify (config/defaults.yaml):
        - true  -  SSL  ()
        - false - Skip (/)
        - <path> - CA bundle  ( CA)

:
    >>> from recon.config_loader import get_tls_verify
    >>> verify = get_tls_verify()
    >>> async with httpx.AsyncClient(verify=verify) as client:
    ...     ...
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SSOT_PATH = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"

# ()
_cached_config: dict[str, Any] | None = None


def _load_config() -> dict[str, Any]:
    """imports defaults.yaml Load (cache)"""
    global _cached_config
    if _cached_config is not None:
        return _cached_config

    try:
        import yaml

        if _SSOT_PATH.exists():
            with open(_SSOT_PATH, encoding="utf-8") as f:
                config = yaml.safe_load(f)
            if isinstance(config, dict):
                _cached_config = config
                return config
    except Exception as e:
        logger.warning("Failed to load defaults.yaml (using empty config): %s", e)

    _cached_config = {}
    return _cached_config


def get_tls_verify() -> bool | str:
    """TLS verify

    Returns:
        - True:  SSL  ()
        - False: Skip
        - str: CA bundle  ( CA)
    """
    config = _load_config()
    tls_verify = config.get("tls_verify", True)

    #
    if isinstance(tls_verify, bool):
        return tls_verify

    # (CA bundle)
    if isinstance(tls_verify, str):
        if tls_verify.lower() in ("true", "yes", "1"):
            return True
        if tls_verify.lower() in ("false", "no", "0"):
            return False
        # CA bundle
        return tls_verify

    # True
    logger.warning(
        "Invalid tls_verify type in defaults.yaml (expected bool/str, got %s), defaulting to True",
        type(tls_verify).__name__,
    )
    return True


def get_positive_float(key: str, fallback: float) -> float:
    """读取 defaults.yaml 中的正浮点标量与 `fallback`。

    BL-038 接真（CP-003）：为 `api_timeout` / `probe_retries` 等此前零消费者的
    标量键提供统一读取入口，保证 C7「defaults.yaml → config_loader → 调用方」
    唯一链路；取值非法时 WARNING 留痕并回退（C9 禁止静默）。

    Args:
        key: defaults.yaml 顶层键名。
        fallback: 缺失或非法时的兜底值。

    Returns:
        正浮点数。
    """
    config = _load_config()
    raw = config.get(key, None)
    if raw is None:
        logger.warning("%s 未在 defaults.yaml 声明（C7 断链），回退 %s", key, fallback)
        return fallback
    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning("%s 取值非法 %r（期望数值），回退 %s", key, raw, fallback)
        return fallback
    if value <= 0:
        logger.warning("%s 必须为正数，实际 %s，回退 %s", key, value, fallback)
        return fallback
    return value


def get_positive_int(key: str, fallback: int) -> int:
    """读取 defaults.yaml 中的正整数标量（语义同 `get_positive_float`）。"""
    return int(get_positive_float(key, float(fallback)))


def clear_config_cache() -> None:
    """cache ()"""
    global _cached_config
    _cached_config = None
    logger.debug("Config cache cleared")
