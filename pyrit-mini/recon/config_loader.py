"""TLS/SSL 配置加载器 — P2-06: TLS verify 配置化 (SSOT)。

从 config/defaults.yaml 读取 tls_verify 配置, 统一控制所有 httpx/aiohttp 客户端的
SSL 证书验证行为。

学术依据:
    - OWASP WSTG-CRYP-01 — 传输层安全测试
    - NIST SP 800-52 Rev. 2 — TLS 实现指南

配置项:
    tls_verify (config/defaults.yaml):
        - true  — 验证 SSL 证书 (生产环境推荐)
        - false — 跳过证书验证 (仅用于测试环境/自签名证书)
        - <path> — CA bundle 路径 (企业内网自签名 CA)

使用示例:
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

# 缓存配置 (避免每次调用都读取文件)
_cached_config: dict[str, Any] | None = None


def _load_config() -> dict[str, Any]:
    """从 defaults.yaml 加载配置 (带缓存)。"""
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
        logger.warning(
            "Failed to load defaults.yaml (falling back to hardcoded defaults): %s", e
        )

    _cached_config = {}
    return _cached_config


def get_tls_verify() -> bool | str:
    """获取 TLS verify 配置值。

    Returns:
        - True: 验证 SSL 证书 (默认)
        - False: 跳过证书验证
        - str: CA bundle 路径 (企业内网自签名 CA)
    """
    config = _load_config()
    tls_verify = config.get("tls_verify", True)

    # 验证配置值类型
    if isinstance(tls_verify, bool):
        return tls_verify

    # 支持字符串路径 (CA bundle)
    if isinstance(tls_verify, str):
        if tls_verify.lower() in ("true", "yes", "1"):
            return True
        if tls_verify.lower() in ("false", "no", "0"):
            return False
        # 假设为 CA bundle 路径
        return tls_verify

    # 其他类型默认 True
    logger.warning(
        "Invalid tls_verify type in defaults.yaml (expected bool/str, got %s), "
        "defaulting to True",
        type(tls_verify).__name__,
    )
    return True


def clear_config_cache() -> None:
    """清除配置缓存 (用于测试或配置热重载)。"""
    global _cached_config
    _cached_config = None
    logger.debug("Config cache cleared")
