# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证层: AuthProvider 抽象 + 具体实现 + 认证探测 + 浏览器会话 + 认证策略。"""

from core.auth.auth_detector import AuthDetector, AuthDetectorFactory
from core.auth.auth_probe import AuthProbe, ProbeResult
from core.auth.auth_strategy import (
    AuthStrategy,
    AuthStrategyFactory,
    AutoAuthStrategy,
    CrossDomainAuthStrategy,
    NoAuthStrategy,
    SameDomainAuthStrategy,
)
from core.auth.browser_session import BrowserSession
from core.auth.human_assisted_auth import HumanAssistedAuth
from core.auth.models import (
    CrossDomainAuthConfig,
    DetectionConfig,
    RedirectChainEntry,
    SameDomainAuthConfig,
)
from core.auth.provider import APIKeyAuthProvider, AuthProvider, NoAuthProvider

__all__ = [
    "APIKeyAuthProvider",
    "AuthDetector",
    "AuthDetectorFactory",
    "AuthProvider",
    "AuthProbe",
    "AuthStrategy",
    "AuthStrategyFactory",
    "AutoAuthStrategy",
    "BrowserSession",
    "CrossDomainAuthConfig",
    "CrossDomainAuthStrategy",
    "DetectionConfig",
    "HumanAssistedAuth",
    "NoAuthProvider",
    "NoAuthStrategy",
    "ProbeResult",
    "RedirectChainEntry",
    "SameDomainAuthConfig",
    "SameDomainAuthStrategy",
]
