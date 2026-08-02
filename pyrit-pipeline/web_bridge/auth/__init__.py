# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证编排层: 浏览器会话管理、认证检测、人工辅助认证、策略选择。."""

from web_bridge.auth.auth_detector import (
    AuthDetectionStrategy,
    AuthDetector,
    CookiePresenceStrategy,
    DOMElementStrategy,
    NetworkTokenStrategy,
    URLPatternStrategy,
)
from web_bridge.auth.auth_probe import AuthProbe, ProbeResult
from web_bridge.auth.auth_strategy import (
    AuthStrategy,
    AuthStrategyFactory,
    AutoAuthStrategy,
    CrossDomainAuthStrategy,
    NoAuthStrategy,
    SameDomainAuthStrategy,
)
from web_bridge.auth.browser_session import BrowserSession
from web_bridge.auth.human_assisted_auth import HumanAssistedAuth

__all__ = [
    "AuthDetectionStrategy",
    "AuthDetector",
    "AuthProbe",
    "AuthStrategy",
    "AuthStrategyFactory",
    "AutoAuthStrategy",
    "BrowserSession",
    "CookiePresenceStrategy",
    "CrossDomainAuthStrategy",
    "DOMElementStrategy",
    "HumanAssistedAuth",
    "NetworkTokenStrategy",
    "NoAuthStrategy",
    "ProbeResult",
    "SameDomainAuthStrategy",
    "URLPatternStrategy",
]
