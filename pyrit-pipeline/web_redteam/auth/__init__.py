# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证编排层: 浏览器会话管理、认证检测、人工辅助认证、策略选择.

独立于 recon-pipeline 的 core.auth 模块, 所有实现均在 web_redteam.auth 下。

G1-G7 修复已集成:
  G1: auto 模式下 profile.auth.type 更新为实际类型, 支持持久化
  G2: AuthDetector.attach_to_page() 自动附加 NetworkTokenStrategy 监听器
  G3: HumanAssistedAuth 公开方法 (auto_fill / print_human_instructions)
  G4: CrossDomainAuthStrategy._wait_for_url_stable() 等待 URL 稳定后填充
  G5: CrossDomainAuthStrategy._collect_human_steps() 利用 redirect_chain 配置
  G6: 未知 human_assisted_steps 直接使用原始字符串
  G7: BrowserSession.relaunch() 复用实例重建浏览器进程
"""

from web_redteam.auth.auth_detector import (
    AuthDetectionStrategy,
    AuthDetector,
    AuthDetectorFactory,
    CookiePresenceStrategy,
    DOMElementStrategy,
    NetworkTokenStrategy,
    URLPatternStrategy,
)
from web_redteam.auth.auth_probe import AuthProbe, ProbeResult
from web_redteam.auth.auth_strategy import (
    AuthStrategy,
    AuthStrategyFactory,
    AutoAuthStrategy,
    CrossDomainAuthStrategy,
    NoAuthStrategy,
    SameDomainAuthStrategy,
)
from web_redteam.auth.browser_session import BrowserSession
from web_redteam.auth.human_assisted_auth import HumanAssistedAuth
from web_redteam.auth.models import (
    CrossDomainAuthConfig,
    DetectionConfig,
    RedirectChainEntry,
    SameDomainAuthConfig,
)

__all__ = [
    "AuthDetectionStrategy",
    "AuthDetector",
    "AuthDetectorFactory",
    "AuthProbe",
    "AuthStrategy",
    "AuthStrategyFactory",
    "AutoAuthStrategy",
    "BrowserSession",
    "CookiePresenceStrategy",
    "CrossDomainAuthConfig",
    "CrossDomainAuthStrategy",
    "DetectionConfig",
    "DOMElementStrategy",
    "HumanAssistedAuth",
    "NetworkTokenStrategy",
    "NoAuthStrategy",
    "ProbeResult",
    "RedirectChainEntry",
    "SameDomainAuthConfig",
    "SameDomainAuthStrategy",
    "URLPatternStrategy",
]
