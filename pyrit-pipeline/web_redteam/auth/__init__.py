# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""认证编排层: 浏览器会话管理、认证检测、人工辅助认证、策略选择.

**认证唯一权威来源** — 所有认证逻辑集中在此目录:
  - 浏览器认证: BrowserSession + AuthStrategy + AuthDetector + MFADetector
  - API 认证: APIAuthenticator + CredentialStore
  - 跨流水线共享: AuthStateBridge (pipeline/integrations/)

独立于 recon-pipeline 的 core.auth 模块, 所有实现均在 web_redteam.auth 下。

G1-G7 修复已集成:
  G1: auto 模式下 profile.auth.type 更新为实际类型, 支持持久化
  G2: AuthDetector.attach_to_page() 自动附加 NetworkTokenStrategy 监听器
  G3: HumanAssistedAuth 公开方法 (auto_fill / print_human_instructions)
  G4: CrossDomainAuthStrategy._wait_for_url_stable() 等待 URL 稳定后填充
  G5: CrossDomainAuthStrategy._collect_human_steps() 利用 redirect_chain 配置
  G6: 未知 human_assisted_steps 直接使用原始字符串
  G7: BrowserSession.relaunch() 复用实例重建浏览器进程

认证架构统一 (2026-8-4):
  - 新增 api_auth.py: API 级认证统一入口 (Basic/Bearer/Cookie/OAuth2)
  - 新增 credential_store.py: 凭据集中管理 (消除硬编码)
  - 删除 pipeline/integrations/auth_manager.py (功能已迁移至此)
"""

from web_redteam.auth.api_auth import APIAuthConfig, APIAuthenticator
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
from web_redteam.auth.credential_store import CredentialStore, DonkAIUser
from web_redteam.auth.human_assisted_auth import HumanAssistedAuth
from web_redteam.auth.models import (
    CrossDomainAuthConfig,
    DetectionConfig,
    RedirectChainEntry,
    SameDomainAuthConfig,
)

__all__ = [
    "APIAuthConfig",
    "APIAuthenticator",
    "AuthDetectionStrategy",
    "AuthDetector",
    "AuthDetectorFactory",
    "AuthProbe",
    "AuthStrategy",
    "AuthStrategyFactory",
    "AutoAuthStrategy",
    "BrowserSession",
    "CookiePresenceStrategy",
    "CredentialStore",
    "CrossDomainAuthConfig",
    "CrossDomainAuthStrategy",
    "DetectionConfig",
    "DOMElementStrategy",
    "DonkAIUser",
    "HumanAssistedAuth",
    "NetworkTokenStrategy",
    "NoAuthStrategy",
    "ProbeResult",
    "RedirectChainEntry",
    "SameDomainAuthConfig",
    "SameDomainAuthStrategy",
    "URLPatternStrategy",
]
