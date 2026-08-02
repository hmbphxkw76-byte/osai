"""认证模块包 — 目标模型认证态获取与搬运

支持三类认证场景：
  - none        : 目标无需认证，直接用 OpenAICompatible
  - cookie_file : 人工/Playwright 登录后导出的 Cookie 文件（跨域/同域 SSO）
  - playwright  : 触发 Playwright 半自动登录，成功后落盘 Cookie 再由 cookie_file 消费

设计原则：
  garak 本身不懂登录，只在每次 HTTP 请求里带正确的认证头（Cookie/Bearer）。
  认证逻辑 100% 在 garak 之外完成，本包只负责「产生认证态」+「把认证态喂给 garak」。
"""

from .bootstrap import AuthBootstrap, UnifiedTargetProfile
from .cookie_session import cookie_header_for, load_cookies, save_cookies
from .provider import AuthProvider, from_config
from .session_refresh import SessionRefresher, create_session_refresher

__all__ = [
    "AuthBootstrap",
    "AuthProvider",
    "SessionRefresher",
    "UnifiedTargetProfile",
    "cookie_header_for",
    "create_session_refresher",
    "from_config",
    "load_cookies",
    "save_cookies",
]
