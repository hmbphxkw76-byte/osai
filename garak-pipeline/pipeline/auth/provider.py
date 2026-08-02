"""AuthProvider 抽象与工厂 — 统一认证接口

下游（stage1 / stage3）只依赖 AuthProvider.get_request_headers()，
不关心具体认证类型，便于后续扩展 OAuth / mTLS 等。
"""

from __future__ import annotations

import logging
from typing import Any

from .cookie_session import api_domain_from_endpoint, cookie_header_for, load_cookies

logger = logging.getLogger(__name__)


class AuthProvider:
    """认证态提供方抽象基类"""

    def get_request_headers(self) -> dict[str, str]:
        """返回注入到 HTTP 请求的认证头（如 {"Cookie": "..."}）"""
        raise NotImplementedError

    def describe(self) -> str:
        return self.__class__.__name__


class NoAuthProvider(AuthProvider):
    """无认证场景"""

    def get_request_headers(self) -> dict[str, str]:
        return {}


class CookieFileProvider(AuthProvider):
    """Cookie 文件认证（人工导出 / Playwright 落盘）"""

    def __init__(self, cookie_source: str, cookie_domain: str) -> None:
        self.cookie_source = cookie_source
        self.cookie_domain = cookie_domain
        self._cookies: list | None = None  # 延迟加载（文件可能尚未登录生成）

    def _ensure_loaded(self) -> list:
        if self._cookies is None:
            self._cookies = load_cookies(self.cookie_source)
        return self._cookies

    def get_request_headers(self) -> dict[str, str]:
        try:
            cookies = self._ensure_loaded()
        except FileNotFoundError:
            # Cookie 文件尚不存在（未登录）：返回空头，由后续连通性测试暴露明确错误
            logger.warning(
                "Cookie 文件不存在: %s（请先运行 --auth-only 登录）", self.cookie_source
            )
            return {}
        header = cookie_header_for(cookies, self.cookie_domain)
        return {"Cookie": header} if header else {}

    def describe(self) -> str:
        return f"CookieFile({self.cookie_domain})"


class StaticKeyProvider(AuthProvider):
    """静态 API Key / Bearer（上一轮纯 key 场景）"""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def get_request_headers(self) -> dict[str, str]:
        if not self.api_key:
            return {}
        if self.api_key.lower().startswith("bearer "):
            return {"Authorization": self.api_key}
        return {"Authorization": f"Bearer {self.api_key}"}

    def describe(self) -> str:
        return "StaticKey"


def from_config(auth_cfg: dict[str, Any] | None, target: dict[str, Any] | None = None) -> AuthProvider:
    """从 target.yaml 的 auth 段构造 AuthProvider

    :param auth_cfg: config["target"]["auth"]，可空
    :param target: config["target"]（用于兼容旧版 api_key 字段）
    :returns: AuthProvider 实例
    """
    auth_cfg = auth_cfg or {}
    auth_type = auth_cfg.get("type", "static")

    if auth_type in (None, "none", "static"):
        # 兼容旧版：无 auth 段但有 api_key → 静态 key
        key = (target or {}).get("api_key", "")
        if key:
            return StaticKeyProvider(key)
        return NoAuthProvider()

    if auth_type == "cookie_file":
        source = auth_cfg.get("cookie_source")
        domain = auth_cfg.get("cookie_domain") or api_domain_from_endpoint(
            (target or {}).get("endpoint", "")
        )
        # cookie_source 留空时按 cookie_domain 自动推导默认路径，避免硬编码
        if not source:
            if not domain:
                raise ValueError(
                    "auth.type=cookie_file 需要 cookie_source 或 cookie_domain 字段"
                )
            import re

            safe = re.sub(r"\W+", "_", domain)
            source = f"sessions/{safe}.json"
        return CookieFileProvider(source, domain)

    raise ValueError(f"不支持的 auth.type: {auth_type}")
