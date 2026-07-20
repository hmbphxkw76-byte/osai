# -*- coding: utf-8 -*-
"""
AI-300 Framework - Credential Manager
统一凭据管理器：跨阶段（认证 → 侦察 → 攻击）的凭据发现、验证与注入

核心职责：
1. 凭据发现：按域名从 config/targets/credentials/ 目录匹配凭据文件
2. 凭据验证：JWT 过期检查 + HTTP 预检验证（可选）
3. 凭据注入：为不同工具（Garak / DeepTeam / PyRIT Target）提供适配的认证格式
4. 最佳实践：优先复用已有有效凭据，仅在过期/缺失时触发重新认证

设计原则（ARCH-002 凭据自动导出/复用规则）：
- 域名 A 只读取 A 的凭据文件，绝不交叉读取 B 的
- JWT Token 预留 5 分钟缓冲，临界过期视为已过期
- 凭据来源优先级：localStorage JWT > API 请求头 Authorization > Playwright Cookie
- 导出格式为 HTTP Request Headers（与 header_parser.py 兼容）

使用方式：
    mgr = CredentialManager()
    profile = mgr.resolve(target_url="https://student.syxy.ouchn.cn/#/home")
    if profile:
        # 注入到 Garak
        garak_env = mgr.for_garak(profile)
        # 注入到 DeepTeam
        dt_headers = mgr.for_deepteam(profile)
        # 注入到 PyRIT OpenAIChatTarget
        oai_kwargs = mgr.for_openai_target(profile)
    else:
        # 无可用凭据，需走认证流程
        ...

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from ..orchestrators.auth import (
    AuthProfile,
    find_credential_file,
    normalize_domain,
    parse_header_file,
)

logger = logging.getLogger(__name__)

# 凭据目录常量
CREDENTIALS_DIR = "config/targets/credentials"

# JWT 过期缓冲时间（秒），临界过期视为已过期
JWT_EXPIRY_BUFFER_SECONDS = 300


@dataclass
class CredentialResolution:
    """
    凭据解析结果

    封装一次凭据解析的完整信息，供各阶段统一使用。

    Attributes:
        profile: AuthProfile 实例（包含 Cookie/Bearer/headers）
        source_file: 凭据文件路径
        domain: 目标域名
        is_valid: 凭据是否有效（未过期）
        is_expired: 凭据是否已过期
        expiry_timestamp: JWT 过期时间戳（无 Token 时为 None）
        resolution_method: 解析方式（"file_match" / "host_match" / "none"）
    """
    profile: Optional[AuthProfile] = None
    source_file: str = ""
    domain: str = ""
    is_valid: bool = False
    is_expired: bool = False
    expiry_timestamp: Optional[int] = None
    resolution_method: str = "none"

    @property
    def has_credentials(self) -> bool:
        """是否有可用凭据"""
        return self.profile is not None and self.profile.has_auth() and self.is_valid

    def summary(self) -> str:
        """摘要信息"""
        if not self.profile:
            return f"domain={self.domain}, status=no_credentials"
        status = "valid" if self.is_valid else "expired"
        return (
            f"domain={self.domain}, auth_type={self.profile.auth_type}, "
            f"status={status}, source={self.source_file}"
        )


class CredentialManager:
    """
    统一凭据管理器

    跨阶段（认证 → 侦察 → 攻击）提供统一的凭据发现、验证与注入接口。

    最佳实践策略：
    1. 优先从 credentials/ 目录读取已有凭据（避免重复登录）
    2. 检查 JWT 过期时间，有效则直接复用
    3. 过期或缺失时，返回空结果，由调用方决定是否重新认证
    4. 重新认证后，凭据自动导出到 credentials/ 目录供后续阶段使用

    使用方式：
        mgr = CredentialManager()
        resolution = mgr.resolve("https://student.syxy.ouchn.cn/#/home")
        if resolution.has_credentials:
            # 直接使用凭据，跳过认证
            ...
        else:
            # 需要认证流程
            ...
    """

    def __init__(self, credentials_dir: str = CREDENTIALS_DIR):
        """
        Args:
            credentials_dir: 凭据目录路径
        """
        self.credentials_dir = credentials_dir

    def resolve(self, target_url: str) -> CredentialResolution:
        """
        解析目标 URL 的凭据

        最佳实践入口：按域名匹配 credentials/ 目录下的凭据文件，
        验证有效性后返回。如果凭据已过期或不存在，返回空结果。

        Args:
            target_url: 目标 URL（如 https://student.syxy.ouchn.cn/#/home）

        Returns:
            CredentialResolution 实例
        """
        domain = normalize_domain(target_url)
        if not domain:
            logger.warning("Cannot extract domain from URL: %s", target_url)
            return CredentialResolution(domain="", resolution_method="none")

        logger.info("Resolving credentials for domain: %s", domain)

        # 查找凭据文件
        cred_file = find_credential_file(domain, self.credentials_dir)
        if not cred_file:
            logger.info("No credential file found for domain: %s", domain)
            return CredentialResolution(
                domain=domain,
                resolution_method="none",
            )

        # 解析凭据文件
        try:
            profile = parse_header_file(cred_file)
        except Exception as e:
            logger.error("Failed to parse credential file %s: %s", cred_file, str(e))
            return CredentialResolution(
                domain=domain,
                source_file=cred_file,
                resolution_method="file_match",
            )

        # 验证凭据有效性
        is_expired = self._check_expiry(profile)
        is_valid = profile.has_auth() and not is_expired

        resolution = CredentialResolution(
            profile=profile,
            source_file=cred_file,
            domain=domain,
            is_valid=is_valid,
            is_expired=is_expired,
            expiry_timestamp=profile.token_expiry,
            resolution_method="file_match",
        )

        logger.info("Credential resolution: %s", resolution.summary())
        return resolution

    def resolve_or_none(self, target_url: str) -> Optional[AuthProfile]:
        """
        便捷方法：解析凭据，有效则返回 AuthProfile，否则返回 None

        Args:
            target_url: 目标 URL

        Returns:
            AuthProfile 实例或 None
        """
        resolution = self.resolve(target_url)
        if resolution.has_credentials:
            return resolution.profile
        return None

    # ── 工具适配方法 ──

    @staticmethod
    def for_garak(resolution: CredentialResolution) -> Dict[str, str]:
        """
        为 Garak 适配器生成环境变量

        Garak 通过环境变量接收认证信息：
        - OPENAI_API_KEY: Bearer Token（从 Authorization 头提取）
        - OPENAI_BASE_URL: 目标端点

        Args:
            resolution: 凭据解析结果

        Returns:
            环境变量字典（合并到 os.environ）
        """
        env: Dict[str, str] = {}
        if not resolution.has_credentials or not resolution.profile:
            return env

        profile = resolution.profile

        # 提取 Bearer Token 作为 API Key
        auth_header = profile.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token:
                env["OPENAI_API_KEY"] = token
                logger.info("Garak auth: Bearer token injected (%d chars)", len(token))

        # Cookie 也通过环境变量传递（Garak 的 openai generator 支持）
        if profile.raw_cookies:
            env["OPENAI_API_KEY"] = env.get("OPENAI_API_KEY", "") or profile.raw_cookies
            logger.info("Garak auth: Cookie injected (%d chars)", len(profile.raw_cookies))

        return env

    @staticmethod
    def for_deepteam(resolution: CredentialResolution) -> Dict[str, str]:
        """
        为 DeepTeam 适配器生成请求头

        DeepTeam 的 model_callback 使用 urllib 发送 HTTP 请求，
        认证信息通过请求头注入。

        Args:
            resolution: 凭据解析结果

        Returns:
            请求头字典（Content-Type + Authorization + Cookie）
        """
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if not resolution.has_credentials or not resolution.profile:
            return headers

        profile = resolution.profile

        # 注入 Authorization 头
        auth_header = profile.headers.get("Authorization", "")
        if auth_header:
            headers["Authorization"] = auth_header
            logger.info("DeepTeam auth: Authorization header injected")

        # 注入 Cookie 头
        if profile.raw_cookies:
            headers["Cookie"] = profile.raw_cookies
            logger.info("DeepTeam auth: Cookie header injected (%d chars)", len(profile.raw_cookies))

        # 注入其他自定义头（User-Agent 等）
        for key, value in profile.headers.items():
            if key not in ("Authorization",) and key not in headers:
                headers[key] = value

        return headers

    @staticmethod
    def for_openai_target(resolution: CredentialResolution) -> Dict[str, Any]:
        """
        为 PyRIT OpenAIChatTarget 生成构造参数

        OpenAIChatTarget 接受 api_key 参数，
        Bearer Token 直接作为 api_key 传入。

        Args:
            resolution: 凭据解析结果

        Returns:
            构造参数字典（api_key + endpoint 覆盖）
        """
        kwargs: Dict[str, Any] = {}
        if not resolution.has_credentials or not resolution.profile:
            return kwargs

        profile = resolution.profile

        # 提取 Bearer Token 作为 api_key
        auth_header = profile.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token:
                kwargs["api_key"] = token
                logger.info("OpenAI target auth: api_key injected (%d chars)", len(token))

        return kwargs

    @staticmethod
    def for_http_target(resolution: CredentialResolution) -> Optional[str]:
        """
        为 PyRIT HTTPTarget 生成 Authorization 头值

        HTTPTarget 使用 http_request 模板，认证信息直接写在 Header 中。

        Args:
            resolution: 凭据解析结果

        Returns:
            Authorization 头值（如 "Bearer eyJ..."），或 None
        """
        if not resolution.has_credentials or not resolution.profile:
            return None

        return resolution.profile.headers.get("Authorization", "") or None

    @staticmethod
    def for_playwright(resolution: CredentialResolution) -> Optional[AuthProfile]:
        """
        为 PlaywrightTarget 直接返回 AuthProfile

        PlaywrightTarget 通过 inject_auth() 注入认证信息，
        直接返回 AuthProfile 实例即可。

        Args:
            resolution: 凭据解析结果

        Returns:
            AuthProfile 实例或 None
        """
        if not resolution.has_credentials:
            return None
        return resolution.profile

    # ── 内部方法 ──

    @staticmethod
    def _check_expiry(profile: AuthProfile) -> bool:
        """
        检查凭据是否已过期

        最佳实践：
        - JWT Token 检查 exp 字段，预留 5 分钟缓冲
        - 无 Token 的 Cookie-only 凭据视为有效（Cookie 过期由服务端控制）
        - 解析失败的 Token 不阻塞流程（返回 False，由服务端拒绝时再处理）

        Args:
            profile: AuthProfile 实例

        Returns:
            True 如果已过期，False 如果有效
        """
        if not profile.token_expiry:
            # 无 Token 或解析失败，不阻塞（Cookie-only 凭据）
            return False

        current_time = int(time.time())
        # 预留缓冲时间，避免临界过期
        return current_time >= (profile.token_expiry - JWT_EXPIRY_BUFFER_SECONDS)

    def validate_with_http(
        self,
        resolution: CredentialResolution,
        target_url: str,
    ) -> bool:
        """
        通过 HTTP 请求验证凭据有效性（可选，用于高可靠场景）

        向目标 URL 发送带认证的 GET 请求，检查返回状态码：
        - 200: 凭据有效
        - 401/403: 凭据无效或过期
        - 其他: 不确定，保持原状态

        Args:
            resolution: 凭据解析结果
            target_url: 验证用 URL

        Returns:
            True 如果验证通过，False 如果验证失败
        """
        if not resolution.has_credentials or not resolution.profile:
            return False

        import ssl
        import urllib.error
        import urllib.request

        # 构建请求头
        headers: Dict[str, str] = {}
        profile = resolution.profile
        if profile.headers.get("Authorization"):
            headers["Authorization"] = profile.headers["Authorization"]
        if profile.raw_cookies:
            headers["Cookie"] = profile.raw_cookies

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(target_url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as resp:
                status = resp.status
                if status == 200:
                    logger.info("Credential HTTP validation: PASS (status=%d)", status)
                    return True
                elif status in (401, 403):
                    logger.warning("Credential HTTP validation: FAIL (status=%d)", status)
                    resolution.is_valid = False
                    resolution.is_expired = True
                    return False
                else:
                    logger.info("Credential HTTP validation: UNCERTAIN (status=%d)", status)
                    return resolution.is_valid  # 保持原状态
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                logger.warning("Credential HTTP validation: FAIL (status=%d)", e.code)
                resolution.is_valid = False
                resolution.is_expired = True
                return False
            logger.info("Credential HTTP validation: UNCERTAIN (error=%s)", str(e))
            return resolution.is_valid
        except Exception as e:
            logger.warning("Credential HTTP validation: ERROR (%s)", str(e))
            return resolution.is_valid  # 网络错误不改变原状态

    def print_status(self, resolution: CredentialResolution) -> None:
        """
        打印凭据状态（终端友好格式，重点突出）

        Args:
            resolution: 凭据解析结果
        """
        print()
        print("═" * 60)
        print("  🔐 凭据状态检查")
        print("═" * 60)
        print(f"  目标域名:   {resolution.domain or '(未提取)'}")

        if not resolution.profile:
            print("  凭据状态:   ❌ 未找到凭据文件")
            print("  建议:       需要执行认证流程（SPA 侦察或手动登录）")
        elif not resolution.profile.has_auth():
            print("  凭据状态:   ⚠️  凭据文件存在但无有效认证信息")
            print(f"  凭据文件:   {resolution.source_file}")
        elif resolution.is_expired:
            print("  凭据状态:   ⏰ 凭据已过期")
            print(f"  凭据文件:   {resolution.source_file}")
            if resolution.expiry_timestamp:
                import datetime
                expiry_dt = datetime.datetime.fromtimestamp(resolution.expiry_timestamp)
                print(f"  过期时间:   {expiry_dt.strftime('%Y-%m-%d %H:%M:%S')}")
            print("  建议:       需要重新认证")
        else:
            print("  凭据状态:   ✅ 凭据有效")
            print(f"  凭据文件:   {resolution.source_file}")
            print(f"  认证类型:   {resolution.profile.auth_type}")
            if resolution.profile.cookies:
                print(f"  Cookie 数:  {len(resolution.profile.cookies)}")
            if resolution.profile.headers.get("Authorization"):
                print(f"  Bearer:     {'是' if 'bearer' in resolution.profile.auth_type else '否'}")
            if resolution.expiry_timestamp:
                import datetime
                expiry_dt = datetime.datetime.fromtimestamp(resolution.expiry_timestamp)
                remaining = resolution.expiry_timestamp - int(time.time())
                print(f"  过期时间:   {expiry_dt.strftime('%Y-%m-%d %H:%M:%S')} (剩余 {remaining // 60} 分钟)")

        print("═" * 60)
        print()
