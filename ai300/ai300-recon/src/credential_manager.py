# -*- coding: utf-8 -*-
"""
Credential Manager
==================

统一凭据管理器：跨阶段（认证 → 侦察 → 攻击）的凭据发现、验证与注入。

核心职责：
  1. 按域名从 credentials/ 目录匹配凭据文件
  2. JWT 过期检查 + HTTP 预检验证（可选）
  3. 为不同攻击/侦察工具输出适配的认证格式
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from src.auth import (
    AuthProfile,
    find_credential_file,
    normalize_domain,
    parse_header_file,
)

logger = logging.getLogger(__name__)

JWT_EXPIRY_BUFFER_SECONDS = 300
DEFAULT_CREDENTIALS_DIR = "credentials"


@dataclass
class CredentialResolution:
    """凭据解析结果"""

    profile: Optional[AuthProfile] = None
    source_file: str = ""
    domain: str = ""
    is_valid: bool = False
    is_expired: bool = False
    expiry_timestamp: Optional[int] = None
    resolution_method: str = "none"

    @property
    def has_credentials(self) -> bool:
        return self.profile is not None and self.profile.has_auth() and self.is_valid

    def summary(self) -> str:
        if not self.profile:
            return f"domain={self.domain}, status=no_credentials"
        status = "valid" if self.is_valid else "expired"
        return (
            f"domain={self.domain}, auth_type={self.profile.auth_type}, "
            f"status={status}, source={self.source_file}"
        )


class CredentialManager:
    """统一凭据管理器"""

    def __init__(self, credentials_dir: str = DEFAULT_CREDENTIALS_DIR):
        self.credentials_dir = credentials_dir

    def resolve(self, target_url: str) -> CredentialResolution:
        """解析目标 URL 的凭据"""
        domain = normalize_domain(target_url)
        if not domain:
            logger.warning("Cannot extract domain from URL: %s", target_url)
            return CredentialResolution(domain="", resolution_method="none")

        logger.info("Resolving credentials for domain: %s", domain)
        cred_file = find_credential_file(domain, self.credentials_dir)
        if not cred_file:
            logger.info("No credential file found for domain: %s", domain)
            return CredentialResolution(domain=domain, resolution_method="none")

        try:
            profile = parse_header_file(cred_file)
        except Exception as e:
            logger.error("Failed to parse credential file %s: %s", cred_file, str(e))
            return CredentialResolution(
                domain=domain, source_file=cred_file, resolution_method="file_match"
            )

        is_expired = self._check_expiry(profile)
        is_valid = profile.has_auth() and not is_expired

        return CredentialResolution(
            profile=profile,
            source_file=cred_file,
            domain=domain,
            is_valid=is_valid,
            is_expired=is_expired,
            expiry_timestamp=profile.token_expiry,
            resolution_method="file_match",
        )

    def resolve_or_none(self, target_url: str) -> Optional[AuthProfile]:
        """便捷方法：有效则返回 AuthProfile，否则 None"""
        resolution = self.resolve(target_url)
        return resolution.profile if resolution.has_credentials else None

    @staticmethod
    def for_playwright(resolution: CredentialResolution) -> Optional[AuthProfile]:
        """为 Playwright 返回 AuthProfile"""
        return resolution.profile if resolution.has_credentials else None

    @staticmethod
    def for_http_auth_header(resolution: CredentialResolution) -> Optional[str]:
        """返回 HTTP Authorization 头值"""
        if not resolution.has_credentials or not resolution.profile:
            return None
        return resolution.profile.headers.get("Authorization", "") or None

    @staticmethod
    def for_openai_api(resolution: CredentialResolution) -> Dict[str, Any]:
        """为 OpenAI 兼容 API 提取 api_key"""
        kwargs: Dict[str, Any] = {}
        if not resolution.has_credentials or not resolution.profile:
            return kwargs
        auth_header = resolution.profile.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token:
                kwargs["api_key"] = token
        return kwargs

    @staticmethod
    def _check_expiry(profile: AuthProfile) -> bool:
        """检查 JWT 是否过期"""
        if not profile.token_expiry:
            return False
        return int(time.time()) >= (profile.token_expiry - JWT_EXPIRY_BUFFER_SECONDS)

    def validate_with_http(
        self,
        resolution: CredentialResolution,
        target_url: str,
    ) -> bool:
        """通过 HTTP 请求验证凭据有效性"""
        if not resolution.has_credentials or not resolution.profile:
            return False

        import ssl
        import urllib.error
        import urllib.request

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
                    return resolution.is_valid
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                logger.warning("Credential HTTP validation: FAIL (status=%d)", e.code)
                resolution.is_valid = False
                resolution.is_expired = True
                return False
            return resolution.is_valid
        except Exception as e:
            logger.warning("Credential HTTP validation: ERROR (%s)", str(e))
            return resolution.is_valid

    def print_status(
        self,
        resolution: CredentialResolution,
        auth_mode: str = "",
    ) -> None:
        """终端友好的凭据状态输出"""
        print()
        print("=" * 60)
        print("  🔐 凭据状态检查")
        print("=" * 60)
        print(f"  目标域名:   {resolution.domain or '(未提取)'}")

        if not resolution.profile:
            if auth_mode == "none":
                print("  凭据状态:   ✅ 无需认证（auth_mode: none）")
            else:
                print("  凭据状态:   ❌ 未找到凭据文件")
                print("  建议:       执行认证流程或从浏览器 F12 复制 Headers 到 credentials/")
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

        print("=" * 60)
        print()
