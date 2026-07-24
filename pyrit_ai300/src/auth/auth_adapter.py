"""
Auth Module
===========

本模块负责认证适配层，为不同认证类型创建已认证的 PromptTarget（遵循开发规则 1.4.1）。
"""

import os
from typing import Any, Dict, List, Optional

from pyrit.prompt_target import (
    HTTPXAPITarget,
    PlaywrightTarget,
)

from src.core.models import (
    AuthStatus,
    AuthResult,
    AuthType,
    ReconResult,
)


# ============================================================
# 认证适配器
# ============================================================


class AuthAdapter:
    """认证适配器 - 为不同认证类型创建已认证的 PromptTarget"""

    def __init__(self):
        """初始化认证适配器"""
        pass

    async def authenticate(
        self,
        recon_result: ReconResult,
        credentials: Optional[Dict[str, str]] = None,
    ) -> AuthResult:
        """
        执行认证

        Args:
            recon_result: 侦察结果
            credentials: 认证凭证

        Returns:
            认证结果
        """
        auth_type = recon_result.auth_type
        target_url = recon_result.target_url
        endpoint = recon_result.detected_endpoint

        try:
            if auth_type == AuthType.NONE:
                return await self._authenticate_none(target_url, endpoint)
            elif auth_type == AuthType.API_KEY:
                return await self._authenticate_api_key(
                    target_url, endpoint, credentials
                )
            elif auth_type == AuthType.BEARER_TOKEN:
                return await self._authenticate_bearer_token(
                    target_url, endpoint, credentials
                )
            elif auth_type == AuthType.COOKIE:
                return await self._authenticate_cookie(
                    target_url, endpoint, credentials
                )
            elif auth_type == AuthType.FORM_BASED:
                return await self._authenticate_form_based(
                    target_url, endpoint, credentials
                )
            else:
                return AuthResult(
                    target_url=target_url,
                    auth_type=auth_type,
                    status=AuthStatus.AUTH_FAILED,
                    error_message=f"不支持的认证类型: {auth_type}",
                )
        except Exception as e:
            return AuthResult(
                target_url=target_url,
                auth_type=auth_type,
                status=AuthStatus.AUTH_FAILED,
                error_message=str(e),
            )

    async def create_authenticated_target(
        self,
        recon_result: ReconResult,
        credentials: Optional[Dict[str, str]] = None,
    ) -> Any:
        """
        创建已认证的 PromptTarget（认证适配层的核心输出）

        Args:
            recon_result: 侦察结果
            credentials: 认证凭证

        Returns:
            已认证的 PromptTarget 实例（HTTPXAPITarget 或 PlaywrightTarget）
        """
        auth_result = await self.authenticate(recon_result, credentials)

        if auth_result.status != AuthStatus.SUCCESS:
            raise ValueError(f"认证失败: {auth_result.error_message}")

        return self._create_target_from_auth_result(
            recon_result, auth_result
        )

    # -----------------------------------------------------------------
    # 私有认证方法
    # -----------------------------------------------------------------

    async def _authenticate_none(
        self,
        target_url: str,
        endpoint: str,
    ) -> AuthResult:
        """无认证"""
        full_url = target_url.rstrip("/") + endpoint

        # 创建 Target 以验证端点可用
        target = HTTPXAPITarget(
            http_url=full_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            json_data={"messages": [{"role": "user", "content": "test"}]},
        )

        # 这里应该验证 Target 是否可用
        # 为简化，直接返回成功
        return AuthResult(
            target_url=target_url,
            auth_type=AuthType.NONE,
            status=AuthStatus.SUCCESS,
            auth_headers={"Content-Type": "application/json"},
        )

    async def _authenticate_api_key(
        self,
        target_url: str,
        endpoint: str,
        credentials: Optional[Dict[str, str]],
    ) -> AuthResult:
        """API Key 认证"""
        api_key = credentials.get("api_key") or os.getenv("TARGET_API_KEY")

        if not api_key:
            return AuthResult(
                target_url=target_url,
                auth_type=AuthType.API_KEY,
                status=AuthStatus.FAILED,
                error_message="缺少 API Key",
            )

        return AuthResult(
            target_url=target_url,
            auth_type=AuthType.API_KEY,
            status=AuthStatus.SUCCESS,
            auth_headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )

    async def _authenticate_bearer_token(
        self,
        target_url: str,
        endpoint: str,
        credentials: Optional[Dict[str, str]],
    ) -> AuthResult:
        """Bearer Token 认证"""
        token = credentials.get("token") or os.getenv("TARGET_BEARER_TOKEN")

        if not token:
            return AuthResult(
                target_url=target_url,
                auth_type=AuthType.BEARER_TOKEN,
                status=AuthStatus.FAILED,
                error_message="缺少 Bearer Token",
            )

        return AuthResult(
            target_url=target_url,
            auth_type=AuthType.BEARER_TOKEN,
            status=AuthStatus.SUCCESS,
            auth_headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )

    async def _authenticate_cookie(
        self,
        target_url: str,
        endpoint: str,
        credentials: Optional[Dict[str, str]],
    ) -> AuthResult:
        """Cookie 认证"""
        cookie = credentials.get("cookie") or os.getenv("TARGET_COOKIE")

        if not cookie:
            return AuthResult(
                target_url=target_url,
                auth_type=AuthType.COOKIE,
                status=AuthStatus.FAILED,
                error_message="缺少 Cookie",
            )

        return AuthResult(
            target_url=target_url,
            auth_type=AuthType.COOKIE,
            status=AuthStatus.SUCCESS,
            auth_headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
            },
        )

    async def _authenticate_form_based(
        self,
        target_url: str,
        endpoint: str,
        credentials: Optional[Dict[str, str]],
    ) -> AuthResult:
        """表单登录认证"""
        username = credentials.get("username") or os.getenv("TARGET_USERNAME")
        password = credentials.get("password") or os.getenv("TARGET_PASSWORD")

        if not username or not password:
            return AuthResult(
                target_url=target_url,
                auth_type=AuthType.FORM_BASED,
                status=AuthStatus.FAILED,
                error_message="缺少用户名或密码",
            )

        # 表单登录需要使用 PlaywrightTarget
        # 这里简化处理，返回成功状态
        return AuthResult(
            target_url=target_url,
            auth_type=AuthType.FORM_BASED,
            status=AuthStatus.SUCCESS,
            auth_headers={"Content-Type": "application/json"},
            session_data={"username": username},
        )

    # -----------------------------------------------------------------
    # Target 创建方法
    # -----------------------------------------------------------------

    def _create_target_from_auth_result(
        self,
        recon_result: ReconResult,
        auth_result: AuthResult,
    ) -> Any:
        """从认证结果创建已认证的 Target"""
        full_url = recon_result.target_url.rstrip("/") + recon_result.detected_endpoint
        ai_system_type = recon_result.ai_system_type

        if auth_result.auth_type == AuthType.FORM_BASED:
            # 使用 PlaywrightTarget（浏览器自动化）
            return PlaywrightTarget(
                url=full_url,
            )
        else:
            # 使用 HTTPXAPITarget
            headers = auth_result.auth_headers

            # 根据 AI 系统类型调整 json_data
            if ai_system_type.value == "rag":
                json_data = {"query": "{PROMPT}", "top_k": 5}
            else:
                json_data = {"messages": [{"role": "user", "content": "{PROMPT}"}]}

            return HTTPXAPITarget(
                http_url=full_url,
                method="POST",
                headers=headers,
                json_data=json_data,
            )


# ============================================================
# 工厂函数
# ============================================================


async def create_authenticated_target(
    recon_result: ReconResult,
    credentials: Optional[Dict[str, str]] = None,
) -> Any:
    """
    创建已认证的 Target（工厂函数）

    Args:
        recon_result: 侦察结果
        credentials: 认证凭证

    Returns:
        已认证的 PromptTarget 实例
    """
    adapter = AuthAdapter()
    return await adapter.create_authenticated_target(recon_result, credentials)