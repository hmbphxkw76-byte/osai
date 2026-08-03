# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""APITargetConfig: API POST 攻击模式的配置模型。.

当用户通过 --api-url 指定目标 AI LLM 应用的 API 端点时，
从 CLI 参数构建此配置，用于创建 HTTPTarget。

支持的 API 格式:
  - OpenAI Chat Completions 兼容 (默认)
  - 自定义 JSON body (通过 --api-body 指定模板)
  - Burp Suite 原始 HTTP 请求 (通过 --api-raw-request 指定文件)

速率与并发控制:
  - max_rpm: 每分钟最大请求数 (通过原生 _max_requests_per_minute 实现)
  - max_concurrency: 最大并发请求数 (通过 RateLimitedTarget 信号量实现)
  - max_retries: 错误重试次数 (通过 RateLimitedTarget 指数退避实现)

> **日期**: 2026-8-3
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# {PROMPT} 占位符 — PyRIT HTTPTarget 原生支持
_PROMPT_PLACEHOLDER = "{PROMPT}"

# R2: OAuth2 token 缓存 (进程级, 避免重复获取)
_oauth2_token_cache: dict[str, str] = {}


@dataclass
class APITargetConfig:
    """API POST 攻击配置。.

    Attributes:
        url: 目标 API 端点 URL (如 https://api.example.com/v1/chat/completions).
        method: HTTP 方法 (默认 POST).
        headers: 请求头字典 (如 {"Content-Type": "application/json", "Authorization": "Bearer xxx"}).
        body_template: 请求体模板 (JSON 字符串, 含 {PROMPT} 占位符).
        response_json_path: 响应 JSON 提取路径 (如 "choices[0].message.content").
        raw_request: Burp Suite 原始 HTTP 请求 (可选, 与 url/body_template 互斥).
        max_rpm: 每分钟最大请求数 (None=不限).
        max_concurrency: 最大并发请求数.
        max_retries: 错误重试次数.
        timeout: 单次请求超时秒数.
        model_name: 目标模型名称 (用于报告标识).
    """

    url: str = ""
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    body_template: str = ""
    response_json_path: str = "choices[0].message.content"
    raw_request: str = ""
    response_format: str = "json"  # G2: "json" or "sse"
    max_rpm: int | None = None
    max_concurrency: int = 3
    max_retries: int = 3
    timeout: int = 30
    health_check: bool = False  # G5: 预检探针
    model_name: str = "api_target"
    # R2: OAuth2 认证配置
    auth_type: str = "bearer"  # "bearer" or "oauth2"
    oauth_token_url: str = ""
    oauth_client_id: str = ""
    oauth_client_secret: str = ""

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        api_key: str | None = None,
        model_name: str | None = None,
        max_rpm: int | None = None,
        max_concurrency: int = 3,
    ) -> APITargetConfig:
        """从 URL 自动构建 APITargetConfig (统一入口用).

        自动推断 API 配置:
          - URL 路径含 /v1/chat/completions → OpenAI Chat Completions 格式
          - URL 路径含 /api/chat → 自定义 Chat API
          - 其他 → 默认 OpenAI 格式

        API Key 优先级: 参数 > .env OPENAI_CHAT_KEY > 无认证

        Args:
            url: 目标 API 端点 URL。
            api_key: API Key (可选, 默认从 .env 读取)。
            model_name: 模型名 (可选, 默认从 .env 读取)。
            max_rpm: 每分钟最大请求数 (可选)。
            max_concurrency: 最大并发请求数。

        Returns:
            APITargetConfig 实例。
        """
        import os

        # 从 .env 获取默认值
        if api_key is None:
            api_key = os.environ.get("OPENAI_CHAT_KEY", "")
        if model_name is None:
            model_name = os.environ.get("OPENAI_CHAT_MODEL", "")

        # 构建请求头
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # 构建请求体模板 (默认 OpenAI Chat Completions 格式)
        if not model_name:
            model_name = _infer_model_name(url)

        body_template = json.dumps({
            "model": model_name,
            "messages": [{"role": "user", "content": _PROMPT_PLACEHOLDER}],
        })

        config = cls(
            url=url,
            method="POST",
            headers=headers,
            body_template=body_template,
            response_json_path="choices[0].message.content",
            raw_request="",
            max_rpm=max_rpm,
            max_concurrency=max_concurrency,
            max_retries=3,
            timeout=30,
            model_name=model_name,
        )

        logger.info(
            f"APITargetConfig.from_url: url={config.url}, "
            f"model={config.model_name}, has_key={bool(api_key)}"
        )
        return config

    @classmethod
    def from_args(cls, args: Any) -> APITargetConfig | None:
        """从 CLI 参数构建 APITargetConfig.

        Args:
            args: argparse.Namespace, 需包含 api_url 等参数。

        Returns:
            APITargetConfig 实例, 如果未提供 --api-url 则返回 None。
        """
        api_url = getattr(args, "api_url", None)
        if not api_url:
            return None

        # 解析请求头
        headers: dict[str, str] = {"Content-Type": "application/json"}
        api_headers_str = getattr(args, "api_headers", None)
        if api_headers_str:
            try:
                headers = json.loads(api_headers_str)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse --api-headers as JSON: {e}")

        # G3: 凭据管理 — --api-key 优先, 然后环境变量 API_KEY
        api_key = getattr(args, "api_key", None) or os.environ.get("API_KEY", "")
        if api_key and not any(k.lower() == "authorization" for k in headers):
            headers["Authorization"] = f"Bearer {api_key}"
            logger.info("G3: API key auto-injected into Authorization header")

        # 解析请求体模板
        body_template = ""
        api_body_str = getattr(args, "api_body", None)
        if api_body_str:
            # 支持 @file_path 从文件加载
            if api_body_str.startswith("@"):
                body_file = Path(api_body_str[1:])
                if body_file.exists():
                    body_template = body_file.read_text(encoding="utf-8")
                else:
                    logger.warning(f"API body template file not found: {body_file}")
            else:
                body_template = api_body_str
        else:
            # 默认 OpenAI Chat Completions 格式
            body_template = json.dumps({
                "model": getattr(args, "api_model", "gpt-3.5-turbo"),
                "messages": [{"role": "user", "content": _PROMPT_PLACEHOLDER}],
            })

        # 验证 body_template 包含 {PROMPT} 占位符
        if _PROMPT_PLACEHOLDER not in body_template:
            logger.warning(
                f"API body template does not contain {_PROMPT_PLACEHOLDER} placeholder, "
                f"prompt injection may not work"
            )

        # 解析原始 HTTP 请求 (Burp Suite 格式)
        raw_request = ""
        api_raw_path = getattr(args, "api_raw_request", None)
        if api_raw_path:
            raw_file = Path(api_raw_path)
            if raw_file.exists():
                raw_request = raw_file.read_text(encoding="utf-8")
                logger.info(f"Loaded raw HTTP request from {api_raw_path}")
            else:
                logger.warning(f"Raw HTTP request file not found: {api_raw_path}")

        # 从 URL 推断模型名称
        model_name = getattr(args, "api_model", "") or _infer_model_name(api_url)

        # R2: OAuth2 client_credentials 支持
        auth_type = getattr(args, "api_auth_type", "bearer")
        oauth_token_url = getattr(args, "api_oauth_token_url", "") or ""
        oauth_client_id = getattr(args, "api_oauth_client_id", "") or ""
        oauth_client_secret = getattr(args, "api_oauth_client_secret", "") or ""

        if auth_type == "oauth2":
            if not oauth_token_url or not oauth_client_id or not oauth_client_secret:
                logger.error(
                    "R2: --api-auth-type oauth2 requires --api-oauth-token-url, "
                    "--api-oauth-client-id, --api-oauth-client-secret"
                )
            else:
                token = _fetch_oauth2_token(
                    token_url=oauth_token_url,
                    client_id=oauth_client_id,
                    client_secret=oauth_client_secret,
                )
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    logger.info("R2: OAuth2 token acquired and injected")
                else:
                    logger.error("R2: OAuth2 token acquisition failed")

        config = cls(
            url=api_url,
            method=getattr(args, "api_method", "POST"),
            headers=headers,
            body_template=body_template,
            response_json_path=getattr(args, "api_response_path", "choices[0].message.content"),
            response_format=getattr(args, "api_response_format", "json"),
            raw_request=raw_request,
            max_rpm=getattr(args, "max_rpm", None),
            max_concurrency=getattr(args, "max_concurrency", 3),
            max_retries=getattr(args, "api_max_retries", 3),
            timeout=getattr(args, "api_timeout", 30),
            health_check=getattr(args, "api_health_check", False),
            model_name=model_name,
            auth_type=auth_type,
            oauth_token_url=oauth_token_url,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )

        logger.info(
            f"APITargetConfig: url={config.url}, method={config.method}, "
            f"max_rpm={config.max_rpm}, max_concurrency={config.max_concurrency}, "
            f"auth_type={config.auth_type}"
        )
        return config

    def to_display_dict(self) -> dict[str, Any]:
        """生成用于显示的配置摘要 (脱敏)。."""
        # 脱敏 Authorization 头
        safe_headers = {}
        for k, v in self.headers.items():
            if k.lower() in ("authorization", "x-api-key", "api-key"):
                safe_headers[k] = _mask_secret(v)
            else:
                safe_headers[k] = v

        return {
            "url": self.url,
            "method": self.method,
            "headers": safe_headers,
            "body_template": self.body_template[:200] + "..." if len(self.body_template) > 200 else self.body_template,
            "response_json_path": self.response_json_path,
            "response_format": self.response_format,
            "has_raw_request": bool(self.raw_request),
            "max_rpm": self.max_rpm,
            "max_concurrency": self.max_concurrency,
            "max_retries": self.max_retries,
            "timeout": self.timeout,
            "health_check": self.health_check,
            "model_name": self.model_name,
        }


def _infer_model_name(url: str) -> str:
    """从 API URL 推断模型名称。."""
    # 简单提取域名作为模型名
    from urllib.parse import urlparse

    domain = urlparse(url).netloc or "unknown"
    return domain.replace(".", "_").replace(":", "_")


def _mask_secret(secret: str) -> str:
    """脱敏密钥 (仅显示前4位和后4位)。."""
    if len(secret) <= 12:
        return "***"
    return f"{secret[:4]}...{secret[-4:]}"


def _fetch_oauth2_token(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    scope: str = "",
) -> str | None:
    """R2: 获取 OAuth2 client_credentials token.

    使用 client_credentials grant type 向 token endpoint 发送 POST 请求,
    获取 access_token 并缓存 (进程级, 避免重复获取).

    学术依据: RFC 6749 Section 4.4 — Client Credentials Grant

    Args:
        token_url: OAuth2 token endpoint URL.
        client_id: Client ID.
        client_secret: Client Secret.
        scope: 请求的 scope (可选).

    Returns:
        access_token 字符串, 失败返回 None.
    """
    import urllib.request

    cache_key = f"{token_url}:{client_id}:{scope}"
    if cache_key in _oauth2_token_cache:
        logger.debug("R2: OAuth2 token from cache")
        return _oauth2_token_cache[cache_key]

    body_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        body_data["scope"] = scope

    body_str = "&".join(f"{k}={v}" for k, v in body_data.items())
    body_bytes = body_str.encode("utf-8")

    req = urllib.request.Request(
        token_url,
        data=body_bytes,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            import json as _json

            token_data = _json.loads(resp.read().decode("utf-8"))
            token = token_data.get("access_token")
            if token:
                _oauth2_token_cache[cache_key] = token
                logger.info("R2: OAuth2 token acquired successfully")
                return token
            logger.error(f"R2: OAuth2 response missing access_token: {token_data}")
            return None
    except Exception as e:
        logger.error(f"R2: OAuth2 token acquisition failed: {e}")
        return None
