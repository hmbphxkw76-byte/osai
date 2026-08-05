# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""G14: 厂商级 API Key 认证策略。

不同公网模型平台使用不同的认证方式:
  - OpenAI / DeepSeek / Moonshot:  Bearer token (sk-xxx)
  - 智谱 (Zhipu):                  JWT 签名 ({id}.{secret} → HMAC-SHA256)
  - 通义千问 (Qwen/DashScope):      API-Key header
  - 百川 (Baichuan):                Bearer token
  - 火山引擎 (Doubao/Ark):          Bearer token
  - 混元 (Hunyuan):                 Bearer token
  - MiniMax:                        Bearer token
  - 内网部署 (Ollama/vLLM/LM Studio): 无需认证或自定义 header

本模块提供 PlatformAuthStrategy 工厂, 根据 PlatformVendor 选择认证方式。
"""

from __future__ import annotations

import hashlib
import hmac
import base64
import json
import logging
import time
from typing import Any

from core.auth.provider import AuthProvider
from core.models.auth_state import AuthState

logger = logging.getLogger(__name__)


class PlatformAuthStrategy(AuthProvider):
    """厂商级认证策略 — 根据 PlatformVendor 选择认证方式。

    Usage::
        from pipeline.models import PlatformVendor
        provider = PlatformAuthStrategy(
            vendor=PlatformVendor.ZHIPU,
            api_key="your-id.your-secret",
        )
        auth_state = await provider.authenticate("https://open.bigmodel.cn")
    """

    # 各厂商的 API Key 环境变量名
    VENDOR_ENV_MAP: dict[str, str] = {
        "openai": "OPENAI_API_KEY",
        "zhipu": "ZHIPU_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "moonshot": "MOONSHOT_API_KEY",
        "baichuan": "BAICHUAN_API_KEY",
        "qwen": "QWEN_API_KEY",
        "doubao": "ARK_API_KEY",
        "hunyuan": "HUNYUAN_API_KEY",
        "minimax": "MINIMAX_API_KEY",
        "spark": "SPARK_API_KEY",
        "ollama": "",
        "vllm": "",
        "lm_studio": "",
        "intranet_llm": "",
        "generic": "API_KEY",
    }

    def __init__(
        self,
        vendor: str = "generic",
        api_key: str = "",
        api_secret: str = "",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._vendor = vendor
        self._api_key = api_key
        self._api_secret = api_secret
        self._extra_headers = extra_headers or {}

    @property
    def name(self) -> str:
        return f"platform:{self._vendor}"

    async def authenticate(self, target_url: str, **kwargs: object) -> AuthState:
        """根据厂商执行认证。"""
        method = self._get_auth_method()
        return method(target_url)

    def _get_auth_method(self):
        """选择认证方法。"""
        methods = {
            "zhipu": self._auth_zhipu,
            "qwen": self._auth_qwen,
            "spark": self._auth_spark,
            "minimax": self._auth_minimax,
            "ollama": self._auth_no_auth,
            "vllm": self._auth_bearer,
            "lm_studio": self._auth_no_auth,
            "intranet_llm": self._auth_bearer,
        }
        return methods.get(self._vendor, self._auth_bearer)

    def _auth_bearer(self, target_url: str) -> AuthState:
        """Bearer token 认证 (OpenAI/DeepSeek/Moonshot/Baichuan/Doubao/Hunyuan/Generic)。"""
        return AuthState(
            auth_type=f"bearer:{self._vendor}",
            tokens={"bearer": self._api_key},
            headers=dict(self._extra_headers),
        )

    def _auth_zhipu(self, target_url: str) -> AuthState:
        """智谱 JWT 签名认证。

        智谱 API Key 格式: {id}.{secret}
        JWT payload: {"api_key": id, "exp": timestamp, "timestamp": timestamp}
        签名: HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)
        """
        try:
            parts = self._api_key.split(".", 1)
            if len(parts) != 2:
                logger.warning("Zhipu API key format invalid (expected id.secret), falling back to Bearer")
                return self._auth_bearer(target_url)

            key_id, secret = parts
            timestamp = int(time.time())
            payload = {
                "api_key": key_id,
                "exp": timestamp + 3600,
                "timestamp": timestamp,
            }

            # JWT header
            header = {"alg": "HS256", "sign_type": "SIGN"}
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

            signing_input = f"{header_b64}.{payload_b64}"
            signature = hmac.new(
                secret.encode(),
                signing_input.encode(),
                hashlib.sha256,
            ).digest()
            sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

            token = f"{signing_input}.{sig_b64}"
            logger.info("PlatformAuthStrategy: Zhipu JWT token generated")
            return AuthState(
                auth_type="bearer:zhipu",
                tokens={"bearer": token},
                headers=dict(self._extra_headers),
            )
        except Exception as e:
            logger.error(f"PlatformAuthStrategy: Zhipu JWT generation failed: {e}")
            return self._auth_bearer(target_url)

    def _auth_qwen(self, target_url: str) -> AuthState:
        """通义千问 DashScope 认证 — API-Key header。"""
        headers = {"Authorization": f"Bearer {self._api_key}"}
        headers.update(self._extra_headers)
        return AuthState(
            auth_type="apikey:qwen",
            headers=headers,
            tokens={"api_key": self._api_key},
        )

    def _auth_spark(self, target_url: str) -> AuthState:
        """星火认证 — API Password 模式 (Bearer)。"""
        return AuthState(
            auth_type="bearer:spark",
            tokens={"bearer": self._api_key},
            headers={"Authorization": f"Bearer {self._api_key}"},
        )

    def _auth_minimax(self, target_url: str) -> AuthState:
        """MiniMax 认证 — Bearer token。"""
        return AuthState(
            auth_type="bearer:minimax",
            tokens={"bearer": self._api_key},
            headers=dict(self._extra_headers),
        )

    def _auth_no_auth(self, target_url: str) -> AuthState:
        """无需认证 (Ollama/LM Studio 等本地服务)。"""
        return AuthState(auth_type="none")


def get_platform_auth(
    vendor: str,
    api_key: str = "",
    api_secret: str = "",
    **kwargs: Any,
) -> PlatformAuthStrategy:
    """工厂函数: 根据 vendor 创建 PlatformAuthStrategy。

    Args:
        vendor: PlatformVendor 的 value (如 "zhipu", "deepseek")
        api_key: API Key (格式因厂商而异)
        api_secret: 可选的 API Secret (智谱等需要)
        **kwargs: 额外 headers

    Returns:
        PlatformAuthStrategy 实例
    """
    return PlatformAuthStrategy(
        vendor=vendor,
        api_key=api_key,
        api_secret=api_secret,
        extra_headers=kwargs.get("extra_headers"),
    )
