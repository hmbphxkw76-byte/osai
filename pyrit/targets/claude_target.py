
"""
===============================================================================
PyRIT Red Team — Anthropic Claude SDK 驱动的稳健 Target
===============================================================================
使用 anthropic SDK 对接 Claude API，不再手工构造 HTTP 请求。

设计决策:
  之前 CustomHttpChatTarget 用 httpx 手工构造 Claude 格式 payload
  (x-api-key / anthropic-version 头 + Messages API) 和解析响应
  (content[0].text)，等效于"重新发明" anthropic SDK。

  ClaudeTarget 是对 anthropic.AsyncAnthropic 的薄封装，将 SDK 能力注入
  PyRIT PromptTarget 管道，删除 ~80 行手工 HTTP 代码。

支持范围:
  ✅ Anthropic Claude API (api.anthropic.com)
  ✅ Claude 3.5 Sonnet / Claude 3 Opus / Claude 3 Haiku
  ✅ 自定义 Claude 兼容代理端点

使用方式:
  from targets.claude_target import ClaudeTarget
  target = ClaudeTarget(
      api_key="YOUR_ANTHROPIC_API_KEY",
      model="claude-3-5-sonnet-20241022",
  )
===============================================================================
"""
from __future__ import annotations

import httpx
from typing import Optional

from anthropic import AsyncAnthropic
from rich.console import Console

from pyrit.prompt_target import PromptTarget
from pyrit.models import MessagePiece
from pyrit.models.messages.message import Message

from utils import DEFAULT_MODEL_NAME

console = Console()


class ClaudeTarget(PromptTarget):
    """基于 anthropic.AsyncAnthropic SDK 的 Claude Target — 零手工 HTTP 处理。

    SDK 自动处理:
    - 请求重试与错误分类
    - 流式/非流式切换
    - 响应反序列化
    - Token 计数与速率控制

    适用场景:
    - Anthropic Claude API 直接调用
    - Claude 兼容代理端点
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-5-sonnet-20241022",
        temperature: float = 0.9,
        max_tokens: int = 4096,
        timeout: int = 60,
        verify_ssl: bool = True,
        max_retries: int = 2,
    ):
        """初始化 Claude Target。

        Args:
            api_key: Anthropic API Key
            model: Claude 模型名称
            temperature: 采样温度 (0.0-1.0)
            max_tokens: 最大输出 token 数
            timeout: 请求超时秒数
            verify_ssl: HTTPS 证书校验
            max_retries: SDK 自动重试次数
        """
        super().__init__(
            endpoint="api.anthropic.com",
            model_name=model,
        )
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens

        # 构建 httpx 客户端
        httpx_kwargs: dict = {"timeout": httpx.Timeout(timeout)}
        if not verify_ssl:
            httpx_kwargs["verify"] = False

        self._async_http_client = httpx.AsyncClient(**httpx_kwargs)

        self._client = AsyncAnthropic(
            api_key=api_key,
            max_retries=max_retries,
            http_client=self._async_http_client,
        )

    async def _send_prompt_to_target_async(
        self, *, normalized_conversation: list[Message]
    ) -> list[Message]:
        """PyRIT 0.14.0 abstract method — 通过 Anthropic SDK 发送 Messages 请求。"""
        last_msg = normalized_conversation[-1] if normalized_conversation else None
        if not last_msg or not last_msg.message_pieces:
            return []

        user_text = (
            last_msg.message_pieces[-1].converted_value
            or last_msg.message_pieces[-1].original_value
        )

        response = await self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            messages=[{"role": "user", "content": user_text}],
        )

        content = ""
        if response.content:
            first_block = response.content[0]
            if hasattr(first_block, "text"):
                content = first_block.text
            elif isinstance(first_block, dict):
                content = first_block.get("text", "")

        resp_piece = MessagePiece(
            role="assistant",
            original_value=content,
            converted_value=content,
            prompt_target_identifier=self.get_identifier(),
        )
        return [Message(message_pieces=[resp_piece])]

    async def close(self):
        """清理 httpx.AsyncClient。"""
        if self._async_http_client:
            await self._async_http_client.aclose()

    def _build_identifier(self):
        """构建 ComponentIdentifier。"""
        return self._create_identifier(params={
            "sdk": "anthropic",
            "model": self._model,
        })
