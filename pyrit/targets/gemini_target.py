
"""
===============================================================================
PyRIT Red Team — Google Gemini SDK 驱动的稳健 Target
===============================================================================
使用 google-genai SDK（google.genai）对接 Gemini API，不再手工构造 HTTP 请求。

设计决策:
  之前 CustomHttpChatTarget 用 httpx 手工构造 Gemini 格式 payload
  (contents/parts/generationConfig) 和解析响应 (candidates[0].content.parts[0].text)，
  等效于"重新发明" Google GenAI SDK。

  GeminiTarget 是对 google.genai.Client 的薄封装，将 SDK 能力注入 PyRIT
  PromptTarget 管道，删除 ~80 行手工 HTTP 代码。

支持范围:
  ✅ Google Gemini API (generativelanguage.googleapis.com)
  ✅ 所有 Gemini 模型 (gemini-2.5-flash, gemini-2.5-pro 等)
  ✅ Vertex AI Gemini 端点

使用方式:
  from targets.gemini_target import GeminiTarget
  target = GeminiTarget(
      api_key="YOUR_GEMINI_API_KEY",
      model="gemini-2.5-flash",
  )
===============================================================================
"""
from __future__ import annotations

import asyncio
from typing import Optional

from google import genai
from rich.console import Console

from pyrit.prompt_target import PromptTarget
from pyrit.models import MessagePiece
from pyrit.models.messages.message import Message

from utils import DEFAULT_MODEL_NAME

console = Console()


class GeminiTarget(PromptTarget):
    """基于 google.genai SDK 的 Gemini Target — 零手工 HTTP 处理。

    SDK 自动处理:
    - 请求重试与错误分类
    - 流式/非流式切换
    - Safety settings 过滤
    - 响应反序列化

    适用场景:
    - Google Gemini API 直接调用
    - Vertex AI Gemini 端点
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.5-flash",
        temperature: float = 0.9,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        """初始化 Gemini Target。

        Args:
            api_key: Google AI API Key
            model: Gemini 模型名称
            temperature: 采样温度 (0.0-2.0)
            max_tokens: 最大输出 token 数
            timeout: 请求超时秒数
        """
        super().__init__(
            endpoint="generativelanguage.googleapis.com",
            model_name=model,
        )
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens

        self._client = genai.Client(
            api_key=api_key,
            http_options={"timeout": timeout * 1000},  # 毫秒
        )

    async def _send_prompt_to_target_async(
        self, *, normalized_conversation: list[Message]
    ) -> list[Message]:
        """PyRIT 0.14.0 abstract method — 通过 Gemini SDK 发送 Chat 请求。"""
        last_msg = normalized_conversation[-1] if normalized_conversation else None
        if not last_msg or not last_msg.message_pieces:
            return []

        user_text = (
            last_msg.message_pieces[-1].converted_value
            or last_msg.message_pieces[-1].original_value
        )

        # google.genai SDK 原生支持 async
        response = await self._client.aio.models.generate_content(
            model=self._model,
            contents=user_text,
            config={
                "temperature": self._temperature,
                "max_output_tokens": self._max_tokens,
            },
        )

        content = response.text or ""

        resp_piece = MessagePiece(
            role="assistant",
            original_value=content,
            converted_value=content,
            prompt_target_identifier=self.get_identifier(),
        )
        return [Message(message_pieces=[resp_piece])]

    def _build_identifier(self):
        """构建 ComponentIdentifier。"""
        return self._create_identifier(params={
            "sdk": "google-genai",
            "model": self._model,
        })
