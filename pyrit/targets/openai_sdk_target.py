
"""
===============================================================================
PyRIT Red Team — OpenAI SDK 驱动的稳健 Target
===============================================================================
代替 CustomHttpChatTarget 处理所有 OpenAI 兼容 API（不再手工构造 HTTP 请求）。

设计决策:
  当前项目 CustomHttpChatTarget 用 httpx 手工构造 payload/解析响应，
  等效于"重新发明" openai SDK 已完美实现的功能:
  - 自动重试（指数退避 + 可重试错误分类）
  - 流式/非流式切换
  - 类型化的异常（AuthenticationError / RateLimitError / APITimeoutError）
  - 所有 OpenAI 兼容 API 零配置接入

  OpenAICompatibleTarget 是对 openai.AsyncOpenAI 的薄封装，
  将 SDK 能力注入 PyRIT PromptTarget 管道，删除 ~300 行手工 HTTP 代码。

支持范围:
  ✅ OpenAI / Azure OpenAI
  ✅ Ollama（通过 /v1 兼容端点，替代 /api/chat）
  ✅ vLLM / TGI / LM Studio / LocalAI
  ✅ ZHIPU / DeepSeek / Qwen / SiliconFlow / 零一万物 等国内平台
  ✅ 任何实现 /v1/chat/completions 的 API

与 PyRIT 内置 OpenAIChatTarget 的差异:
  PyRIT OpenAIChatTarget 依赖 os.environ 环境变量（AZURE_* / OPENAI_*），
  且不支持 verify_ssl=False、extra_headers 等红队渗透场景参数。
  OpenAICompatibleTarget 通过构造参数直接传入所有配置，
  完全独立于环境变量，适合红队多目标切换场景。

使用方式:
  from targets.openai_sdk_target import OpenAICompatibleTarget
  target = OpenAICompatibleTarget(
      base_url="http://192.168.0.20:11434/v1",
      api_key="ollama",
      model="qwen3:0.6b",
  )
===============================================================================
"""
from __future__ import annotations

from typing import Optional

from openai import AsyncOpenAI
from rich.console import Console

from pyrit.prompt_target import PromptTarget
from pyrit.models import MessagePiece
from pyrit.models.messages.message import Message

from utils import DEFAULT_MODEL_NAME
from utils.http_transport import create_http_client

console = Console()


class OpenAICompatibleTarget(PromptTarget):
    """基于 openai.AsyncOpenAI 的稳健 Target — 零手工 HTTP 处理。

    适用场景:
    - 所有 OpenAI 兼容 Chat API（Ollama /v1、vLLM、ZHIPU、DeepSeek 等）
    - 内网自部署 LLM（HTTP/HTTPS，可跳过 SSL 证书校验）
    - 需要自定义 HTTP 头（X-API-Key 等非标准认证）的场景

    不适用场景（请用对应 SDK Target）:
    - Gemini 原生 API → GeminiTarget (google-genai SDK)
    - Claude 原生 API → ClaudeTarget (anthropic SDK)
    - 非 Chat API 的 Web 应用 → CustomHttpChatTarget (httpx 手工 HTTP)
    """

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        model: str = DEFAULT_MODEL_NAME,
        temperature: float = 0.9,
        max_tokens: int = 4096,
        timeout: int = 60,
        verify_ssl: bool = True,
        extra_headers: Optional[dict] = None,
        max_retries: int = 2,
        tls_impersonate: Optional[str] = None,
    ):
        """初始化 OpenAI 兼容 Target。

        Args:
            base_url: OpenAI 兼容 API 基础 URL（如 http://host:11434/v1）
            api_key: API Key（Ollama 等不需要的传任意非空字符串）
            model: 模型名称
            temperature: 采样温度 (0.0-2.0)
            max_tokens: 最大输出 token 数
            timeout: 请求超时秒数
            verify_ssl: HTTPS 证书校验（内网自签证书设为 False）
            extra_headers: 额外 HTTP 请求头
            max_retries: SDK 自动重试次数（0 为不重试）
            tls_impersonate: TLS 指纹伪装 profile (chrome124/safari17_0/...)
        """
        super().__init__(
            endpoint=base_url.rstrip("/"),
            model_name=model,
        )
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._base_url = base_url.rstrip("/")

        # 构建 httpx 客户端（httpx 核心 + 可选 curl_cffi TLS 伪装）
        self._async_http_client = create_http_client(
            verify_ssl=verify_ssl,
            tls_impersonate=tls_impersonate,
            timeout=timeout,
        )

        self._client = AsyncOpenAI(
            base_url=self._base_url,
            api_key=api_key or "not-needed",
            max_retries=max_retries,
            default_headers=extra_headers or None,
            http_client=self._async_http_client,
        )

    async def _send_prompt_to_target_async(
        self, *, normalized_conversation: list[Message]
    ) -> list[Message]:
        """PyRIT 0.14.0 abstract method — 通过 OpenAI SDK 发送 Chat 请求。

        OpenAI SDK 自动处理:
        - 请求重试（max_retries 次，仅限可重试错误）
        - 超时控制（httpx.Timeout）
        - 错误分类（AuthenticationError / RateLimitError / APIStatusError）
        - 响应反序列化
        """
        last_msg = normalized_conversation[-1] if normalized_conversation else None
        if not last_msg or not last_msg.message_pieces:
            return []

        user_text = (
            last_msg.message_pieces[-1].converted_value
            or last_msg.message_pieces[-1].original_value
        )

        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": user_text}],
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        content = response.choices[0].message.content or ""

        resp_piece = MessagePiece(
            role="assistant",
            original_value=content,
            converted_value=content,
            prompt_target_identifier=self.get_identifier(),
        )
        return [Message(message_pieces=[resp_piece])]

    async def close(self):
        """清理 httpx.AsyncClient（遵循 PyRIT PromptTarget 资源管理最佳实践）。"""
        if self._async_http_client:
            await self._async_http_client.aclose()

    def _build_identifier(self):
        """构建 ComponentIdentifier。"""
        return self._create_identifier(params={
            "sdk": "openai",
            "base_url": self._base_url,
        })
