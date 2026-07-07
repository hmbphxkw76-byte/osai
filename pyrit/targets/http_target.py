"""
===============================================================================
OffSec AI-300 — 自定义 HTTP Chat Target (PyRIT 0.14.0 原生 httpx 后端)
===============================================================================
PyRIT 框架集成:
  ✅ 继承 pyrit.prompt_target.PromptTarget（PyRIT 原生抽象基类）
  ✅ 实现 _send_prompt_to_target_async()（PyRIT 0.14.0 abstract method）
  ✅ 使用 pyrit.models.MessagePiece, Message（PyRIT 原生数据模型）
  ✅ 使用 httpx.AsyncClient（与 PyRIT 内置 Target 使用同一 HTTP 库）
  ✅ 不污染 os.environ（通过构造参数直接传入 endpoint/api_key/model）

与 PyRIT 内置 HttpTarget 的差异:
  PyRIT 内置 HttpTarget 不支持 Gemini/Claude/raw 多格式 payload 构建，
  不支持 JWT/Cookie/form-urlencoded 等多样化认证方式。
  CustomHttpChatTarget 是 PromptTarget 的合理子类，完全兼容 PyRIT orchestrator 管道。

重试策略（PyRIT 最佳实践）:
  传输层（httpx）: 不做 HTTP 级重试，避免与 PyRIT 框架层重试冲突
  框架层（PyRIT）: PromptSendingAttack(max_attempts_on_failure=3) 在 orchestrator 中管理
  业务层: _send_prompt_to_target_async 内 3 次优雅重试 + 指数退避

CustomHttpChatTarget: 基于 httpx 的多格式 HTTP Target，支持:
- 4 种 API 格式: openai / gemini / claude / raw
- 认证: api_key (Bearer/x-api-key) / JWT / Cookie / extra_headers
- HTTPS 自签证书跳过 / 浏览器 UA 伪装
- GET 信息收集 / POST Chat API
- 原生 async（httpx.AsyncClient，无需 asyncio.to_thread 桥接）
===============================================================================
"""
import asyncio
import json
from typing import Optional
from urllib.parse import urlencode

import httpx
from rich.console import Console

from pyrit.prompt_target import PromptTarget
from pyrit.models import MessagePiece
from pyrit.models.messages.message import Message

from utils import DEFAULT_MODEL_NAME, backoff_delay

console = Console()


class CustomHttpChatTarget(PromptTarget):
    """
    自定义 HTTP Chat Target — 基于 requests 库，用于攻击任意 Chat API。

    适用场景:
    - 内网自部署 LLM 应用（HTTP/HTTPS）
    - 自签证书的 HTTPS 端点
    - 需要 Cookie / Session / Token 等 Web 认证的应用
    - 非标准请求/响应格式的 Chat API

    认证方式:
    1. api_key → Bearer (openai) / x-api-key (claude) / URL param (gemini)
    2. extra_headers → 任意自定义头 (Cookie, X-API-Key 等)
    3. verify_ssl → HTTPS 证书校验开关
    """

    _BROWSER_HEADERS: dict = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Priority": "u=0, i",
    }
    
    def __init__(
        self,
        endpoint: str,
        api_key: str = "",
        model: str = DEFAULT_MODEL_NAME,
        temperature: float = 0.9,
        max_tokens: int = 4096,
        timeout: int = 60,
        verify_ssl: bool = False,
        extra_headers: Optional[dict] = None,
        api_format: str = "openai",
        content_type: str = "application/json",
        http_method: str = "POST",
        jwt_token: str = "",
    ):
        """
        Args:
            endpoint: 目标 Chat API URL
            api_key: API Key（自动转为 Bearer / x-api-key 或 Gemini URL param）
            model: 模型名称
            temperature: 采样温度
            max_tokens: 最大输出 token
            timeout: 请求超时（秒）
            verify_ssl: HTTPS 证书校验（内网自签证书设为 False）
            extra_headers: 额外的 HTTP 请求头（覆盖默认浏览器头）
            api_format: API 格式: "openai"(默认) / "gemini" / "claude" / "raw"
            content_type: POST Content-Type: json / form-urlencoded / text
            http_method: HTTP 方法: POST(默认, Chat API) / GET(信息收集/探测)
            jwt_token: JWT Token — 快捷方式，自动转为 Authorization: Bearer <jwt>
                       若同时设置 jwt_token 和 api_key，jwt_token 优先
        """
        super().__init__(
            endpoint=endpoint.rstrip("/"),
            model_name=model,
        )
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._extra_headers = extra_headers or {}
        self._api_format = api_format
        self._content_type = self._extra_headers.get("Content-Type", content_type)
        self._http_method = http_method.upper()
        self._jwt_token = jwt_token
        # SSL: HTTP 时强制 False
        self._verify_ssl = False if endpoint.lower().startswith("http://") else verify_ssl
        # httpx.AsyncClient — 延迟初始化（在首次请求时创建，确保在正确的 event loop 中）
        self._client: httpx.AsyncClient | None = None
    
    # ── Payload 构建 ──

    def _build_request_payload(self, prompt: str, conversation_id: str = "") -> dict:
        if self._api_format == "gemini":
            return self._build_gemini_payload(prompt)
        elif self._api_format == "claude":
            return self._build_claude_payload(prompt)
        elif self._api_format == "raw":
            return self._build_raw_payload(prompt, conversation_id)
        else:
            return self._build_openai_payload(prompt)

    def _build_openai_payload(self, prompt: str) -> dict:
        return {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }

    def _build_gemini_payload(self, prompt: str) -> dict:
        return {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self._temperature,
                "maxOutputTokens": self._max_tokens,
            },
        }

    def _build_claude_payload(self, prompt: str) -> dict:
        return {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

    def _build_raw_payload(self, prompt: str, conversation_id: str = "") -> dict:
        """通用 Chat API payload — 兼容常见 Web 应用格式"""
        if self._extra_headers.get("X-Payload-Format") == "prompt":
            return {"prompt": prompt}
        return {"message": prompt, "conversation_id": conversation_id or ""}

    # ── Headers 组装 & POST body 编码 ──

    def _build_headers(self) -> dict:
        """组装请求头: 默认浏览器头 ⊂ extra_headers ⊂ 认证头（JWT 优先于 api_key）。"""
        headers = dict(self._BROWSER_HEADERS)
        headers.update(self._extra_headers)
        if "Content-Type" not in headers:
            headers["Content-Type"] = self._content_type
        # JWT token 优先覆盖 api_key
        effective_key = self._jwt_token or self._api_key
        if effective_key:
            if self._api_format == "claude":
                headers["x-api-key"] = effective_key
                headers["anthropic-version"] = "2023-06-01"
            elif self._api_format != "gemini":
                headers["Authorization"] = f"Bearer {effective_key}"
        return headers

    def _encode_body(self, payload: dict, headers: dict) -> tuple:
        """根据 Content-Type 编码 POST body，返回 (body_kwargs, data_or_json)。
        
        requests 库原生支持 json= / data= 参数选择:
        - application/json             → json=payload (自动序列化)
        - application/x-www-form-urlencoded → data=urlencode字符串
        - 其他                          → data=json字符串
        """
        ct = headers.get("Content-Type", self._content_type)
        if "json" in ct:
            return ("json", payload)
        elif "form" in ct or "urlencoded" in ct:
            flat = {}
            for k, v in payload.items():
                flat[k] = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
            return ("data", urlencode(flat))
        else:
            return ("data", json.dumps(payload, ensure_ascii=False))

    @staticmethod
    def _safe_read_response(resp: httpx.Response):
        """安全读取响应: 优先 JSON，回退文本。（与 PyRIT 内置 Target 行为一致）"""
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            return resp.text

    # ── 响应解析 ──

    def _parse_response(self, response_data) -> str:
        """从 HTTP 响应中提取文本。纯文本直接返回，dict 按格式解析。"""
        if isinstance(response_data, str):
            return response_data
        if self._api_format == "gemini":
            return self._parse_gemini_response(response_data)
        elif self._api_format == "claude":
            return self._parse_claude_response(response_data)
        elif self._api_format == "raw":
            return json.dumps(response_data, ensure_ascii=False)
        else:
            return self._parse_openai_response(response_data)

    def _parse_openai_response(self, response_data: dict) -> str:
        try:
            return response_data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            pass
        for key in ("response", "content", "text"):
            if key in response_data:
                return str(response_data[key])
        if "data" in response_data and isinstance(response_data["data"], str):
            return response_data["data"]
        return json.dumps(response_data, ensure_ascii=False)

    def _parse_gemini_response(self, response_data: dict) -> str:
        try:
            return response_data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            return self._parse_openai_response(response_data)

    def _parse_claude_response(self, response_data: dict) -> str:
        try:
            content = response_data["content"]
            if isinstance(content, list) and len(content) > 0:
                return content[0].get("text", "")
            return str(content)
        except (KeyError, IndexError, TypeError):
            return self._parse_openai_response(response_data)

    # ── 核心: 原生 async HTTP（httpx.AsyncClient，与 PyRIT 内置 Target 一致）──

    def _ensure_client(self) -> httpx.AsyncClient:
        """延迟创建 httpx.AsyncClient（确保在正确的 asyncio event loop 中）。
        
        PyRIT 最佳实践:
          - 使用 httpx（与 PyRIT OpenAIChatTarget 内部 HTTP 库一致）
          - 不做 HTTP 传输层重试（httpx 默认无重试），完全由 PyRIT 框架层管理
          - 框架层: PromptSendingAttack(max_attempts_on_failure=3)
          - 业务层: 本方法内 3 次重试 + 指数退避
        """
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                verify=self._verify_ssl,
            )
        return self._client

    async def send_prompt_async(self, *, message: Message) -> list[Message]:
        return await self._send_prompt_to_target_async(normalized_conversation=[message])

    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        """PyRIT 0.14.0 abstract method — 核心 HTTP 发送逻辑（httpx 原生 async）。
        
        支持 POST (Chat API) / GET (信息收集/探测)。
        
        重试架构（PyRIT 最佳实践）:
          ┌─────────────┐
          │ 传输层       │  httpx — 无内置重试，避免与框架层冲突
          ├─────────────┤
          │ 业务层       │  本方法 — 3 次重试 + 指数退避（utils.backoff_delay）
          ├─────────────┤
          │ 框架层       │  PromptSendingAttack(max_attempts_on_failure=N)
          └─────────────┘
        """
        last_msg = normalized_conversation[-1] if normalized_conversation else None
        if not last_msg or not last_msg.message_pieces:
            return []

        user_text = last_msg.message_pieces[-1].converted_value or last_msg.message_pieces[-1].original_value
        conversation_id = last_msg.message_pieces[0].conversation_id if last_msg.message_pieces else ""

        headers = self._build_headers()

        # GET 请求: 无 body，prompt 拼接为 query param；POST 请求: 构建 body
        target_url = self._endpoint
        max_retries = 3
        last_error = None

        for attempt in range(max_retries):
            try:
                client = self._ensure_client()

                if self._http_method == "GET":
                    separator = "&" if "?" in target_url else "?"
                    target_url = f"{target_url}{separator}prompt={urlencode({'q': user_text})[2:]}"
                    resp = await client.get(target_url, headers=headers)
                else:
                    payload = self._build_request_payload(user_text, conversation_id)
                    body_mode, body_content = self._encode_body(payload, headers)
                    # Gemini: API Key 追加为 URL query 参数
                    if self._api_format == "gemini" and self._api_key:
                        separator = "&" if "?" in target_url else "?"
                        target_url = f"{target_url}{separator}key={self._api_key}"

                    if body_mode == "json":
                        resp = await client.request(
                            self._http_method, target_url, headers=headers, json=body_content
                        )
                    else:
                        resp = await client.request(
                            self._http_method, target_url, headers=headers, content=body_content
                        )

                response_data = self._safe_read_response(resp)

                if resp.status_code >= 400:
                    error_detail = (
                        json.dumps(response_data, ensure_ascii=False)[:300]
                        if isinstance(response_data, dict)
                        else str(response_data)[:300]
                    )
                    raise httpx.HTTPStatusError(
                        f"HTTP {resp.status_code}: {error_detail}",
                        request=resp.request,
                        response=resp,
                    )

                response_text = self._parse_response(response_data)

                resp_piece = MessagePiece(
                    role="assistant",
                    original_value=response_text,
                    converted_value=response_text,
                    prompt_target_identifier=self.get_identifier(),
                )
                return [Message(message_pieces=[resp_piece])]

            except (httpx.HTTPError, httpx.RequestError, OSError) as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = backoff_delay(attempt)
                    console.print(
                        f"[yellow]⚠️ 目标 [{self._endpoint}] 连接失败，"
                        f"{wait_time:.1f}s 后重试 ({attempt+1}/{max_retries})...[/yellow]"
                    )
                    await asyncio.sleep(wait_time)

        raise ConnectionError(
            f"无法连接目标 [{self._endpoint}]，已重试 {max_retries} 次。最后错误: {last_error}"
        )

    async def close(self):
        """清理 httpx.AsyncClient（遵循 PyRIT PromptTarget 资源管理最佳实践）。"""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_identifier(self):
        """构建 ComponentIdentifier，包含 api_format/http_method 等特有参数。"""
        return self._create_identifier(params={
            "api_format": self._api_format,
            "http_method": self._http_method,
        })
