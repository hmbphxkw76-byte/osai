"""
===============================================================================
PyRIT Red Team — 通用 HTTP Chat Target（仅 raw 格式，非标准 API 兜底）
===============================================================================
PyRIT 框架集成:
  ✅ 继承 pyrit.prompt_target.PromptTarget（PyRIT 原生抽象基类）
  ✅ 实现 _send_prompt_to_target_async()（PyRIT 0.14.0 abstract method）
  ✅ 使用 httpx.AsyncClient（与 PyRIT 内置 Target 使用同一 HTTP 库）
  ✅ 不污染 os.environ（通过构造参数直接传入 endpoint/api_key/model）

与标准 SDK Target 的分工:
  OpenAI/Ollama → OpenAICompatibleTarget (openai SDK)
  Gemini         → GeminiTarget (google-genai SDK)
  Claude         → ClaudeTarget (anthropic SDK)
  raw/非标准 API → CustomHttpChatTarget (本模块，httpx 手工 HTTP)

CustomHttpChatTarget: 基于 httpx 的通用 HTTP Target，支持:
- 认证: api_key (Bearer) / JWT / Cookie / extra_headers
- HTTPS 自签证书跳过 / 浏览器 UA 伪装
- GET 信息收集 / POST Chat API
- form-urlencoded 编码
- 原生 async（httpx.AsyncClient）
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
from utils.target_url import normalize_target_url, DEFAULT_OPEN_TIMEOUT, DEFAULT_READ_TIMEOUT
from utils.http_transport import create_http_client, is_tls_block_error, BROWSER_HEADERS

console = Console()


class CustomHttpChatTarget(PromptTarget):
    """
    通用 HTTP Chat Target — 基于 httpx，仅用于非标准 API 兜底。

    标准 API 请使用对应的 SDK Target:
    - OpenAI/Ollama → OpenAICompatibleTarget
    - Gemini → GeminiTarget
    - Claude → ClaudeTarget

    适用场景:
    - 内网自部署 Web Chat 应用（HTTP/HTTPS）
    - 自签证书的 HTTPS 端点
    - 需要 Cookie / Session / Token 等 Web 认证的应用
    - 非标准请求/响应格式的 Chat API
    """

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
        api_format: str = "raw",
        content_type: str = "application/json",
        http_method: str = "POST",
        jwt_token: str = "",
        query_token: str = "",
        stream: bool = False,
        tls_impersonate: Optional[str] = None,
    ):
        """
        Args:
            endpoint: 目标 Chat API URL
            api_key: API Key（自动转为 Bearer 认证）
            model: 模型名称
            temperature: 采样温度
            max_tokens: 最大输出 token
            timeout: 请求超时（秒）
            verify_ssl: HTTPS 证书校验（内网自签证书设为 False）
            extra_headers: 额外的 HTTP 请求头（覆盖默认浏览器头）
            api_format: API 格式 — raw / sse / ollama / openai / etc
            content_type: POST Content-Type: json / form-urlencoded / text
            http_method: HTTP 方法: POST(默认) / GET
            jwt_token: JWT Token — 快捷方式，自动转为 Authorization: Bearer <jwt>
            query_token: URL Query Token — 拼接到 URL ?token=xxx（SSA 等 Chat 组件常用）
            stream: 是否启用 SSE 流式响应解析
            tls_impersonate: TLS 指纹伪装 profile (chrome124/safari17_0/...)
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
        self._query_token = query_token
        self._stream = stream
        self._tls_impersonate = tls_impersonate
        # SSL 策略：委托 normalize_target_url 判断（HTTP=不验证，HTTPS=验证）
        try:
            nurl = normalize_target_url(endpoint)
            self._verify_ssl = verify_ssl if verify_ssl is not None else nurl.verify_ssl
        except ValueError:
            self._verify_ssl = False
        self._client: httpx.AsyncClient | None = None
        self._tls_fallback_attempted: bool = False

    # ── Payload 构建 ──

    def _build_request_payload(self, prompt: str) -> dict:
        """通用 Chat API payload。SSE 格式支持 stream=true 参数。"""
        payload = {"prompt": prompt}
        if self._stream:
            payload["stream"] = True
        return payload

    def _build_url_with_auth(self, base_url: str) -> str:
        """将 query_token 拼接到 URL（如 ?token=xxx）。"""
        if not self._query_token:
            return base_url
        separator = "&" if "?" in base_url else "?"
        return f"{base_url}{separator}token={self._query_token}"

    @staticmethod
    def _parse_sse_response(text: str) -> str:
        """解析 SSE (Server-Sent Events) 响应体，提取并组装 content 文本。

        支持格式:
            data:{"data":{"messageType":"continue","content":"你好"}}
            data:DONE
            data:{"choices":[{"delta":{"content":"你好"}}]}  (OpenAI stream)
        """
        parts = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "DONE" or payload == "[DONE]":
                continue
            try:
                obj = json.loads(payload)
                # SSA 风格: {"data":{"messageType":"continue","content":"..."}}
                if "data" in obj and isinstance(obj["data"], dict):
                    inner = obj["data"]
                    content = inner.get("content", "")
                    if content:
                        parts.append(content)
                # OpenAI 流式风格: {"choices":[{"delta":{"content":"..."}}]}
                elif "choices" in obj and isinstance(obj["choices"], list) and obj["choices"]:
                    delta = obj["choices"][0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        parts.append(content)
                # 直接 content 字段
                elif "content" in obj:
                    parts.append(obj["content"])
                # 纯文本回退
                else:
                    parts.append(payload[:500])
            except (json.JSONDecodeError, KeyError):
                parts.append(payload[:500])
        return "".join(parts)

    # ── Headers 组装 & POST body 编码 ──

    def _build_headers(self) -> dict:
        """组装请求头: 默认浏览器头 ⊂ extra_headers ⊂ 认证头（JWT 优先于 api_key）。"""
        headers = dict(BROWSER_HEADERS)
        headers.update(self._extra_headers)
        if "Content-Type" not in headers:
            headers["Content-Type"] = self._content_type
        # SSE 流式请求需要 Accept header
        if self._stream or self._api_format == "sse":
            headers["Accept"] = "text/event-stream"
        effective_key = self._jwt_token or self._api_key
        if effective_key:
            headers["Authorization"] = f"Bearer {effective_key}"
        return headers

    def _encode_body(self, payload: dict, headers: dict) -> tuple:
        """根据 Content-Type 编码 POST body，返回 (body_kwargs, data_or_json)。"""
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
        """安全读取响应: 优先 JSON，回退文本。"""
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            return resp.text

    # ── 响应解析 ──

    def _parse_response(self, response_data) -> str:
        """从 HTTP 响应中提取文本。纯文本直接返回，dict 序列化。"""
        if isinstance(response_data, str):
            return response_data
        return json.dumps(response_data, ensure_ascii=False)

    # ── 核心: 原生 async HTTP ──

    def _ensure_client(self) -> httpx.AsyncClient:
        """延迟创建 HTTP 客户端（httpx 核心 + 可选 curl_cffi TLS 伪装）。"""
        if self._client is None:
            self._client = create_http_client(
                verify_ssl=self._verify_ssl,
                tls_impersonate=self._tls_impersonate,
                timeout=self._timeout,
            )
        return self._client

    async def send_prompt_async(self, *, message: Message) -> list[Message]:
        return await self._send_prompt_to_target_async(normalized_conversation=[message])

    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        """PyRIT 0.14.0 abstract method — 核心 HTTP 发送逻辑（httpx 原生 async）。

        支持 POST (Chat API) / GET (信息收集/探测)。
        支持 SSE 流式响应（api_format=sse）和 Query Token 认证。
        业务层: 3 次重试 + 指数退避。
        """
        last_msg = normalized_conversation[-1] if normalized_conversation else None
        if not last_msg or not last_msg.message_pieces:
            return []

        user_text = last_msg.message_pieces[-1].converted_value or last_msg.message_pieces[-1].original_value

        headers = self._build_headers()
        target_url = self._build_url_with_auth(self._endpoint)
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
                    payload = self._build_request_payload(user_text)
                    body_mode, body_content = self._encode_body(payload, headers)
                    if body_mode == "json":
                        resp = await client.request(
                            self._http_method, target_url, headers=headers, json=body_content
                        )
                    else:
                        resp = await client.request(
                            self._http_method, target_url, headers=headers, content=body_content
                        )

                # ── SSE 流式响应解析 ──
                ct = (resp.headers.get("content-type") or "").lower()
                if self._stream or "event-stream" in ct:
                    response_text = self._parse_sse_response(resp.text)
                else:
                    response_data = self._safe_read_response(resp)
                    response_text = self._parse_response(response_data)

                if resp.status_code >= 400:
                    error_detail = response_text[:300]
                    raise httpx.HTTPStatusError(
                        f"HTTP {resp.status_code}: {error_detail}",
                        request=resp.request,
                        response=resp,
                    )

                resp_piece = MessagePiece(
                    role="assistant",
                    original_value=response_text,
                    converted_value=response_text,
                    prompt_target_identifier=self.get_identifier(),
                )
                return [Message(message_pieces=[resp_piece])]

            except (httpx.HTTPError, httpx.RequestError, OSError) as e:
                last_error = e
                # 🆕 TLS 指纹拦截检测 + 自动降级到 curl_cffi
                if (is_tls_block_error(e) and not self._tls_fallback_attempted
                        and not self._tls_impersonate):
                    self._tls_fallback_attempted = True
                    console.print(
                        "[bold yellow]⚠️ 检测到 TLS 指纹可能被拦截，"
                        "自动切换到 curl_cffi 伪装 (chrome124)...[/bold yellow]"
                    )
                    # 销毁当前 httpx client，创建 curl_cffi 伪装 client
                    if self._client:
                        await self._client.aclose()
                        self._client = None
                    self._tls_impersonate = "chrome124"
                    self._client = self._ensure_client()
                    continue  # 用新 client 重试本次 attempt

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
        """清理 httpx.AsyncClient。"""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_identifier(self):
        """构建 ComponentIdentifier。"""
        return self._create_identifier(params={
            "api_format": self._api_format,
            "http_method": self._http_method,
        })
