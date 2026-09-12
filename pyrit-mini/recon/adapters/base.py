"""recon/adapters/base.py — TargetAdapter 统一协议与传输态归一（REQ-149 ①③）。

职责（REQ-149 验收）：
    ① 提供统一 `send()` 协议接口（`TargetAdapter` Protocol）；
    ③ **认证态**（Bearer / Cookie / API Key / OAuth / mTLS 配置位）与**会话态**
       （chat_id / thread_id / session_id）在 adapter 内闭环 —— **编排层不可见协议差异**。

设计约束：
    - 零新增运行时依赖（NEG-4）：标准库 + `httpx`（已在 pyproject）；
    - 每个 adapter 提供 `close()`（I13：副作用步必须可清理）；
    - 结果一律归一为 `AdapterResponse`，不向编排层泄漏协议细节；
    - 认证材料在 `redacted()` 中脱敏，避免进入日志/证据（R-S3）。

学术/标准依据：
    - OWASP API Security Top 10 2023 API2（Broken Authentication）
    - PTES §Intelligence Gathering（协议与认证态枚举）
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# 视为认证承载的请求头（大小写不敏感）
_AUTH_HEADER_NAMES = frozenset(
    {"authorization", "x-api-key", "api-key", "x-auth-token", "x-access-token", "x-csrf-token", "proxy-authorization"}
)
# 输出必须脱敏的头/字段
_SENSITIVE_NAMES = frozenset({"authorization", "cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token", "proxy-authorization"})
_REDACTED = "***REDACTED***"

# 会话态占位符（Burp 模板中常见）
CHAT_ID_PLACEHOLDER = "{CHAT_ID}"
THREAD_ID_PLACEHOLDER = "{THREAD_ID}"
SESSION_ID_PLACEHOLDER = "{SESSION_ID}"

# 会话 ID 常见响应字段
_SESSION_ID_FIELDS = ("chat_id", "chatId", "conversation_id", "conversationId", "thread_id", "threadId", "session_id", "sessionId", "id")


class AdapterError(RuntimeError):
    """Adapter 层不可恢复错误（编排层只需处理这一种异常类型）。"""


@dataclass
class AuthState:
    """认证态：在 adapter 内闭环，编排层仅看到"已认证的请求"。"""

    kind: str = "none"  # none | bearer | apikey | cookie | oauth2 | mtls
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    api_key_header: str = "Authorization"
    api_key: str = ""
    oauth_token_url: str = ""
    client_cert: str = ""
    client_key: str = ""

    # -- 构造 ------------------------------------------------------------
    @classmethod
    def from_raw_headers(cls, pairs: Any) -> "AuthState":
        """Build auth state from Burp-style `raw_headers` pairs (never raises)."""
        state = cls()
        explicit = False
        try:
            items = list(pairs or [])
        except TypeError:
            return state

        for pair in items:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                continue
            key, value = str(pair[0]).strip(), str(pair[1]).strip()
            lower = key.lower()

            if lower == "authorization" and value.lower().startswith("bearer "):
                state.kind, state.bearer_token, explicit = "bearer", value[7:].strip(), True
                state.headers[key] = value
            elif lower == "authorization":
                state.kind, state.api_key_header, state.api_key, explicit = "apikey", key, value, True
                state.headers[key] = value
            elif lower == "cookie":
                if not explicit:
                    state.kind = "cookie"
                for chunk in value.split(";"):
                    if "=" in chunk:
                        ck, cv = chunk.split("=", 1)
                        state.cookies[ck.strip()] = cv.strip()
            elif lower in _AUTH_HEADER_NAMES:
                if not explicit:
                    state.kind, explicit = "apikey", True
                state.api_key_header, state.api_key = key, value
                state.headers[key] = value
        return state

    # -- 属性 ------------------------------------------------------------
    @property
    def mtls_configured(self) -> bool:
        return bool(self.client_cert and self.client_key)

    @property
    def refreshable(self) -> bool:
        return self.kind == "oauth2" and bool(self.oauth_token_url)

    # -- 应用 ------------------------------------------------------------
    def apply(self, headers: dict[str, str] | None = None) -> dict[str, str]:
        """Return request headers with auth material applied (idempotent)."""
        merged = dict(headers or {})
        merged.update(self.headers)
        lower_keys = {k.lower() for k in merged}

        if self.kind == "bearer" and self.bearer_token and "authorization" not in lower_keys:
            merged["Authorization"] = f"Bearer {self.bearer_token}"
        if self.cookies:
            existing = next((k for k in merged if k.lower() == "cookie"), None)
            serialized = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            if existing:
                merged[existing] = f"{merged[existing]}; {serialized}"
            else:
                merged["Cookie"] = serialized
        return merged

    def redacted(self) -> dict[str, Any]:
        """Auth state safe for logs/evidence/reports (secrets masked, R-S3)."""
        return {
            "kind": self.kind,
            "has_bearer": bool(self.bearer_token),
            "cookie_names": sorted(self.cookies),
            "api_key_header": self.api_key_header if self.kind == "apikey" else "",
            "mtls_configured": self.mtls_configured,
            "oauth_token_url": self.oauth_token_url,
            "header_names": sorted(k for k in self.headers),
        }


@dataclass
class SessionState:
    """会话态：chat_id / thread_id / session_id 的占位符替换与响应回填。"""

    chat_id: str = ""
    thread_id: str = ""
    session_id: str = ""
    id_fields: dict[str, str] = field(default_factory=dict)

    def apply_to_body(self, body: dict[str, Any]) -> dict[str, Any]:
        """Inject session identifiers into a JSON body (additive, template-driven)."""
        if not body:
            return body
        for field_name, value in self.id_fields.items():
            if value and not body.get(field_name):
                body[field_name] = value
        return body

    def expand(self, text: str) -> str:
        """Replace session placeholders inside a raw body template."""
        if not text:
            return text
        replacements = {
            CHAT_ID_PLACEHOLDER: self.chat_id,
            THREAD_ID_PLACEHOLDER: self.thread_id,
            SESSION_ID_PLACEHOLDER: self.session_id,
        }
        for token, value in replacements.items():
            text = text.replace(token, value or "")
        return text

    def capture(self, payload: Any) -> str:
        """Extract a session id from a response payload. Returns the id found ("" if none)."""
        found = ""
        cursors: list[Any] = [payload]
        while cursors:
            node = cursors.pop()
            if isinstance(node, dict):
                for key in _SESSION_ID_FIELDS:
                    value = node.get(key)
                    if isinstance(value, str) and value:
                        found = found or value
                cursors.extend(node.values())
            elif isinstance(node, list):
                cursors.extend(node)

        if found:
            if not self.chat_id:
                self.chat_id = found
            if not self.session_id:
                self.session_id = found
        return found

    def snapshot(self) -> dict[str, Any]:
        return {"chat_id": self.chat_id, "thread_id": self.thread_id, "session_id": self.session_id, "id_fields": dict(self.id_fields)}


@dataclass
class AdapterRequest:
    """协议无关的请求描述（由各 adapter 解释为具体线上格式）。"""

    prompt: str = ""
    method: str = "POST"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    body_template: str = ""
    files: dict[str, Any] = field(default_factory=dict)
    rpc_method: str = ""
    rpc_params: dict[str, Any] | None = None


@dataclass
class AdapterResponse:
    """协议无关的响应（编排层唯一可见的返回形态）。"""

    status: int = 0
    text: str = ""
    payload: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    raw: bytes = b""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 300

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ok": self.ok,
            "error": self.error,
            "text_length": len(self.text or ""),
            "text": (self.text or "")[:2000],
            "header_names": sorted(self.headers or {}),
        }


@runtime_checkable
class TargetAdapter(Protocol):
    """统一 `send()` 协议（REQ-149 ①）：编排层只依赖本接口。"""

    name: str

    async def send(self, prompt: str, *, session: SessionState | None = None) -> AdapterResponse: ...

    async def send_request(self, request: AdapterRequest) -> AdapterResponse: ...

    async def close(self) -> None: ...


class BaseAdapter:
    """共享实现：httpx 生命周期 + 认证/会话注入 + 响应归一。

    子类只需覆盖「请求成形」（`build_body` / `send_request`）与「响应取文」
    （`extract_text`），认证态与会话态由本基类统一闭环（REQ-149 ③）。
    """

    name = "base"

    def __init__(
        self,
        *,
        url: str = "",
        method: str = "POST",
        auth: AuthState | None = None,
        session: SessionState | None = None,
        timeout: float = 30.0,
        verify: bool = False,
        headers: dict[str, str] | None = None,
        body_template: str = "",
        response_json_path: str | None = None,
    ) -> None:
        self.url = url
        self.method = (method or "POST").upper()
        self.auth = auth or AuthState()
        self.session = session or SessionState()
        self.timeout = timeout
        self.verify = verify
        self.headers = dict(headers or {})
        self.body_template = body_template
        self.response_json_path = response_json_path
        self._client: Any = None

    # -- 生命周期（I13）--------------------------------------------------
    def _http_client(self) -> Any:
        if self._client is None:
            import httpx

            kwargs: dict[str, Any] = {"timeout": self.timeout, "verify": self.verify, "follow_redirects": True}
            if self.auth.mtls_configured:
                kwargs["cert"] = (self.auth.client_cert, self.auth.client_key)
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception as e:  # 清理失败不得掩盖主流程结果
                logger.debug("[Adapter:%s] close failed: %s", self.name, e)
            finally:
                self._client = None

    async def __aenter__(self) -> "BaseAdapter":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    # -- 请求成形 --------------------------------------------------------
    def build_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        merged = {**self.headers, **(extra or {})}
        return self.auth.apply(merged)

    def build_body(self, prompt: str) -> dict[str, Any]:
        """Default JSON body: template placeholders win, else `{"prompt": ...}`."""
        if self.body_template:
            expanded = self.session.expand(self.body_template)
            if "{PROMPT}" in expanded:
                return {"_raw": expanded.replace("{PROMPT}", prompt)}
            return {"_raw": expanded.replace("{PROMPT}", prompt)}
        return self.session.apply_to_body({"prompt": prompt})

    def build_request(self, prompt: str, *, session: SessionState | None = None) -> AdapterRequest:
        if session is not None:
            self.session = session
        return AdapterRequest(
            prompt=prompt,
            method=self.method,
            url=self.url,
            headers=self.build_headers(),
            body=self.build_body(prompt),
        )

    # -- 发送 ------------------------------------------------------------
    async def send(self, prompt: str, *, session: SessionState | None = None) -> AdapterResponse:
        return await self.send_request(self.build_request(prompt, session=session))

    async def send_request(self, request: AdapterRequest) -> AdapterResponse:
        client = self._http_client()
        headers = request.headers or self.build_headers()
        body = request.body
        try:
            if isinstance(body, dict) and body.get("_raw") is not None:
                response = await client.request(request.method, request.url, headers=headers, content=str(body["_raw"]).encode("utf-8"))
            else:
                response = await client.request(request.method, request.url, headers=headers, json=body)
        except Exception as e:
            logger.debug("[Adapter:%s] request failed: %s", self.name, e)
            return AdapterResponse(status=0, error=f"{type(e).__name__}: {e}")

        return self._normalize(response)

    def _normalize(self, response: Any) -> AdapterResponse:
        raw = getattr(response, "content", b"") or b""
        text = raw.decode("utf-8", "replace")
        payload = None
        try:
            payload = response.json()
        except Exception:
            payload = None
        if payload is not None:
            self.session.capture(payload)
        return AdapterResponse(
            status=int(getattr(response, "status_code", 0) or 0),
            text=text,
            payload=payload,
            headers={str(k): str(v) for k, v in dict(getattr(response, "headers", {}) or {}).items()},
            raw=raw,
        )

    # -- 响应取文 --------------------------------------------------------
    def extract_text(self, response: AdapterResponse) -> str:
        """Extract assistant-visible text from a normalized response."""
        if response.payload is None:
            return response.text or ""
        node: Any = response.payload
        if self.response_json_path:
            for token in self.response_json_path.replace("[", ".").replace("]", "").split("."):
                if not token or token == "$":
                    continue
                if isinstance(node, dict):
                    node = node.get(token)
                elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
                    node = node[int(token)]
                else:
                    return response.text or ""
        if isinstance(node, str):
            return node
        if isinstance(node, dict):
            for key in ("content", "text", "message", "result", "answer", "response"):
                value = node.get(key)
                if isinstance(value, str):
                    return value
                if isinstance(value, dict) and isinstance(value.get("content"), str):
                    return value["content"]
        return response.text or ""

    def describe(self) -> dict[str, Any]:
        return {"adapter": self.name, "url": self.url, "method": self.method, "auth": self.auth.redacted(), "session": self.session.snapshot()}
