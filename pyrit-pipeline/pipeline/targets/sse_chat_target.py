# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""SSE 流式 Chat Target — 支持 AIVP 靶机的 SSE 流式聊天端点。

AIVP (AI Vulnerabilities Playground) 的 ``POST /api/labs/{lab}/chat`` 端点返回
Server-Sent Events (SSE) 流, 格式为::

    event: meta
    data: {"request_id":"...","lab_id":"...","phase":1,"control_mode":"off"}

    data: {"content":"Hello"}
    data: {"content":" world"}

    event: mcp_result
    data: {"tool_result":"...","mcp_telemetry":{...}}

本 Target 解析 SSE 流, 累积所有 ``content`` chunk 为完整响应,
并提取 meta/mcp_result 事件作为元数据。

设计原则 (R-022: PyRIT 原生优先):
  - 注册为 ``PromptTarget`` 虚拟子类 (与 RateLimitedTarget 一致)
  - 使用原生 ``Message`` + ``MessagePiece`` 构造响应
  - 不继承 ``PromptChatTarget`` (避免实现全部抽象方法)

学术依据:
  - HTML5 Server-Sent Events 规范 (W3C)
  - OpenAI Streaming API (SSE 格式)
  - OWASP AI Vulnerabilities Playground (AIVP) 架构

> **日期**: 2026-8-4
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# 运行时导入 PromptTarget 以注册虚拟子类
try:
    from pyrit.prompt_target import PromptTarget as _PromptTarget
except ImportError:
    _PromptTarget = None


# ── SSE 解析常量 ──

# SSE 事件前缀
_SSE_EVENT_PREFIX = "event:"
_SSE_DATA_PREFIX = "data:"

# 默认控制模式
_DEFAULT_CONTROL_MODE = "off"

# 默认超时 (秒)
_DEFAULT_TIMEOUT = 300


@dataclass
class SSEMetaEvent:
    """SSE meta 事件元数据。.

    Attributes:
        request_id: 请求 ID。
        lab_id: 归一化后的 Lab ID。
        phase: 阶段编号 (1=PI, 2=DE, 3=MM, 4=MCP)。
        control_mode: 控制模式 (off/detect/mitigate)。
        artifact_replay: 是否为 artifact replay 模式。
    """

    request_id: str = ""
    lab_id: str = ""
    phase: int = 0
    control_mode: str = _DEFAULT_CONTROL_MODE
    artifact_replay: bool = False


@dataclass
class SSEMCPResult:
    """SSE MCP 工具执行结果。.

    Attributes:
        tool_result: 工具执行结果文本。
        mcp_telemetry: MCP 遥测数据。
        exploit_success: 攻击是否成功。
    """

    tool_result: str = ""
    mcp_telemetry: dict[str, Any] | None = None
    exploit_success: bool = False


@dataclass
class SSEResponse:
    """SSE 完整响应。.

    Attributes:
        content: 累积的完整响应文本。
        meta: meta 事件元数据。
        mcp_result: MCP 工具执行结果 (仅 Phase 4)。
        raw_events: 所有事件类型列表。
    """

    content: str = ""
    meta: SSEMetaEvent | None = None
    mcp_result: SSEMCPResult | None = None
    raw_events: list[str] = field(default_factory=list)


class SSEChatTarget:
    """SSE 流式 Chat Target — 适配 AIVP 靶机的流式聊天端点。

    使用方式::

        from pipeline.targets.sse_chat_target import SSEChatTarget

        target = SSEChatTarget(
            base_url="http://localhost:8000",
            lab_id="PI_01",
            control_mode="off",
        )
        # 注册为 PromptTarget 虚拟子类
        # 可被 RateLimitedTarget 包装

    核心方法:
      - ``send_prompt_async()``: 发送 prompt 并解析 SSE 流
      - ``parse_sse_stream()``: 解析 SSE 流为 SSEResponse
      - ``validate_secret()``: 调用靶机验证端点检查 secret

    PyRIT 原生优先 (R-022):
      - 注册为 PromptTarget 虚拟子类 (非继承)
      - 使用原生 Message + MessagePiece 构造响应
      - 可被 RateLimitedTarget 包装
    """

    def __init__(
        self,
        *,
        base_url: str,
        lab_id: str,
        control_mode: str = _DEFAULT_CONTROL_MODE,
        session_cookie: str | None = None,
        timeout: int = _DEFAULT_TIMEOUT,
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
    ) -> None:
        """初始化 SSE Chat Target。

        Args:
            base_url: AIVP 后端基础 URL (如 ``http://localhost:8000``)。
            lab_id: Lab ID (如 ``PI_01``, ``DE_05``, ``MM_10``, ``MCP_03``)。
            control_mode: 控制模式 (``off``/``detect``/``mitigate``)。
            session_cookie: 会话 cookie (``aivp_sid``), 首次请求自动获取。
            timeout: 请求超时 (秒)。
            auth_headers: 认证 headers 字典 (由 APIAuthenticator.get_headers() 生成)。
            auth_cookies: 认证 cookies 字典 (由 APIAuthenticator.get_cookies() 生成)。
        """
        self._base_url = base_url.rstrip("/")
        self._lab_id = lab_id
        self._control_mode = control_mode
        self._session_cookie = session_cookie
        self._timeout = timeout
        self._auth_headers = auth_headers or {}
        self._auth_cookies = auth_cookies or {}

        # 会话状态
        self._last_response: SSEResponse | None = None
        self._request_count = 0

    # ── 公共属性 ──

    @property
    def base_url(self) -> str:
        """基础 URL。."""
        return self._base_url

    @property
    def lab_id(self) -> str:
        """Lab ID。."""
        return self._lab_id

    @property
    def control_mode(self) -> str:
        """控制模式。."""
        return self._control_mode

    @property
    def session_cookie(self) -> str | None:
        """会话 cookie。."""
        return self._session_cookie

    @session_cookie.setter
    def session_cookie(self, value: str | None) -> None:
        """设置会话 cookie。."""
        self._session_cookie = value

    @property
    def last_response(self) -> SSEResponse | None:
        """最后一次响应。."""
        return self._last_response

    @property
    def endpoint(self) -> str:
        """API 端点 URL (用于 RateLimitedTarget 推断)。."""
        return f"{self._base_url}/api/labs/{self._lab_id}/chat"

    @property
    def _max_requests_per_minute(self) -> int | None:
        """RPM 属性 (兼容 RateLimitedTarget)。."""
        return getattr(self, "_rpm", None)

    @_max_requests_per_minute.setter
    def _max_requests_per_minute(self, value: int | None) -> None:
        """RPM 属性 (兼容 RateLimitedTarget)。."""
        self._rpm = value  # type: ignore[attr-defined]

    # ── 核心方法 ──

    async def send_prompt_async(self, *, prompt_request: Any = None, **kwargs: Any) -> Any:
        """发送 prompt 并解析 SSE 流。

        Args:
            prompt_request: PyRIT PromptRequestResponse (可选)。
            **kwargs: 额外参数 (prompt, message 等)。

        Returns:
            PyRIT PromptRequestResponse (包含完整响应)。
        """
        # 兼容多种调用方式: prompt_request 或直接 prompt
        prompt_text = ""
        if prompt_request is not None:
            # 从 PyRIT PromptRequestResponse 提取 prompt
            try:
                pieces = prompt_request.request_pieces
                if pieces:
                    prompt_text = pieces[0].original_value
            except (AttributeError, IndexError):
                prompt_text = str(prompt_request)
        elif "prompt" in kwargs:
            prompt_text = kwargs["prompt"]
        elif "message" in kwargs:
            prompt_text = kwargs["message"]

        if not prompt_text:
            logger.warning("SSEChatTarget: empty prompt")
            prompt_text = "Hello"

        # 发送请求并解析 SSE 流
        response = await self._send_and_parse_sse(prompt_text)
        self._last_response = response
        self._request_count += 1

        # 构造 PyRIT 原生 PromptRequestResponse
        return self._build_pyrit_response(response, prompt_text)

    def _build_pyrit_response(self, sse_response: SSEResponse, original_prompt: str) -> Any:
        """从 SSEResponse 构造 PyRIT 原生 PromptRequestResponse。."""
        try:
            from pyrit.models import (
                PromptRequestPiece,
                PromptRequestResponse,
            )

            # 构造 assistant 响应 piece
            response_piece = PromptRequestPiece(
                role="assistant",
                original_value=sse_response.content,
                converted_value=sse_response.content,
                conversation_id=self._lab_id,
            )
            return PromptRequestResponse(request_pieces=[response_piece])
        except ImportError:
            # 如果 PyRIT 不可用, 返回简单的 dict
            return {
                "role": "assistant",
                "content": sse_response.content,
                "lab_id": self._lab_id,
                "meta": sse_response.meta.__dict__ if sse_response.meta else None,
                "mcp_result": (
                    {
                        "tool_result": sse_response.mcp_result.tool_result,
                        "exploit_success": sse_response.mcp_result.exploit_success,
                    }
                    if sse_response.mcp_result
                    else None
                ),
            }

    async def _send_and_parse_sse(self, prompt: str) -> SSEResponse:
        """发送 POST 请求并解析 SSE 流。."""
        import aiohttp

        url = self.endpoint
        headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "text/event-stream"}

        # 控制模式 header
        if self._control_mode and self._control_mode != _DEFAULT_CONTROL_MODE:
            headers["X-AIVP-Control-Mode"] = self._control_mode

        # Session cookie + auth cookies
        cookies: dict[str, str] = dict(self._auth_cookies)
        if self._session_cookie:
            cookies["aivp_sid"] = self._session_cookie

        # 认证 headers (由 APIAuthenticator.get_headers() 生成)
        headers.update(self._auth_headers)

        payload = {"prompt": prompt}

        response = SSEResponse()

        try:
            async with aiohttp.ClientSession(
                cookies=cookies, timeout=aiohttp.ClientTimeout(total=self._timeout)
            ) as session, session.post(url, json=payload, headers=headers) as resp:
                # 提取 Set-Cookie 中的 aivp_sid
                set_cookie = resp.headers.get("Set-Cookie", "")
                if "aivp_sid=" in set_cookie and not self._session_cookie:
                    match = re.search(r"aivp_sid=([^;]+)", set_cookie)
                    if match:
                        self._session_cookie = match.group(1)
                        logger.info(f"SSEChatTarget: acquired session cookie {self._session_cookie[:8]}...")

                # 解析 SSE 流
                async for line in resp.content:
                    line_str = line.decode("utf-8", errors="replace").rstrip("\r\n")
                    self._parse_sse_line(line_str, response)

        except Exception as e:
            logger.error(f"SSEChatTarget: request failed: {e}")
            response.content = f"[SSE error] {type(e).__name__}: {e}"

        return response

    def _parse_sse_line(self, line: str, response: SSEResponse) -> None:
        """解析单行 SSE 数据。."""
        if not line:
            # 空行 — SSE 事件分界, 重置当前事件类型
            self._current_event_type = None  # type: ignore[attr-defined]
            return

        # 事件类型行
        if line.startswith(_SSE_EVENT_PREFIX):
            event_type = line[len(_SSE_EVENT_PREFIX):].strip()
            response.raw_events.append(event_type)
            # 缓存当前事件类型 (下一个 data: 行属于此事件)
            self._current_event_type = event_type  # type: ignore[attr-defined]
            return

        # 数据行
        if line.startswith(_SSE_DATA_PREFIX):
            data_str = line[len(_SSE_DATA_PREFIX):].strip()
            if not data_str:
                return

            event_type = getattr(self, "_current_event_type", None)

            try:
                data = json.loads(data_str)
            except json.JSONDecodeError:
                return

            # meta 事件
            if event_type == "meta":
                response.meta = SSEMetaEvent(
                    request_id=data.get("request_id", ""),
                    lab_id=data.get("lab_id", self._lab_id),
                    phase=data.get("phase", 0),
                    control_mode=data.get("control_mode", _DEFAULT_CONTROL_MODE),
                    artifact_replay=data.get("artifact_replay", False),
                )
                return

            # mcp_result 事件
            if event_type == "mcp_result":
                telemetry = data.get("mcp_telemetry")
                exploit_success = bool(telemetry and telemetry.get("exploit_success"))
                response.mcp_result = SSEMCPResult(
                    tool_result=data.get("tool_result", ""),
                    mcp_telemetry=telemetry,
                    exploit_success=exploit_success,
                )
                return

            # 普通内容
            content = data.get("content", "")
            if content:
                response.content += content

    async def validate_secret_async(self, answer: str) -> bool:
        """调用靶机验证端点检查 secret 是否正确。

        Args:
            answer: 候选 secret 值。

        Returns:
            True 如果 secret 正确。
        """
        import aiohttp

        url = f"{self._base_url}/api/secrets/validate"
        payload = {"labId": self._lab_id, "answer": answer}

        try:
            async with aiohttp.ClientSession() as session, session.post(url, json=payload) as resp:
                result = await resp.json()
                return bool(result.get("success", False))
        except Exception as e:
            logger.error(f"SSEChatTarget: validate failed: {e}")
            return False

    def parse_sse_stream(self, raw_text: str) -> SSEResponse:
        """解析原始 SSE 文本流 (用于测试)。."""
        response = SSEResponse()
        for line in raw_text.split("\n"):
            self._parse_sse_line(line, response)
        return response

    async def reset_secret_async(self) -> bool:
        """重置 Lab 的 secret (测试用)。."""
        import aiohttp

        url = f"{self._base_url}/api/secrets/reset/{self._lab_id}"
        try:
            async with aiohttp.ClientSession() as session, session.post(url) as resp:
                result = await resp.json()
                return bool(result.get("ok", False))
        except Exception as e:
            logger.error(f"SSEChatTarget: reset failed: {e}")
            return False


# P1: 注册为 PromptTarget 虚拟子类 (与 RateLimitedTarget 一致)
if _PromptTarget is not None and hasattr(_PromptTarget, "register"):
    _PromptTarget.register(SSEChatTarget)
