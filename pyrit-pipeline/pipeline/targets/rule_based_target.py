# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""规则引擎 Chat Target — 支持 DonkAI 靶机的规则引擎聊天端点。

DonkAI 是一个**无 LLM** 的规则引擎靶机, 所有响应由 ``RuleBasedChatbot``
和正则评估器生成。端点 ``POST /chat`` 返回标准 JSON::

    {
      "response": "...",
      "session_id": 1,
      "tokens_used": 5,
      "vulnerability_detected": "LLM01: Prompt Injection - instruction_override"
    }

本 Target 解析 JSON 响应, 提取 ``response`` 作为模型输出,
``vulnerability_detected`` 作为额外攻击信号。

设计原则 (R-022: PyRIT 原生优先):
  - 注册为 ``PromptTarget`` 虚拟子类 (与 RateLimitedTarget 一致)
  - 使用原生 ``Message`` + ``MessagePiece`` 构造响应
  - 不继承 ``PromptChatTarget`` (避免实现全部抽象方法)

学术依据:
  - OWASP Top 10 for LLM Applications 2025
  - DonkAI: Deliberately vulnerable web app for LLM security

> **日期**: 2026-8-4
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyrit.prompt_target import PromptTarget

logger = logging.getLogger(__name__)

# 运行时导入 PromptTarget 以注册虚拟子类
try:
    from pyrit.prompt_target import PromptTarget as _PromptTarget
except ImportError:
    _PromptTarget = None


# 默认超时 (秒)
_DEFAULT_TIMEOUT = 60

# 默认用户 ID (DonkAI 需要 user_id)
_DEFAULT_USER_ID = 1


@dataclass
class RuleBasedResponse:
    """规则引擎响应。.

    Attributes:
        response: 聊天响应文本。
        session_id: DonkAI 会话 ID。
        tokens_used: 使用的 token 数。
        vulnerability_detected: 检测到的漏洞类型 (None 表示未检测到)。
    """

    response: str = ""
    session_id: int = 0
    tokens_used: int = 0
    vulnerability_detected: str | None = None


class RuleBasedTarget:
    """规则引擎 Chat Target — 适配 DonkAI 靶机的 JSON 聊天端点。

    使用方式::

        from pipeline.targets.rule_based_target import RuleBasedTarget

        target = RuleBasedTarget(
            base_url="http://localhost:8000",
            username="alice",
            password="password123",
        )
        # 注册为 PromptTarget 虚拟子类
        # 可被 RateLimitedTarget 包装

    核心方法:
      - ``send_prompt_async()``: 发送 prompt 并解析 JSON 响应
      - ``get_challenge_response()``: 获取挑战专属响应

    PyRIT 原生优先 (R-022):
      - 注册为 PromptTarget 虚拟子类 (非继承)
      - 使用原生 Message + MessagePiece 构造响应
    """

    def __init__(
        self,
        *,
        base_url: str,
        username: str = "",
        password: str = "",
        user_id: int = _DEFAULT_USER_ID,
        session_id: int | None = None,
        timeout: int = _DEFAULT_TIMEOUT,
        auth_manager: Any | None = None,
    ) -> None:
        """初始化规则引擎 Target。

        Args:
            base_url: DonkAI 后端基础 URL (如 ``http://localhost:8000``)。
            username: 认证用户名 (HTTP Basic)。
            password: 认证密码 (HTTP Basic)。
            user_id: DonkAI user_id (默认 1=alice)。
            session_id: DonkAI session_id (None=自动创建)。
            timeout: 请求超时 (秒)。
            auth_manager: 认证管理器实例 (可选, 优先于 username/password)。
        """
        self._base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._user_id = user_id
        self._session_id = session_id
        self._timeout = timeout
        self._auth_manager = auth_manager

        # 会话状态
        self._last_response: RuleBasedResponse | None = None
        self._request_count = 0

    # ── 公共属性 ──

    @property
    def base_url(self) -> str:
        """基础 URL。."""
        return self._base_url

    @property
    def endpoint(self) -> str:
        """API 端点 URL。."""
        return f"{self._base_url}/chat"

    @property
    def session_id(self) -> int | None:
        """当前会话 ID。."""
        return self._session_id

    @session_id.setter
    def session_id(self, value: int | None) -> None:
        """设置会话 ID。."""
        self._session_id = value

    @property
    def last_response(self) -> RuleBasedResponse | None:
        """最后一次响应。."""
        return self._last_response

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
        """发送 prompt 并解析 JSON 响应。

        Args:
            prompt_request: PyRIT PromptRequestResponse (可选)。
            **kwargs: 额外参数 (prompt, message 等)。

        Returns:
            PyRIT PromptRequestResponse (包含完整响应)。
        """
        # 兼容多种调用方式
        prompt_text = ""
        if prompt_request is not None:
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
            logger.warning("RuleBasedTarget: empty prompt")
            prompt_text = "Hello"

        # 发送请求
        response = await self._send_chat_request(prompt_text)
        self._last_response = response
        self._request_count += 1

        # 更新 session_id
        if response.session_id:
            self._session_id = response.session_id

        # 构造 PyRIT 原生 PromptRequestResponse
        return self._build_pyrit_response(response, prompt_text)

    def _build_pyrit_response(self, rb_response: RuleBasedResponse, original_prompt: str) -> Any:
        """从 RuleBasedResponse 构造 PyRIT 原生 PromptRequestResponse。."""
        try:
            from pyrit.models import (
                PromptRequestPiece,
                PromptRequestResponse,
            )

            response_piece = PromptRequestPiece(
                role="assistant",
                original_value=rb_response.response,
                converted_value=rb_response.response,
                conversation_id=f"donkai_session_{rb_response.session_id}",
            )
            return PromptRequestResponse(request_pieces=[response_piece])
        except ImportError:
            return {
                "role": "assistant",
                "content": rb_response.response,
                "session_id": rb_response.session_id,
                "vulnerability_detected": rb_response.vulnerability_detected,
            }

    async def _send_chat_request(self, message: str) -> RuleBasedResponse:
        """发送 POST /chat 请求。."""
        import aiohttp

        url = self.endpoint
        headers: dict[str, str] = {"Content-Type": "application/json"}

        # HTTP Basic auth
        if self._auth_manager:
            auth_headers = self._auth_manager.get_headers()
            headers.update(auth_headers)
        elif self._username:
            import base64

            credentials = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"

        payload: dict[str, Any] = {
            "message": message,
            "user_id": self._user_id,
        }
        if self._session_id is not None:
            payload["session_id"] = self._session_id

        response = RuleBasedResponse()

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self._timeout)
            ) as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    data = await resp.json()
                    response.response = data.get("response", "")
                    response.session_id = data.get("session_id", 0)
                    response.tokens_used = data.get("tokens_used", 0)
                    response.vulnerability_detected = data.get("vulnerability_detected")

        except Exception as e:
            logger.error(f"RuleBasedTarget: request failed: {e}")
            response.response = f"[error] {type(e).__name__}: {e}"

        return response

    async def validate_attack(
        self,
        *,
        challenge_category: str,
        challenge_id: str,
        payload: str,
    ) -> dict[str, Any]:
        """调用 DonkAI 挑战验证接口。

        Args:
            challenge_category: 挑战类别 (如 ``llm01``)。
            challenge_id: 挑战 ID (如 ``c1``)。
            payload: 攻击载荷。

        Returns:
            验证结果字典。
        """
        import aiohttp

        url = f"{self._base_url}/challenges/{challenge_category}/{challenge_id}/validate"
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self._auth_manager:
            headers.update(self._auth_manager.get_headers())
        elif self._username:
            import base64

            credentials = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"

        payload_dict = {"payload": payload}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload_dict, headers=headers) as resp:
                    return await resp.json()
        except Exception as e:
            logger.error(f"RuleBasedTarget: validate failed: {e}")
            return {"success": False, "error": str(e)}


# P1: 注册为 PromptTarget 虚拟子类
if _PromptTarget is not None and hasattr(_PromptTarget, "register"):
    _PromptTarget.register(RuleBasedTarget)
