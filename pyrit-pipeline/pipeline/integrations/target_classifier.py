# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""TargetClassifier: 目标 URL 类型自动判别器 + 多维攻击面拓扑。

三路并行探测, 投票决策目标类型:
  1. HTTP 响应分析 (Content-Type, Server, 状态码)
  2. URL 路径模式匹配 (复用 EndpointClassifier 规则)
  3. 页面 DOM 特征 (如需浏览器, 延迟检测)

判别结果:
  - llm_web_app:     基于 LLM 的 Web 应用 (有聊天 UI, HTML 页面)
  - llm_api_platform: LLM API 平台 (JSON 响应, API 端点路径)
  - unknown:          无法确定, 降级为用户手动选择

v56 攻击者视角增强 — AttackSurfaceTopology:
  在原有二元分类基础上, 新增多维攻击面拓扑, 从攻击者视角回答:
    "这个目标有哪些可注入的攻击面?"
  覆盖 5 层: 传输面 / 应用面 / 认证面 / 攻击面 / Kill Chain 映射

学术依据:
  - PyRIT (arXiv:2407.01232): PlaywrightTarget (Web UI) vs HTTPTarget (API)
  - OWASP Top 10 for LLMs 2025: Web 注入和 API 注入的攻击面对应
  - MITRE ATT&CK T1592: 主动扫描 → 初始访问前需识别目标类型
  - Greshake et al. (arXiv:2302.12173): Agent 应用是主要攻击面
  - OWASP ASI01-10: Agentic Security 攻击面拓扑

> **日期**: 2026-8-3
> **更新记录**:
  2026-8-16 — v56: 新增 AttackSurfaceTopology 多维攻击面拓扑 + Burp请求体Agent结构分析 + 认证拓扑增强
  2026-8-18 — v57: URL路径驱动的拓扑推断 (MCP/Agent路径模式) + Kill Chain扩展
    (execution/defense_evasion/persistence) + 极简请求体场景深度分析 +
    Session Cookie过期时间提取

学术依据 (v57 新增):
  - MITRE ATT&CK for LLMs (Atlas): execution/defense_evasion/persistence 阶段
  - OWASP ASI01-10: Agentic Security — URL路径暗示的Agent攻击面
  - Microsoft PyRIT Best Practices: 最少3-5样本才能判断防御强度
"""

from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass
from typing import Any

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── 高风险 Agent 工具关键词 (offensive 视角: 这些工具被劫持后危害最大) ──
_HIGH_RISK_TOOL_NAMES: frozenset[str] = frozenset({
    "execute_command", "exec_command", "run_command", "shell", "terminal",
    "write_file", "create_file", "modify_file",
    "delete_file", "remove_file", "rm",
    "send_email", "email", "smtp",
    "http_request", "fetch", "curl", "wget", "request",
    "get_environment", "env", "environment", "getenv",
    "list_directory", "ls", "dir", "readdir",
    "read_file", "cat",
    "sql_query", "database", "db_query",
    "upload_file", "download_file",
    "create_user", "add_user", "modify_permissions",
})

# ── RAG 特征字段名 (用于从 Burp 请求体检测 RAG 管道) ──
_RAG_FIELD_NAMES: frozenset[str] = frozenset({
    "context", "retrieved_context", "knowledge", "knowledge_base",
    "retrieved_documents", "sources", "reference", "references",
    "documents", "citations", "evidence",
})

# ── MCP 协议特征字段 ──
_MCP_FIELD_NAMES: frozenset[str] = frozenset({
    "mcp", "mcp_server", "mcp_config", "server_config",
    "tool_server", "protocol_version",
})

# ── API 端点 URL 路径模式 (复用 recon-pipeline EndpointClassifier 规则) ──
_API_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/v1/chat/completions", re.IGNORECASE),
    re.compile(r"/v1/responses", re.IGNORECASE),
    re.compile(r"/v1/completions", re.IGNORECASE),
    re.compile(r"/api/(chat|completion|generate|inference)", re.IGNORECASE),
    re.compile(r"/(openai|anthropic|llama|gemini|mistral)/", re.IGNORECASE),
]

# ── SSE / 流式 API URL 路径模式 ──
_STREAMING_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/stream", re.IGNORECASE),
    re.compile(r"/sse", re.IGNORECASE),
    re.compile(r"/events", re.IGNORECASE),
    re.compile(r"/v1/chat/completions", re.IGNORECASE),  # OpenAI streaming endpoint
    re.compile(r"/api/stream", re.IGNORECASE),
    re.compile(r"/subscribe", re.IGNORECASE),
]

# ── Web 应用 URL 路径模式 ──
_WEB_APP_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/(chat|playground|app|dashboard)", re.IGNORECASE),
    re.compile(r"/#", re.IGNORECASE),  # SPA hash 路由
]

# ── v57: Agent/MCP/Lab URL 路径模式 (offensive 视角: 路径暗示架构) ──
# /api/labs/MCP_* → MCP 实验场景 (Agent + 工具调用)
# /api/agent/* → Agent 应用
# /api/assistant/* → AI 助手 (多轮 + system prompt)
# /api/mcp/* → MCP 协议端点
_AGENT_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/api/labs/MCP_", re.IGNORECASE),
    re.compile(r"/api/mcp[/?]", re.IGNORECASE),
    re.compile(r"/api/agent[/?]", re.IGNORECASE),
    re.compile(r"/api/assistant[/?]", re.IGNORECASE),
    re.compile(r"/labs/.* MCP", re.IGNORECASE),
    re.compile(r"/tools?/invoke", re.IGNORECASE),
]

# ── v57: Cookie 名称特征模式 (offensive 视角: Cookie名暗示认证架构) ──
# aivp_sid → AI Valley Platform session (AI应用平台)
# *_sid → 通用 session ID
# session_token → session token 认证
# jwt_* → JWT 认证
_COOKIE_AUTH_PATTERNS: dict[str, re.Pattern[str]] = {
    "session_id": re.compile(r"\b(\w+)_sid\b", re.IGNORECASE),
    "session_token": re.compile(r"\bsession_token\b", re.IGNORECASE),
    "jwt": re.compile(r"\bjwt\b", re.IGNORECASE),
    "auth_token": re.compile(r"\bauth_token\b", re.IGNORECASE),
    "access_token": re.compile(r"\baccess_token\b", re.IGNORECASE),
}

# ── 聊天 UI DOM 选择器 (与 dynamic_profile.py 一致, P5 扩展框架特征) ──
_CHAT_UI_SELECTORS = [
    # ── 通用 HTML 元素 ──
    "textarea",
    "[contenteditable='true']",
    '[class*="chat"]',
    '[class*="message"]',
    '[class*="conversation"]',
    '[data-role="assistant"]',
    # ── React 框架特征 ──
    "[data-reactroot]",  # React 16 SSR
    '[data-reactroot] [class*="chat"]',
    # ── Vue 框架特征 ──
    "[data-v-app]",  # Vue 3 app root
    '[data-v-app] [class*="chat"]',
    # ── Next.js / Nuxt 框架特征 ──
    "#__next",  # Next.js app root
    '#__next [class*="chat"]',
    "#__nuxt",  # Nuxt app root
    # ── 常见 AI 聊天 UI 组件库 ──
    '[class*="ant-message"]',  # Ant Design message
    '[class*="el-chat"]',  # Element Plus chat
    '[class*="prosemirror"]',  # ProseMirror 编辑器 (常用作聊天输入框)
    '[class*="tiptap"]',  # Tiptap 编辑器 (基于 ProseMirror)
    '[class*="ql-editor"]',  # Quill 编辑器
    '[role="log"]',  # ARIA role: chat log
    '[aria-live="polite"]',  # ARIA live region (常见于 AI 回复区)
]


@dataclass
class AttackSurfaceTopology:
    """v56: 多维攻击面拓扑 — 攻击者视角的目标画像.

    从 5 个维度刻画目标的攻击面, 回答 "这个目标有哪些可注入的攻击面?":
      层1 传输面: Web App / API / MCP Server
      层2 应用面: 简单LLM / Agent+工具 / RAG管道 / 多Agent / MCP编排
      层3 认证面: 认证拓扑 + 持久性 + Token过期 + MFA
      层4 攻击面: 可注入面列表 + 已发现工具 + 信任边界
      层5 Kill Chain: 推荐攻击阶段 + OWASP 类别

    学术依据:
      - MITRE ATT&CK T1592 (Gather Victim Host Info)
      - Greshake et al. (arXiv:2302.12173): Agent 应用攻击面发现
      - OWASP ASI01-10: Agentic Security 攻击面拓扑

    Attributes:
        transport_type: 传输类型 ("web_app" | "api_platform" | "mcp_server" | "unknown")
        app_architecture: 应用架构 (simple_llm/agent_with_tools/rag_pipeline/multi_agent/mcp_orchestrator)
        has_tool_calling: 请求体含 tools/functions 字段
        has_multi_turn: 请求体含 messages 数组 (多轮对话)
        has_streaming: SSE/stream 流式响应
        has_system_prompt: 请求体含 system message
        auth_topology: 认证拓扑 (none/session_cookie/bearer_token/oauth2_jwt/api_key/basic/custom_header)
        auth_persistence: 认证持久性 ("stateless" | "session" | "persistent")
        token_expiry_seconds: JWT 过期时间秒 (0=无过期/不适用)
        has_mfa: 检测到 MFA 挑战
        injection_surfaces: 可注入面列表
        discovered_tools: 已发现的工具定义列表
        trust_boundaries: 信任边界列表
        model_fingerprint: 模型族/版本指纹
        recommended_kill_chain: 推荐 Kill Chain 阶段
        recommended_owasp: 推荐 OWASP 类别
    """

    # ── 层1: 传输面 ──
    transport_type: str = "unknown"
    # ── 层2: 应用面 ──
    app_architecture: str = "simple_llm"
    has_tool_calling: bool = False
    has_multi_turn: bool = False
    has_streaming: bool = False
    has_system_prompt: bool = False
    # ── 层3: 认证面 ──
    auth_topology: str = "none"
    auth_persistence: str = "stateless"
    token_expiry_seconds: int = 0
    has_mfa: bool = False
    # ── 层4: 攻击面 ──
    injection_surfaces: list[str] = None  # type: ignore[assignment]
    discovered_tools: list[dict] = None  # type: ignore[assignment]
    trust_boundaries: list[str] = None  # type: ignore[assignment]
    model_fingerprint: dict = None  # type: ignore[assignment]
    # ── 层5: Kill Chain 映射 ──
    recommended_kill_chain: list[str] = None  # type: ignore[assignment]
    recommended_owasp: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        """Initialize default collections."""
        if self.injection_surfaces is None:
            self.injection_surfaces = ["user_message"]
        if self.discovered_tools is None:
            self.discovered_tools = []
        if self.trust_boundaries is None:
            self.trust_boundaries = ["user→llm"]
        if self.model_fingerprint is None:
            self.model_fingerprint = {}
        if self.recommended_kill_chain is None:
            self.recommended_kill_chain = ["recon", "initial_access"]
        if self.recommended_owasp is None:
            self.recommended_owasp = ["LLM01"]

    def __str__(self) -> str:
        """Return string representation."""
        lines = [
            "AttackSurfaceTopology:",
            f"  transport:       {self.transport_type}",
            f"  architecture:    {self.app_architecture}",
            f"  tool_calling:    {self.has_tool_calling}",
            f"  multi_turn:      {self.has_multi_turn}",
            f"  streaming:       {self.has_streaming}",
            f"  system_prompt:   {self.has_system_prompt}",
            f"  auth_topology:   {self.auth_topology}",
            f"  auth_persistence: {self.auth_persistence}",
            f"  token_expiry:    {self.token_expiry_seconds}s",
            f"  has_mfa:         {self.has_mfa}",
            f"  injection_surfaces: {self.injection_surfaces}",
            f"  discovered_tools:   {len(self.discovered_tools)} tools",
            f"  trust_boundaries:   {self.trust_boundaries}",
            f"  kill_chain:      {self.recommended_kill_chain}",
            f"  owasp:           {self.recommended_owasp}",
        ]
        return "\n".join(lines)


@dataclass
class TargetClassification:
    """目标类型判别结果。.

    Attributes:
        target_type: 目标类型 ("llm_web_app" | "llm_api_platform" | "unknown")
        target_url: 原始目标 URL
        http_status: HTTP 响应状态码 (0 表示未发送请求)
        content_type: HTTP 响应 Content-Type
        is_html: 响应是否为 HTML
        has_chat_ui: DOM 是否包含聊天 UI 组件 (仅 Web App)
        api_endpoint_pattern: 匹配到的 API 路径模式 (仅 API Platform)
        detection_reason: 判别依据的人类可读描述
        recommended_mode: 推荐模式 ("browser" | "api")
        api_auth_type: API 认证类型 (bearer | api_key | oauth2 | basic | unknown)
        api_auth_header: API 认证头名称
        has_openapi_spec: 是否检测到 OpenAPI/Swagger 规范
        streaming_type: 流式类型 ("sse" | "ndjson" | "stream_json" | "" 非流式)
        is_streaming: 是否为流式 API
        attack_surface: v56 多维攻击面拓扑 (None=未构建)
    """

    target_type: str = "unknown"
    target_url: str = ""
    http_status: int = 0
    content_type: str = ""
    is_html: bool = False
    has_chat_ui: bool = False
    api_endpoint_pattern: str | None = None
    detection_reason: str = ""
    recommended_mode: str = "api"  # unknown 默认走 API (更安全)
    # A3: API 认证信息自动提取
    api_auth_type: str = ""  # bearer | api_key | oauth2 | basic | unknown
    api_auth_header: str = ""  # Authorization | X-API-Key | X-Auth-Token
    has_openapi_spec: bool = False
    # SSE / 流式 API 检测 (Round 24 增强)
    streaming_type: str = ""  # sse | ndjson | stream_json | "" (非流式)
    is_streaming: bool = False
    # v56: 多维攻击面拓扑
    attack_surface: AttackSurfaceTopology | None = None

    def __str__(self) -> str:
        """Return string representation."""
        lines = [
            "TargetClassification:",
            f"  target_type:          {self.target_type}",
            f"  target_url:           {self.target_url}",
            f"  http_status:          {self.http_status}",
            f"  content_type:         {self.content_type}",
            f"  is_html:              {self.is_html}",
            f"  has_chat_ui:          {self.has_chat_ui}",
            f"  api_endpoint_pattern: {self.api_endpoint_pattern}",
            f"  recommended_mode:     {self.recommended_mode}",
            f"  streaming_type:       {self.streaming_type or 'none'}",
            f"  is_streaming:         {self.is_streaming}",
            f"  reason:               {self.detection_reason}",
        ]
        if self.attack_surface is not None:
            lines.append(str(self.attack_surface))
        return "\n".join(lines)


class TargetClassifier:
    """目标 URL 类型自动判别器。.

    通过 HTTP 探测 + URL 模式匹配, 自动判别目标类型。
    对于需要浏览器访问的 Web 应用, 可选执行 DOM 特征检测。

    用法::

        classifier = TargetClassifier()
        result = await classifier.classify("https://chat.example.com")
        # result.target_type → "llm_web_app" | "llm_api_platform" | "unknown"
        # result.recommended_mode → "browser" | "api"
    """

    def __init__(
        self,
        http_timeout: int = 10,
        user_agent: str = "Mozilla/5.0 (compatible; OSAI-RedTeam/1.0)",
        render_check: bool = True,
    ) -> None:
        """Initialize TargetClassifier.

        Args:
            http_timeout: HTTP 探测超时秒数。
            user_agent: HTTP 请求 User-Agent。
            render_check: 是否在静态 HTML 无聊天 UI 时启用浏览器渲染后 DOM 检测。
        """
        self._timeout = http_timeout
        self._user_agent = user_agent
        self._render_check = render_check

    async def classify(
        self,
        target_url: str,
        *,
        force_type: str = "auto",
        stream: bool | None = None,
    ) -> TargetClassification:
        """判别目标 URL 的类型。.

        三路并行探测:
          1. URL 路径模式匹配 (最快, 无网络请求)
          2. HTTP 响应分析 (中等, 需发送 GET 请求)
          3. DOM 特征检测 (最慢, 仅在 HTML 响应时执行)

        Args:
            target_url: 目标 URL。
            force_type: 强制类型 ("auto" | "web_app" | "api_platform")。
            stream: 用户通过 --stream/--no-stream 指定的流式模式。
                None = 自动检测 (默认行为);
                True = 强制标记为流式 (streaming_type=sse);
                False = 强制标记为非流式 (覆盖 URL 模式匹配结果)。
            render_check: 是否启用 SPA 渲染后 DOM 检测 (覆盖实例默认值)。

        Returns:
            TargetClassification 判别结果。
        """
        # 强制类型覆盖
        if force_type == "web_app":
            return TargetClassification(
                target_type="llm_web_app",
                target_url=target_url,
                detection_reason="Forced to web_app by --target-type",
                recommended_mode="browser",
            )
        if force_type == "api_platform":
            result = TargetClassification(
                target_type="llm_api_platform",
                target_url=target_url,
                detection_reason="Forced to api_platform by --target-type",
                recommended_mode="api",
            )
            if stream:
                result.streaming_type = "sse"
                result.is_streaming = True
            return result

        result = TargetClassification(target_url=target_url)

        # 路径 1: URL 路径模式匹配 (无网络请求)
        url_match = self._match_url_patterns(target_url)
        streaming_url_match = self._match_streaming_url_patterns(target_url)
        if url_match == "api":
            result.target_type = "llm_api_platform"
            result.api_endpoint_pattern = "url_pattern"
            result.recommended_mode = "api"
            # SSE URL 模式 → 标记流式 (受 stream 参数覆盖)
            if streaming_url_match and stream is not False:
                result.streaming_type = "sse"
                result.is_streaming = True
                result.detection_reason = (
                    "URL 路径匹配 API 端点模式 + 流式端点模式 "
                    f"(如 /stream, /sse, /events) — streaming_type={result.streaming_type}"
                )
            elif stream is True:
                # 用户强制启用流式 (即使 URL 不含流式路径)
                result.streaming_type = "sse"
                result.is_streaming = True
                result.detection_reason = (
                    "URL 路径匹配 API 端点模式 + --stream 强制启用流式 "
                    f"— streaming_type={result.streaming_type}"
                )
            else:
                result.detection_reason = (
                    "URL 路径匹配 API 端点模式 (如 /v1/chat/completions, /api/chat)"
                )
            # A3: API 认证信息提取
            self._extract_api_auth_info(result, http_info={})
            logger.info(
                f"TargetClassifier: URL pattern → llm_api_platform"
                f"{' (streaming)' if result.is_streaming else ''}"
            )
            return result

        # 流式 URL 模式 (非 API 路径但匹配流式端点) → API 平台 (流式)
        # 受 stream=False 覆盖: 用户可强制关闭流式
        if streaming_url_match and stream is not False:
            result.target_type = "llm_api_platform"
            result.api_endpoint_pattern = "streaming_url"
            result.recommended_mode = "api"
            result.streaming_type = "sse"
            result.is_streaming = True
            result.detection_reason = (
                "URL 路径匹配流式端点模式 (如 /stream, /sse, /events) — "
                "streaming_type=sse"
            )
            self._extract_api_auth_info(result, http_info={})
            logger.info("TargetClassifier: streaming URL → llm_api_platform (streaming)")
            return result

        # 路径 2: HTTP 响应分析
        http_info = await self._http_probe(target_url)
        result.http_status = http_info.get("status", 0)
        result.content_type = http_info.get("content_type", "")
        result.is_html = "text/html" in result.content_type.lower()

        # JSON 响应 → API 平台
        ct_lower = result.content_type.lower()
        if "application/json" in ct_lower:
            result.target_type = "llm_api_platform"
            result.api_endpoint_pattern = "http_json_response"
            result.recommended_mode = "api"
            # 检查是否为流式 JSON (NDJSON / stream+json)
            streaming = self._detect_streaming_json(ct_lower, http_info)
            if streaming:
                result.streaming_type = streaming
                result.is_streaming = True
                result.detection_reason = (
                    f"HTTP 响应 Content-Type={result.content_type} "
                    f"(status={result.http_status}) — streaming_type={streaming}"
                )
            else:
                result.detection_reason = (
                    f"HTTP 响应 Content-Type=application/json (status={result.http_status})"
                )
            # A3: API 认证信息提取
            self._extract_api_auth_info(result, http_info)
            logger.info(
                f"TargetClassifier: JSON response → llm_api_platform"
                f"{' (streaming: ' + streaming + ')' if streaming else ''}"
            )
            return result

        # SSE (Server-Sent Events) 响应 → API 平台 (流式)
        if "text/event-stream" in ct_lower:
            result.target_type = "llm_api_platform"
            result.api_endpoint_pattern = "http_sse"
            result.recommended_mode = "api"
            result.streaming_type = "sse"
            result.is_streaming = True
            result.detection_reason = (
                f"HTTP 响应 Content-Type=text/event-stream (SSE 流式 API, "
                f"status={result.http_status})"
            )
            # A3: API 认证信息提取
            self._extract_api_auth_info(result, http_info)
            logger.info("TargetClassifier: SSE response → llm_api_platform (streaming)")
            return result

        # HTTP 405 Method Not Allowed → API 平台 (仅支持 POST)
        if result.http_status == 405:
            result.target_type = "llm_api_platform"
            result.api_endpoint_pattern = "http_405"
            result.recommended_mode = "api"
            result.detection_reason = (
                "HTTP 405 Method Not Allowed — 目标仅支持 POST (API 端点)"
            )
            logger.info("TargetClassifier: HTTP 405 → llm_api_platform")
            return result

        # HTML 响应 → 可能是 Web 应用, 进一步检查 DOM
        if result.is_html:
            result.has_chat_ui = self._check_chat_ui_in_html(http_info.get("body", ""))
            if result.has_chat_ui:
                result.target_type = "llm_web_app"
                result.recommended_mode = "browser"
                result.detection_reason = (
                    "HTTP 响应为 HTML 且包含聊天 UI 组件 (textarea/chat/message)"
                )
                logger.info("TargetClassifier: HTML + chat UI → llm_web_app")
                return result

            # A1: HTML 但静态分析未发现聊天 UI, 尝试浏览器渲染后检测 SPA
            if self._render_check:
                rendered_has_chat = await self._check_chat_ui_via_render(target_url)
                if rendered_has_chat:
                    result.target_type = "llm_web_app"
                    result.has_chat_ui = True
                    result.recommended_mode = "browser"
                    result.detection_reason = (
                        "浏览器渲染后 DOM 包含聊天 UI 组件 (SPA 应用, 静态 HTML 无法检测)"
                    )
                    logger.info("TargetClassifier: rendered DOM + chat UI → llm_web_app (SPA)")
                    return result

            # HTML 但没有聊天 UI, 检查 URL 是否像 Web 应用
            if url_match == "web_app":
                result.target_type = "llm_web_app"
                result.recommended_mode = "browser"
                result.detection_reason = (
                    "HTTP 响应为 HTML 且 URL 路径匹配 Web 应用模式"
                )
                logger.info("TargetClassifier: HTML + URL pattern → llm_web_app")
                return result

        # 路径 3: 无法确定
        result.target_type = "unknown"
        result.recommended_mode = "api"  # 默认走 API 模式 (更安全)
        result.detection_reason = (
            f"无法自动判别目标类型 (status={result.http_status}, "
            f"content_type={result.content_type}). "
            f"请使用 --target-type 手动指定."
        )
        logger.warning(f"TargetClassifier: unknown target type for {target_url}")
        return result

    def _match_url_patterns(self, url: str) -> str:
        """URL 路径模式匹配。.

        Returns:
            "api" | "web_app" | "unknown"
        """
        for pattern in _API_PATH_PATTERNS:
            if pattern.search(url):
                return "api"

        for pattern in _WEB_APP_PATH_PATTERNS:
            if pattern.search(url):
                return "web_app"

        return "unknown"

    def _match_streaming_url_patterns(self, url: str) -> bool:
        """检测 URL 是否匹配流式端点模式。.

        Returns:
            True 如果 URL 匹配流式端点模式 (如 /stream, /sse, /events)。
        """
        return any(pattern.search(url) for pattern in _STREAMING_PATH_PATTERNS)

    def _detect_streaming_json(
        self,
        content_type_lower: str,
        http_info: dict[str, Any],
    ) -> str:
        """检测 JSON 响应是否为流式 JSON。.

        检测模式:
          1. Content-Type: application/x-ndjson → ndjson
          2. Content-Type: application/stream+json → stream_json
          3. Transfer-Encoding: chunked + JSON Content-Type → stream_json

        Args:
            content_type_lower: 小写的 Content-Type。
            http_info: HTTP 响应信息字典。

        Returns:
            流式类型 ("ndjson" | "stream_json" | "" 非流式)。
        """
        if "x-ndjson" in content_type_lower or "ndjson" in content_type_lower:
            return "ndjson"
        if "stream+json" in content_type_lower or "streaming+json" in content_type_lower:
            return "stream_json"

        # Transfer-Encoding: chunked + JSON → 推断为流式 JSON
        headers = http_info.get("headers", {}) or {}
        transfer_encoding = (
            headers.get("transfer-encoding", "")
            or headers.get("Transfer-Encoding", "")
            or http_info.get("transfer-encoding", "")
            or http_info.get("Transfer-Encoding", "")
        )
        if "chunked" in transfer_encoding.lower() and "json" in content_type_lower:
            return "stream_json"

        return ""

    async def _http_probe(self, url: str) -> dict[str, Any]:
        """发送 HTTP GET 请求探测目标。.

        Returns:
            包含 status, content_type, body 的字典。
        """
        try:
            import aiohttp

            headers = {"User-Agent": self._user_agent}
            async with aiohttp.ClientSession() as session, session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self._timeout),
                allow_redirects=True,
                ssl=False,
            ) as response:
                body = await response.text(errors="replace")
                return {
                    "status": response.status,
                    "content_type": response.headers.get("Content-Type", ""),
                    "body": body[:50000],  # 限制大小
                    "headers": dict(response.headers),
                }
        except ImportError:
            logger.warning("aiohttp not installed, falling back to urllib")
            return self._http_probe_sync(url)
        except Exception as e:
            logger.debug(f"TargetClassifier: HTTP probe failed: {e}")
            return {"status": 0, "content_type": "", "body": ""}

    def _http_probe_sync(self, url: str) -> dict[str, Any]:
        """同步 HTTP 探测 (fallback, 当 aiohttp 不可用时)。."""
        try:
            import ssl
            from urllib.request import Request, urlopen

            req = Request(url, headers={"User-Agent": self._user_agent})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urlopen(req, timeout=self._timeout, context=ctx) as resp:
                body = resp.read(50000).decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "body": body,
                    "headers": dict(resp.headers),
                }
        except Exception as e:
            # HTTP 错误也可能包含有用信息 (如 405)
            if hasattr(e, "code") and e.code:
                return {
                    "status": e.code,
                    "content_type": e.headers.get("Content-Type", "") if hasattr(e, "headers") else "",
                    "body": "",
                    "headers": dict(e.headers) if hasattr(e, "headers") else {},
                }
            logger.debug(f"TargetClassifier: sync HTTP probe failed: {e}")
            return {"status": 0, "content_type": "", "body": ""}

    def _check_chat_ui_in_html(self, html: str) -> bool:
        """检查 HTML 是否包含聊天 UI 组件 (P2: 使用 BeautifulSoup4 CSS 选择器).

        相比原正则方案, BeautifulSoup4 的 CSS 选择器引擎能:
          1. 正确解析嵌套 DOM 结构 (如 ``div.class > textarea``)
          2. 支持 ``[class*="chat"]`` 属性子串匹配
          3. 支持 ``[contenteditable='true']`` 精确属性匹配
          4. 避免正则误匹配 (如 HTML 注释中的文本)
        """
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            logger.debug("TargetClassifier: BeautifulSoup parse failed, falling back to regex")
            return self._check_chat_ui_in_html_regex(html)

        for selector in _CHAT_UI_SELECTORS:
            try:
                element = soup.select_one(selector)
                if element is not None:
                    logger.debug(f"TargetClassifier: chat UI selector matched: {selector}")
                    return True
            except Exception:
                continue

        return False

    async def _check_chat_ui_via_render(self, url: str) -> bool:
        """A1: 使用 Playwright 渲染页面后检测聊天 UI (SPA 应用)。.

        当静态 HTML 中未检测到聊天 UI 时, 可能是 SPA 应用 (React/Vue/Next.js)
        需要浏览器执行 JavaScript 后才能看到渲染的 DOM。

        设计原则 (R-010): 使用 PyRIT 原生 PlaywrightTarget 的底层 Playwright 库
        不修改 PyRIT 代码, 仅在探测层使用 Playwright API。
        """
        try:
            from playwright.async_api import async_playwright

            pw = await async_playwright().start()
            try:
                browser = await pw.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, wait_until="networkidle", timeout=self._timeout * 1000)
                # 等待 SPA 渲染
                await page.wait_for_timeout(2000)

                for selector in _CHAT_UI_SELECTORS:
                    try:
                        element = await page.query_selector(selector)
                        if element is not None:
                            logger.debug(f"TargetClassifier: rendered chat UI matched: {selector}")
                            return True
                    except Exception:
                        continue
                return False
            finally:
                with contextlib.suppress(Exception):
                    await browser.close()
                with contextlib.suppress(Exception):
                    await pw.stop()
        except ImportError:
            logger.debug("TargetClassifier: Playwright not installed, render check skipped")
            return False
        except Exception as e:
            logger.debug(f"TargetClassifier: render check failed: {e}")
            return False

    def _check_chat_ui_in_html_regex(self, html: str) -> bool:
        """正则回退方案 (当 BeautifulSoup 不可用或解析失败时).

        保留原有正则匹配逻辑作为 fallback, 确保功能不退化。
        """
        html_lower = html.lower()
        for selector in _CHAT_UI_SELECTORS:
            if "[" in selector:
                tag = selector.split("[")[0].strip()
                attr_part = selector[len(tag):]
                class_match = re.search(r'class\*="([^"]+)"', attr_part)
                if class_match:
                    keyword = class_match.group(1)
                    if keyword in html_lower:
                        return True
                role_match = re.search(r'data-role="([^"]+)"', attr_part)
                if role_match:
                    keyword = role_match.group(1)
                    if keyword in html_lower:
                        return True
            else:
                tag = selector.split(":")[0].strip()
                if tag and tag in html_lower:
                    return True
        return False

    def _extract_api_auth_info(
        self,
        result: TargetClassification,
        http_info: dict[str, Any],
    ) -> None:
        """A3: 从 HTTP 响应中自动提取 API 认证信息。.

        检测模式:
          1. WWW-Authenticate 头 → Bearer/OAuth2/Basic
          2. X-API-Key / X-Auth-Token 头 → API Key 认证
          3. OpenAPI/Swagger spec (swagger.json/openapi.json)
          4. 401 响应体中的认证提示

        设计原则 (R-010): 不修改 PyRIT 原生 Target,
        仅在判别层提取信息, 供编排层使用。
        """
        headers = http_info.get("headers", {}) or {}
        body = http_info.get("body", "") or ""
        status = http_info.get("status", 0)

        # 检查 WWW-Authenticate 头
        www_auth = headers.get("www-authenticate", "") or headers.get("WWW-Authenticate", "")
        if www_auth:
            www_auth_lower = www_auth.lower()
            if "bearer" in www_auth_lower:
                result.api_auth_type = "bearer"
                result.api_auth_header = "Authorization"
            elif "oauth" in www_auth_lower:
                result.api_auth_type = "oauth2"
                result.api_auth_header = "Authorization"
            elif "basic" in www_auth_lower:
                result.api_auth_type = "basic"
                result.api_auth_header = "Authorization"

        # 检查常见 API Key 头
        if not result.api_auth_type:
            for header_name in ("x-api-key", "x-auth-token", "api-key"):
                if header_name in headers or header_name.title() in headers:
                    result.api_auth_type = "api_key"
                    result.api_auth_header = header_name
                    break

        # 检查 OpenAPI/Swagger spec
        if "swagger" in body.lower() or "openapi" in body.lower():
            result.has_openapi_spec = True

        # 401 未认证 → 推断需要认证
        if status == 401 and not result.api_auth_type:
            result.api_auth_type = "unknown"
            result.api_auth_header = "Authorization"

        if result.api_auth_type:
            logger.info(
                f"TargetClassifier: API auth detected: type={result.api_auth_type}, "
                f"header={result.api_auth_header}, openapi={result.has_openapi_spec}"
            )

    # ── v56: 多维攻击面拓扑构建 ──

    def build_attack_surface_topology(
        self,
        classification: TargetClassification,
        *,
        burp_raw_request: str | None = None,
        burp_body_json: dict[str, Any] | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> AttackSurfaceTopology:
        """v56: 从判别结果 + Burp 请求体构建多维攻击面拓扑.

        攻击者视角: 不问 "这是什么类型目标", 而问 "有哪些可注入攻击面".

        5 层构建:
          层1 传输面: 从 target_type 映射
          层2 应用面: 从 Burp 请求体 JSON 分析 Agent/RAG/MCP 结构
          层3 认证面: 从 auth_headers + api_auth_type 推断认证拓扑
          层4 攻击面: 从层2结果推导注入面 + 工具 + 信任边界
          层5 Kill Chain: 从层4结果映射 OWASP + Kill Chain 阶段

        Args:
            classification: TargetClassification 判别结果.
            burp_raw_request: Burp 原始 HTTP 请求文本 (可选).
            burp_body_json: 已解析的 Burp 请求体 JSON (可选, 优先于 raw_request).
            auth_headers: 认证 headers 字典 (可选).

        Returns:
            AttackSurfaceTopology 多维攻击面拓扑.

        学术依据:
            - MITRE ATT&CK T1592: 主动扫描
            - Greshake et al. (arXiv:2302.12173): Agent 攻击面发现
            - OWASP ASI01-10: Agentic Security
        """
        topology = AttackSurfaceTopology()

        # ── 层1: 传输面 ──
        if classification.target_type == "llm_web_app":
            topology.transport_type = "web_app"
        elif classification.target_type == "llm_api_platform":
            topology.transport_type = "api_platform"
        else:
            topology.transport_type = "unknown"

        topology.has_streaming = classification.is_streaming

        # v57: URL 路径驱动的拓扑推断 — 从 URL 路径推断 Agent/MCP 架构
        # 学术依据: OWASP ASI01-10 — URL路径是攻击面发现的重要信号
        # 当请求体极简 (如 {"prompt":"..."}) 无法从 body 检测架构时,
        # URL 路径模式 (如 /api/labs/MCP_07/chat) 可推断 Agent/MCP 架构
        url_path_hints = self._infer_architecture_from_url(classification.target_url)

        # ── 层2: 应用面 — 从 Burp 请求体分析 Agent 结构 ──
        body_json: dict[str, Any] = {}
        if burp_body_json is not None:
            body_json = burp_body_json
        elif burp_raw_request:
            body_json = self._parse_burp_body(burp_raw_request)

        if body_json:
            # 工具调用检测
            tools_raw = body_json.get("tools") or body_json.get("functions") or []
            if isinstance(tools_raw, list) and tools_raw:
                topology.has_tool_calling = True
                for t in tools_raw:
                    if isinstance(t, dict):
                        tool_name = t.get("name", t.get("function", {}).get("name", ""))
                        tool_desc = t.get("description", t.get("function", {}).get("description", ""))
                        topology.discovered_tools.append({
                            "name": tool_name,
                            "description": tool_desc,
                            "parameters": t.get("parameters", t.get("function", {}).get("parameters", {})),
                        })

            # 多轮对话检测
            messages = body_json.get("messages", [])
            if isinstance(messages, list) and len(messages) > 0:
                topology.has_multi_turn = True
                for msg in messages:
                    if isinstance(msg, dict) and msg.get("role") == "system":
                        topology.has_system_prompt = True
                        break
                    if isinstance(msg, dict) and "tool_calls" in msg:
                        topology.has_tool_calling = True
                        break

            # RAG 特征检测
            for field_name in _RAG_FIELD_NAMES:
                if field_name in body_json:
                    topology.app_architecture = "rag_pipeline"
                    break

            # MCP 特征检测
            for field_name in _MCP_FIELD_NAMES:
                if field_name in body_json:
                    topology.app_architecture = "mcp_orchestrator"
                    break

            # 应用架构判定 (优先级: MCP > RAG > Agent > Simple)
            if topology.app_architecture == "simple_llm":
                if topology.has_tool_calling:
                    topology.app_architecture = "agent_with_tools"
                elif topology.has_multi_turn and topology.has_system_prompt:
                    topology.app_architecture = "simple_llm"

        # v57: 当请求体分析未发现 Agent/MCP 特征时, 使用 URL 路径推断
        # 攻击者视角: /api/labs/MCP_07/chat 中的 MCP_07 暗示 Agent 实验场景
        if topology.app_architecture == "simple_llm" and url_path_hints:
            if url_path_hints.get("is_mcp"):
                topology.app_architecture = "mcp_orchestrator"
                topology.model_fingerprint["url_inferred_architecture"] = "mcp_orchestrator"
                logger.info(
                    f"v57: URL path inferred architecture=mcp_orchestrator "
                    f"(url={classification.target_url})"
                )
            elif url_path_hints.get("is_agent"):
                topology.app_architecture = "agent_with_tools"
                topology.model_fingerprint["url_inferred_architecture"] = "agent_with_tools"
                logger.info(
                    f"v57: URL path inferred architecture=agent_with_tools "
                    f"(url={classification.target_url})"
                )

        # v57: 从 Burp 原始请求头提取 Cookie 信息 (极简请求体场景的补充信号)
        if burp_raw_request:
            cookie_hints = self._extract_cookie_hints(burp_raw_request)
            if cookie_hints:
                topology.model_fingerprint["cookie_analysis"] = cookie_hints

        # ── 层3: 认证面 ──
        topology.auth_topology = self._infer_auth_topology(classification, auth_headers)
        topology.auth_persistence = self._infer_auth_persistence(topology.auth_topology)
        topology.token_expiry_seconds = self._extract_jwt_expiry(auth_headers or {})

        # v57: Session Cookie 过期时间提取 — 从 Set-Cookie 或 Cookie 头提取
        # 攻击者视角: Cookie 过期时间决定攻击窗口大小
        if topology.auth_topology == "session_cookie" and burp_raw_request:
            cookie_expiry = self._extract_cookie_expiry(burp_raw_request)
            if cookie_expiry > 0:
                topology.token_expiry_seconds = cookie_expiry
                topology.model_fingerprint["cookie_expiry_seconds"] = cookie_expiry

        # ── 层4: 攻击面推导 ──
        topology.injection_surfaces = self._derive_injection_surfaces(topology)
        topology.trust_boundaries = self._derive_trust_boundaries(topology)

        # 高风险工具标记
        high_risk = [
            t["name"] for t in topology.discovered_tools
            if t.get("name", "").lower() in _HIGH_RISK_TOOL_NAMES
        ]
        if high_risk:
            topology.model_fingerprint["high_risk_tools"] = high_risk

        # ── 层5: Kill Chain 映射 ──
        topology.recommended_owasp = self._map_owasp_categories(topology)
        topology.recommended_kill_chain = self._map_kill_chain(topology)

        logger.info(
            f"v56 AttackSurfaceTopology: transport={topology.transport_type}, "
            f"arch={topology.app_architecture}, "
            f"tools={len(topology.discovered_tools)}, "
            f"auth={topology.auth_topology}, "
            f"surfaces={topology.injection_surfaces}, "
            f"owasp={topology.recommended_owasp}"
        )

        return topology

    def _parse_burp_body(self, raw_request: str) -> dict[str, Any]:
        """从 Burp 原始 HTTP 请求解析请求体 JSON."""
        import contextlib
        import json

        parts = raw_request.split("\r\n\r\n", 1)
        if len(parts) < 2:
            parts = raw_request.split("\n\n", 1)
        body = parts[1] if len(parts) > 1 else ""

        with contextlib.suppress(json.JSONDecodeError, TypeError):
            data = json.loads(body)
            if isinstance(data, dict):
                return data
        return {}

    def _infer_auth_topology(
        self,
        classification: TargetClassification,
        auth_headers: dict[str, str] | None,
    ) -> str:
        """推断认证拓扑."""
        headers = auth_headers or {}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Cookie → session_cookie
        if "cookie" in headers_lower:
            return "session_cookie"

        # Authorization header
        auth_val = headers_lower.get("authorization", "")
        if auth_val:
            if auth_val.startswith("Bearer "):
                token = auth_val[7:]
                # JWT 检测: 3 段式以 . 分隔
                if token.count(".") == 2:
                    return "oauth2_jwt"
                return "bearer_token"
            if auth_val.startswith("Basic "):
                return "basic"

        # 自定义 API Key 头
        for h_name in ("x-api-key", "x-auth-token", "api-key"):
            if h_name in headers_lower:
                return "api_key"

        # 从 classification 回退
        if classification.api_auth_type:
            at = classification.api_auth_type
            if at == "bearer":
                return "bearer_token"
            if at == "oauth2":
                return "oauth2_jwt"
            if at == "basic":
                return "basic"
            if at == "api_key":
                return "api_key"

        return "none"

    def _infer_auth_persistence(self, auth_topology: str) -> str:
        """推断认证持久性."""
        if auth_topology in ("session_cookie",):
            return "session"
        if auth_topology in ("oauth2_jwt",):
            return "persistent"
        if auth_topology in ("bearer_token", "api_key", "basic"):
            return "stateless"
        return "stateless"

    def _extract_jwt_expiry(self, auth_headers: dict[str, str]) -> int:
        """从 JWT Token 的 exp claim 提取过期时间.

        攻击者视角: Token 过期时间决定攻击窗口大小.
        """
        import base64
        import contextlib
        import json
        import time

        auth_val = auth_headers.get("Authorization", auth_headers.get("authorization", ""))
        if not auth_val.startswith("Bearer "):
            return 0

        token = auth_val[7:]
        parts = token.split(".")
        if len(parts) != 3:
            return 0  # 非 JWT

        with contextlib.suppress(Exception):
            # JWT payload 是第 2 段
            payload_bytes = parts[1]
            # 补齐 base64 padding
            payload_bytes += "=" * (4 - len(payload_bytes) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_bytes))
            exp = payload.get("exp")
            if exp and isinstance(exp, (int, float)):
                remaining = int(exp - time.time())
                return max(remaining, 0)

        return 0

    def _infer_architecture_from_url(self, url: str) -> dict[str, bool]:
        """v57: 从 URL 路径推断应用架构.

        攻击者视角: URL 路径是攻击面发现的重要信号.
        当请求体极简 (如 {"prompt":"..."}) 时, URL 路径模式
        (如 /api/labs/MCP_07/chat) 可推断 Agent/MCP 架构.

        Args:
            url: 目标 URL.

        Returns:
            包含架构提示的字典:
              - is_mcp: 是否为 MCP 协议场景
              - is_agent: 是否为 Agent 应用
              - is_lab: 是否为实验/测试场景
        """
        hints: dict[str, bool] = {
            "is_mcp": False,
            "is_agent": False,
            "is_lab": False,
        }
        for pattern in _AGENT_PATH_PATTERNS:
            if pattern.search(url):
                hints["is_agent"] = True
                # MCP 特定模式
                if "mcp" in pattern.pattern.lower() or "MCP" in url:
                    hints["is_mcp"] = True
                if "/labs/" in url:
                    hints["is_lab"] = True
                logger.debug(
                    f"v57: URL path pattern matched: {pattern.pattern} "
                    f"(mcp={hints['is_mcp']}, agent={hints['is_agent']}, lab={hints['is_lab']})"
                )
                break
        return hints

    def _extract_cookie_hints(self, raw_request: str) -> dict[str, Any]:
        """v57: 从 Burp 原始请求头提取 Cookie 分析信息.

        攻击者视角: Cookie 名称暗示认证架构和平台类型.
        如 aivp_sid → AI Valley Platform session ID.

        Args:
            raw_request: Burp 原始 HTTP 请求文本.

        Returns:
            Cookie 分析字典 (cookie_name, auth_type, platform_hint).
        """
        hints: dict[str, Any] = {}
        # 提取 Cookie 头
        cookie_match = re.search(r"Cookie:\s*(.+?)\r?\n", raw_request, re.IGNORECASE)
        if not cookie_match:
            return hints
        cookie_str = cookie_match.group(1).strip()
        # 解析 cookie name=value 对
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            name = name.strip()
            value = value.strip()
            # 匹配 Cookie 名称模式
            for auth_type, pattern in _COOKIE_AUTH_PATTERNS.items():
                if pattern.search(name):
                    hints["cookie_name"] = name
                    hints["auth_type"] = auth_type
                    # 推断平台
                    if "_sid" in name:
                        platform = name.replace("_sid", "")
                        hints["platform_hint"] = platform
                    break
            if hints:
                break
        return hints

    def _extract_cookie_expiry(self, raw_request: str) -> int:
        """v57: 从 Burp 请求或 Set-Cookie 头提取 Cookie 过期时间.

        攻击者视角: Cookie 过期时间决定攻击窗口大小.

        Args:
            raw_request: Burp 原始 HTTP 请求文本.

        Returns:
            过期时间 (秒), 0 表示无法提取.
        """
        import contextlib
        import datetime

        # 尝试从 Set-Cookie 头提取 (通常在响应中, 但 Burp 请求可能包含)
        with contextlib.suppress(Exception):
            set_cookie_match = re.search(
                r"Set-Cookie:\s*.+?expires=([^;\r\n]+)",
                raw_request,
                re.IGNORECASE,
            )
            if set_cookie_match:
                expires_str = set_cookie_match.group(1).strip()
                # 尝试解析 HTTP 日期格式
                with contextlib.suppress(Exception):
                    from email.utils import parsedate_to_datetime
                    expires_dt = parsedate_to_datetime(expires_str)
                    if expires_dt:
                        remaining = int((expires_dt - datetime.datetime.now(expires_dt.tzinfo)).total_seconds())
                        return max(remaining, 0)

            # 尝试从 Max-Age 提取
            max_age_match = re.search(
                r"Set-Cookie:\s*.+?Max-Age=(\d+)",
                raw_request,
                re.IGNORECASE,
            )
            if max_age_match:
                return int(max_age_match.group(1))

        # 无法从请求中提取, 返回默认 session 过期时间 (通常 30 分钟 = 1800s)
        # 攻击者视角: 保守估计 session cookie 有 30 分钟攻击窗口
        return 0

    def _derive_injection_surfaces(self, topology: AttackSurfaceTopology) -> list[str]:
        """从应用架构推导可注入攻击面.

        攻击者视角: 每个架构特征对应一个注入面.
        """
        surfaces = ["user_message"]  # 基础: 用户消息注入

        if topology.has_tool_calling:
            surfaces.append("tool_result")  # 工具返回值注入 (InjecAgent)
        if topology.has_system_prompt:
            surfaces.append("system_prompt")  # 系统提示提取 (LLM07)
        if topology.app_architecture == "rag_pipeline":
            surfaces.append("rag_content")  # RAG 内容投毒 (LLM07)
        if topology.app_architecture == "mcp_orchestrator":
            surfaces.append("mcp_protocol")  # MCP 协议注入 (ASI01)
        if topology.transport_type == "web_app":
            surfaces.append("file_upload")  # 文件上传 (XPIA)
        if topology.has_multi_turn:
            surfaces.append("conversation_history")  # 对话历史注入

        return surfaces

    def _derive_trust_boundaries(self, topology: AttackSurfaceTopology) -> list[str]:
        """推导信任边界.

        攻击者视角: 信任边界 = 可跨越的权限线.
        """
        boundaries = ["user→llm"]  # 基础

        if topology.has_tool_calling:
            boundaries.append("llm→tool")  # LLM 调用工具的信任传递
        if topology.app_architecture == "rag_pipeline":
            boundaries.append("llm→rag")  # LLM 信任 RAG 内容
        if topology.app_architecture == "mcp_orchestrator":
            boundaries.append("llm→mcp_server")  # LLM 信任 MCP 服务器
        if topology.app_architecture == "multi_agent":
            boundaries.append("agent→agent")  # Agent 间信任传递

        return boundaries

    def _map_owasp_categories(self, topology: AttackSurfaceTopology) -> list[str]:
        """从攻击面拓扑映射 OWASP 类别.

        攻击者视角: 每个攻击面对应一个 OWASP 类别.
        v57: 增加 MCP/Agent 架构的 OWASP 映射 (LLM06/ASI01-10).
        """
        owasp: list[str] = ["LLM01"]  # 基础: Prompt Injection

        if "system_prompt" in topology.injection_surfaces:
            owasp.append("LLM07")  # System Prompt Leakage
        if "rag_content" in topology.injection_surfaces:
            owasp.append("LLM07")  # RAG 投毒 → 间接注入
        if "tool_result" in topology.injection_surfaces:
            owasp.extend(["ASI02", "ASI05"])  # Tool Injection / Excessive Agency
        if "mcp_protocol" in topology.injection_surfaces:
            owasp.extend(["ASI01", "ASI02"])  # MCP Security / Tool Injection
        if topology.auth_topology != "none":
            owasp.append("LLM02")  # Sensitive Info (Token 本身是攻击目标)
        if topology.has_tool_calling:
            owasp.append("ASI06")  # Excessive Agency
        if "agent→agent" in topology.trust_boundaries:
            owasp.append("ASI05")  # Multi-Agent 信任传播

        # v57: 架构驱动的 OWASP 映射 — MCP/Agent 架构自动添加相关分类
        if topology.app_architecture == "mcp_orchestrator":
            owasp.extend(["LLM06", "ASI01", "ASI02"])  # Excessive Agency + MCP Security
        elif topology.app_architecture == "agent_with_tools":
            owasp.extend(["LLM06", "ASI02"])  # Excessive Agency + Tool Misuse

        # v57: Session 认证 → 横向移动风险
        if topology.auth_topology == "session_cookie":
            owasp.append("LLM02")  # Session Token 是攻击目标

        # 去重保持顺序
        seen: set[str] = set()
        result: list[str] = []
        for o in owasp:
            if o not in seen:
                seen.add(o)
                result.append(o)
        return result

    def _map_kill_chain(self, topology: AttackSurfaceTopology) -> list[str]:
        """从攻击面拓扑映射 Kill Chain 阶段.

        攻击者视角: 攻击链路规划.
        v57: 对齐 MITRE ATT&CK for LLMs (Atlas) 完整阶段:
          recon → initial_access → execution → persistence →
          credential_access → discovery → collection → exfiltration
        新增阶段:
          - execution: prompt injection 本身就是代码执行 (LLM 执行恶意指令)
          - defense_evasion: Converter 编码绕过 (ROT13/Base64) = 防御规避
          - persistence: session cookie 维持持久访问 + 工具劫持
        学术依据:
          - MITRE Atlas: execution/defense_evasion/persistence 是 LLM 攻击核心阶段
          - Crescendo (arXiv:2402.12109): 渐进式攻击是多阶段 execution
          - InjecAgent (arXiv:2307.00929): 工具劫持是 persistence + collection
        """
        chain = ["recon", "initial_access"]

        # v57: execution — prompt injection 注入面存在即添加
        # 攻击者视角: 用户消息注入 = 通过 LLM 执行恶意指令
        if "user_message" in topology.injection_surfaces:
            chain.append("execution")

        # v57: persistence — session 认证或工具调用支持持久访问
        if topology.auth_topology == "session_cookie":
            chain.append("persistence")  # Session 维持持久访问
        if topology.has_tool_calling:
            chain.append("persistence")  # 工具劫持持续利用

        if topology.auth_topology != "none":
            chain.append("credential_access")  # Token 窃取

        # v57: defense_evasion — Converter 编码或多轮对话历史注入
        # 攻击者视角: ROT13/Base64 编码绕过内容过滤 = 防御规避
        # 多轮对话历史注入也是一种规避手段 (渐进式逼近)
        if topology.has_multi_turn or topology.has_streaming:
            chain.append("defense_evasion")

        if topology.has_tool_calling or "mcp_protocol" in topology.injection_surfaces:
            chain.append("discovery")  # 工具/MCP 发现
        if "rag_content" in topology.injection_surfaces:
            chain.append("discovery")  # RAG 内容发现
        if topology.has_tool_calling or "mcp_protocol" in topology.injection_surfaces:
            chain.append("collection")  # 工具调用收集数据
        if topology.has_tool_calling:
            chain.append("exfiltration")  # 工具调用外传数据

        # 去重保持顺序
        seen: set[str] = set()
        result: list[str] = []
        for c in chain:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return result
