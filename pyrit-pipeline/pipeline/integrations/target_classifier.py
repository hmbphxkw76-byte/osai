# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""TargetClassifier: 目标 URL 类型自动判别器。.

三路并行探测, 投票决策目标类型:
  1. HTTP 响应分析 (Content-Type, Server, 状态码)
  2. URL 路径模式匹配 (复用 EndpointClassifier 规则)
  3. 页面 DOM 特征 (如需浏览器, 延迟检测)

判别结果:
  - llm_web_app:     基于 LLM 的 Web 应用 (有聊天 UI, HTML 页面)
  - llm_api_platform: LLM API 平台 (JSON 响应, API 端点路径)
  - unknown:          无法确定, 降级为用户手动选择

学术依据:
  - PyRIT (arXiv:2407.01232): PlaywrightTarget (Web UI) vs HTTPTarget (API)
  - OWASP Top 10 for LLMs 2025: Web 注入和 API 注入的攻击面对应
  - MITRE ATT&CK: Reconnaissance → 初始访问前需识别目标类型

> **日期**: 2026-8-3
"""

from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass
from typing import Any

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── API 端点 URL 路径模式 (复用 recon-pipeline EndpointClassifier 规则) ──
_API_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/v1/chat/completions", re.IGNORECASE),
    re.compile(r"/v1/responses", re.IGNORECASE),
    re.compile(r"/v1/completions", re.IGNORECASE),
    re.compile(r"/api/(chat|completion|generate|inference)", re.IGNORECASE),
    re.compile(r"/(openai|anthropic|llama|gemini|mistral)/", re.IGNORECASE),
]

# ── Web 应用 URL 路径模式 ──
_WEB_APP_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/(chat|playground|app|dashboard)", re.IGNORECASE),
    re.compile(r"/#", re.IGNORECASE),  # SPA hash 路由
]

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
            f"  reason:               {self.detection_reason}",
        ]
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
    ) -> TargetClassification:
        """判别目标 URL 的类型。.

        三路并行探测:
          1. URL 路径模式匹配 (最快, 无网络请求)
          2. HTTP 响应分析 (中等, 需发送 GET 请求)
          3. DOM 特征检测 (最慢, 仅在 HTML 响应时执行)

        Args:
            target_url: 目标 URL。
            force_type: 强制类型 ("auto" | "web_app" | "api_platform")。
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
            return TargetClassification(
                target_type="llm_api_platform",
                target_url=target_url,
                detection_reason="Forced to api_platform by --target-type",
                recommended_mode="api",
            )

        result = TargetClassification(target_url=target_url)

        # 路径 1: URL 路径模式匹配 (无网络请求)
        url_match = self._match_url_patterns(target_url)
        if url_match == "api":
            result.target_type = "llm_api_platform"
            result.api_endpoint_pattern = "url_pattern"
            result.recommended_mode = "api"
            result.detection_reason = (
                "URL 路径匹配 API 端点模式 (如 /v1/chat/completions, /api/chat)"
            )
            # A3: API 认证信息提取
            self._extract_api_auth_info(result, http_info={})
            logger.info("TargetClassifier: URL pattern → llm_api_platform")
            return result

        # 路径 2: HTTP 响应分析
        http_info = await self._http_probe(target_url)
        result.http_status = http_info.get("status", 0)
        result.content_type = http_info.get("content_type", "")
        result.is_html = "text/html" in result.content_type.lower()

        # JSON 响应 → API 平台
        if "application/json" in result.content_type.lower():
            result.target_type = "llm_api_platform"
            result.api_endpoint_pattern = "http_json_response"
            result.recommended_mode = "api"
            result.detection_reason = (
                f"HTTP 响应 Content-Type=application/json (status={result.http_status})"
            )
            # A3: API 认证信息提取
            self._extract_api_auth_info(result, http_info)
            logger.info("TargetClassifier: JSON response → llm_api_platform")
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
                }
        except Exception as e:
            # HTTP 错误也可能包含有用信息 (如 405)
            if hasattr(e, "code") and e.code:
                return {
                    "status": e.code,
                    "content_type": e.headers.get("Content-Type", "") if hasattr(e, "headers") else "",
                    "body": "",
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
        """A1: 使用 Playwright 渲染页面后检测聊天 UI (SPA 应用)。

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
        """A3: 从 HTTP 响应中自动提取 API 认证信息。

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
