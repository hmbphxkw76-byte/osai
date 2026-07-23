# -*- coding: utf-8 -*-
"""
AI-300 Framework - Target Builder
PyRIT PromptTarget 构建模块

职责：
- 根据目标配置构建对应的 PyRIT PromptTarget
- 支持类型：ollama / openai / http / playwright
- 自动创建速率控制器（RateController）

从 AttackOrchestrator 拆分，遵循单一职责原则。

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from pyrit.prompt_target import PromptTarget, OpenAIChatTarget

from ..rate_controller import RateController, create_rate_controller
from ...utils.async_helper import run_async

logger = logging.getLogger(__name__)


class TargetBuilder:
    """
    PyRIT PromptTarget 构建器

    根据目标配置字典构建对应的 PyRIT PromptTarget 实例，
    同时创建速率控制器用于并发管理。

    使用方式：
        builder = TargetBuilder()
        target = builder.build(target_config)
        controller = builder.rate_controller
    """

    def __init__(self):
        self._rate_controller: Optional[RateController] = None

    @property
    def rate_controller(self) -> Optional[RateController]:
        """获取最近一次构建的速率控制器"""
        return self._rate_controller

    def build(self, target_config: Dict[str, Any]) -> PromptTarget:
        """
        根据配置构建 PyRIT PromptTarget

        支持类型：
        - ollama / openai → OpenAIChatTarget
        - http → HTTPTarget（原始 HTTP 请求）
        - rest_api → ApiTargetAdapter（REST JSON 请求/响应，如 OWASP DonkAI）
        - sse_chat → ApiTargetAdapter（SSE 流式响应，如 AIVP）
        - playwright / spa_chat / spa_chat_recon → PlaywrightTarget（浏览器自动化，SPA 支持）

        Args:
            target_config: 目标配置字典（包含 type, connection, auth 等字段）

        Returns:
            PyRIT PromptTarget 实例
        """
        target_type = target_config.get("type", "openai")
        connection = target_config.get("connection", {})

        # 创建速率控制器（基于目标类型默认值或配置覆盖）
        self._rate_controller = self._create_rate_controller(target_config)

        if target_type in ("ollama", "openai"):
            return self._build_openai_target(connection)
        elif target_type == "http":
            return self._build_http_target(connection)
        elif target_type in ("rest_api", "sse_chat"):
            return self._build_api_target(target_config)
        elif target_type in ("playwright", "spa_chat", "spa_chat_recon"):
            # spa_chat / spa_chat_recon 是新统一类型，复用 playwright builder
            return self._build_playwright_target(target_config)
        else:
            raise ValueError(f"Unsupported target type: {target_type}")

    def _create_rate_controller(self, target_config: Dict[str, Any]) -> RateController:
        """
        根据目标配置创建速率控制器

        优先级：
        1. 配置中显式指定的 concurrency / rate_limit
        2. 目标类型默认值
        """
        target_type = target_config.get("type", "openai")
        rate_config = target_config.get("rate_control", {})

        max_concurrent = rate_config.get("max_concurrent", 0)
        rate_limit = rate_config.get("rate_limit", 0.0)

        # rest_api / sse_chat 使用 http 速率控制器配置
        rate_target_type = target_type
        if target_type in ("spa_chat", "spa_chat_recon"):
            rate_target_type = "playwright"
        elif target_type in ("rest_api", "sse_chat"):
            rate_target_type = "http"

        return create_rate_controller(
            target_type=rate_target_type,
            max_concurrent=max_concurrent,
            rate_limit=rate_limit,
        )

    def _build_openai_target(self, connection: Dict[str, Any]) -> OpenAIChatTarget:
        """构建 OpenAIChatTarget（ollama/openai 共用）"""
        return OpenAIChatTarget(
            endpoint=connection.get("endpoint", "http://localhost:11434/v1"),
            api_key=connection.get("api_key", "not-needed"),
            model_name=connection.get("model", "llama3.2:latest"),
        )

    def _build_api_target(self, target_config: Dict[str, Any]) -> Any:
        """
        构建 API 目标适配器（REST API / SSE Chat）

        支持 OWASP DonkAI (REST JSON) 和 AIVP (SSE Streaming) 两种靶机。
        使用 ApiTargetAdapter 封装 HTTP 请求/响应，返回解析后的纯文本。

        配置格式见 api_target_builder.build_api_target() 文档。
        """
        from .api_target_builder import build_api_target
        adapter = build_api_target(target_config)
        logger.info(
            "ApiTarget created: type=%s, base_url=%s, endpoint=%s, response_format=%s",
            target_config.get("type", "rest_api"),
            adapter.config.base_url,
            adapter.config.endpoint_path,
            adapter.config.response_format,
        )
        return adapter

    def _build_http_target(self, connection: Dict[str, Any]) -> Any:
        """构建 HTTPTarget"""
        from pyrit.prompt_target.http_target.http_target import HTTPTarget

        http_request = connection.get("http_request")
        if not http_request:
            raise ValueError(
                "HTTPTarget requires 'http_request' in connection config."
            )
        return HTTPTarget(
            http_request=http_request,
            prompt_regex_string=connection.get("prompt_regex_string", "{PROMPT}"),
            use_tls=connection.get("use_tls", True),
        )

    def _build_playwright_target(self, target_config: Dict[str, Any]) -> Any:
        """
        构建 PlaywrightTarget（SPA 浏览器自动化）

        流程：
        1. 解析认证配置（如有）→ AuthProfile
        2. 启动 Playwright 浏览器
        3. 注入认证信息（Cookie + Authorization）
        4. 创建带认证的 Page
        5. 构建交互函数
        6. 返回 PlaywrightTarget
        """
        from pyrit.prompt_target.playwright_target import PlaywrightTarget

        connection = target_config.get("connection", {})
        auth_config = target_config.get("auth", {})
        # 兼容新旧格式：新格式 spa.selectors / 旧格式 selectors
        spa_config = target_config.get("spa", {})
        selectors = spa_config.get("selectors") or target_config.get("selectors", {})

        # 1. 解析认证配置
        # 优先级：显式 header_file > 域名自动发现 credentials/{domain}.txt
        auth_profile = None
        header_file = auth_config.get("header_file", "")
        if not header_file:
            # 自动发现：基于目标 URL 域名匹配 credentials 文件
            from ..auth import find_credential_file
            from urllib.parse import urlparse
            _domain = urlparse(connection.get("url", "")).hostname or ""
            if _domain:
                header_file = find_credential_file(_domain) or ""
        if header_file:
            from ..auth import parse_header_file
            auth_profile = parse_header_file(header_file)
            logger.info("Auth loaded: %s (from %s)", auth_profile.summary(), header_file)

        # 2. 启动 Playwright 浏览器
        page = self._launch_playwright_browser(connection, auth_profile)

        # 3. 构建交互函数
        from ..interactions.web_chat import create_web_chat_interaction
        interaction_func = create_web_chat_interaction(selectors)

        # 4. 创建 PlaywrightTarget
        target = PlaywrightTarget(
            interaction_func=interaction_func,
            page=page,
        )

        logger.info(
            "PlaywrightTarget created: url=%s, auth=%s",
            connection.get("url", ""),
            auth_profile.auth_type if auth_profile else "none",
        )
        return target

    def _launch_playwright_browser(
        self,
        connection: Dict[str, Any],
        auth_profile: Any = None,
    ) -> Any:
        """启动 Playwright 浏览器并创建带认证的页面"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise ImportError(
                "Playwright is required for playwright target. "
                "Install with: pip install playwright && playwright install chromium"
            )

        import asyncio

        async def _launch():
            async with async_playwright() as p:
                browser_type = connection.get("browser", "chromium")
                headless = connection.get("headless", True)

                if browser_type == "firefox":
                    browser = await p.firefox.launch(headless=headless)
                elif browser_type == "webkit":
                    browser = await p.webkit.launch(headless=headless)
                else:
                    browser = await p.chromium.launch(headless=headless)

                ignore_https = connection.get("ignore_https_errors", True)
                context = await browser.new_context(ignore_https_errors=ignore_https)

                if auth_profile and auth_profile.has_auth():
                    from ..auth import inject_auth
                    page = await context.new_page()
                    await inject_auth(context, page, auth_profile)
                else:
                    page = await context.new_page()

                url = connection.get("url", "")
                if url:
                    wait_until = connection.get("wait_until", "domcontentloaded")
                    await page.goto(url, wait_until=wait_until)

                page._browser_ref = browser  # noqa: SLF001
                return page

        return run_async(_launch())
