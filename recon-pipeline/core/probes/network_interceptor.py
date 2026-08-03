# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""网络拦截器 — Playwright 驱动的 API 端点发现。.

通过 page.on("response") 拦截浏览器所有 HTTP 响应,
自动发现和分类目标系统的 API 端点。

发现能力:
  1. Model API: /v1/chat/completions, /v1/responses, /api/chat
  2. RAG API: /api/search, /api/retrieve, /api/embeddings, /api/vector
  3. Agent Tool API: /tools/, /function/, fetch_website 调用
  4. Auth API: /oauth/, /token, /login (与 AuthProbe 互补)
  5. File Upload: multipart/form-data 上传端点

对齐 PyRIT 原生模式:
  - CopilotAuthenticator 用 page.on("response") 拦截网络响应
  - NetworkTokenStrategy 同样的 response handler 模式

学术依据:
  - Greshake et al. (arXiv:2302.12173): 间接注入需发现 Agent 工具调用端点
  - MITRE ATT&CK T1595: Active Scanning — 主动发现目标攻击面

> **日期**: 2026-8-2
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from core.probes.ai_signal_catalog import (
    match_ai_body_fingerprint,
    match_ai_header,
    match_ai_title,
)
from core.probes.endpoint_classifier import EndpointClassifier
from core.probes.recon_result import DiscoveredEndpoint

if TYPE_CHECKING:
    from playwright.async_api import Page, Response

logger = logging.getLogger(__name__)

# 拦截持续时间 (秒) — 等待页面加载和用户交互产生的 API 调用
_DEFAULT_INTERCEPT_DURATION = 10

# 最大响应体预览长度
_MAX_BODY_PREVIEW = 200

# 需要过滤的静态资源 Content-Type
_STATIC_CONTENT_TYPES = frozenset({
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/font",
    "font/",
    "image/",
    "video/",
    "audio/",
})


class NetworkInterceptor:
    """Playwright 网络拦截器。.

    通过注册 page.on("response") 事件处理器,
    拦截浏览器所有 HTTP 响应, 分类并记录 API 端点。

    用法::

        interceptor = NetworkInterceptor()
        interceptor.attach_to_page(page)
        # ... 页面加载和交互 ...
        await interceptor.wait_for_idle(duration=10)
        endpoints = interceptor.get_discovered_endpoints()
        interceptor.detach_from_page(page)

    对齐 CopilotAuthenticator 的 response_handler_async 模式。
    """

    def __init__(self, *, max_body_preview: int = _MAX_BODY_PREVIEW) -> None:
        """初始化网络拦截器。.

        Args:
            max_body_preview: 响应体预览最大长度 (字符)。
        """
        self._max_body_preview = max_body_preview
        self._endpoints: list[DiscoveredEndpoint] = []
        self._seen_urls: set[str] = set()
        self._classifier = EndpointClassifier()
        self._response_count = 0
        self._last_response_time: float = 0.0

    def attach_to_page(self, page: Page) -> None:
        """将响应处理器附加到 Page。.

        在页面导航前调用, 确保拦截所有响应。

        Args:
            page: Playwright Page 对象。
        """
        page.on("response", self._handle_response)
        logger.info("NetworkInterceptor: attached to page")

    def detach_from_page(self, page: Page) -> None:
        """从 Page 分离响应处理器。.

        Args:
            page: Playwright Page 对象。
        """
        with contextlib.suppress(Exception):
            page.remove_listener("response", self._handle_response)
        logger.info("NetworkInterceptor: detached from page")

    async def wait_for_idle(
        self,
        page: Page,
        duration: float = _DEFAULT_INTERCEPT_DURATION,
        idle_threshold: float = 3.0,
    ) -> None:
        """等待网络空闲或超时。.

        持续监控网络活动, 当 idle_threshold 秒内无新响应时认为空闲。

        Args:
            page: Playwright Page 对象。
            duration: 最大等待时间 (秒)。
            idle_threshold: 网络空闲判定阈值 (秒)。
        """
        self._last_response_time = time.time()
        start = time.time()

        while time.time() - start < duration:
            elapsed_since_last = time.time() - self._last_response_time
            if elapsed_since_last >= idle_threshold:
                logger.info(
                    f"NetworkInterceptor: network idle after {elapsed_since_last:.1f}s"
                )
                return
            await asyncio.sleep(0.5)

        logger.info(
            f"NetworkInterceptor: wait_for_idle timed out after {duration}s "
            f"({self._response_count} responses captured)"
        )

    async def probe_endpoints(
        self,
        page: Page,
        target_url: str,
        duration: float = _DEFAULT_INTERCEPT_DURATION,
    ) -> list[DiscoveredEndpoint]:
        """主动探测 API 端点。.

        导航到 target_url, 拦截所有网络响应, 返回发现的端点列表。

        Args:
            page: Playwright Page 对象。
            target_url: 目标 URL。
            duration: 拦截持续时间 (秒)。

        Returns:
            发现的 DiscoveredEndpoint 列表。
        """
        self.attach_to_page(page)

        try:
            # 导航到目标页面
            try:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                logger.debug(f"NetworkInterceptor: navigation raised (may be redirect): {e}")

            # 等待网络活动
            await self.wait_for_idle(page, duration=duration)

            # 尝试触发更多 API 调用: 模拟滚动和点击
            await self._trigger_lazy_loads(page)

            # 再次等待
            await self.wait_for_idle(page, duration=min(duration, 5), idle_threshold=2.0)

        finally:
            self.detach_from_page(page)

        logger.info(
            f"NetworkInterceptor: discovered {len(self._endpoints)} endpoints "
            f"from {self._response_count} responses"
        )
        return self._endpoints

    def get_discovered_endpoints(self) -> list[DiscoveredEndpoint]:
        """获取已发现的端点列表。."""
        return list(self._endpoints)

    @property
    def response_count(self) -> int:
        """拦截到的总响应数。."""
        return self._response_count

    # ── 内部方法 ──

    async def _handle_response(self, response: Response) -> None:
        """响应处理器 (对齐 CopilotAuthenticator.response_handler_async)。.

        拦截每个 HTTP 响应, 分类并记录 API 端点。
        """
        self._response_count += 1
        self._last_response_time = time.time()

        try:
            url = response.url
            method = response.request.method
            status = response.status
            content_type = response.headers.get("content-type", "")

            # 过滤静态资源
            if _is_static_resource(url, content_type):
                return

            # 去重 (同 URL + 方法)
            dedup_key = f"{method}:{url}"
            if dedup_key in self._seen_urls:
                return
            self._seen_urls.add(dedup_key)

            # 提取响应体预览 (先提取, 用于分类)
            body_preview = ""
            if _is_json_response(content_type):
                try:
                    body = await response.text()
                    body_preview = body[: self._max_body_preview]
                except Exception:
                    pass

            # 分类端点 (传入响应体以支持 MCP JSON-RPC 检测)
            endpoint_type = self._classifier.classify(url, method, content_type, body_preview)

            # 跳过未知类型的静态端点
            if endpoint_type.value == "unknown" and _is_likely_static(url):
                return

            # 提取请求头摘要
            request_headers: dict[str, str] = {}
            try:
                for h in ("authorization", "cookie", "x-api-key", "content-type"):
                    val = response.request.headers.get(h, "")
                    if val:
                        request_headers[h] = val
                for name, value in response.headers.items():
                    if name.lower() in {"x-openai-beta", "x-anthropic-version", "x-mcp-server", "server"}:
                        request_headers[name.lower()] = value
            except Exception:
                pass

            response_title = ""
            try:
                response_title = response.url.split("/")[-1]
            except Exception:
                response_title = ""
            signal_title = match_ai_title(response_title)
            if signal_title:
                request_headers["ai_title"] = signal_title

            header_signal = match_ai_header(" ".join(response.headers.keys()))
            if header_signal:
                request_headers["ai_header"] = f"{header_signal[0]}:{header_signal[1]}"

            # AI framework detection from body fingerprint
            ai_framework_name = ""
            ai_framework_category = ""
            if body_preview:
                body_fp = match_ai_body_fingerprint(body_preview)
                if body_fp:
                    ai_framework_name, ai_framework_category = body_fp

            endpoint = DiscoveredEndpoint(
                url=url,
                method=method,
                endpoint_type=endpoint_type,
                status_code=status,
                content_type=content_type or None,
                request_headers=request_headers,
                response_body_preview=body_preview,
                discovered_at=datetime.now().isoformat(),
                ai_framework_name=ai_framework_name,
                ai_framework_category=ai_framework_category,
            )
            self._endpoints.append(endpoint)

            logger.debug(
                f"NetworkInterceptor: {method} {url} → {endpoint_type.value} "
                f"({status})"
            )

        except Exception as e:
            logger.debug(f"NetworkInterceptor: error handling response: {e}")

    async def _trigger_lazy_loads(self, page: Page) -> None:
        """触发懒加载 API 调用 (滚动 + 常见交互)。."""
        # 模拟滚动到底部触发分页/加载
        with contextlib.suppress(Exception):
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)
            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(0.5)

        # 尝试点击常见交互元素
        for selector in ('button[class*="send"]', 'button[class*="submit"]', 'button[aria-label*="send"]'):
            with contextlib.suppress(Exception):
                el = await page.query_selector(selector)
                if el:
                    # 不实际点击, 仅检查存在性
                    pass


def _is_static_resource(url: str, content_type: str) -> bool:
    """判断是否为静态资源 (应跳过)。."""
    ct = content_type.lower()
    for static_type in _STATIC_CONTENT_TYPES:
        if static_type in ct:
            return True

    # 常见静态文件扩展名
    parsed = urlparse(url)
    path = parsed.path.lower()
    static_extensions = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                         ".woff", ".woff2", ".ttf", ".eot", ".ico", ".mp4",
                         ".webm", ".webp", ".map")
    return path.endswith(static_extensions)


def _is_likely_static(url: str) -> bool:
    """进一步判断未知类型的 URL 是否可能为静态资源。."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    # 无路径或根路径
    if not path or path == "/":
        return True
    # 版本化的静态资源路径
    return bool(any(seg in path for seg in ("/static/", "/assets/", "/public/", "/dist/", "/vendor/")))


def _is_json_response(content_type: str) -> bool:
    """判断响应是否为 JSON。."""
    return "json" in content_type.lower()