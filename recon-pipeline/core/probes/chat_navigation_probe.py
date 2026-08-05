# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""ChatNavigationProbe: 聊天页面导航与模型信息提取探针。

职责 (对应需求):
  1. 自动探测聊天窗口入口 (DOM 链接/按钮)
  2. 导航进入 LLM 交互页面
  3. 提取模型名称、端点、API 路径等信息
  4. 形成完整 AI 攻击面画像的导航层

对齐 DESIGN.md 六类探针架构:
  - 输入: browser_page (已认证)
  - 产出: chat_url, model_name, api_endpoints, ui_features
  - 浏览器需求: True (必须)

> **日期**: 2026-8-4
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from core.probes.base import ReconProbe

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class ChatNavigationProbe(ReconProbe):
    """聊天页面导航探针。

    自动发现并进入聊天页面, 提取 AI 组件信息。

    用法::
        probe = ChatNavigationProbe()
        result = await probe.probe(session)
        # result["chat_url"] → 聊天页面 URL
        # result["model_name"] → 检测到的模型名
        # result["api_endpoints"] → 拦截到的 API 端点
        # result["ui_features"] → UI 功能特性
    """

    # 聊天入口常见选择器
    _CHAT_LINK_SELECTORS = [
        'a[href*="chat"]', 'a[href*="conversation"]',
        'a[href*="new-chat"]', 'a[href*="/c/"]',
        '[class*="chat-link"]', '[class*="new-chat"]',
        'button[class*="chat"]', 'a[aria-label*="Chat"]',
        'a[aria-label*="New"]', 'nav a[href*="chat"]',
    ]

    # 聊天输入框选择器
    _CHAT_INPUT_SELECTORS = [
        'textarea[placeholder*="Message"]',
        'textarea[placeholder*="message"]',
        'textarea[placeholder*="chat"]',
        'textarea[placeholder*="输入"]',
        'textarea[placeholder*="发送"]',
        'div[contenteditable="true"][class*="chat"]',
        'textarea[class*="chat"]',
        'textarea[class*="message"]',
        'div[role="textbox"][contenteditable="true"]',
    ]

    # 模型名常见选择器
    _MODEL_NAME_SELECTORS = [
        '[class*="model-name"]', '[class*="model-selector"]',
        '[data-model]', '[class*="model-display"]',
        'select[class*="model"] option[selected]',
        '[class*="current-model"]',
    ]

    def __init__(self, navigation_timeout: float = 15.0) -> None:
        self._nav_timeout = navigation_timeout
        # G11: SPA 路由感知 — 检测 hash / History API 路由
        self._spa_router_type: str | None = None  # "hash" | "history" | None

    @property
    def name(self) -> str:
        return "ChatNavigationProbe"

    @property
    def requires_browser(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """执行聊天页面导航探针。

        Args:
            session: 侦察会话 (需包含 browser_page)。

        Returns:
            包含 chat_url, model_name, api_endpoints, ui_features 的结果字典。
        """
        if session.browser_page is None:
            logger.warning("ChatNavigationProbe: no browser_page available, skipping")
            return {
                "chat_url": None,
                "model_name": None,
                "api_endpoints": [],
                "ui_features": [],
                "error": "no_browser_page",
            }

        page = session.browser_page
        result: dict[str, Any] = {
            "chat_url": None,
            "model_name": None,
            "api_endpoints": [],
            "ui_features": [],
            "navigation_path": [],
        }

        # 步骤1: 检测 SPA 路由类型 (G11)
        await self._detect_spa_router(page)

        # 步骤2: 检查当前页是否已是聊天页
        is_chat_page = await self._detect_chat_page(page)
        if is_chat_page:
            result["chat_url"] = page.url
            result["navigation_path"].append({"action": "already_on_chat", "url": page.url})
            logger.info(f"ChatNavigationProbe: already on chat page ({page.url})")
        else:
            # 步骤3: 查找并点击聊天入口
            chat_url = await self._find_and_navigate_to_chat(page)
            if chat_url:
                result["chat_url"] = chat_url
                result["navigation_path"].append({"action": "navigated", "url": chat_url})
                logger.info(f"ChatNavigationProbe: navigated to chat page ({chat_url})")
            else:
                result["error"] = "chat_entry_not_found"
                logger.warning("ChatNavigationProbe: could not find chat entry point")
                # 即使没找到入口, 仍然尝试从当前页提取信息
                result["chat_url"] = page.url

        # 步骤4: 提取模型名
        model_name = await self._extract_model_name(page)
        if model_name:
            result["model_name"] = model_name
            logger.info(f"ChatNavigationProbe: model name detected: {model_name}")

        # 步骤5: 拦截网络请求, 发现 API 端点
        api_endpoints = await self._intercept_api_endpoints(page)
        result["api_endpoints"] = api_endpoints
        if api_endpoints:
            logger.info(
                f"ChatNavigationProbe: intercepted {len(api_endpoints)} API endpoints"
            )

        # 步骤6: 检测 UI 功能特性
        ui_features = await self._detect_ui_features(page)
        result["ui_features"] = ui_features
        if ui_features:
            logger.info(
                f"ChatNavigationProbe: detected UI features: {ui_features}"
            )

        # 步骤7: 从页面文本/JS 中提取模型名 (兜底)
        if not result["model_name"]:
            text_model = await self._extract_model_from_text(page)
            if text_model:
                result["model_name"] = text_model
                logger.info(f"ChatNavigationProbe: model name from text: {text_model}")

        return result

    async def _detect_spa_router(self, page: Any) -> None:
        """G11: 检测 SPA 路由类型 (hash router / History API)。"""
        try:
            # 检测 hash router: URL 中 #/ 或 #!/
            current_url = page.url
            if "#/" in current_url or "#!/" in current_url:
                self._spa_router_type = "hash"
                logger.info("ChatNavigationProbe: SPA router detected (hash)")
                return

            # 检测 History API router: 页面有 pushState/replaceState 覆写
            has_history_router = await page.evaluate("""
                () => {
                    // 检查是否有 vue-router / react-router / angular-router
                    const hasVueRouter = !!(window.__VUE_DEVTOOLS_GLOBAL_HOOK__
                        || document.querySelector('[data-v-app]')
                        || document.querySelector('#app'));
                    const hasReactRouter = !!(document.querySelector('#root')
                        && window.history.state);
                    const hasAngularRouter = !!document.querySelector('app-root');
                    // 检查 history.pushState 是否被覆写
                    const pushStateOverwritten = window.history.pushState.toString().includes('native code') === false;
                    return hasVueRouter || hasReactRouter || hasAngularRouter || pushStateOverwritten;
                }
            """)
            if has_history_router:
                self._spa_router_type = "history"
                logger.info("ChatNavigationProbe: SPA router detected (History API)")
        except Exception as e:
            logger.debug(f"ChatNavigationProbe: SPA router detection failed: {e}")

    async def _detect_chat_page(self, page: Any) -> bool:
        """检测当前页是否已是聊天页面。"""
        for selector in self._CHAT_INPUT_SELECTORS:
            try:
                el = await page.query_selector(selector)
                if el:
                    return True
            except Exception:
                continue
        return False

    async def _find_and_navigate_to_chat(self, page: Any) -> str | None:
        """查找聊天入口并导航。"""
        # 策略1: 查找聊天链接
        for selector in self._CHAT_LINK_SELECTORS:
            try:
                el = await page.query_selector(selector)
                if el:
                    href = await el.get_attribute("href")
                    if href:
                        # 构建完整 URL
                        if href.startswith("/"):
                            from urllib.parse import urljoin
                            href = urljoin(page.url, href)
                        logger.debug(f"ChatNavigationProbe: found chat link {href}")
                        await page.goto(href, wait_until="domcontentloaded")
                        await page.wait_for_timeout(2000)  # 等待动态内容加载
                        return page.url
                    else:
                        # 无 href, 尝试点击
                        await el.click()
                        await page.wait_for_timeout(3000)
                        return page.url
            except Exception as e:
                logger.debug(f"ChatNavigationProbe: selector {selector} failed: {e}")
                continue

        # 策略2: 在当前 URL 后追加 /chat 或 /new
        from urllib.parse import urljoin
        for path in ("/chat", "/new", "/new-chat", "/c/new"):
            try:
                # G11: SPA hash 路由用 #/path, History API 用 /path
                if self._spa_router_type == "hash":
                    chat_url = urljoin(page.url, f"#{path}")
                    # hash 路由不需要页面跳转, 修改 hash 即可
                    await page.evaluate(f"window.location.hash = '{path}'")
                    await page.wait_for_timeout(2000)
                else:
                    chat_url = urljoin(page.url, path)
                    response = await page.goto(chat_url, wait_until="domcontentloaded")
                    if response and response.status == 200:
                        await page.wait_for_timeout(2000)
                if await self._detect_chat_page(page):
                    return page.url
            except Exception:
                continue

        return None

    async def _extract_model_name(self, page: Any) -> str | None:
        """从 DOM 提取模型名。"""
        for selector in self._MODEL_NAME_SELECTORS:
            try:
                el = await page.query_selector(selector)
                if el:
                    text = await el.text_content()
                    if text and text.strip():
                        return text.strip()
                    value = await el.get_attribute("data-model")
                    if value:
                        return value
            except Exception:
                continue
        return None

    async def _extract_model_from_text(self, page: Any) -> str | None:
        """从页面文本/JS 变量中提取模型名 (兜底)。"""
        # 常见模型名模式
        model_patterns = [
            r'(?:model|engine)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-._/]+)["\']',
            r'(?:gpt-[0-9]+(?:-[a-z]+)?)',
            r'(?:claude-[0-9]+(?:-[a-z]+)?)',
            r'(?:gemini-[0-9]+(?:-[a-z]+)?)',
            r'(?:llama-[0-9]+(?:-[a-z]+)?)',
            r'(?:qwen[0-9]*(?:-[a-z]+)?)',
            r'(?:deepseek[a-z0-9\-]*)',
            r'(?:mistral[a-z0-9\-]*)',
        ]
        try:
            content = await page.content()
            for pattern in model_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    # 返回第一个匹配
                    match = matches[0] if isinstance(matches[0], str) else matches[0][0]
                    if match and len(match) < 100:  # 避免误匹配
                        return match
        except Exception:
            pass
        return None

    async def _intercept_api_endpoints(self, page: Any) -> list[dict[str, str]]:
        """通过短暂监听网络请求发现 API 端点。"""
        endpoints: list[dict[str, str]] = []
        seen_urls: set[str] = set()

        def on_request(request: Any) -> None:
            url = request.url
            method = request.method
            # 过滤: 只保留 API 相关请求
            if any(kw in url.lower() for kw in (
                "/api/", "/v1/", "/chat/", "/completions", "/messages",
                "/model", "/embed", "/retrieve", "/search", "/mcp/",
                "/paas/", "/dashscope/", "/aigc/",
            )):
                if url not in seen_urls:
                    seen_urls.add(url)
                    endpoints.append({"url": url, "method": method})

        try:
            page.on("request", on_request)

            # G11: SPA 页面可能需要更长的拦截窗口, 因为路由切换是异步的
            intercept_timeout = 5000 if self._spa_router_type else 3000

            # 触发页面交互以产生网络请求
            try:
                await page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
            except Exception:
                pass
            await page.wait_for_timeout(intercept_timeout)

            # G11: 尝试触发 SPA 路由变化以产生更多请求
            if self._spa_router_type:
                try:
                    await page.evaluate("""
                        () => {
                            // 触发可能的 lazy-load 路由
                            const links = document.querySelectorAll('a[href]');
                            if (links.length > 0 && links[0].href !== window.location.href) {
                                // 仅 hover, 不导航
                                const event = new MouseEvent('mouseover', {bubbles: true});
                                links[0].dispatchEvent(event);
                            }
                        }
                    """)
                    await page.wait_for_timeout(2000)
                except Exception:
                    pass

            page.remove_listener("request", on_request)
        except Exception as e:
            logger.debug(f"ChatNavigationProbe: network interception error: {e}")

        return endpoints

    async def _detect_ui_features(self, page: Any) -> list[str]:
        """检测页面 UI 功能特性。"""
        features: list[str] = []
        feature_selectors: dict[str, list[str]] = {
            "chat_input": self._CHAT_INPUT_SELECTORS,
            "file_upload": [
                'input[type="file"]', '[class*="upload"]',
                '[class*="attachment"]', 'button[aria-label*="upload"]',
            ],
            "voice_input": [
                'button[class*="voice"]', 'button[aria-label*="mic"]',
                '[class*="audio-input"]',
            ],
            "model_selector": self._MODEL_NAME_SELECTORS,
            "tool_panel": [
                '[class*="tool"]', '[class*="plugin"]',
                '[class*="function"]', '[class*="agent"]',
            ],
            "settings": [
                '[class*="settings"]', 'button[aria-label*="Settings"]',
                '[class*="config"]',
            ],
            "streaming": [
                '[class*="stream"]', '[class*="typing"]',
                '[class*="generating"]',
            ],
            "stop_button": [
                'button[class*="stop"]', 'button[aria-label*="Stop"]',
                '[class*="stop-generate"]',
            ],
            "history_sidebar": [
                '[class*="sidebar"]', '[class*="history"]',
                '[class*="conversation-list"]',
            ],
            "regenerate": [
                'button[class*="regenerate"]', 'button[aria-label*="regenerate"]',
                '[class*="retry"]',
            ],
        }
        for feature, selectors in feature_selectors.items():
            for selector in selectors:
                try:
                    el = await page.query_selector(selector)
                    if el:
                        features.append(feature)
                        break
                except Exception:
                    continue
        return features
