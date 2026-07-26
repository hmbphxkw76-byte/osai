# -*- coding: utf-8 -*-
"""
DOM Detector
============

DOM 侦察器：输入框 / 发送按钮 / 响应区 / 登录页检测，
支持三级发送降级（Enter / 按钮 / 父容器点击）。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .selector_pool import (
    INPUT_BOX_SELECTORS,
    LOGIN_PAGE_SELECTORS,
    RESPONSE_SELECTORS,
    SEND_BUTTON_SELECTORS,
)

logger = logging.getLogger(__name__)

DEFAULT_DETECTION_RESULT = {
    "url": "",
    "input_box": {},
    "send_button": {},
    "response_area": {},
    "input_selector": "",
    "send_selector": "",
    "response_selector": "",
    "input_score": 0.0,
    "send_score": 0.0,
    "response_score": 0.0,
    "login_page": False,
}

DEFAULT_RESPONSE_RESULT = {
    "selector": "",
    "response_source": "",
    "response_text": "",
}


class DOMDetector:
    """DOM 侦察器：输入框 / 发送按钮 / 响应区 / 登录页检测"""

    def __init__(
        self,
        page: Any,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.page = page
        self.config = config or {}
        self.timeout = self.config.get("selector_timeout_ms", 5000)
        self.send_probe = self.config.get("send_probe_text", "你好，请介绍一下你自己")

    async def detect_all(self) -> Dict[str, Any]:
        """执行完整 DOM 侦察"""
        result = DEFAULT_DETECTION_RESULT.copy()
        result["url"] = self.page.url

        input_result = await self.detect_input_box()
        result["input_box"] = input_result
        result["input_selector"] = input_result["selector"]
        result["input_score"] = input_result["score"]

        send_result = await self.detect_send_button()
        result["send_button"] = send_result
        result["send_selector"] = send_result["selector"]
        result["send_score"] = send_result["score"]

        response_result = await self.detect_response_area()
        result["response_area"] = response_result
        result["response_selector"] = response_result["selector"]
        result["response_score"] = response_result["score"]

        result["login_page"] = await self.is_login_page()
        return result

    async def detect_input_box(self) -> Dict[str, Any]:
        """评分检测输入框"""
        # 1. 使用内置选择器池
        scored = []
        for item in INPUT_BOX_SELECTORS:
            try:
                el = await self.page.query_selector(item["sel"])
                if el and await el.is_visible():
                    score = item["score"]
                    rect = await el.bounding_box()
                    if rect and rect["width"] > 50 and rect["height"] > 20:
                        score += 0.05
                    scored.append({"selector": item["sel"], "score": score, "source": "selector_pool"})
            except Exception:
                continue

        if scored:
            scored.sort(key=lambda x: x["score"], reverse=True)
            return scored[0]

        # 2. 兜底：查找页面上最大的可见 textarea / contenteditable
        fallback = await self.page.evaluate(
            """
            () => {
                let best = null;
                let bestScore = 0;
                const elements = document.querySelectorAll('textarea, [contenteditable="true"], input[type="text"]');
                for (const el of elements) {
                    const rect = el.getBoundingClientRect();
                    if (rect.width === 0 || rect.height === 0) continue;
                    let score = rect.width * rect.height;
                    const tag = el.tagName.toLowerCase();
                    if (tag === 'textarea') score *= 1.5;
                    if (el.getAttribute('contenteditable') === 'true') score *= 1.3;
                    if (score > bestScore) {
                        bestScore = score;
                        best = el;
                    }
                }
                if (!best) return null;
                let selector = best.tagName.toLowerCase();
                if (best.id) selector = '#' + best.id;
                else if (best.className) selector += '.' + best.className.split(' ')[0];
                return {selector, score: bestScore / 100000};
            }
            """
        )
        if fallback:
            return {"selector": fallback["selector"], "score": min(fallback["score"], 0.5), "source": "fallback_scan"}

        return {"selector": "", "score": 0.0, "source": "none"}

    async def detect_send_button(self) -> Dict[str, Any]:
        """检测发送按钮"""
        scored = []
        for item in SEND_BUTTON_SELECTORS:
            try:
                el = await self.page.query_selector(item["sel"])
                if el and await el.is_visible():
                    score = item["score"]
                    rect = await el.bounding_box()
                    if rect and rect["width"] > 10 and rect["height"] > 10:
                        score += 0.02
                    scored.append({"selector": item["sel"], "score": score, "source": "selector_pool"})
            except Exception:
                continue

        if scored:
            scored.sort(key=lambda x: x["score"], reverse=True)
            return scored[0]

        return {"selector": "", "score": 0.0, "source": "none"}

    async def detect_response_area(self) -> Dict[str, Any]:
        """检测响应区域"""
        scored = []
        for item in RESPONSE_SELECTORS:
            try:
                el = await self.page.query_selector(item["sel"])
                if el and await el.is_visible():
                    score = item["score"]
                    scored.append({"selector": item["sel"], "score": score, "source": "selector_pool"})
            except Exception:
                continue

        if scored:
            scored.sort(key=lambda x: x["score"], reverse=True)
            return scored[0]

        # 兜底：查找包含 assistant/ai/answer 文本的可见容器
        fallback = await self.page.evaluate(
            """
            () => {
                const keywords = ['assistant', 'ai', 'answer', 'response', 'reply', '消息'];
                const elements = document.querySelectorAll('div, article, section');
                let best = null;
                let bestScore = 0;
                for (const el of elements) {
                    const rect = el.getBoundingClientRect();
                    if (rect.width === 0 || rect.height === 0) continue;
                    const text = (el.innerText || '').toLowerCase();
                    let score = 0;
                    for (const kw of keywords) {
                        if (text.includes(kw)) score += 5;
                    }
                    if (score > bestScore) {
                        bestScore = score;
                        best = el;
                    }
                }
                if (!best) return null;
                let selector = best.tagName.toLowerCase();
                if (best.id) selector = '#' + best.id;
                else if (best.className) selector += '.' + best.className.split(' ')[0];
                return {selector, score: Math.min(bestScore / 50, 0.5)};
            }
            """
        )
        if fallback:
            return {"selector": fallback["selector"], "score": fallback["score"], "source": "fallback_scan"}

        return {"selector": "", "score": 0.0, "source": "none"}

    async def is_login_page(self) -> bool:
        """检测当前页面是否为登录页"""
        if not self.page:
            return False
        return await self.page.evaluate(
            """
            (selectors) => {
                const hasUsername = selectors.username.some(s => !!document.querySelector(s));
                const hasPassword = selectors.password.some(s => !!document.querySelector(s));
                const hasSubmit = selectors.submit.some(s => {
                    const el = document.querySelector(s);
                    return el && el.offsetParent !== null;
                });
                return hasPassword && (hasUsername || hasSubmit);
            }
            """,
            LOGIN_PAGE_SELECTORS,
        )

    async def type_and_send(
        self,
        text: str = "",
        input_selector: str = "",
        send_selector: str = "",
    ) -> Dict[str, Any]:
        """
        发送消息并捕获响应。

        三级发送降级：
          1. Enter 键
          2. 发送按钮点击
          3. 父容器点击（cursor: pointer）
        """
        text = text or self.send_probe
        result = {
            "success": False,
            "used_input_selector": input_selector,
            "used_send_selector": send_selector,
            "send_strategy": "none",
            "response": DEFAULT_RESPONSE_RESULT.copy(),
            "error": "",
        }

        if not input_selector:
            input_result = await self.detect_input_box()
            input_selector = input_result["selector"]
            result["used_input_selector"] = input_selector

        if not input_selector:
            result["error"] = "No input box found"
            return result

        try:
            await self.page.fill(input_selector, "")
            await self.page.fill(input_selector, text)
            await self.page.wait_for_timeout(500)
        except Exception as e:
            result["error"] = f"Failed to fill input: {str(e)[:120]}"
            return result

        # 策略 1：Enter 键
        try:
            await self.page.press(input_selector, "Enter")
            await self.page.wait_for_timeout(1500)
            resp = await self._capture_response()
            result["success"] = True
            result["send_strategy"] = "enter_key"
            result["response"] = resp
            return result
        except Exception:
            pass

        # 策略 2：发送按钮点击
        if not send_selector:
            send_result = await self.detect_send_button()
            send_selector = send_result["selector"]
            result["used_send_selector"] = send_selector

        if send_selector:
            try:
                btn = await self.page.query_selector(send_selector)
                if btn:
                    await btn.scroll_into_view_if_needed()
                    await btn.click(timeout=3000)
                    await self.page.wait_for_timeout(1500)
                    resp = await self._capture_response()
                    result["success"] = True
                    result["send_strategy"] = "send_button_click"
                    result["response"] = resp
                    return result
            except Exception as e:
                result["error"] = f"Send button click failed: {str(e)[:120]}"

        # 策略 3：父容器点击（cursor: pointer）
        try:
            clicked = await self.page.evaluate(
                """
                (inputSelector) => {
                    const input = document.querySelector(inputSelector);
                    if (!input) return false;
                    let el = input.parentElement;
                    for (let i = 0; i < 5 && el; i++, el = el.parentElement) {
                        const style = window.getComputedStyle(el);
                        if (style.cursor === 'pointer' || el.tagName === 'BUTTON') {
                            el.click();
                            return true;
                        }
                    }
                    return false;
                }
                """,
                input_selector,
            )
            if clicked:
                await self.page.wait_for_timeout(1500)
                resp = await self._capture_response()
                result["success"] = True
                result["send_strategy"] = "parent_container_click"
                result["response"] = resp
                return result
        except Exception as e:
            result["error"] = f"Parent container click failed: {str(e)[:120]}"

        result["success"] = False
        if not result["error"]:
            result["error"] = "All send strategies failed"
        return result

    async def _capture_response(self) -> Dict[str, Any]:
        """从 DOM 捕获响应"""
        response_result = await self.detect_response_area()
        if not response_result["selector"]:
            return DEFAULT_RESPONSE_RESULT.copy()

        try:
            text = await self.page.text_content(response_result["selector"])
            html = await self.page.inner_html(response_result["selector"])
            return {
                "selector": response_result["selector"],
                "response_source": "dom",
                "response_text": (text or "").strip()[:1000],
                "response_html": (html or "")[:2000],
            }
        except Exception:
            return DEFAULT_RESPONSE_RESULT.copy()
