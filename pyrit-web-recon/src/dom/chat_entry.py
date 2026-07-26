# -*- coding: utf-8 -*-
"""
Chat Entry Discovery
====================

AI 聊天入口按钮自动发现：
  - YAML 配置优先
  - 内置选择器池渐进式匹配
  - 全屏评分扫描兜底
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .selector_pool import CHAT_ENTRY_FALLBACK_SELECTORS, CHAT_ENTRY_SELECTORS

logger = logging.getLogger(__name__)

_CHAT_ENTRY_KEYWORDS = [
    "chat", "ai", "助手", "智能", "聊天", "对话", "问答", "客服",
    "robot", "bot", "assistant", "copilot", "genie", "sparkle",
    "知识库", "智能体", "knowledge", "agent", "playground",
]


async def discover_chat_entry(
    page: Any,
    yaml_selector: str = "",
    timeout_ms: int = 5000,
    click_verify: bool = False,
    click_timeout_ms: int = 5000,
    post_click_wait_ms: int = 3000,
) -> Dict[str, Any]:
    """
    发现 AI 聊天入口按钮。

    策略：
      1. YAML 显式配置优先
      2. 使用 CHAT_ENTRY_SELECTORS 渐进式匹配
      3. 评分扫描兜底，返回前 N 个候选
      4. 若 click_verify=True，则逐个点击候选并验证聊天输入框是否出现

    Returns:
        {"selector": str, "source": str, "score": float, "candidates": list}
    """
    # 1. YAML 显式配置优先
    if yaml_selector:
        try:
            el = await page.wait_for_selector(yaml_selector, state="visible", timeout=timeout_ms)
            if el:
                if click_verify:
                    clicked = await _try_click_and_verify(
                        page, yaml_selector, click_timeout_ms, post_click_wait_ms
                    )
                    if clicked:
                        return {"selector": yaml_selector, "source": "yaml", "score": 1.0}
                else:
                    return {"selector": yaml_selector, "source": "yaml", "score": 1.0}
        except Exception:
            pass

    # 2. 内置选择器池渐进式匹配
    for sel in CHAT_ENTRY_SELECTORS:
        try:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                if click_verify:
                    clicked = await _try_click_and_verify(page, sel, click_timeout_ms, post_click_wait_ms)
                    if clicked:
                        return {"selector": sel, "source": "selector_pool", "score": 0.9}
                    continue
                return {"selector": sel, "source": "selector_pool", "score": 0.9}
        except Exception:
            continue

    # 3. 评分扫描候选
    candidates = await _score_scan_chat_entry(page)
    if candidates:
        if click_verify:
            for candidate in candidates:
                sel = candidate.get("selector", "")
                if not sel:
                    continue
                clicked = await _try_click_and_verify(page, sel, click_timeout_ms, post_click_wait_ms)
                if clicked:
                    return {
                        "selector": sel,
                        "source": "score_scan",
                        "score": min(candidate.get("score", 0) / 20.0, 1.0),
                        "signals": candidate.get("signals", ""),
                        "candidates": candidates,
                    }
            # 评分扫描未命中，尝试兜底选择器
            for sel in CHAT_ENTRY_FALLBACK_SELECTORS:
                try:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible():
                        clicked = await _try_click_and_verify(
                            page, sel, click_timeout_ms, post_click_wait_ms
                        )
                        if clicked:
                            return {"selector": sel, "source": "fallback", "score": 0.5}
                except Exception:
                    continue
        else:
            best = candidates[0]
            return {
                "selector": best.get("selector", ""),
                "source": "score_scan",
                "score": min(best.get("score", 0) / 20.0, 1.0),
                "signals": best.get("signals", ""),
                "candidates": candidates,
            }

    return {"selector": "", "source": "none", "score": 0.0, "candidates": []}


async def _try_click_and_verify(
    page: Any,
    selector: str,
    click_timeout_ms: int = 5000,
    post_click_wait_ms: int = 3000,
) -> bool:
    """点击候选入口并验证聊天输入框是否出现"""
    try:
        el = await page.query_selector(selector)
        if not el or not await el.is_visible():
            return False
        await el.scroll_into_view_if_needed()
        await el.click(timeout=click_timeout_ms)
        await page.wait_for_timeout(post_click_wait_ms)

        has_input = await page.evaluate(
            """() => {
                const sels = [
                    'textarea.send-box-default-text', 'textarea[class*="send-box"]',
                    'textarea[class*="chat-input"]', 'textarea[class*="chat"]',
                    '[placeholder*="请输入"]', '[placeholder*="输入"]',
                    'textarea:not([disabled])', '[contenteditable="true"]'
                ];
                for (const sel of sels) {
                    const e = document.querySelector(sel);
                    if (e && e.offsetParent !== null) return true;
                }
                return false;
            }"""
        )
        return bool(has_input)
    except Exception as exc:
        logger.debug("Click and verify failed for %s: %s", selector, exc)
        return False


async def _score_scan_chat_entry(page: Any) -> Optional[List[Dict[str, Any]]]:
    """全屏评分扫描聊天入口候选，返回排序后的候选列表"""
    candidates = await page.evaluate(
        """
        (keywords) => {
            const candidates = [];
            const elements = document.querySelectorAll(
                'button, a, [role="button"], [onclick], img[class*="action"], ' +
                '[class*="chat"], [class*="ai"], [class*="assistant"], ' +
                '[class*="robot"], [class*="help"], [class*="show-chat"], ' +
                '[class*="open-chat"], [class*="toggle-chat"]'
            );
            for (const el of elements) {
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) continue;
                const text = (el.innerText || '').trim();
                const className = el.className || '';
                const ariaLabel = el.getAttribute('aria-label') || '';
                const title = el.getAttribute('title') || '';
                const alt = el.getAttribute('alt') || '';
                const combined = (className + ' ' + text + ' ' + ariaLabel + ' ' + title + ' ' + alt).toLowerCase();
                let score = 0;
                const signals = [];
                for (const kw of keywords) {
                    if (combined.includes(kw.toLowerCase())) {
                        score += 10;
                        signals.push(kw);
                    }
                }
                if (rect.x > window.innerWidth * 0.7 && rect.y > window.innerHeight * 0.5
                    && rect.width < 100 && rect.height < 100) {
                    score += 5;
                    signals.push('fab-position');
                }
                if (score > 0) {
                    let selector = '';
                    if (el.id) selector = '#' + el.id;
                    else if (el.getAttribute('data-testid')) selector = '[data-testid="' + el.getAttribute('data-testid') + '"]';
                    else if (ariaLabel) selector = '[aria-label="' + ariaLabel + '"]';
                    else if (className && typeof className === 'string') {
                        const cls = className.split(' ')[0];
                        selector = el.tagName.toLowerCase() + '.' + cls;
                    } else {
                        selector = el.tagName.toLowerCase();
                    }
                    candidates.push({selector, score, signals: signals.join(','), className});
                }
            }
            candidates.sort((a, b) => b.score - a.score);
            return candidates.slice(0, 5);
        }
        """,
        _CHAT_ENTRY_KEYWORDS,
    )

    # 过滤掉不可见或无法 query 的候选
    valid = []
    for candidate in candidates:
        sel = candidate.get("selector", "")
        if not sel:
            continue
        try:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                valid.append(candidate)
        except Exception:
            continue
    return valid if valid else None
