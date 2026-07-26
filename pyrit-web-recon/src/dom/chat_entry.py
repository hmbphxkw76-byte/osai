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

from .selector_pool import CHAT_ENTRY_SELECTORS

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
) -> Dict[str, Any]:
    """
    发现 AI 聊天入口按钮。

    策略：
      1. YAML 显式配置优先
      2. 使用 CHAT_ENTRY_SELECTORS 渐进式匹配
      3. 评分扫描兜底

    Returns:
        {"selector": str, "source": str, "score": float}
    """
    if yaml_selector:
        try:
            el = await page.wait_for_selector(yaml_selector, state="visible", timeout=timeout_ms)
            if el:
                return {"selector": yaml_selector, "source": "yaml", "score": 1.0}
        except Exception:
            pass

    for sel in CHAT_ENTRY_SELECTORS:
        try:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                return {"selector": sel, "source": "selector_pool", "score": 0.9}
        except Exception:
            continue

    candidate = await _score_scan_chat_entry(page)
    if candidate:
        return candidate

    return {"selector": "", "source": "none", "score": 0.0}


async def _score_scan_chat_entry(page: Any) -> Optional[Dict[str, Any]]:
    """全屏评分扫描聊天入口候选"""
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

    if candidates:
        best = candidates[0]
        try:
            el = await page.query_selector(best["selector"])
            if el and await el.is_visible():
                return {
                    "selector": best["selector"],
                    "source": "score_scan",
                    "score": min(best["score"] / 20.0, 1.0),
                    "signals": best["signals"],
                }
        except Exception:
            pass

    return None
