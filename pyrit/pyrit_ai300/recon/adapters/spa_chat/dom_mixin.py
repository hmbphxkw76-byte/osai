# -*- coding: utf-8 -*-
"""
SPA Chat Recon - DOM 侦测 Mixin

提供 SPA 聊天侦察的 DOM 元素侦测能力（作为 SPAChatReconAdapter 的 Mixin）：
- AI 应用类型识别（URL 模式 + 关键词评分）
- 选择器分类过滤（按 AI 应用类型优先级排序）
- DOM 快照批量提取（单次 page.evaluate 替代 600 次 IPC）
- 多信号加权评分（tag/class/aria-label/placeholder/text/parent/role）
- 稳健 CSS 选择器生成（优先级: #id > [data-testid] > [aria-label] > tag.class）
- 自动检测聊天入口/输入框/发送按钮/响应区域
- 聊天页面识别（URL 模式 + DOM 特征）
- WAF 安全延迟（避免触发 WAF 速率限制）

从 spa_chat_recon_adapter.py 提取（模块化拆分）
"""

from __future__ import annotations

import logging
import random
import re
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    AI_APP_TYPE_RULES,
    CHAT_PAGE_DOM_FEATURES,
    CHAT_URL_PATTERNS,
    DEFAULT_CHAT_ENTRY_SELECTORS,
    GENERIC_SELECTOR_CATEGORY_NUMBERS,
    HIGH_CONFIDENCE_CHAT_URL_PATTERNS,
    HIGH_SIGNAL_DOM_FEATURES,
    ROLE_TO_SNAPSHOT_KEY,
    SCORE_WEIGHTS,
    SIGNAL_KEYWORDS,
    WAF_SAFE_DELAYS,
)

logger = logging.getLogger(__name__)


class DOMMixin:
    """DOM 侦测 Mixin：为 SPAChatReconAdapter 提供页面元素侦测能力。"""


    # ── AI 应用类型预判（v1.3 新增）──
    #
    # 设计原则：
    #   1. 基于 URL 预判 AI 应用类型，减少选择器搜索空间
    #   2. 渐进式匹配：类型专属 → 通用核心 → 全量兜底
    #   3. 高置信度 URL 直接判定，跳过 DOM 检查
    #   4. 遵循 AI Red Team 最佳实践：最小化交互，降低 WAF 触发风险

    @staticmethod
    def _detect_ai_app_type(url: str) -> List[Tuple[str, float]]:
        """
        基于 URL 预判 AI 应用类型，返回按置信度降序排列的类型列表

        预判逻辑：
        1. 对每个 AI 应用类型，检查 URL 是否匹配其 url_patterns
        2. 匹配的模式越具体，置信度越高
        3. 返回所有匹配类型及其置信度，按降序排列

        AI Red Team 最佳实践：
        - 预判不等于确认，仅用于优化选择器优先级
        - 避免基于单一信号下结论，保留多类型候选
        - 始终有 generic_chat 作为兜底类型

        Args:
            url: 目标 URL

        Returns:
            [(type_name, confidence), ...] 按置信度降序排列
            confidence 范围 [0.0, 1.0]
            始终包含 ("generic_chat", 0.1) 作为兜底
        """
        url_lower = url.lower()
        results: List[Tuple[str, float]] = []

        for type_name, rules in AI_APP_TYPE_RULES.items():
            patterns = rules.get("url_patterns", [])
            if not patterns:
                continue

            matched_count = 0
            for pattern in patterns:
                if re.search(pattern, url_lower, re.IGNORECASE):
                    matched_count += 1

            if matched_count > 0:
                # 置信度计算：基础 0.6 + 每个额外匹配 +0.15，上限 0.95
                confidence = min(0.6 + (matched_count - 1) * 0.15, 0.95)
                results.append((type_name, confidence))

        # 始终包含 generic_chat 作为兜底
        results.append(("generic_chat", 0.1))

        # 按置信度降序排列
        results.sort(key=lambda x: x[1], reverse=True)

        return results

    @staticmethod
    def _filter_selectors_by_type(
        all_selectors: str,
        type_name: str,
    ) -> str:
        """
        从全量选择器字符串中过滤出指定类型专属的选择器

        过滤逻辑：
        1. 将逗号分隔的选择器字符串拆分为单个选择器
        2. 检查每个选择器是否包含类型对应的 selector_keywords
        3. 返回匹配的选择器组成的逗号分隔字符串

        Args:
            all_selectors: 逗号分隔的全量选择器字符串（DEFAULT_CHAT_ENTRY_SELECTORS）
            type_name: AI 应用类型名称

        Returns:
            过滤后的逗号分隔选择器字符串
        """
        rules = AI_APP_TYPE_RULES.get(type_name, {})
        keywords = rules.get("selector_keywords", [])

        if not keywords:
            return ""

        # 拆分选择器并过滤
        selectors = [s.strip() for s in all_selectors.split(",")]
        filtered = []
        for sel in selectors:
            sel_lower = sel.lower()
            for kw in keywords:
                if kw in sel_lower:
                    filtered.append(sel)
                    break

        return ", ".join(filtered)

    @staticmethod
    def _get_generic_core_selectors(all_selectors: str) -> str:
        """
        从全量选择器中提取通用核心选择器（分类 1-9）

        通用核心选择器是所有 AI 应用类型都可能使用的高频选择器，
        包括：精确类名、ARIA 标签、文本匹配、图标、FAB、data 属性、模糊类名。
        不包括类型专属选择器（Copilot/RAG/Agent/Playground/SaaS）。

        提取策略：排除包含类型专属关键词的选择器，保留其余选择器。

        Args:
            all_selectors: 逗号分隔的全量选择器字符串

        Returns:
            通用核心选择器组成的逗号分隔字符串
        """
        # 收集所有类型专属关键词
        type_specific_keywords: List[str] = []
        for type_name in ("copilot", "rag", "agent", "playground", "saas_chatbot"):
            kws = AI_APP_TYPE_RULES.get(type_name, {}).get("selector_keywords", [])
            type_specific_keywords.extend(kws)

        selectors = [s.strip() for s in all_selectors.split(",")]
        core_selectors = []
        for sel in selectors:
            sel_lower = sel.lower()
            # 排除包含任何类型专属关键词的选择器
            is_type_specific = False
            for kw in type_specific_keywords:
                if kw in sel_lower:
                    is_type_specific = True
                    break
            if not is_type_specific:
                core_selectors.append(sel)

        return ", ".join(core_selectors)

    def _get_priority_selectors(
        self,
        url: str,
        all_selectors: str,
    ) -> List[Tuple[str, str, int]]:
        """
        基于 URL 预判，返回分阶段优先级选择器列表

        渐进式匹配策略（AI Red Team 最佳实践：精准优先，逐步放宽）：
        - Phase 1: 类型专属选择器（高精度，快速匹配，短超时）
        - Phase 2: 通用核心选择器（中精度，中等超时）
        - Phase 3: 全量选择器兜底（低精度，长超时，确保不遗漏）

        每个阶段返回 (selector_string, phase_label, timeout_ms) 三元组。
        如果某个阶段的选择器为空，自动跳过该阶段。

        Args:
            url: 目标 URL，用于类型预判
            all_selectors: 全量选择器字符串（DEFAULT_CHAT_ENTRY_SELECTORS）

        Returns:
            [(selector_str, label, timeout_ms), ...] 非空的匹配阶段列表
        """
        # 1. URL 预判 AI 应用类型
        type_ranking = self._detect_ai_app_type(url)
        top_type, top_confidence = type_ranking[0]

        phases: List[Tuple[str, str, int]] = []

        # Phase 1: 类型专属选择器（仅当置信度 > 0.3 且不是 generic_chat）
        if top_confidence > 0.3 and top_type != "generic_chat":
            type_selectors = self._filter_selectors_by_type(all_selectors, top_type)
            if type_selectors:
                phases.append((type_selectors, f"类型专属[{top_type}]", 5000))
                logger.info(
                    "AI app type predicted: %s (confidence=%.2f), %d type-specific selectors queued",
                    top_type, top_confidence, type_selectors.count(",") + 1,
                )

        # Phase 2: 通用核心选择器
        core_selectors = self._get_generic_core_selectors(all_selectors)
        if core_selectors:
            phases.append((core_selectors, "通用核心", 5000))

        # Phase 3: 全量选择器兜底
        phases.append((all_selectors, "全量兜底", 5000))

        return phases

    # ── DOM 快照提取 + 语义评分 + 选择器生成（v1.4 新增）──
    #
    # 设计原则：
    #   1. 单次 page.evaluate() 批量提取所有元素（1 次 IPC 替代 600 次）
    #   2. Python 侧多信号加权评分（0 次 IPC）
    #   3. 从最高分元素生成稳健 CSS 选择器
    #   4. 自动发现 > YAML 配置 > 硬编码默认值（三层降级）

    @staticmethod
    async def _extract_dom_snapshot(page: Any) -> Dict[str, List[Dict[str, Any]]]:
        """
        单次 page.evaluate() 批量提取页面所有可交互元素

        提取范围：
        - inputs: textarea / input[text] / contenteditable
        - buttons: button / [role=button] / [class*=btn] / [onclick] / a[href]
        - containers: [class*=response|message|answer] / [role=log] / [aria-live]

        每个元素提取：tag/id/class/text/aria-label/title/placeholder/name/type/
                     contentEditable/data-attrs/has-svg/has-img/position/z-index/
                     rect/parent-class/parent-role

        Returns:
            {"inputs": [...], "buttons": [...], "containers": [...]}
        """
        js_script = """() => {
            const results = { inputs: [], buttons: [], containers: [] };
            const isVisible = (el) => {
                const rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0 &&
                       getComputedStyle(el).visibility !== 'hidden' &&
                       getComputedStyle(el).display !== 'none';
            };
            const extractAttrs = (el) => {
                const rect = el.getBoundingClientRect();
                const style = getComputedStyle(el);
                const dataAttrs = {};
                for (const attr of el.attributes) {
                    if (attr.name.startsWith('data-')) dataAttrs[attr.name] = attr.value;
                }
                // 检测子元素中的 markdown/prose/code-block
                const hasMarkdown = el.querySelector('.markdown, .prose, .code-block, .hljs, pre, code') !== null;
                // 检测 send/upload 箭头 SVG
                const svgPaths = el.querySelectorAll('svg path');
                let hasSendIcon = false;
                for (const p of svgPaths) {
                    const d = (p.getAttribute('d') || '').toLowerCase();
                    if (d.includes('m2') || d.includes('l2') || d.includes('arrow') || d.includes('send')) {
                        hasSendIcon = true; break;
                    }
                }
                return {
                    tag: el.tagName.toLowerCase(),
                    id: el.id || '',
                    class: (typeof el.className === 'string' ? el.className : '').substring(0, 120),
                    text: (el.innerText || '').trim().substring(0, 100),
                    ariaLabel: el.getAttribute('aria-label') || '',
                    ariaRole: el.getAttribute('role') || '',
                    title: el.getAttribute('title') || '',
                    placeholder: el.getAttribute('placeholder') || '',
                    name: el.getAttribute('name') || '',
                    type: el.getAttribute('type') || '',
                    contentEditable: el.contentEditable,
                    dataAttrs: dataAttrs,
                    hasSvg: el.querySelector('svg') !== null,
                    hasImg: el.querySelector('img') !== null,
                    hasMarkdown: hasMarkdown,
                    hasSendIcon: hasSendIcon,
                    position: style.position,
                    zIndex: style.zIndex,
                    rect: { x: Math.round(rect.x), y: Math.round(rect.y),
                            w: Math.round(rect.width), h: Math.round(rect.height) },
                    parentClass: el.parentElement ? (typeof el.parentElement.className === 'string' ? el.parentElement.className : '').substring(0, 80) : '',
                    parentRole: el.parentElement ? (el.parentElement.getAttribute('role') || '') : '',
                };
            };

            // 输入框
            document.querySelectorAll(
                'textarea, input[type="text"], input:not([type]), [contenteditable="true"]'
            ).forEach(el => { if (isVisible(el)) results.inputs.push(extractAttrs(el)); });

            // 按钮
            document.querySelectorAll(
                'button, [role="button"], [class*="btn"], [class*="button"], [onclick], a[href]'
            ).forEach(el => { if (isVisible(el)) results.buttons.push(extractAttrs(el)); });

            // 响应容器
            document.querySelectorAll(
                '[class*="response"], [class*="message"], [class*="answer"], [class*="reply"], ' +
                '[class*="chat-msg"], [class*="ai-msg"], [class*="assistant"], [role="log"], ' +
                '[aria-live="polite"], [aria-live="assertive"], [class*="markdown"], [class*="prose"]'
            ).forEach(el => { if (isVisible(el)) results.containers.push(extractAttrs(el)); });

            // ── iframe 内扫描（如京东京言AI） ──
            // 某些网站将聊天界面嵌入 iframe，需要扫描 iframe 内的可交互元素
            for (const iframe of document.querySelectorAll('iframe')) {
                try {
                    const doc = iframe.contentDocument || iframe.contentWindow?.document;
                    if (!doc) continue;

                    // 检查 iframe 是否可见
                    const iframeRect = iframe.getBoundingClientRect();
                    if (iframeRect.width <= 0 || iframeRect.height <= 0) continue;

                    // iframe 内输入框
                    doc.querySelectorAll(
                        'textarea, input[type="text"], input:not([type]), [contenteditable="true"]'
                    ).forEach(el => {
                        if (isVisible(el)) {
                            const attrs = extractAttrs(el);
                            attrs.inIframe = true;
                            attrs.iframeSrc = (iframe.src || '').substring(0, 120);
                            results.inputs.push(attrs);
                        }
                    });

                    // iframe 内按钮
                    doc.querySelectorAll(
                        'button, [role="button"], [class*="btn"], [class*="button"], [onclick], a[href]'
                    ).forEach(el => {
                        if (isVisible(el)) {
                            const attrs = extractAttrs(el);
                            attrs.inIframe = true;
                            attrs.iframeSrc = (iframe.src || '').substring(0, 120);
                            results.buttons.push(attrs);
                        }
                    });

                    // iframe 内响应容器
                    doc.querySelectorAll(
                        '[class*="response"], [class*="message"], [class*="answer"], [class*="reply"], ' +
                        '[class*="chat-msg"], [class*="ai-msg"], [class*="assistant"], [role="log"], ' +
                        '[aria-live="polite"], [aria-live="assertive"], [class*="markdown"], [class*="prose"]'
                    ).forEach(el => {
                        if (isVisible(el)) {
                            const attrs = extractAttrs(el);
                            attrs.inIframe = true;
                            attrs.iframeSrc = (iframe.src || '').substring(0, 120);
                            results.containers.push(attrs);
                        }
                    });
                } catch(e) {
                    // 跨域 iframe 无法访问 contentDocument，跳过
                }
            }

            return results;
        }"""

        try:
            snapshot = await page.evaluate(js_script)
            logger.debug(
                "DOM snapshot extracted: %d inputs, %d buttons, %d containers",
                len(snapshot.get("inputs", [])),
                len(snapshot.get("buttons", [])),
                len(snapshot.get("containers", [])),
            )
            return snapshot
        except Exception as e:
            logger.warning("DOM snapshot extraction failed: %s", str(e))
            return {"inputs": [], "buttons": [], "containers": []}

    @staticmethod
    def _score_elements(
        snapshot: Dict[str, List[Dict[str, Any]]],
        role: str,
        url: str = "",
    ) -> List[Dict[str, Any]]:
        """
        对快照中的元素按角色做多信号加权评分

        信号源（按角色不同权重组合）：
        - tag（textarea/contenteditable/submit）
        - class（含 AI 应用类型专属关键词加权）
        - aria-label / aria-role / aria-live
        - placeholder（input 专属）
        - text（send_button 专属）
        - parent-class（上下文信号）
        - data-testid（稳定性信号）
        - position（浮动按钮信号）
        - has-svg-icon / has-markdown

        Args:
            snapshot: _extract_dom_snapshot 的返回值
            role: "input" / "send_button" / "response"
            url: 用于 AI 应用类型预判（加权类型专属关键词）

        Returns:
            [{"element": {...}, "score": float, "signals": [str, ...]}, ...]
            按分数降序排列
        """
        snapshot_key = ROLE_TO_SNAPSHOT_KEY.get(role, role + "s")
        elements = snapshot.get(snapshot_key, [])
        weights = SCORE_WEIGHTS.get(role, {})
        signals = SIGNAL_KEYWORDS.get(role, [])

        # AI 应用类型预判（加权类型专属关键词）
        type_keywords: List[str] = []
        if url:
            type_ranking = DOMMixin._detect_ai_app_type(url)
            top_type = type_ranking[0][0]
            type_keywords = AI_APP_TYPE_RULES.get(top_type, {}).get("selector_keywords", [])

        scored: List[Dict[str, Any]] = []

        for el in elements:
            score = 0.0
            matched: List[str] = []

            el_class_lower = el.get("class", "").lower()
            el_aria_lower = el.get("ariaLabel", "").lower()
            el_text_lower = el.get("text", "").lower()
            el_parent_lower = el.get("parentClass", "").lower()
            el_placeholder_lower = el.get("placeholder", "").lower()
            el_tag = el.get("tag", "")
            el_role = el.get("ariaRole", "")

            # ── tag 信号 ──
            if role == "input":
                if el_tag == "textarea":
                    score += weights.get("tag_textarea", 0)
                    matched.append("tag=textarea")
                if el.get("contentEditable") == "true":
                    score += weights.get("tag_contenteditable", 0)
                    matched.append("contenteditable")

            if role == "send_button":
                if el.get("type") == "submit" or el_tag == "button":
                    score += weights.get("type_submit", 0)
                    matched.append("type=submit")

            # ── class 信号 ──
            class_matched = False
            for sig in signals:
                if sig in el_class_lower:
                    score += weights.get("class_match", 0)
                    matched.append("class:" + sig)
                    class_matched = True
                    break
            # 类型专属关键词加权（半权重，避免过拟合）
            if not class_matched:
                for sig in type_keywords:
                    if sig in el_class_lower:
                        score += weights.get("class_match", 0) * 0.5
                        matched.append("type_class:" + sig)
                        break

            # ── aria-label 信号 ──
            for sig in signals:
                if sig in el_aria_lower:
                    score += weights.get("aria_label_match", 0)
                    matched.append("aria:" + sig)
                    break

            # ── placeholder 信号（input 专属）──
            if role == "input":
                for sig in signals:
                    if sig in el_placeholder_lower:
                        score += weights.get("placeholder_match", 0)
                        matched.append("placeholder:" + sig)
                        break

            # ── text 信号 ──
            if role == "send_button":
                for sig in signals:
                    if sig in el_text_lower:
                        score += weights.get("text_match", 0)
                        matched.append("text:" + sig)
                        break

            # ── parent-class 上下文信号 ──
            for sig in signals:
                if sig in el_parent_lower:
                    score += weights.get("parent_class_match", 0)
                    matched.append("parent:" + sig)
                    break

            # ── ARIA role / aria-live 信号（response 专属）──
            if role == "response":
                if el_role == "log":
                    score += weights.get("role_log", 0)
                    matched.append("role=log")
                if el.get("ariaRole") == "status" or "polite" in el_aria_lower:
                    score += weights.get("aria_live", 0)
                    matched.append("aria-live=polite")

            # ── has-markdown 信号（response 专属）──
            if role == "response":
                if el.get("hasMarkdown"):
                    score += weights.get("has_markdown", 0)
                    matched.append("has-markdown")
                # 文本长度信号（回复区通常有较长文本）
                text_len = len(el.get("text", ""))
                if text_len > 50:
                    score += weights.get("text_length", 0)
                    matched.append("text_len=%d" % text_len)

            # ── has-send-icon 信号（send_button 专属）──
            if role == "send_button":
                if el.get("hasSendIcon"):
                    score += weights.get("has_send_icon", 0)
                    matched.append("send-icon")

            # ── 空间邻近信号 ──
            if role == "input" and "near_send_button" in weights:
                # 检查同快照中是否有 send button 在附近（简化：同 parent class）
                buttons = snapshot.get("buttons", [])
                for btn in buttons:
                    if el.get("parentClass") and el["parentClass"] == btn.get("parentClass"):
                        score += weights.get("near_send_button", 0)
                        matched.append("near-send-btn")
                        break

            if role == "send_button" and "near_input" in weights:
                inputs = snapshot.get("inputs", [])
                for inp in inputs:
                    if el.get("parentClass") and el["parentClass"] == inp.get("parentClass"):
                        score += weights.get("near_input", 0)
                        matched.append("near-input")
                        break

            scored.append({"element": el, "score": score, "signals": matched})

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    @staticmethod
    def _generate_selector(el: Dict[str, Any]) -> str:
        """
        从元素属性生成稳健的 CSS 选择器

        优先级（从高到低）：
        1. #id — 唯一性最强
        2. [data-testid] — 测试属性，开发者故意命名
        3. [aria-label] — 语义属性，WCAG 合规要求
        4. tag.class — 类名组合（排除 hash 类名）
        5. tag[placeholder] — 输入框专属
        6. tag[role] — ARIA 角色
        7. tag — 兜底

        返回逗号分隔的多候选选择器，Playwright 按顺序匹配第一个。
        """
        tag = el.get("tag", "")
        el_id = el.get("id", "")
        el_class = el.get("class", "")
        aria_label = el.get("ariaLabel", "")
        placeholder = el.get("placeholder", "")
        data_attrs = el.get("dataAttrs", {})
        aria_role = el.get("ariaRole", "")

        candidates: List[str] = []

        # 1. ID
        if el_id:
            candidates.append("#" + el_id)

        # 2. data-testid / data-test / data-cy / data-ai
        for key in ("data-testid", "data-test", "data-cy", "data-ai"):
            if key in data_attrs and data_attrs[key]:
                candidates.append('[%s="%s"]' % (key, data_attrs[key]))

        # 3. aria-label
        if aria_label and len(aria_label) < 40:
            candidates.append('[aria-label="%s"]' % aria_label)

        # 4. tag.class（排除 hash 类名：css-/sc-/chakra-/emotion-）
        if el_class:
            meaningful = [
                c for c in el_class.split()
                if len(c) > 2
                and not c.startswith("_")
                and not c.startswith("css-")
                and not c.startswith("sc-")
                and not c.startswith("chakra")
                and not c.startswith("emotion-")
            ][:2]
            if meaningful:
                candidates.append("%s.%s" % (tag, ".".join(meaningful)))

        # 5. placeholder（输入框专属）
        if placeholder and len(placeholder) < 40:
            candidates.append('%s[placeholder="%s"]' % (tag, placeholder))

        # 6. role
        if aria_role:
            candidates.append('%s[role="%s"]' % (tag, aria_role))

        # 7. tag 兜底
        if not candidates:
            candidates.append(tag)

        return ", ".join(candidates[:3])

    async def _auto_detect_selectors(
        self,
        page: Any,
        url: str,
        yaml_selectors: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        自动发现聊天 DOM 选择器（input / send_button / response）

        编排 Phase A→B→C：
        1. _extract_dom_snapshot — 单次 page.evaluate 批量提取
        2. _score_elements — 多信号加权评分
        3. _generate_selector — 从最高分元素生成 CSS 选择器

        降级链：
        - 自动发现（score >= 0.3 且选择器验证通过）
        - YAML 配置（用户手动配置的选择器）
        - 硬编码默认值

        Args:
            page: Playwright 页面
            url: 目标 URL（用于 AI 应用类型预判）
            yaml_selectors: YAML 配置中的 selectors 字典

        Returns:
            {input, send_button, response, wait_timeout, *_source}
            source 标注来源: "auto" / "yaml" / "default"
        """
        result: Dict[str, Any] = {
            "wait_timeout": yaml_selectors.get("wait_timeout", 15000),
            "response_wait_delay": yaml_selectors.get("response_wait_delay", 5.0),
        }

        defaults = {
            "input": "textarea, input[type='text'], [contenteditable='true']",
            "send_button": "button[type='submit'], .send-btn, [aria-label='Send']",
            "response": ".response, .ai-message, .assistant-message",
        }

        try:
            # ── 获取聊天操作上下文（page 或 iframe frame） ──
            # 某些网站（如京东京言AI）将聊天界面嵌入 iframe，
            # 此时选择器验证需要在 iframe 内执行
            chat_ctx = await self._get_chat_context(page)
            is_iframe_ctx = chat_ctx != page
            if is_iframe_ctx:
                logger.info(
                    "Auto-detect selectors using iframe context: %s",
                    getattr(chat_ctx, 'url', '')[:80],
                )
            result["chat_context"] = "iframe" if is_iframe_ctx else "page"

            # Phase A: 批量提取
            snapshot = await self._extract_dom_snapshot(page)

            # Phase B+C: 评分 + 生成（3 种角色）
            for role in ("input", "send_button", "response"):
                scored = self._score_elements(snapshot, role, url)

                auto_found = False
                if scored and scored[0]["score"] >= 0.3:
                    selector = self._generate_selector(scored[0]["element"])
                    # 验证选择器在上下文中有效（page 或 frame）
                    try:
                        await chat_ctx.wait_for_selector(selector, timeout=2000)
                        result[role] = selector
                        result[role + "_source"] = "auto"
                        result[role + "_score"] = round(scored[0]["score"], 2)
                        result[role + "_signals"] = scored[0]["signals"]
                        logger.info(
                            "Auto-detected %s selector: %s (score=%.2f, signals=%s)",
                            role, selector, scored[0]["score"], scored[0]["signals"],
                        )
                        auto_found = True
                    except Exception:
                        # 如果在 iframe 上下文中验证失败，尝试在 page 上验证
                        if is_iframe_ctx:
                            try:
                                await page.wait_for_selector(selector, timeout=2000)
                                result[role] = selector
                                result[role + "_source"] = "auto"
                                result[role + "_score"] = round(scored[0]["score"], 2)
                                result[role + "_signals"] = scored[0]["signals"]
                                logger.info(
                                    "Auto-detected %s selector (on page): %s (score=%.2f)",
                                    role, selector, scored[0]["score"],
                                )
                                auto_found = True
                            except Exception:
                                logger.debug(
                                    "Auto-detected %s selector validation failed (page+iframe): %s",
                                    role, selector,
                                )
                        else:
                            logger.debug(
                                "Auto-detected %s selector validation failed: %s",
                                role, selector,
                            )

                if not auto_found:
                    # 降级到 YAML
                    yaml_val = yaml_selectors.get(role)
                    if yaml_val:
                        result[role] = yaml_val
                        result[role + "_source"] = "yaml"
                    else:
                        result[role] = defaults[role]
                        result[role + "_source"] = "default"

            print("\n  🔍 聊天 DOM 选择器自动发现")
            print("  ──────────────────────────────────────────")
            for role in ("input", "send_button", "response"):
                src = result.get(role + "_source", "?")
                icon = {"auto": "✅", "yaml": "📋", "default": "⚙️"}.get(src, "?")
                print("  %s %-14s [%s] %s" % (
                    icon, role + ":", src, result[role][:60],
                ))
            print("  ──────────────────────────────────────────\n")

        except Exception as e:
            logger.warning("Auto detect selectors failed: %s, falling back to yaml/defaults", e)
            for role in ("input", "send_button", "response"):
                yaml_val = yaml_selectors.get(role)
                result[role] = yaml_val if yaml_val else defaults[role]
                result[role + "_source"] = "fallback"

        return result

    # ── 聊天页检测与入口点击 ──

    async def _detect_chat_page(self, page: Any, url: str) -> bool:
        """
        自动检测当前页面是否已是聊天界面（v1.3 优化）

        优化逻辑（三层渐进式检测）：
        1. 高置信度 URL 匹配 → 直接返回 True（跳过 DOM 检查）
        2. 普通 URL 模式匹配 → 返回 True
        3. 高信号 DOM 特征快速检查（~18 个高频特征）→ 命中即返回
        4. 全量 DOM 特征检查（220+ 特征）→ 兜底

        优化收益：
        - 高置信度 URL 匹配省去全部 DOM 检查（220+ query_selector 调用）
        - 高信号 DOM 特征优先检查，命中率高（textarea/send-btn 等）
        - 遵循 AI Red Team 最小交互原则：减少 DOM 查询 = 降低 WAF 触发概率

        Args:
            page: Playwright 页面
            url: 当前 URL

        Returns:
            True 如果页面已是聊天界面
        """
        url_lower = url.lower()

        # ── Phase 1: 高置信度 URL 匹配（直接返回，跳过 DOM 检查）──
        for pattern in HIGH_CONFIDENCE_CHAT_URL_PATTERNS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                logger.info("Chat page detected (HIGH confidence) by URL: %s → %s", pattern, url)
                return True

        # ── Phase 2: 普通 URL 模式匹配 ──
        for pattern in CHAT_URL_PATTERNS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                logger.debug("Chat page detected by URL pattern: %s → %s", pattern, url)
                return True

        # ── Phase 3: 高信号 DOM 特征快速检查 ──
        for selector in HIGH_SIGNAL_DOM_FEATURES:
            try:
                element = await page.query_selector(selector)
                if element:
                    logger.debug("Chat page detected by high-signal DOM feature: %s", selector)
                    return True
            except Exception:
                continue

        # ── Phase 4: 全量 DOM 特征兜底检查 ──
        for selector in CHAT_PAGE_DOM_FEATURES:
            try:
                element = await page.query_selector(selector)
                if element:
                    logger.debug("Chat page detected by DOM feature: %s", selector)
                    return True
            except Exception:
                continue

        # ── Phase 5: iframe 检查（如京东京言AI） ──
        # 某些网站（如京东）将聊天界面嵌入 iframe 中
        # 检查可见的 iframe 是否包含聊天 DOM 特征
        if await self._detect_chat_iframe(page):
            logger.info("Chat page detected via iframe (chat-like iframe found)")
            return True

        return False

    async def _detect_chat_iframe(self, page: Any) -> Optional[Any]:
        """
        检测页面中是否存在聊天相关的 iframe

        某些网站（如京东京言AI）将聊天界面嵌入 iframe 中，
        需要检查 iframe 的 URL 和内容来判断是否为聊天界面。

        检测策略：
        1. iframe URL 匹配聊天 URL 模式（如 aishopping.jd.com）
        2. iframe 的 id/name/class 包含聊天关键词
        3. iframe 内容包含聊天 DOM 特征

        Args:
            page: Playwright 页面

        Returns:
            匹配的 Frame 对象，如果未找到则返回 None
        """
        try:
            frames = page.frames
            for frame in frames:
                if frame == page.main_frame:
                    continue

                frame_url = frame.url or ""
                frame_url_lower = frame_url.lower()

                # 策略 1: iframe URL 匹配聊天 URL 模式
                for pattern in HIGH_CONFIDENCE_CHAT_URL_PATTERNS:
                    if re.search(pattern, frame_url_lower, re.IGNORECASE):
                        logger.info(
                            "Chat iframe detected by URL pattern: %s → %s",
                            pattern, frame_url[:80],
                        )
                        return frame

                for pattern in CHAT_URL_PATTERNS:
                    if re.search(pattern, frame_url_lower, re.IGNORECASE):
                        logger.debug(
                            "Chat iframe detected by URL pattern: %s → %s",
                            pattern, frame_url[:80],
                        )
                        return frame

                # 策略 2: iframe 的 id/name/class 包含聊天关键词
                try:
                    iframe_element = await page.query_selector(
                        f'iframe[src*="{frame_url_lower[:50]}"]'
                    )
                    if iframe_element:
                        iframe_id = await iframe_element.get_attribute("id") or ""
                        iframe_class = await iframe_element.get_attribute("class") or ""
                        iframe_name = await iframe_element.get_attribute("name") or ""
                        iframe_attrs = (iframe_id + " " + iframe_class + " " + iframe_name).lower()

                        chat_keywords = [
                            "chat", "jingyan", "assistant", "ai", "bot",
                            "dialog", "message", "support",
                        ]
                        if any(kw in iframe_attrs for kw in chat_keywords):
                            logger.info(
                                "Chat iframe detected by attribute: %s",
                                iframe_attrs[:60],
                            )
                            return frame
                except Exception:
                    pass

                # 策略 3: iframe 内容包含聊天 DOM 特征
                try:
                    for selector in HIGH_SIGNAL_DOM_FEATURES:
                        element = await frame.query_selector(selector)
                        if element:
                            logger.info(
                                "Chat iframe detected by DOM feature: %s (url=%s)",
                                selector, frame_url[:60],
                            )
                            return frame
                except Exception:
                    continue
        except Exception as e:
            logger.debug("Chat iframe detection failed: %s", str(e))

        return None

    async def _get_chat_context(self, page: Any) -> Any:
        """
        获取聊天操作上下文（page 或 frame）

        某些网站（如京东京言AI）将聊天界面嵌入 iframe 中，
        此时需要在 iframe 内执行 DOM 操作（输入/点击/读取响应）。

        检测逻辑：
        1. 先检查页面本身是否有聊天 DOM 特征（非 iframe 场景）
        2. 如果没有，检查是否存在聊天 iframe
        3. 返回 page 或匹配的 frame

        Args:
            page: Playwright 页面

        Returns:
            page 或 frame 对象（都支持 wait_for_selector/click/fill 等）
        """
        # 先检查页面本身是否有高信号 DOM 特征
        try:
            for selector in HIGH_SIGNAL_DOM_FEATURES:
                element = await page.query_selector(selector)
                if element:
                    return page
        except Exception:
            pass

        # 检查是否有聊天 iframe
        frame = await self._detect_chat_iframe(page)
        if frame:
            logger.info("Using iframe context for chat operations: %s", frame.url[:80])
            return frame

        # 默认返回 page
        return page

    # ── WAF 安全延迟辅助 ──
    #
    # 设计原则：所有浏览器操作间隔使用随机延迟，模拟人类行为
    # 固定间隔是 WAF/Bot 检测的首要特征（如 Cloudflare Bot Management、
    # Akamai Bot Manager、AWS WAF rate-based rules）
    # 参考：OWasp WSTG-07-01 (Testing for Bot Protection)

    @staticmethod
    def _waf_safe_delay(key: str) -> float:
        """返回 WAF 安全的随机延迟（秒），key 对应 WAF_SAFE_DELAYS 中的键"""
        lo = WAF_SAFE_DELAYS.get(key + "_min", 1.0)
        hi = WAF_SAFE_DELAYS.get(key + "_max", 3.0)
        return random.uniform(lo, hi) / 1000.0 if key in ("typing", "pre_click", "post_click", "page_load") else random.uniform(lo, hi)

    @staticmethod
    def _waf_safe_delay_ms(key: str) -> int:
        """返回 WAF 安全的随机延迟（毫秒），用于 page.wait_for_timeout()"""
        lo = WAF_SAFE_DELAYS.get(key + "_min", 1000)
        hi = WAF_SAFE_DELAYS.get(key + "_max", 3000)
        return random.randint(int(lo), int(hi))

    @staticmethod
    def _waf_safe_typing_delay() -> int:
        """返回 WAF 安全的打字延迟（ms/字符）"""
        return random.randint(
            WAF_SAFE_DELAYS["typing_min"],
            WAF_SAFE_DELAYS["typing_max"],
        )
