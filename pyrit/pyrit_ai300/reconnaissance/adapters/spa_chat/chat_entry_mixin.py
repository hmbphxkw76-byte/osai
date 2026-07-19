# -*- coding: utf-8 -*-
"""
SPA Chat Recon - 聊天入口点击 Mixin

提供 SPA 聊天侦察的聊天入口点击能力（作为 SPAChatReconAdapter 的 Mixin）：
- 渐进式聊天入口点击（2 阶段：通用核心 → 全量兜底）
- Playwright 错误信息提取
- 交互式聊天入口选择器手工指定
- 多选择器依次尝试 + 超时降级

从 spa_chat_recon_adapter.py 提取（模块化拆分）
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .constants import (
    DEFAULT_CHAT_ENTRY_SELECTORS,
    LOGIN_PAGE_PATTERNS,
    LOGIN_PAGE_DOM_FEATURES,
    OIDC_CALLBACK_WHITELIST,
)

logger = logging.getLogger(__name__)


class ChatEntryMixin:
    """聊天入口点击 Mixin：为 SPAChatReconAdapter 提供聊天入口点击能力。"""


    async def _detect_login_page(self, page: Any) -> bool:
        """
        检测当前页面是否为登录页

        当 Cookie/Header 认证在 HTTP 层有效但应用层无效时，
        SPA 会重定向到登录页。此时继续探测毫无意义，应提前终止。

        检测逻辑：
        1. URL 是否匹配登录页模式（login, signin, passport, oauth 等）
        2. DOM 是否包含登录表单特征（password input, login form 等）

        Args:
            page: Playwright 页面

        Returns:
            True 如果当前页面是登录页
        """
        current_url = page.url.lower()

        # 0. OIDC 回调白名单检查
        # #/signin-oidc、callback?code=... 等是 OIDC 回调中间路由，
        # SPA 正在处理 token，不是登录页。此时误判会中断正常的 SSO 流程。
        for callback_pattern in OIDC_CALLBACK_WHITELIST:
            if callback_pattern in current_url:
                logger.debug(
                    "URL matches OIDC callback whitelist (%s), not a login page: %s",
                    callback_pattern, current_url,
                )
                return False

        # 1. URL 模式匹配
        for pattern in LOGIN_PAGE_PATTERNS:
            if re.search(pattern, current_url, re.IGNORECASE):
                logger.debug("Login page detected by URL pattern: %s → %s", pattern, current_url)
                return True

        # 2. DOM 特征检测
        for selector in LOGIN_PAGE_DOM_FEATURES:
            try:
                element = await page.query_selector(selector)
                if element:
                    is_visible = await element.is_visible()
                    if is_visible:
                        logger.debug("Login page detected by DOM feature: %s", selector)
                        return True
            except Exception:
                continue

        return False

    async def _prompt_user_continue(
        self, prompt: str, default: bool = False
    ) -> bool:
        """
        在终端交互式询问用户是否继续，支持 y/n 输入。

        用于认证部分失效等需要用户即时决策的场景：
          - y / yes / 是: 继续
          - n / no / 否: 中断
          - 直接回车: 按 default 处理

        在 async 上下文中通过 asyncio.to_thread 调用同步 input()，
        避免阻塞事件循环；同时在非交互式环境（无 TTY / EOF / Ctrl+C）
        下安全降级为 default。

        Args:
            prompt: 提示信息（方法会自动追加 [y/N] 或 [Y/n] 提示符）
            default: 默认值（True=默认继续, False=默认中断），按回车时生效

        Returns:
            True 表示用户选择继续，False 表示中断
        """
        hint = "[Y/n]" if default else "[y/N]"
        full_prompt = "%s %s " % (prompt, hint)

        try:
            raw = await asyncio.to_thread(input, full_prompt)
        except (EOFError, KeyboardInterrupt):
            # 非交互式环境（无 TTY）或用户按 Ctrl+C → 按默认值处理
            logger.warning(
                "Non-interactive input or interrupted, using default: %s",
                "continue" if default else "abort",
            )
            return default

        answer = raw.strip().lower()
        if answer in ("y", "yes", "是"):
            return True
        if answer in ("n", "no", "否"):
            return False
        if answer == "":
            return default
        # 无法识别的输入，按默认值处理
        return default

    async def _try_click_chat_entry(
        self,
        page: Any,
        selector: str,
        wait_after_click: int,
        errors: List[str],
        findings: List[Dict[str, Any]],
        url: str = "",
    ) -> bool:
        """
        尝试通过选择器定位并点击聊天入口按钮（v1.3 渐进式匹配优化）

        当使用默认选择器集（DEFAULT_CHAT_ENTRY_SELECTORS，900+ 个）且提供 url 时，
        自动启用渐进式匹配：
          Phase 1: URL 预判 AI 应用类型 → 类型专属选择器（~50 个，5s 超时）
          Phase 2: 通用核心选择器（~200 个，5s 超时）
          Phase 3: 全量选择器兜底（900+ 个，5s 超时）

        当使用用户自定义选择器或未提供 url 时，使用传统单次匹配（15s 超时）。

        AI Red Team 最佳实践：
        - 精准优先：类型专属选择器优先匹配，减少暴力搜索
        - 最小交互：每个阶段独立超时，命中即停，降低 WAF 触发概率
        - 平衡准确性与效率：三阶段确保不遗漏，同时避免无谓等待

        Args:
            page: Playwright 页面
            selector: CSS 选择器（支持逗号分隔多个）
            wait_after_click: 点击后等待毫秒数
            errors: 错误收集列表
            findings: 发现收集列表
            url: 目标 URL（可选，用于 AI 应用类型预判）

        Returns:
            True 如果成功点击入口
        """
        # 统计选择器数量
        selector_count = selector.count(",") + 1
        is_default = selector_count > 20  # 超过 20 个视为默认选择器集

        # ── 渐进式匹配路径（默认选择器 + 有 URL）──
        if is_default and url:
            return await self._try_click_chat_entry_progressive(
                page, selector, url, wait_after_click, errors, findings,
            )

        # ── 传统单次匹配路径（用户自定义选择器或无 URL）──
        selector_desc = "内置默认选择器(%d个)" % selector_count if is_default else "配置选择器: %s" % selector[:60]

        logger.info("Looking for chat entry with %s", selector_desc)
        print("\n  🔍 查找聊天入口 (%s)..." % selector_desc)

        try:
            await page.wait_for_selector(selector, state="visible", timeout=15000)
            await page.click(selector)
            logger.info("Clicked chat entry button")
            print("  ✅ 聊天入口点击成功")
            await page.wait_for_timeout(wait_after_click)
            return True
        except Exception as e:
            # 提取简洁的错误原因，移除 Playwright Call log 噪音
            error_brief = self._extract_playwright_error_brief(str(e))
            logger.warning("Failed to click chat entry (%s): %s", selector_desc, error_brief)

            print("  ❌ 聊天入口未找到 (%s)" % selector_desc)
            print("     原因: %s" % error_brief)
            print("     当前页面: %s" % page.url[:80])

            errors.append("Chat entry not found: %s" % error_brief)
            findings.append({
                "category": "chat_entry_not_found",
                "severity": "medium",
                "description": "聊天入口按钮未找到。可能原因: %s" % error_brief,
                "evidence": "selector: %s | page: %s" % (selector_desc, page.url[:80]),
                "owasp_mapping": "",
                "confidence": 0.6,
            })
            return False

    async def _try_click_chat_entry_progressive(
        self,
        page: Any,
        all_selectors: str,
        url: str,
        wait_after_click: int,
        errors: List[str],
        findings: List[Dict[str, Any]],
    ) -> bool:
        """
        渐进式聊天入口匹配（v1.3 新增）

        三阶段匹配策略：
          Phase 1: 类型专属选择器 — URL 预判 AI 应用类型，优先匹配该类型专属选择器
          Phase 2: 通用核心选择器 — 排除类型专属后的高频通用选择器
          Phase 3: 全量选择器兜底 — 所有 900+ 选择器，确保不遗漏

        每个阶段独立超时，命中即停止后续阶段。

        Args:
            page: Playwright 页面
            all_selectors: 全量选择器字符串
            url: 目标 URL，用于类型预判
            wait_after_click: 点击后等待毫秒数
            errors: 错误收集列表
            findings: 发现收集列表

        Returns:
            True 如果任一阶段成功点击入口
        """
        # 获取分阶段选择器列表
        phases = self._get_priority_selectors(url, all_selectors)

        print("\n  🔍 渐进式查找聊天入口（%d 阶段）..." % len(phases))

        for idx, (phase_selectors, phase_label, phase_timeout) in enumerate(phases, 1):
            phase_count = phase_selectors.count(",") + 1

            print("  ▶ Phase %d/%d: %s (%d个选择器, %dms超时)" % (
                idx, len(phases), phase_label, phase_count, phase_timeout,
            ))
            logger.info(
                "Progressive chat entry Phase %d/%d: %s (%d selectors, %dms timeout)",
                idx, len(phases), phase_label, phase_count, phase_timeout,
            )

            try:
                await page.wait_for_selector(
                    phase_selectors, state="visible", timeout=phase_timeout,
                )
                await page.click(phase_selectors)
                logger.info("Chat entry clicked in Phase %d (%s)", idx, phase_label)
                print("  ✅ 聊天入口点击成功 [Phase %d: %s]" % (idx, phase_label))
                await page.wait_for_timeout(wait_after_click)

                findings.append({
                    "category": "chat_entry_found",
                    "severity": "low",
                    "description": "聊天入口点击成功（渐进式匹配 Phase %d: %s）" % (idx, phase_label),
                    "evidence": "phase: %s | selectors: %d | url: %s" % (
                        phase_label, phase_count, url[:60],
                    ),
                    "owasp_mapping": "",
                    "confidence": 0.9 if idx == 1 else (0.8 if idx == 2 else 0.7),
                })
                return True

            except Exception as e:
                error_brief = self._extract_playwright_error_brief(str(e))
                logger.debug("Phase %d (%s) failed: %s", idx, phase_label, error_brief)
                print("  ⏭ Phase %d 未命中 (%s): %s" % (idx, phase_label, error_brief))
                continue

        # 所有阶段都失败
        print("  ❌ 所有阶段均未找到聊天入口")
        print("     当前页面: %s" % page.url[:80])

        errors.append("Chat entry not found (all %d phases failed)" % len(phases))
        findings.append({
            "category": "chat_entry_not_found",
            "severity": "medium",
            "description": "聊天入口按钮未找到（渐进式匹配 %d 阶段全部失败）" % len(phases),
            "evidence": "phases: %d | url: %s | page: %s" % (
                len(phases), url[:60], page.url[:80],
            ),
            "owasp_mapping": "",
            "confidence": 0.6,
        })
        return False

    @staticmethod
    def _extract_playwright_error_brief(error_str: str) -> str:
        """从 Playwright 错误消息中提取简洁原因，移除 Call log 噪音"""
        # 移除 Call log 部分
        if "Call log:" in error_str:
            error_str = error_str.split("Call log:")[0].strip()
        # 移除 "waiting for locator(...)" 中的超长选择器
        if "waiting for locator(" in error_str:
            # 提取超时信息
            if "Timeout" in error_str:
                timeout_match = error_str.split("Timeout")[1].split("exceeded")[0].strip()
                return "等待超时 %sms，页面未匹配到聊天入口元素" % timeout_match
            return "页面未匹配到聊天入口元素"
        # 处理 "Page.wait_for_selector: Timeout 5000ms exceeded." 格式
        if "wait_for_selector" in error_str and "Timeout" in error_str:
            timeout_match = error_str.split("Timeout")[1].split("exceeded")[0].strip()
            return "等待元素超时 %sms，未找到目标 DOM 元素" % timeout_match
        # 处理 "Page.click: Timeout" 格式
        if "Page.click" in error_str and "Timeout" in error_str:
            timeout_match = error_str.split("Timeout")[1].split("exceeded")[0].strip()
            return "点击超时 %sms，目标元素不可点击或不可见" % timeout_match
        # 处理 "Page.fill" / "Page.type" 错误
        if "Page.fill" in error_str or "Page.type" in error_str:
            return "输入失败，目标输入框不可用或被遮挡"
        # 处理导航错误
        if "net::ERR" in error_str:
            return "网络错误，目标不可达或被拒绝"
        # 移除多余换行和空格
        error_str = error_str.replace("\n", " ").strip()
        # 限制长度
        if len(error_str) > 120:
            error_str = error_str[:120] + "..."
        return error_str

    async def _interactive_chat_entry_retry(
        self,
        page: Any,
        candidates: List[Dict[str, Any]],
        wait_after_click: int,
        errors: List[str],
        findings: List[Dict[str, Any]],
        headless: bool = False,
    ) -> bool:
        """
        交互式手工输入聊天入口选择器并重试点击

        当自动选择器（内置默认 + 配置）均未匹配到聊天入口时，
        引导用户通过浏览器 F12 开发者工具手工获取"智能聊天"等
        入口按钮的 CSS 选择器，输入后重试点击。

        交互方式：
          - 直接输入 CSS 选择器（如 .show-chat-button、#chat-btn、[aria-label='AI助手']）
          - 输入候选编号（如 1、2）直接使用探测到的候选选择器
          - 直接回车 → 跳过手工输入

        支持多轮重试（最多 5 次），直到点击成功或用户放弃。

        Args:
            page: Playwright 页面
            candidates: _score_elements 的评分结果列表，可为 None
            wait_after_click: 点击后等待毫秒数
            errors: 错误收集列表
            findings: 发现收集列表
            headless: 是否为 headless 模式（影响 F12 操作提示）

        Returns:
            True 如果用户输入的选择器成功点击了聊天入口
        """
        print("\n" + "─" * 60)
        print("  🛠️  手工指定聊天入口选择器")
        print("─" * 60)

        if headless:
            print("  ℹ️  当前为 headless 模式，浏览器窗口不可见，无法用 F12 检查元素")
            print("     如需通过 F12 可视化获取选择器，请在配置中将")
            print("     connection.headless 设为 false 后重新运行")
            print("     你仍可直接输入已知的 CSS 选择器：")
        else:
            print("  自动选择器未匹配到聊天入口，可通过 F12 手工获取选择器：")
            print("    1. 在浏览器窗口中按 F12 打开开发者工具")
            print("    2. 点击「元素」(Elements) 面板左上角的 🔲 选择图标")
            print("    3. 在页面上点击「智能聊天」/「AI 助手」等入口按钮")
            print("    4. 在 Elements 面板查看被框选中的元素")
            print("    5. 复制元素的 class / id / aria-label 等属性值")
            print("    6. 按 CSS 选择器格式输入：")
            print("       · class 选择器: .show-chat-button（class 前加英文句点）")
            print("       · id 选择器:    #chat-btn（id 前加井号）")
            print("       · 属性选择器:  [aria-label='AI助手']")

        # 展示探测到的候选聊天入口
        if candidates:
            print("\n  🎯 探测到的聊天入口候选（可直接输入编号或选择器）:")
            for i, c in enumerate(candidates[:10]):
                el = c.get("element", {})
                hint = self._generate_selector(el)
                text = el.get("text", "")
                cls = el.get("class", "")
                score = c.get("score", 0)
                print("     [%d] %s (score=%.2f)" % (i + 1, hint, score))
                if text:
                    print("         文本: %s" % text[:40])
                if cls:
                    print("         class: %s" % cls[:60])
        else:
            print("\n  ℹ️  未探测到候选聊天入口，请直接输入 CSS 选择器")

        print("─" * 60)

        # 多轮重试
        max_retries = 5
        for attempt in range(1, max_retries + 1):
            try:
                raw = await asyncio.to_thread(
                    input, "\n  请输入聊天入口 CSS 选择器（回车跳过）: "
                )
            except (EOFError, KeyboardInterrupt):
                logger.info(
                    "Interactive selector input skipped "
                    "(non-interactive/interrupted)"
                )
                return False

            user_input = raw.strip()
            if not user_input:
                # 空输入 → 放弃
                print("  ⏭️  跳过手工选择器输入")
                return False

            # 支持输入候选编号
            selector = user_input
            if user_input.isdigit():
                idx = int(user_input) - 1
                if 0 <= idx < len(candidates):
                    cand = candidates[idx]
                    el = cand.get("element", {})
                    hint = self._generate_selector(el)
                    if hint:
                        selector = hint.split(",")[0].strip()
                        print(
                            "  ▶️  使用候选 [%s] 的选择器: %s"
                            % (user_input, selector)
                        )
                else:
                    print("  ⚠️  编号超出范围，请重新输入")
                    continue

            logger.info(
                "User-provided chat entry selector (attempt %d): %s",
                attempt,
                selector,
            )
            print("  🔍 尝试选择器: %s" % selector)

            clicked = await self._try_click_chat_entry(
                page, selector, wait_after_click, errors, findings
            )
            if clicked:
                print("  ✅ 手工指定选择器点击成功！")
                findings.append({
                    "category": "chat_entry_manual_selector",
                    "severity": "info",
                    "description": "聊天入口通过用户手工指定的 CSS 选择器成功点击",
                    "evidence": "selector: %s" % selector,
                    "owasp_mapping": "",
                    "confidence": 1.0,
                })
                return True
            else:
                print("  ❌ 选择器 '%s' 未匹配，请重试或回车跳过" % selector)
                if attempt < max_retries:
                    print("     剩余重试次数: %d" % (max_retries - attempt))

        print(
            "  ⏹️  已达到最大重试次数 (%d)，跳过手工选择器输入"
            % max_retries
        )
        return False
