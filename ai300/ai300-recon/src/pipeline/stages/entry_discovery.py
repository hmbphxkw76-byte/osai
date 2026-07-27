# -*- coding: utf-8 -*-
"""
阶段 4：聊天入口发现

如果当前页面未直接暴露聊天输入框，则尝试发现 AI 聊天入口并点击。
增强：若当前仍处于登录页，则跳过入口发现，避免误点登录页元素。
"""

from __future__ import annotations

import logging

from src.dom import DOMDetector, discover_chat_entry

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class EntryDiscoveryStage(PipelineStage):
    """聊天入口发现阶段"""

    name = "entry_discovery"
    description = "发现 AI 聊天入口"

    async def run(self, context: PipelineContext) -> StageResult:
        if context.target_type == "api":
            return StageResult(
                success=True,
                skipped=True,
                message="API 目标无需聊天入口发现",
                data={},
            )

        page = context.page
        if not page:
            return StageResult(success=False, message="页面未初始化")

        # 登录页守卫：若仍在登录页，跳过入口发现，避免误点
        spa_config = self._config(context, "spa_config", {})
        detector = DOMDetector(page, spa_config)
        if await detector.is_login_page():
            return StageResult(
                success=True,
                skipped=True,
                message="当前为登录页，跳过聊天入口发现",
                data={},
            )

        # 若页面已有聊天输入框，无需再点入口
        has_input = await self._page_has_chat_input(page)
        if has_input:
            return StageResult(
                success=True,
                skipped=True,
                message="当前页面已存在聊天输入框，无需点击入口",
                data={"has_chat_input": True},
            )

        entry_selector = self._spa_config(context, "entry_selector", "")
        timeout_ms = self._spa_config(context, "entry_discovery_timeout_ms", 5000)
        click_timeout_ms = self._spa_config(context, "click_timeout_ms", 5000)
        entry_click_wait_ms = self._spa_config(context, "entry_click_wait_ms", 3000)

        entry = await discover_chat_entry(
            page,
            yaml_selector=entry_selector,
            timeout_ms=timeout_ms,
            click_verify=True,
            click_timeout_ms=click_timeout_ms,
            post_click_wait_ms=entry_click_wait_ms,
        )
        context.chat_entry = entry

        if entry.get("selector"):
            return StageResult(
                success=True,
                message=f"发现并点击聊天入口: {entry.get('selector')} (来源: {entry.get('source')})",
                data={"entry": entry},
            )

        return StageResult(
            success=True,
            skipped=True,
            message="未发现可点击的聊天入口，页面可能本身就是聊天页",
            data={"entry": entry},
        )

    async def _page_has_chat_input(self, page) -> bool:
        """检查当前页面是否已存在可见的聊天输入框"""
        try:
            return await page.evaluate(
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
        except Exception:
            return False
