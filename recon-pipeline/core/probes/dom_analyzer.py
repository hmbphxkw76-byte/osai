# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""DOM 分析器 — 发现页面中的注入面。.

通过 Playwright 的 page.query_selector_all() 扫描 DOM,
发现以下注入面:
  1. 文件上传表单 — 知识库投毒入口 (LLM04/LLM08)
  2. 多模态输入 — 图像/音频上传 (LLM01/LLM05)
  3. Agent 工具面板 — function calling UI (LLM06)
  4. 聊天输入框 — 直接注入面 (LLM01)
  5. 自定义输入 — contenteditable 等

对齐 PyRIT 原生模式:
  - DOMElementStrategy 用 page.query_selector 检测元素
  - AuthProbe 用 page.query_selector 检测登录表单

学术依据:
  - OWASP Top 10 for LLM Applications 2025:
    LLM04 Data Poisoning / LLM08 Vector Weaknesses — 文件上传是投毒入口
  - MITRE ATT&CK T1059.007: JavaScript — DOM 注入面发现

> **日期**: 2026-8-2
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

from core.probes.recon_result import InjectionSurface, InjectionSurfaceType

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)

# ── DOM 注入面扫描规则 ──
# 每条规则: (CSS 选择器列表, 注入面类型, OWASP IDs, 描述)
_SCAN_RULES: list[tuple[list[str], InjectionSurfaceType, list[str], str]] = [
    # 文件上传表单
    (
        [
            'input[type="file"]',
            'form[enctype="multipart/form-data"]',
            '[class*="upload"]',
            '[class*="file-input"]',
            '[data-role="file-upload"]',
        ],
        InjectionSurfaceType.FILE_UPLOAD_FORM,
        ["LLM04", "LLM08"],
        "文件上传表单 — 知识库投毒入口",
    ),
    # 多模态输入 (图像/音频/视频上传)
    (
        [
            'input[accept*="image"]',
            'input[accept*="audio"]',
            'input[accept*="video"]',
            '[class*="image-upload"]',
            '[class*="media-input"]',
            '[class*="voice-input"]',
            'canvas[class*="draw"]',
        ],
        InjectionSurfaceType.MULTIMODAL_INPUT,
        ["LLM01", "LLM05"],
        "多模态输入 — 图像/音频注入面",
    ),
    # Agent 工具面板
    (
        [
            '[class*="tool-panel"]',
            '[class*="function-call"]',
            '[class*="agent-action"]',
            '[data-role="tool"]',
            '[data-role="function"]',
            'button[class*="tool"]',
            'div[class*="copilot"]',
        ],
        InjectionSurfaceType.AGENT_TOOL_PANEL,
        ["LLM01", "LLM06"],
        "Agent 工具面板 — function calling 注入面",
    ),
    # 聊天输入框
    (
        [
            'textarea[class*="chat"]',
            'textarea[class*="message"]',
            'textarea[class*="input"]',
            'textarea[placeholder*="消息"]',
            'textarea[placeholder*="输入"]',
            'textarea[placeholder*="message"]',
            'textarea[placeholder*="chat"]',
            '[contenteditable="true"]',
        ],
        InjectionSurfaceType.CHAT_INPUT,
        ["LLM01"],
        "聊天输入框 — 直接提示注入面",
    ),
]


class DOMAnalyzer:
    """DOM 注入面分析器。.

    扫描页面 DOM, 发现可被攻击的输入面。

    用法::
        analyzer = DOMAnalyzer()
        surfaces = await analyzer.scan(page)
    """

    async def scan(self, page: Page) -> list[InjectionSurface]:
        """扫描页面 DOM, 发现注入面。.

        Args:
            page: Playwright Page 对象。

        Returns:
            发现的 InjectionSurface 列表。
        """
        surfaces: list[InjectionSurface] = []
        seen_selectors: set[str] = set()

        for selectors, surface_type, owasp_ids, description in _SCAN_RULES:
            for selector in selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    if not elements:
                        continue

                    # 去重 (同一选择器只记录一次)
                    if selector in seen_selectors:
                        continue
                    seen_selectors.add(selector)

                    # 提取元素属性
                    element_tag = ""
                    attributes: dict[str, str] = {}
                    if elements:
                        try:
                            el = elements[0]
                            tag_name = await el.evaluate("el => el.tagName.toLowerCase()")
                            element_tag = tag_name

                            # 提取关键属性
                            for attr in ("type", "accept", "multiple", "name", "id", "class"):
                                val = await el.get_attribute(attr)
                                if val:
                                    attributes[attr] = val
                        except Exception:
                            pass

                    surfaces.append(InjectionSurface(
                        selector=selector,
                        surface_type=surface_type,
                        element_tag=element_tag,
                        attributes=attributes,
                        owasp_ids=list(owasp_ids),
                        description=description,
                    ))
                    logger.debug(
                        f"DOMAnalyzer: found {surface_type.value} "
                        f"(selector={selector}, tag={element_tag})"
                    )

                except Exception as e:
                    logger.debug(f"DOMAnalyzer: error scanning selector '{selector}': {e}")

        # 额外检查: 可拖拽上传区域
        await self._check_drop_zone(page, surfaces, seen_selectors)

        logger.info(f"DOMAnalyzer: found {len(surfaces)} injection surfaces")
        return surfaces

    async def _check_drop_zone(
        self,
        page: Page,
        surfaces: list[InjectionSurface],
        seen_selectors: set[str],
    ) -> None:
        """检查拖拽上传区域 (drag-and-drop zone)。."""
        drop_selectors = [
            '[class*="drop-zone"]',
            '[class*="dropzone"]',
            '[class*="drag-drop"]',
            '[data-role="drop-zone"]',
        ]
        for selector in drop_selectors:
            if selector in seen_selectors:
                continue
            with contextlib.suppress(Exception):
                elements = await page.query_selector_all(selector)
                if elements:
                    seen_selectors.add(selector)
                    surfaces.append(InjectionSurface(
                        selector=selector,
                        surface_type=InjectionSurfaceType.FILE_UPLOAD_FORM,
                        element_tag="div",
                        attributes={},
                        owasp_ids=["LLM04", "LLM08"],
                        description="拖拽上传区域 — 知识库投毒入口",
                    ))
                    logger.debug(f"DOMAnalyzer: found drop zone (selector={selector})")

    @staticmethod
    def get_surfaces_by_type(
        surfaces: list[InjectionSurface],
        surface_type: InjectionSurfaceType,
    ) -> list[InjectionSurface]:
        """按类型过滤注入面。."""
        return [s for s in surfaces if s.surface_type == surface_type]

    @staticmethod
    def get_surfaces_by_owasp(
        surfaces: list[InjectionSurface],
        owasp_id: str,
    ) -> list[InjectionSurface]:
        """按 OWASP ID 过滤注入面。."""
        return [s for s in surfaces if owasp_id in s.owasp_ids]