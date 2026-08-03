# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""DOMProbe: DOM 注入面扫描探针。.

职责:
  1. 委托 DOMAnalyzer 扫描页面 DOM
  2. 发现聊天输入框、文件上传、Agent 工具面板、多模态输入等注入面

对齐 DESIGN.md 六类探针架构:
  - 输入: browser_page
  - 产出: injection_surfaces
  - 浏览器需求: True (必须)

> **日期**: 2026-8-3
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.probes.base import ReconProbe
from core.probes.dom_analyzer import DOMAnalyzer

if TYPE_CHECKING:
    from core.session import ReconSession

logger = logging.getLogger(__name__)


class DOMProbe(ReconProbe):
    """DOM 注入面扫描探针。.

    扫描已认证页面的 DOM, 发现所有可被攻击的输入面。

    用法::
        probe = DOMProbe()
        result = await probe.probe(session)
        # result["injection_surfaces"] → 注入面列表
    """

    def __init__(self) -> None:
        self._analyzer = DOMAnalyzer()

    @property
    def name(self) -> str:
        return "DOMProbe"

    @property
    def requires_browser(self) -> bool:
        return True

    async def probe(self, session: ReconSession) -> dict[str, Any]:
        """执行 DOM 探针。.

        Args:
            session: 侦察会话。

        Returns:
            包含 injection_surfaces 的结果字典。

        Raises:
            RuntimeError: 如果 browser_page 不可用。
        """
        if session.browser_page is None:
            raise RuntimeError("DOMProbe requires a browser page, but none is available")

        surfaces = await self._analyzer.scan(session.browser_page)

        logger.info(
            f"DOMProbe: found {len(surfaces)} injection surfaces "
            f"({sum(1 for s in surfaces if s.surface_type.value == 'chat_input')} chat, "
            f"{sum(1 for s in surfaces if s.surface_type.value == 'file_upload_form')} upload)"
        )

        return {
            "injection_surfaces": surfaces,
        }
