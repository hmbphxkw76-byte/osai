# -*- coding: utf-8 -*-
"""
Web Chat Interaction
====================

参数化 Web 聊天交互：
  - 自动检测选择器
  - 发送消息（三级降级）
  - 获取响应文本
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class WebChatInteraction:
    """参数化 Web 聊天交互函数"""

    def __init__(
        self,
        page: Any,
        input_selector: str = "",
        send_selector: str = "",
        response_selector: str = "",
        config: Optional[Dict[str, Any]] = None,
    ):
        self.page = page
        self.input_selector = input_selector
        self.send_selector = send_selector
        self.response_selector = response_selector
        self.config = config or {}
        self.post_send_wait = self.config.get("post_send_wait_ms", 3000) / 1000.0

    async def detect_selectors(self) -> Dict[str, Any]:
        """自动检测并更新选择器"""
        from src.dom import DOMDetector

        detector = DOMDetector(self.page, self.config)
        result = await detector.detect_all()
        self.input_selector = result["input_selector"] or self.input_selector
        self.send_selector = result["send_selector"] or self.send_selector
        self.response_selector = result["response_selector"] or self.response_selector
        return result

    async def send(
        self,
        message: str,
        wait_for_response: bool = True,
    ) -> Dict[str, Any]:
        """
        发送消息并返回响应。

        支持三级发送降级：
          1. Enter 键
          2. 发送按钮点击
          3. 父容器点击
        """
        if not self.input_selector:
            await self.detect_selectors()

        if not self.input_selector:
            return {"success": False, "error": "No input selector available"}

        from src.dom import DOMDetector

        detector = DOMDetector(self.page, self.config)
        return await detector.type_and_send(
            text=message,
            input_selector=self.input_selector,
            send_selector=self.send_selector,
        )

    async def get_last_response(self, timeout_ms: int = 5000) -> str:
        """获取响应区最新文本"""
        if not self.response_selector:
            return ""
        try:
            await self.page.wait_for_selector(
                self.response_selector,
                state="visible",
                timeout=timeout_ms,
            )
            text = await self.page.text_content(self.response_selector)
            return (text or "").strip()
        except Exception as e:
            logger.warning("Failed to get response: %s", str(e)[:120])
            return ""

    async def clear_input(self) -> bool:
        """清空输入框"""
        if not self.input_selector:
            return False
        try:
            await self.page.fill(self.input_selector, "")
            return True
        except Exception as e:
            logger.warning("Failed to clear input: %s", str(e)[:120])
            return False
