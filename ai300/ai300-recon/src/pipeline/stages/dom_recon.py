# -*- coding: utf-8 -*-
"""
阶段 5：DOM 侦察

检测当前页面的登录页、输入框、发送按钮、响应区等 DOM 元素。
如果检测到登录页且启用了人工登录，则进入等待流程。
"""

from __future__ import annotations

import logging

from src.dom import DOMDetector
from src.utils import truncate_error, wait_for_manual_login

from ..base import PipelineStage
from ..context import PipelineContext, StageResult

logger = logging.getLogger(__name__)


class DOMReconStage(PipelineStage):
    """DOM 侦察阶段"""

    name = "dom_recon"
    description = "检测 DOM 元素与登录页"

    async def run(self, context: PipelineContext) -> StageResult:
        if context.target_type == "api":
            return StageResult(
                success=True,
                skipped=True,
                message="API 目标无需 DOM 侦察",
                data={},
            )

        page = context.page
        if not page:
            return StageResult(success=False, message="页面未初始化")

        spa_config = self._config(context, "spa_config", {})
        detector = DOMDetector(page, spa_config)
        context.dom_detector = detector

        # 若前面阶段已点击聊天入口，给面板渲染留足时间
        if context.chat_entry and context.chat_entry.get("selector"):
            await page.wait_for_timeout(self._spa_config(context, "entry_click_wait_ms", 3000))

        detection = await detector.detect_all()
        is_login = await detector.is_login_page()

        # 若 navigation 阶段已成功处理登录，直接继续 DOM 侦察，不再等待
        already_logged_in = context.config.get("_manual_login_wait_result", {}).get("login_resolved", False)
        if already_logged_in:
            context.detection = detection
            has_input = bool(detection.get("input_selector"))
            has_send = bool(detection.get("send_selector"))
            has_response = bool(detection.get("response_selector"))
            return StageResult(
                success=True,
                message=f"DOM 检测完成: 输入框={has_input}, 发送按钮={has_send}, 响应区={has_response} (登录已由 navigation 处理)",
                data={
                    "input_selector": detection.get("input_selector"),
                    "send_selector": detection.get("send_selector"),
                    "response_selector": detection.get("response_selector"),
                    "confidence": detection.get("confidence", 0),
                },
            )

        # 如果当前在登录页且启用了人工登录，等待用户完成
        if is_login and self._spa_config(context, "manual_login", False):
            wait_result = await wait_for_manual_login(
                page,
                detector,
                timeout_ms=self._spa_config(context, "manual_login_timeout_ms", 300000),
                poll_interval_ms=self._spa_config(context, "manual_login_poll_ms", 2000),
                require_enter=self._spa_config(context, "manual_login_require_enter", True),
                target_url=context.target_url,
                captcha_selectors=self._spa_config(context, "captcha_selectors", None),
                config=context.config,
            )
            context.config["_manual_login_wait_result"] = wait_result

            if not wait_result["login_resolved"]:
                return StageResult(
                    success=False,
                    message="登录未完成或超时",
                    data={"wait_result": wait_result},
                )

            # 登录完成后可能已跳转回目标域，重新检测
            await self._ensure_target_page(context)
            spa_config = self._config(context, "spa_config", {})
            detector = DOMDetector(context.page, spa_config)
            context.dom_detector = detector
            detection = await detector.detect_all()
            is_login = await detector.is_login_page()

        context.detection = detection

        # 如果仍在登录页且未启用人工登录，提示需要认证
        if is_login:
            return StageResult(
                success=False,
                message="检测到登录页但未启用人工登录，请使用 --manual-login",
                data={"login_page": True},
            )

        has_input = bool(detection.get("input_selector"))
        has_send = bool(detection.get("send_selector"))
        has_response = bool(detection.get("response_selector"))

        return StageResult(
            success=True,
            message=f"DOM 检测完成: 输入框={has_input}, 发送按钮={has_send}, 响应区={has_response}",
            data={
                "input_selector": detection.get("input_selector"),
                "send_selector": detection.get("send_selector"),
                "response_selector": detection.get("response_selector"),
                "confidence": detection.get("confidence", 0),
            },
        )

    async def _ensure_target_page(self, context: PipelineContext) -> None:
        """确保当前页面回到目标 URL"""
        from src.auth.header_parser import extract_domain_from_url

        page = context.page
        target_domain = extract_domain_from_url(context.target_url)
        current_domain = extract_domain_from_url(page.url)

        if target_domain and current_domain != target_domain:
            try:
                ensure_timeout = self._spa_config(context, "ensure_target_timeout_ms", 60000)
                ensure_wait = self._spa_config(context, "ensure_target_wait_ms", 2000)
                await page.goto(context.target_url, wait_until="networkidle", timeout=ensure_timeout)
                await page.wait_for_timeout(ensure_wait)
                logger.info("Navigated back to target page: %s", page.url)
            except Exception as exc:
                logger.warning("Failed to navigate back to target: %s", truncate_error(str(exc), context.config))
