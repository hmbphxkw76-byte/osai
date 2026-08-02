# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""人工辅助认证流程。.

职责:
  1. 导航到登录页
  2. 自动填充可自动化的字段 (用户名/密码, 如已配置)
  3. 提示人工完成需要人工干预的步骤 (验证码/滑块/扫码/OTP)
  4. 轮询 AuthDetector 检测认证完成
  5. 认证完成后导航到目标页面 (聊天/RAG)

设计原则:
  程序做: 导航、填充已知字段、检测完成、跳转
  人工做: 验证码、滑块、扫码、OTP

不尝试:
  - 自动绕过验证码 (不安全且不可靠)
  - 自动完成滑块验证 (反爬检测)
  - 自动获取 OTP (需人工手机)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from core.auth.auth_detector import AuthDetector
# TargetProfile moved to TYPE_CHECKING (depends on PyRIT YamlLoadable)

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)


class HumanAssistedAuth:
    """人工辅助认证流程。.

    程序负责导航和自动填充, 人工负责验证码/滑块/扫码/OTP,
    程序通过 AuthDetector 自动检测认证完成。

    用法:
        auth = HumanAssistedAuth()
        page = await auth.authenticate(page, profile, detector)
    """

    # 人工步骤的中文提示
    HUMAN_STEP_MESSAGES = {
        "captcha": "图形验证码 — 请在浏览器中输入验证码",
        "slider": "滑块验证 — 请在浏览器中完成滑块拖动",
        "qr_scan": "扫码登录 — 请使用手机扫描浏览器中的二维码",
        "otp": "短信/邮件验证码 — 请在浏览器中输入收到的验证码",
    }

    async def authenticate(
        self,
        page: Page,
        profile: TargetProfile,
        detector: AuthDetector,
    ) -> Page:
        """执行完整认证流程。.

        流程:
          1. page.goto(login_url)
          2. auto_fill (如已配置)
          3. 提示人工完成验证码/滑块/扫码/OTP
          4. detector.wait_for_completion(page) — 轮询等待认证完成
          5. page.goto(target_url) — 跳转到聊天页
          6. return page — 已认证的 page

        Args:
            page: Playwright Page 对象。
            profile: 目标配置 Profile。
            detector: 认证完成检测器。

        Returns:
            已认证的 Page 对象。

        Raises:
            TimeoutError: 如果认证在超时时间内未完成。
        """
        auth = profile.auth

        # Step 1: 导航到登录页
        logger.info(f"HumanAssistedAuth: navigating to login URL: {auth.login_url}")
        await page.goto(auth.login_url, wait_until="domcontentloaded")

        # Step 2: 自动填充 (如已配置)
        if auth.auto_fill:
            await self._auto_fill(page, auth.auto_fill)

        # Step 3: 提示人工
        if auth.human_assisted_steps:
            self._print_human_instructions(auth.human_assisted_steps)
        else:
            logger.info("HumanAssistedAuth: no human-assisted steps declared, waiting for auth completion...")

        # Step 4: 等待认证完成
        is_complete = await detector.wait_for_completion(page)
        if not is_complete:
            raise TimeoutError(
                "Authentication did not complete within the timeout period. "
                "Please check if the detection strategies are correctly configured."
            )

        logger.info("HumanAssistedAuth: authentication completed")

        # Step 5: 跳转到目标页面
        logger.info(f"HumanAssistedAuth: navigating to target URL: {auth.target_url}")
        await page.goto(auth.target_url, wait_until="domcontentloaded")

        return page

    async def _auto_fill(self, page: Page, auto_fill_config: dict[str, str]) -> None:
        """自动填充表单字段。.

        遍历 auto_fill_config: {selector: value}
        对每个选择器:
          1. 先检查元素是否存在 (query_selector)
          2. 如存在, 填充值并记录
          3. 如不存在, 静默跳过 (多选择器场景下正常)

        不填充验证码/OTP 字段 (不在 auto_fill_config 中)。

        Args:
            page: Playwright Page 对象。
            auto_fill_config: {CSS 选择器: 值} 字典。
        """
        filled_count = 0
        for selector, value in auto_fill_config.items():
            if not value:
                logger.warning(f"HumanAssistedAuth: skipping auto-fill for '{selector}' — empty value")
                continue
            try:
                # 先检查元素是否存在 (避免 fill 报错)
                element = await page.query_selector(selector)
                if element is None:
                    continue  # 选择器不匹配, 静默跳过

                # 尝试 fill (适用于 input, textarea)
                await page.fill(selector, value)
                filled_count += 1
                logger.info(f"HumanAssistedAuth: auto-filled '{selector}'")
            except Exception:
                # Fallback: click + type (适用于 contenteditable)
                try:
                    await page.click(selector)
                    await page.type(selector, value)
                    filled_count += 1
                    logger.info(f"HumanAssistedAuth: auto-filled '{selector}' (click+type)")
                except Exception as e:
                    logger.warning(f"HumanAssistedAuth: could not auto-fill '{selector}': {e}")

        if filled_count > 0:
            print(f"  ✓ 自动填充了 {filled_count} 个表单字段")
            logger.info(f"HumanAssistedAuth: auto-filled {filled_count} field(s)")
        else:
            logger.info("HumanAssistedAuth: no form fields matched auto_fill selectors")

    def _print_human_instructions(self, human_steps: list[str]) -> None:
        """打印人工操作提示。."""
        print("\n" + "=" * 60)
        print("  人工辅助认证 — 请在浏览器窗口中完成以下操作:")
        print("=" * 60)
        for step in human_steps:
            message = self.HUMAN_STEP_MESSAGES.get(step, f"未知步骤: {step}")
            print(f"  • {message}")
        print()
        print("  程序将自动检测认证完成, 无需手动通知。")
        print("=" * 60 + "\n")

        logger.info(f"HumanAssistedAuth: waiting for human to complete steps: {human_steps}")
