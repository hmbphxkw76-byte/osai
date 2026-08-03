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

G3 修复:
  _auto_fill → auto_fill (公开方法)
  _print_human_instructions → print_human_instructions (公开方法)
  CrossDomainAuthStrategy 不再调用私有方法。

G6 修复:
  未知 human_assisted_steps 直接使用原始字符串作为提示,
  不再显示"未知步骤"。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from web_redteam.auth.auth_detector import AuthDetector

if TYPE_CHECKING:
    from playwright.async_api import Page

    from web_redteam.targets.target_profile import TargetProfile

logger = logging.getLogger(__name__)


class HumanAssistedAuth:
    """人工辅助认证流程。.

    程序负责导航和自动填充, 人工负责验证码/滑块/扫码/OTP,
    程序通过 AuthDetector 自动检测认证完成。

    用法:
        auth = HumanAssistedAuth()
        auth.mfa_timeout = 300  # MFA 等待超时
        page = await auth.authenticate(page, profile, detector)
    """

    # MFA 等待超时 (秒) — 可被外部设置
    mfa_timeout: int = 300

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
          4. detector.attach_to_page(page) — G2: 导航前附加监听器
          5. detector.wait_for_completion(page) — 轮询等待认证完成
          6. page.goto(target_url) — 跳转到聊天页
          7. return page — 已认证的 page

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

        # Step 2: 自动填充 (如已配置) — G3: 使用公开方法
        if auth.auto_fill:
            await self.auto_fill(page, auth.auto_fill)

        # Step 3: 提示人工 — G3: 使用公开方法
        if auth.human_assisted_steps:
            self.print_human_instructions(auth.human_assisted_steps)
        else:
            logger.info("HumanAssistedAuth: no human-assisted steps declared, waiting for auth completion...")

        # Step 4: 网络监听器已在策略层 (SameDomain/CrossDomain) 导航前附加,
        # 此处不再重复调用 attach_to_page, 避免双重注册 response handler

        # Step 5: 等待认证完成
        is_complete = await detector.wait_for_completion(page)
        if not is_complete:
            # A4: MFA 超时降级 — 不直接抛出异常, 先尝试降级方案
            degraded = await self._handle_mfa_timeout(page, profile, detector)
            if not degraded:
                raise TimeoutError(
                    "Authentication did not complete within the timeout period. "
                    "Please check if the detection strategies are correctly configured."
                )
            logger.warning("HumanAssistedAuth: MFA timeout, used degraded auth path")

        logger.info("HumanAssistedAuth: authentication completed")

        # Step 6: 跳转到目标页面
        logger.info(f"HumanAssistedAuth: navigating to target URL: {auth.target_url}")
        await page.goto(auth.target_url, wait_until="domcontentloaded")

        return page

    async def _handle_mfa_timeout(
        self,
        page: Page,
        profile: TargetProfile,
        detector: AuthDetector,
    ) -> bool:
        """A4: MFA 超时降级处理。.

        当 MFA 等待超时后, 不直接抛出异常, 而是尝试以下降级方案:
          1. 检查是否已经意外登录 (URL 已跳转)
          2. 检查是否存在 session cookie (可能已通过其他方式认证)
          3. 尝试直接导航到目标页面, 检查是否被重定向回登录页

        Args:
            page: Playwright Page。
            profile: 目标配置。
            detector: 认证检测器。

        Returns:
            True 如果降级方案成功, False 如果需要抛出异常。
        """
        try:
            # 方案 1: 检查当前 URL 是否已不在登录页 (可能已意外完成)
            current_url = page.url
            auth = profile.auth
            if auth.login_url and auth.login_url not in current_url:
                logger.info(f"HumanAssistedAuth: URL already changed to {current_url}, auth may have completed")
                return True

            # 方案 2: 检查 cookie
            cookies = await page.context.cookies()
            session_cookies = [c for c in cookies if c.get("name", "").lower() in (
                "session", "token", "auth", "jwt", "sid", "phpsessid",
            )]
            if session_cookies:
                logger.info(
                    f"HumanAssistedAuth: found {len(session_cookies)} session cookies, attempting degraded path"
                )
                # 方案 3: 尝试直接导航到目标页面
                await page.goto(auth.target_url, wait_until="domcontentloaded")
                # 检查是否被重定向回登录页
                if auth.login_url and auth.login_url not in page.url:
                    logger.info("HumanAssistedAuth: degraded auth path successful (cookie-based)")
                    return True
        except Exception as e:
            logger.debug(f"HumanAssistedAuth: MFA timeout degradation failed: {e}")

        return False

    async def auto_fill(self, page: Page, auto_fill_config: dict[str, str]) -> None:
        """自动填充表单字段 (G3: 公开方法, 原 _auto_fill).

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
        total = len(auto_fill_config)
        for idx, (selector, value) in enumerate(auto_fill_config.items(), 1):
            if not value:
                logger.warning(f"HumanAssistedAuth: skipping auto-fill field {idx}/{total} — empty value")
                continue
            try:
                # 先检查元素是否存在 (避免 fill 报错)
                element = await page.query_selector(selector)
                if element is None:
                    continue  # 选择器不匹配, 静默跳过

                # 尝试 fill (适用于 input, textarea)
                await page.fill(selector, value)
                filled_count += 1
                logger.info(f"HumanAssistedAuth: auto-filled field {idx}/{total}")
            except Exception:
                # Fallback: click + type (适用于 contenteditable)
                try:
                    await page.click(selector)
                    await page.type(selector, value)
                    filled_count += 1
                    logger.info(f"HumanAssistedAuth: auto-filled field {idx}/{total} (click+type)")
                except Exception as e:
                    # G14: 日志中不出现 selector 名称, 避免泄露表单结构
                    logger.warning(f"HumanAssistedAuth: could not auto-fill field {idx}/{total}: {e}")

        if filled_count > 0:
            logger.info(f"HumanAssistedAuth: auto-filled {filled_count} field(s)")
        else:
            logger.info("HumanAssistedAuth: no form fields matched auto_fill selectors")

    def print_human_instructions(self, human_steps: list[str]) -> None:
        """打印人工操作提示 (G3: 公开方法, 原 _print_human_instructions).

        G6 修复:
          未知步骤直接使用原始字符串作为提示,
          不再显示"未知步骤: xxx"。

        R4 修复:
          使用 logger 输出, 替代 print, 保持与全框架日志一致。
        """
        logger.info("=" * 60)
        logger.info("  人工辅助认证 — 请在浏览器窗口中完成以下操作:")
        logger.info("=" * 60)
        for step in human_steps:
            # G6: 未知步骤直接使用原始字符串, 不显示"未知步骤"
            message = self.HUMAN_STEP_MESSAGES.get(step, step)
            logger.info(f"  • {message}")
        logger.info("  程序将自动检测认证完成, 无需手动通知。")
        logger.info("=" * 60)

        logger.info(f"HumanAssistedAuth: waiting for human to complete steps: {human_steps}")
