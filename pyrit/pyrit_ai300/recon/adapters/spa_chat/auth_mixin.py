# -*- coding: utf-8 -*-
"""
SPA Chat Recon - 认证 Mixin

提供 SPA 聊天侦察的认证能力（作为 SPAChatReconAdapter 的 Mixin）：
- SSO / OIDC 单点登录（表单填写 + 验证码等待 + OIDC 回调落地检测）
- 账号密码登录（credentials 模式）
- HTTP 预检认证（preflight，浏览器启动前验证凭据）
- 凭据缓存复用（credentials/ 目录自动匹配）
- 凭据导出（Cookie / JWT / API Key 自动导出）
- 手动登录 / OAuth / 内联 Cookie / 内联 Headers
- 验证码检测 / 人工干预等待 / 登录页检测

从 spa_chat_recon_adapter.py 提取（模块化拆分）
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .constants import (
    CAPTCHA_SELECTORS,
    LOGIN_PAGE_PATTERNS,
    LOGIN_PAGE_DOM_FEATURES,
    OIDC_CALLBACK_WHITELIST,
    OIDC_CALLBACK_PATTERNS,
)

logger = logging.getLogger(__name__)


class AuthMixin:
    """认证 Mixin：为 SPAChatReconAdapter 提供认证相关方法。"""

    # ── 增强版登录表单选择器（问题②修复） ──
    #
    # 扩充覆盖京东、淘宝、拼多等国内主流平台的非标准命名模式，
    # 同时覆盖 iframe 内嵌登录表单、动态渲染表单等场景。

    # 用户名输入框选择器（v2 扩充：覆盖京东/淘宝等非标准命名）
    ENHANCED_USERNAME_SELECTORS = [
        # 标准命名
        "input[name='username']", "input[name='account']",
        "input[name='userName']", "#username", "#account",
        # placeholder 匹配
        "input[type='text'][placeholder*='账号']",
        "input[type='text'][placeholder*='用户']",
        "input[type='text'][placeholder*='学号']",
        "input[type='text'][placeholder*='手机']",
        "input[type='text'][placeholder*='邮箱']",
        "input[type='text'][placeholder*='手机号']",
        "input[type='text'][placeholder*='邮箱/手机']",
        # 京东/电商专属
        "input[name='loginname']", "#loginname",
        "input[name='mobile']", "#mobile",
        "input[class*='login-name']", "input[class*='account-input']",
        # 通配
        "input[type='text']",
        "input[type='tel']",  # 手机号输入可能用 tel 类型
    ]

    # 密码输入框选择器（v2 扩充）
    ENHANCED_PASSWORD_SELECTORS = [
        "input[name='password']", "input[name='passwd']",
        "#password", "input[type='password']",
        # 非标准命名
        "input[name='pwd']", "#pwd",
        "input[class*='password']", "input[class*='pwd']",
    ]

    # 提交按钮选择器（v2 扩充：覆盖更多中文按钮文本）
    ENHANCED_SUBMIT_SELECTORS = [
        "button[type='submit']", "input[type='submit']",
        "button.login-btn", ".submit-btn",
        # 中文文本匹配
        "button:has-text('登录')", "button:has-text('Login')",
        "button:has-text('登 录')", "button:has-text('登入')",
        "a:has-text('登录')", "a:has-text('Login')",
        "button:has-text('Sign')", "button:has-text('确定')",
        # 京东/电商专属
        ".btn-login", ".J-login-btn",
        "button[class*='login']", "a[class*='login']",
        "div[class*='login-btn']", "span[class*='login-btn']",
        # 带图标的登录按钮
        "[role='button']:has-text('登录')",
    ]

    # 账号登录标签页选择器（部分平台默认显示扫码登录，需切换到账号登录）
    ACCOUNT_LOGIN_TAB_SELECTORS = [
        "a:has-text('账号登录')",
        "li:has-text('账号登录')",
        "span:has-text('账号登录')",
        "div:has-text('账号登录')",
        "a:has-text('密码登录')",
        "li:has-text('密码登录')",
        "span:has-text('密码登录')",
        "a:has-text('账户登录')",
        "li:has-text('账户登录')",
        "div:has-text('账户登录')",
        "a:has-text('普通登录')",
        "li:has-text('普通登录')",
        "a:has-text('账号密码登录')",
        "[data-type='account']",
        "[data-login-type='account']",
        "[data-tab='account']",
        ".tab-account",
        ".tab-password",
    ]

    async def _switch_to_account_login_tab(self, page: Any) -> bool:
        """
        切换到账号密码登录标签页

        部分平台（如京东、淘宝）默认显示扫码登录，
        需要先点击"账号登录"标签页才能看到用户名/密码输入框。

        Args:
            page: Playwright 页面

        Returns:
            True 如果成功切换到账号登录标签页
        """
        for sel in self.ACCOUNT_LOGIN_TAB_SELECTORS:
            try:
                el = await page.query_selector(sel)
                if el:
                    await el.click()
                    logger.info("Switched to account login tab via: %s", sel)
                    print("  ✅ 切换到账号登录标签页 (%s)" % sel)
                    await page.wait_for_timeout(1000)  # 等待表单渲染
                    return True
            except Exception:
                continue
        return False

    async def _find_element_in_iframes(
        self,
        page: Any,
        selectors: list,
        timeout: int = 3000,
    ) -> Tuple[Optional[Any], Optional[Any]]:
        """
        在主页面和所有 iframe 中查找元素

        部分平台（如京东、银行系统）将登录表单嵌套在 iframe 中，
        Playwright 默认只在主页面查找，需要遍历 iframe。

        Args:
            page: Playwright 页面
            selectors: 选择器列表（依次尝试）
            timeout: 每个选择器的等待超时（毫秒）

        Returns:
            (element, frame) 元组，如果找到则返回元素和所在的 frame（None 表示主页面）
        """
        # 1. 先在主页面查找
        for sel in selectors:
            try:
                el = await page.wait_for_selector(sel, state="visible", timeout=timeout)
                if el:
                    return el, None  # None 表示主页面
            except Exception:
                continue

        # 2. 遍历 iframe 查找
        try:
            frames = page.frames
            for frame in frames:
                if frame == page.main_frame:
                    continue  # 跳过主框架（已在步骤 1 搜索）
                for sel in selectors:
                    try:
                        el = await frame.wait_for_selector(sel, state="visible", timeout=timeout)
                        if el:
                            logger.info("Element found in iframe: %s (frame URL: %s)", sel, frame.url[:80])
                            return el, frame
                    except Exception:
                        continue
        except Exception as e:
            logger.debug("iframe search failed: %s", str(e))

        return None, None

    async def _login_with_credentials(
        self,
        page: Any,
        login_config: dict,
        errors: List[str],
    ) -> None:
        """
        账号密码登录

        自动填写账号密码并提交登录表单。
        如果检测到验证码（滑窗拼图/图形验证码），会提示用户手动完成。

        支持场景：
          - 直接在登录页填写账号密码
          - 登录后需要验证码（自动检测并等待用户完成）
          - 登录成功后跳转到目标页（自动等待 URL 变化）
        """
        username = login_config.get("username", "")
        password = login_config.get("password", "")
        login_selectors = login_config.get("selectors", {})

        # 登录表单选择器（与 _login_with_sso / auto_spa_recon.py 一致的选择器列表）
        default_username_selectors = self.ENHANCED_USERNAME_SELECTORS
        default_password_selectors = self.ENHANCED_PASSWORD_SELECTORS
        default_submit_selectors = self.ENHANCED_SUBMIT_SELECTORS

        cfg_username = login_selectors.get("username_input")
        cfg_password = login_selectors.get("password_input")
        cfg_submit = login_selectors.get("submit_button")
        username_selectors = (
            [s.strip() for s in cfg_username.split(",")] if cfg_username
            else default_username_selectors
        )
        password_selectors = (
            [s.strip() for s in cfg_password.split(",")] if cfg_password
            else default_password_selectors
        )
        submit_selectors = (
            [s.strip() for s in cfg_submit.split(",")] if cfg_submit
            else default_submit_selectors
        )

        if not username or not password:
            errors.append("Credentials login mode requires 'username' and 'password' in config")
            return

        try:
            # ── 先尝试切换到账号登录标签页（问题②修复） ──
            # 京东/淘宝等平台默认扫码登录，需先切换到账号密码登录
            await self._switch_to_account_login_tab(page)

            logger.info("Filling login form (selector list + type delay)...")

            # 填用户名（依次尝试选择器列表 + iframe 降级）
            username_ok = False
            for sel in username_selectors:
                try:
                    el = await page.wait_for_selector(sel, state="visible", timeout=3000)
                    if el:
                        await el.click()
                        await el.fill("")
                        await page.type(sel, username, delay=30)
                        logger.info("Username filled via: %s", sel)
                        print("  ✅ 用户名已填入 (%s)" % sel)
                        username_ok = True
                        break
                except Exception:
                    continue
            # 主页面未找到 → 尝试 iframe
            if not username_ok:
                el, frame = await self._find_element_in_iframes(page, username_selectors, timeout=2000)
                if el:
                    target = frame if frame else page
                    await el.click()
                    await el.fill("")
                    await target.type(username_selectors[0], username, delay=30)
                    logger.info("Username filled via iframe: %s", username_selectors[0])
                    print("  ✅ 用户名已填入 (iframe)")
                    username_ok = True
            if not username_ok:
                print("  ⚠️ 未找到用户名输入框，请手动填写")

            # 填密码
            password_ok = False
            for sel in password_selectors:
                try:
                    el = await page.wait_for_selector(sel, state="visible", timeout=3000)
                    if el:
                        await el.click()
                        await el.fill("")
                        await page.type(sel, password, delay=30)
                        logger.info("Password filled via: %s", sel)
                        print("  ✅ 密码已填入 (%s)" % sel)
                        password_ok = True
                        break
                except Exception:
                    continue
            # 主页面未找到 → 尝试 iframe
            if not password_ok:
                el, frame = await self._find_element_in_iframes(page, password_selectors, timeout=2000)
                if el:
                    target = frame if frame else page
                    await el.click()
                    await el.fill("")
                    await target.type(password_selectors[0], password, delay=30)
                    logger.info("Password filled via iframe: %s", password_selectors[0])
                    print("  ✅ 密码已填入 (iframe)")
                    password_ok = True
            if not password_ok:
                print("  ⚠️ 未找到密码输入框，请手动填写")

            # 点击登录
            await page.wait_for_timeout(1000)
            submit_ok = False
            for sel in submit_selectors:
                try:
                    el = await page.wait_for_selector(sel, state="visible", timeout=2000)
                    if el:
                        await el.click()
                        logger.info("Submit button clicked via: %s", sel)
                        print("  ✅ 已点击登录按钮 (%s)" % sel)
                        submit_ok = True
                        break
                except Exception:
                    continue
            # 主页面未找到 → 尝试 iframe
            if not submit_ok:
                el, frame = await self._find_element_in_iframes(page, submit_selectors, timeout=2000)
                if el:
                    await el.click()
                    logger.info("Submit button clicked via iframe")
                    print("  ✅ 已点击登录按钮 (iframe)")
                    submit_ok = True
            if not submit_ok:
                print("  ⚠️ 未找到登录按钮，请手动点击登录")

            logger.info("Login form submitted")

            # 等待页面响应
            await page.wait_for_timeout(2000)

            # 检测是否出现验证码（轮询检测，避免因弹出延迟漏检）
            # 根因分析 v1.6.1：与 SSO 模式保持一致，轮询 3 次共 6 秒
            captcha_found = False
            for attempt in range(3):
                captcha_found = await self._detect_captcha(page)
                if captcha_found:
                    break
                await page.wait_for_timeout(2000)
                logger.debug("Captcha detection attempt %d/3: not found, retrying...", attempt + 1)

            if captcha_found:
                logger.info("Captcha detected after login submit, waiting for human")
                await self._wait_for_human(
                    "检测到验证码（滑窗拼图/图形验证码/短信验证码），请完成验证",
                    timeout=login_config.get("captcha_timeout", 120),
                )
            else:
                # 无验证码，等待登录完成
                await page.wait_for_timeout(3000)
                logger.info("Login completed (no captcha)")

            # 如果表单未完整填写，记录 error
            if not (username_ok and password_ok and submit_ok):
                errors.append(
                    "Credentials login form not fully filled "
                    f"(username={username_ok}, password={password_ok}, submit={submit_ok})"
                )

        except Exception as e:
            logger.error("Credentials login failed: %s", str(e))
            errors.append(f"Login failed: {str(e)}")

    async def _login_with_sso(
        self,
        page: Any,
        login_config: dict,
        target_url: str,
        errors: List[str],
    ) -> None:
        """
        SSO/OIDC 单点登录模式

        适用于跨域 SSO 认证流程：
          1. 访问目标应用 → 自动重定向到 SSO 认证中心
          2. 在认证中心填写账号密码
          3. 完成验证码（滑窗拼图/图形验证码等）
          4. OIDC 回调跳转回目标应用

        典型场景：
          - student.syxy.ouchn.cn → passport.syxy.ouchn.cn/Account/Login → 滑窗验证 → 回调
- www.example.com → www.example.com → www.example.com/Account/Login → 滑窗验证 → 回调
          - 企业应用 → 钉钉/企业微信 SSO → 验证码 → 回调
          - SaaS 应用 → Okta/Auth0 SSO → MFA → 回调

        配置示例：
            login:
              mode: "sso"
              url: ""                           # 留空则从 connection.url 触发重定向
              username: "student001"
              password: "password123"
sso_login_url: "https://www.example.com/Account/Login"
    sso_domain: "www.example.com"
              target_domain: "www.example.com"  # 目标应用域名（回调后检测）
              selectors:
                username_input: "#username, input[name='username']"
                password_input: "#password, input[name='password']"
                submit_button: "#login-btn, button[type='submit']"
              captcha_timeout: 120             # 验证码完成等待超时（秒）
        """
        from urllib.parse import urlparse

        username = login_config.get("username", "")
        password = login_config.get("password", "")
        login_selectors = login_config.get("selectors", {})
        captcha_timeout = login_config.get("captcha_timeout", 120)

        # 调试日志：显示实际接收到的凭据值（脱敏）
        logger.debug("SSO credentials: username=%s, password=%s",
                     username[:3] + "***" if username else "(empty)",
                     "***" if password else "(empty)")

        # SSO 配置
        sso_login_url = login_config.get("sso_login_url", "")
        sso_domain = login_config.get("sso_domain", "")
        target_domain = login_config.get("target_domain", "")

        # 从 target_url 提取目标域名
        if not target_domain and target_url:
            target_domain = urlparse(target_url).netloc

        # 登录表单选择器（支持配置覆盖，默认使用增强版选择器列表）
        # 使用列表依次尝试，比逗号分隔的单选择器更稳健（避免 fill 选中错误元素）
        default_username_selectors = self.ENHANCED_USERNAME_SELECTORS
        default_password_selectors = self.ENHANCED_PASSWORD_SELECTORS
        default_submit_selectors = self.ENHANCED_SUBMIT_SELECTORS

        # 如果配置了单个选择器字符串，拆成列表；否则用默认列表
        cfg_username = login_selectors.get("username_input")
        cfg_password = login_selectors.get("password_input")
        cfg_submit = login_selectors.get("submit_button")
        username_selectors = (
            [s.strip() for s in cfg_username.split(",")] if cfg_username
            else default_username_selectors
        )
        password_selectors = (
            [s.strip() for s in cfg_password.split(",")] if cfg_password
            else default_password_selectors
        )
        submit_selectors = (
            [s.strip() for s in cfg_submit.split(",")] if cfg_submit
            else default_submit_selectors
        )

        logger.info(
            "SSO login mode: target_domain=%s, sso_domain=%s, sso_login_url=%s",
            target_domain, sso_domain, sso_login_url or "(auto-redirect)",
        )

        # 步骤 1：导航到 SSO 登录页（复用当前页面，避免重复导航）
        #
        # 根因分析 v1.6.1：多次 page.goto(target_url) 会导致 SPA 多次重定向到 SSO 登录页，
        # SSO 系统每次重定向都会重置验证码状态，导致用户需要多次滑窗。
        # 修复策略：检测当前 URL 是否已在 SSO 登录页，如果是则不重新导航。
        try:
            current_url = page.url or ""
        except Exception:
            current_url = ""
        url_lower = current_url.lower()

        # 判断当前是否已在 SSO 登录页
        already_on_sso_login = False
        if sso_domain and sso_domain.lower() in url_lower:
            already_on_sso_login = True
        elif any(ind in url_lower for ind in (
            "/account/login", "/login", "/signin", "/connect/authorize"
        )):
            already_on_sso_login = True

        if already_on_sso_login:
            logger.info("Already on SSO login page, skipping navigation: %s", current_url)
            print("  ✅ 当前已在 SSO 登录页，跳过导航（避免重复触发验证码）")
        elif sso_login_url:
            logger.info("Navigating to SSO login URL: %s", sso_login_url)
            await page.goto(sso_login_url, wait_until="networkidle")
        else:
            # 已经在 _execute_recon 中导航到 login_url 或 target_url
            # 轮询等待重定向到 SSO 登录页（最多 30s）
            logger.info("Waiting for SSO redirect from target page...")
            print("  ⏳ 等待 SSO 重定向到登录页（最多 30s）...")
            _login_form_detected = False
            for _i in range(30):
                await page.wait_for_timeout(1000)
                _cur = page.url.lower()
                # URL 级检测
                if any(k in _cur for k in ("passport", "login", "signin", "/account/login", "/auth")):
                    if not any(p in _cur for p in OIDC_CALLBACK_PATTERNS):
                        logger.info("Login page detected via URL: %s", page.url)
                        print("  ✅ 检测到登录页: %s" % page.url[:80])
                        _login_form_detected = True
                        break
                # DOM 级降级检测（URL 不含关键词但有密码输入框）
                try:
                    _pw = await page.query_selector("input[type='password']")
                    if _pw:
                        logger.info("Login form detected via DOM (password input)")
                        print("  ✅ DOM 检测到密码输入框，识别为登录页")
                        _login_form_detected = True
                        break
                except Exception:
                    pass
                if _i % 5 == 0 and _i > 0:
                    print("  ⏳ 等待中 (%ds)... 当前: %s" % (_i, page.url[:60]))
            if not _login_form_detected:
                # ── 问题①修复：游客可访问平台检测 ──
                # 某些平台（如京东）允许游客访问，不会重定向到登录页。
                # 此时不应误判为"已登录"，而应检测是否是游客访问模式。
                logger.info("No login form detected after 30s, checking guest access...")
                print("  ℹ️  30s 未检测到登录页，检查是否为游客可访问平台...")

                # 检测当前页面是否有 AI/聊天元素（游客可访问的 AI 应用）
                _has_chat_elements = False
                try:
                    # 检测常见的聊天输入框/按钮
                    _chat_selectors = [
                        "textarea", "input[type='text'][placeholder*='问']",
                        "input[type='text'][placeholder*='输入']",
                        "input[type='text'][placeholder*='chat']",
                        "[contenteditable='true']",
                        ".chat-fab", ".ai-assistant", ".chat-entry",
                        "button:has-text('聊天')", "button:has-text('对话')",
                        "button:has-text('问')", "button:has-text('AI')",
                    ]
                    for _sel in _chat_selectors:
                        try:
                            _el = await page.query_selector(_sel)
                            if _el:
                                _has_chat_elements = True
                                logger.info("Guest access detected: found chat element '%s'", _sel)
                                break
                        except Exception:
                            continue
                except Exception:
                    pass

                if _has_chat_elements:
                    logger.info("Guest access mode detected (AI elements found without login)")
                    print("  ✅ 检测到游客可访问的 AI 聊天元素，跳过登录流程")
                    print("     当前页面可能为游客模式，将直接进行侦察")
                    # 不等待登录，直接返回让侦察流程继续
                    return
                else:
                    # ── 游客可访问但无聊天元素：需手动导航到登录页/聊天页 ──
                    # 典型场景：京东首页允许游客访问，但 AI 聊天需要登录后导航
                    logger.info("No login form and no chat elements — manual navigation needed")
                    print("  ℹ️  未检测到登录页或聊天元素，可能需要手动导航")
                    print("     请在浏览器中手动操作：")
                    print("       1. 导航到登录页并完成登录")
                    print("       2. 或直接导航到 AI 聊天页面")
                    print("     完成后按 Enter，代码将接管后续流程")
                    await self._wait_for_human(
                        "未检测到登录页或聊天入口，请手动导航到目标页面后按 Enter",
                        timeout=login_config.get("manual_timeout", 180),
                    )

                    # ── 关键修复：手动操作后检查用户是否已完成登录 ──
                    # 用户可能已经手动完成了登录（输入账号密码+验证码），
                    # 此时不应再执行自动填表（Step 2），应直接进入后续流程。
                    try:
                        _post_manual_url = (page.url or "").lower()
                    except Exception:
                        _post_manual_url = ""

                    # 检查是否已落地到目标域名（用户已完成登录+回调）
                    if target_domain and target_domain in _post_manual_url:
                        logger.info("After manual intervention, landed on target domain: %s", _post_manual_url[:80])
                        print("  ✅ 手动操作完成，已落地到目标域名")
                        return  # 跳过自动填表，直接进入后续侦察流程

                    # 检查是否仍在登录页（用户可能只是导航到了登录页，尚未完成登录）
                    _on_login_page = any(ind in _post_manual_url for ind in (
                        "passport", "login", "signin", "/account/login", "/auth",
                    )) and not any(p in _post_manual_url for p in OIDC_CALLBACK_PATTERNS)

                    if not _on_login_page:
                        # 不在登录页，可能已经登录并导航到了其他页面
                        logger.info("After manual intervention, not on login page: %s", _post_manual_url[:80])
                        print("  ✅ 手动操作完成，当前页面: %s" % _post_manual_url[:80])
                        return  # 跳过自动填表

                    # 仍在登录页 → 继续执行 Step 2 自动填表
                    logger.info("Still on login page after manual intervention, proceeding with auto form fill")
                    print("  ▶️  仍在登录页，尝试自动填写表单...")

        # 步骤 2：填写账号密码（如果配置了）
        # 使用选择器列表依次尝试 + page.type(delay=30) 逐字输入
        # （与 auto_spa_recon.py 一致，确保触发 Vue/React 前端校验）
        #
        # v2 增强（问题②修复）：
        #   1. 先尝试切换到账号登录标签页（京东/淘宝默认扫码登录）
        #   2. 使用增强版选择器列表（覆盖非标准命名）
        #   3. 支持 iframe 内嵌表单（通过 _find_element_in_iframes 降级）
        if username and password:
            # ── 先尝试切换到账号登录标签页 ──
            await self._switch_to_account_login_tab(page)

            form_filled = False
            try:
                logger.info("Filling SSO login form (selector list + type delay)...")

                # 填用户名（依次尝试选择器列表，含 iframe 降级）
                username_ok = False
                for sel in username_selectors:
                    try:
                        el = await page.wait_for_selector(sel, state="visible", timeout=3000)
                        if el:
                            await el.click()
                            await el.fill("")
                            await page.type(sel, username, delay=30)
                            logger.info("Username filled via: %s", sel)
                            print("  ✅ 用户名已填入 (%s)" % sel)
                            username_ok = True
                            break
                    except Exception:
                        continue

                # 主页面未找到 → 尝试 iframe 查找
                if not username_ok:
                    el, frame = await self._find_element_in_iframes(page, username_selectors, timeout=2000)
                    if el:
                        target = frame if frame else page
                        await el.click()
                        await el.fill("")
                        await target.type(username_selectors[0], username, delay=30)
                        logger.info("Username filled via iframe: %s", username_selectors[0])
                        print("  ✅ 用户名已填入 (iframe: %s)" % username_selectors[0])
                        username_ok = True

                if not username_ok:
                    print("  ⚠️ 未找到用户名输入框，请手动填写")

                # 填密码
                password_ok = False
                for sel in password_selectors:
                    try:
                        el = await page.wait_for_selector(sel, state="visible", timeout=3000)
                        if el:
                            await el.click()
                            await el.fill("")
                            await page.type(sel, password, delay=30)
                            logger.info("Password filled via: %s", sel)
                            print("  ✅ 密码已填入 (%s)" % sel)
                            password_ok = True
                            break
                    except Exception:
                        continue

                # 主页面未找到 → 尝试 iframe 查找
                if not password_ok:
                    el, frame = await self._find_element_in_iframes(page, password_selectors, timeout=2000)
                    if el:
                        target = frame if frame else page
                        await el.click()
                        await el.fill("")
                        await target.type(password_selectors[0], password, delay=30)
                        logger.info("Password filled via iframe: %s", password_selectors[0])
                        print("  ✅ 密码已填入 (iframe: %s)" % password_selectors[0])
                        password_ok = True

                if not password_ok:
                    print("  ⚠️ 未找到密码输入框，请手动填写")

                # 点击登录
                await page.wait_for_timeout(1000)
                submit_ok = False
                for sel in submit_selectors:
                    try:
                        el = await page.wait_for_selector(sel, state="visible", timeout=2000)
                        if el:
                            await el.click()
                            logger.info("Submit button clicked via: %s", sel)
                            print("  ✅ 已点击登录按钮 (%s)" % sel)
                            submit_ok = True
                            break
                    except Exception:
                        continue

                # 主页面未找到 → 尝试 iframe 查找
                if not submit_ok:
                    el, frame = await self._find_element_in_iframes(page, submit_selectors, timeout=2000)
                    if el:
                        await el.click()
                        logger.info("Submit button clicked via iframe: %s", submit_selectors[0])
                        print("  ✅ 已点击登录按钮 (iframe: %s)" % submit_selectors[0])
                        submit_ok = True

                if not submit_ok:
                    print("  ⚠️ 未找到登录按钮，请手动点击登录")

                form_filled = username_ok and password_ok and submit_ok

                # 等待页面响应
                await page.wait_for_timeout(2000)

            except Exception as e:
                logger.warning("SSO form fill failed: %s", str(e))
                # 表单填写失败，回退到手动模式
                logger.info("Falling back to manual login for SSO")
                await self._wait_for_human(
                    "SSO 表单自动填写失败，请在浏览器中手动完成登录",
                    timeout=login_config.get("manual_timeout", 180),
                )
                if target_domain:
                    await self._wait_for_landing(page, target_domain)
                return

            # 如果表单未完整填写，等待人工完成
            if not form_filled:
                print("  ⚠️ 表单未完整填写，请在浏览器中手动完成登录")
                await self._wait_for_human(
                    "表单自动填写不完整，请在浏览器中手动完成登录",
                    timeout=login_config.get("manual_timeout", 180),
                )
                if target_domain:
                    await self._wait_for_landing(page, target_domain)
                return
        else:
            # 未配置账号密码，使用手动登录
            logger.info("No credentials configured for SSO, using manual mode")
            await self._wait_for_human(
                "未配置 SSO 账号密码，请在浏览器中手动完成登录",
                timeout=login_config.get("manual_timeout", 180),
            )
            if target_domain:
                await self._wait_for_landing(page, target_domain)
            return

        # 步骤 3：检测验证码（轮询检测，避免因弹出延迟漏检）
        #
        # 根因分析 v1.6.1：某些 SSO 系统验证码弹出需要 3-5 秒，原代码只等 2 秒就检测，
        # 可能漏检。改为轮询检测（最多 3 次 × 2 秒 = 6 秒），增加检测成功率。
        captcha_found = False
        for attempt in range(3):
            captcha_found = await self._detect_captcha(page)
            if captcha_found:
                break
            # 检测是否已经落地（可能无验证码直接登录成功）
            if target_domain and target_domain in page.url:
                # 已落地，无需继续检测验证码
                logger.info("Already landed on target domain, no captcha needed")
                break
            await page.wait_for_timeout(2000)
            logger.debug("Captcha detection attempt %d/3: not found, retrying...", attempt + 1)

        if captcha_found:
            logger.info("Captcha detected during SSO login, waiting for human")
            await self._wait_for_human(
                "检测到验证码（滑窗拼图/图形验证码/短信验证码），请完成验证",
                timeout=captcha_timeout,
            )
        else:
            # 无验证码，等待跳转
            await page.wait_for_timeout(2000)

        # 步骤 4：等待 OIDC 回调跳转回目标域名（代码接管）
        if target_domain:
            landed = await self._wait_for_landing(
                page, target_domain, timeout=captcha_timeout
            )
            if landed:
                logger.info("SSO callback completed, now on: %s", page.url)
                print("  ✅ SSO 登录成功，已落地到目标域名: %s" % page.url[:80])
            else:
                logger.warning("SSO redirect may not have completed, current URL: %s", page.url)
                print("  ⚠️ SSO 登录后未检测到落地，当前 URL: %s" % page.url[:80])
                # 记录 error，让 _execute_recon 知道认证失败（关键修复）
                errors.append(
                    f"SSO login did not land on target domain '{target_domain}', "
                    f"current URL: {page.url[:100]}"
                )
                await page.wait_for_timeout(3000)
        else:
            # 没有配置 target_domain，从 target_url 提取后重试
            if target_url:
                target_domain = urlparse(target_url).netloc
            if target_domain:
                landed = await self._wait_for_landing(
                    page, target_domain, timeout=captcha_timeout
                )
                if not landed:
                    errors.append(
                        f"SSO login did not land on target domain '{target_domain}', "
                        f"current URL: {page.url[:100]}"
                    )
            else:
                await self._wait_for_human(
                    "未配置 target_domain，请确认已进入目标页面",
                    timeout=login_config.get("manual_timeout", 180),
                )

    # ── 认证预检（Pre-flight Auth Check） ──
    #
    # 设计原则：在浏览器启动前，先用 HTTP 请求验证凭据有效性。
    # 读取 credentials 文件 → 携带认证头访问目标 URL → 显示 HTTP 状态和认证判定。
    # 如果认证有效，后续直接注入凭据到浏览器，跳过登录流程。

    async def _preflight_auth_check(
        self,
        playwright: Any,
        config: dict,
        target_url: str,
        findings: List[Dict[str, Any]],
        errors: List[str],
    ) -> Dict[str, Any]:
        """
        侦查前认证预检

        在浏览器启动前执行：
        1. 读取 credentials 文件（优先 config.auth.header_file，其次 credentials/{域名}.txt）
        2. 解析认证头（Cookie / Bearer / Basic）
        3. 用 HTTP 请求携带认证头访问目标 URL
        4. 分析 HTTP 响应状态码，判定认证是否有效
        5. 输出详细的认证状态报告

        判定逻辑：
        - HTTP 200: 认证有效
        - HTTP 301/302/303/307/308: 检查 Location 头，重定向到登录页则认证失效
        - HTTP 401/403: 认证无效或过期
        - 其他: 未知状态

        Args:
            playwright: Playwright 实例（用于创建 APIRequestContext）
            config: 配置字典（可能包含 auth.header_file）
            target_url: 目标 URL
            findings: 发现收集列表
            errors: 错误收集列表

        Returns:
            预检结果字典，包含：
            - performed: 是否执行了预检
            - credential_file: 凭据文件路径
            - auth_type: 认证类型
            - http_status: HTTP 状态码
            - auth_valid: 认证是否有效
            - redirect_url: 重定向 URL（如有）
            - auth_profile: AuthProfile 实例（认证有效时返回，供后续注入）
        """
        from ....attack.auth import (
            parse_header_file,
            normalize_domain,
            find_credential_file,
        )

        print("\n" + "═" * 60)
        print("  🔍 认证预检（Pre-flight Auth Check）")
        print("═" * 60)

        target_domain = normalize_domain(target_url)

        # 1. 查找凭据文件
        cred_file = None

        # 优先从配置中的 auth.header_file 读取（如 spa_target.yaml 的 auth 配置）
        auth_config = config.get("auth", {})
        header_file = auth_config.get("header_file", "")
        if header_file and os.path.exists(header_file):
            cred_file = header_file
            print("  📄 凭据来源: 配置 auth.header_file")
        else:
            # 从 credentials/ 目录按域名查找
            cred_file = find_credential_file(target_domain, self.CREDENTIALS_DIR)
            if cred_file:
                print("  📄 凭据来源: credentials/ 目录自动匹配")

        if not cred_file:
            print("  ⚠️  未找到凭据文件")
            print(f"     查找位置 1: config/targets/credentials/{target_domain}.txt")
            if header_file:
                print(f"     查找位置 2: {header_file}")
            print("  ℹ️  跳过认证预检，将在浏览器阶段处理认证")
            print("═" * 60 + "\n")
            return {
                "performed": False,
                "reason": "no_credential_file",
                "target_url": target_url,
                "target_domain": target_domain,
            }

        print(f"  📄 凭据文件: {cred_file}")

        # 2. 解析凭据文件
        try:
            auth_profile = parse_header_file(cred_file)
        except Exception as e:
            print(f"  ❌ 凭据解析失败: {e}")
            print("═" * 60 + "\n")
            return {
                "performed": False,
                "reason": f"parse_error: {e}",
                "credential_file": cred_file,
            }

        if not auth_profile.has_auth():
            print("  ⚠️  凭据文件中无认证信息（无 Cookie / Authorization 头）")
            print("═" * 60 + "\n")
            return {
                "performed": False,
                "reason": "no_auth_in_file",
                "credential_file": cred_file,
            }

        print(f"  🔑 认证类型: {auth_profile.auth_type}")
        print(f"  🌐 目标域名: {auth_profile.get_domain() or target_domain}")

        # 检查 JWT 过期
        if auth_profile.is_token_expired():
            print("  ⏰ JWT Token 已过期，需要重新认证")
            print("═" * 60 + "\n")
            findings.append({
                "category": "preflight_token_expired",
                "severity": "high",
                "description": f"Pre-flight check: JWT token expired for {target_domain}",
                "evidence": f"Credential file: {cred_file}",
                "owasp_mapping": "LLM02",
                "confidence": 0.9,
            })
            return {
                "performed": True,
                "credential_file": cred_file,
                "auth_type": auth_profile.auth_type,
                "auth_valid": False,
                "reason": "token_expired",
                "target_url": target_url,
            }

        # 3. 构建请求头
        request_headers: Dict[str, str] = {}
        # 添加 Authorization 头
        if "Authorization" in auth_profile.headers:
            request_headers["Authorization"] = auth_profile.headers["Authorization"]
        # 添加 Cookie
        if auth_profile.raw_cookies:
            request_headers["Cookie"] = auth_profile.raw_cookies
        # 添加 User-Agent（部分服务器会根据 UA 返回不同响应）
        if "User-Agent" in auth_profile.headers:
            request_headers["User-Agent"] = auth_profile.headers["User-Agent"]

        # 4. 发送 HTTP 请求验证认证
        print(f"\n  📤 发送预检请求:")
        print(f"     URL: {target_url}")
        print(f"     方法: GET")
        print(f"     请求头:")
        for k, v in request_headers.items():
            display_v = v[:80] + "..." if len(v) > 80 else v
            print(f"       {k}: {display_v}")

        http_status = None
        resp_headers: Dict[str, str] = {}
        body_preview = ""
        redirect_url = ""
        auth_valid = False

        try:
            # 使用 Playwright 的 APIRequestContext 发送 HTTP 请求
            request_context = await playwright.request.new_context(
                ignore_https_errors=True,
                extra_http_headers=request_headers if request_headers else None,
            )

            response = await request_context.get(target_url, max_redirects=0)
            http_status = response.status
            resp_headers = dict(response.headers)

            # 尝试获取部分 body
            try:
                body = await response.text()
                body_preview = body[:500] if body else ""
            except Exception:
                body_preview = ""

            await request_context.dispose()

        except Exception as e:
            # Playwright request API 不可用时的降级方案：使用 urllib
            logger.warning("Playwright request API failed (%s), falling back to urllib", str(e))
            try:
                body_preview, http_status, resp_headers = await self._urllib_http_request(
                    target_url, request_headers
                )
            except Exception as e2:
                print(f"\n  ❌ 预检请求失败: {e2}")
                errors.append(f"Preflight auth check failed: {e2}")
                print("═" * 60 + "\n")
                return {
                    "performed": False,
                    "reason": f"request_error: {e2}",
                    "credential_file": cred_file,
                    "auth_type": auth_profile.auth_type,
                    "target_url": target_url,
                }

        # 5. 分析响应
        redirect_url = resp_headers.get("location", "")

        print(f"\n  📥 响应结果:")
        print(f"     状态码: {http_status}")
        print(f"     响应头:")
        for k in ("content-type", "location", "set-cookie", "server"):
            v = resp_headers.get(k, "")
            if v:
                display_v = v[:80] + "..." if len(v) > 80 else v
                print(f"       {k}: {display_v}")

        if http_status == 200:
            auth_valid = True
            print("\n  ✅ 认证预检通过（HTTP 200 — 认证有效）")
        elif http_status in (301, 302, 303, 307, 308):
            # 重定向：检查是否重定向到登录页
            if redirect_url:
                redirect_lower = redirect_url.lower()
                login_indicators = [
                    "/login", "/signin", "/account/login", "/auth",
                    "#/login", "#/signin", "#login",
                    "passport.", "/connect/authorize",
                ]
                if any(ind in redirect_lower for ind in login_indicators):
                    auth_valid = False
                    print(f"\n  ❌ 认证失败（重定向到登录页）")
                    print(f"     Location: {redirect_url}")
                else:
                    # 重定向到非登录页，可能是正常跳转
                    auth_valid = True
                    print(f"\n  ✅ 认证预检通过（重定向到非登录页）")
                    print(f"     Location: {redirect_url}")
            else:
                print(f"\n  ⚠️  收到重定向({http_status})但无 Location 头")
        elif http_status in (401, 403):
            auth_valid = False
            print(f"\n  ❌ 认证失败（HTTP {http_status} — 认证无效或被拒绝）")
        elif http_status == 404:
            print(f"\n  ⚠️  目标页面不存在（HTTP 404）")
            print("     认证状态无法判定，将继续浏览器侦察")
        else:
            print(f"\n  ⚠️  未预期的状态码: {http_status}")
            print("     认证状态无法判定，将继续浏览器侦察")

        # 6. 记录 finding
        if auth_valid:
            findings.append({
                "category": "preflight_auth_valid",
                "severity": "low",
                "description": f"Pre-flight auth check passed: credentials are valid for {target_domain}",
                "evidence": f"HTTP {http_status}, auth_type={auth_profile.auth_type}, file={cred_file}",
                "owasp_mapping": "",
                "confidence": 0.9,
            })
        elif http_status is not None:
            findings.append({
                "category": "preflight_auth_invalid",
                "severity": "high",
                "description": f"Pre-flight auth check failed: credentials invalid or expired for {target_domain}",
                "evidence": f"HTTP {http_status}, redirect={redirect_url or 'N/A'}",
                "owasp_mapping": "LLM02",
                "confidence": 0.85,
            })

        result = {
            "performed": True,
            "credential_file": cred_file,
            "auth_type": auth_profile.auth_type,
            "target_url": target_url,
            "target_domain": target_domain,
            "http_status": http_status,
            "auth_valid": auth_valid,
            "redirect_url": redirect_url,
            "response_summary": {
                "status": http_status,
                "content_type": resp_headers.get("content-type", ""),
                "body_length": len(body_preview),
                "body_preview": body_preview[:200],
            },
        }

        # 认证有效时返回 auth_profile 供后续注入
        if auth_valid:
            result["auth_profile"] = auth_profile

        print("\n" + "─" * 60)
        print(f"  📋 预检结论: {'✅ 认证有效' if auth_valid else '❌ 认证无效或无法判定'}")
        print("─" * 60 + "\n")

        return result

    async def _urllib_http_request(
        self,
        url: str,
        headers: Dict[str, str],
    ) -> Tuple[str, int, Dict[str, str]]:
        """
        使用 urllib 发送 HTTP 请求（Playwright request API 不可用时的降级方案）

        Args:
            url: 目标 URL
            headers: 请求头字典

        Returns:
            (body_preview, status_code, response_headers)
        """
        import ssl
        import urllib.request
        import urllib.error

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as resp:
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read(500).decode("utf-8", errors="replace")
                return body, status, resp_headers
        except urllib.error.HTTPError as e:
            status = e.code
            resp_headers = {k.lower(): v for k, v in dict(e.headers).items()}
            try:
                body = e.read(500).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return body, status, resp_headers

    # ── 凭据预检与自动复用 ──
    #
    # 设计原则：优先复用已有凭据，失败再走完整认证流程，避免重复登录。
    # 域名匹配：credentials/{domain}.txt，域名 A 只读取 A 的凭据文件。

    CREDENTIALS_DIR = "config/targets/credentials"

    async def _try_cached_credentials(
        self,
        page: Any,
        context: Any,
        target_url: str,
        errors: List[str],
    ) -> bool:
        """
        尝试从 credentials/ 目录复用已有凭据

        流程：
        1. 从 target_url 提取域名
        2. 在 credentials/ 目录中精准匹配凭据文件
        3. 解析凭据，检查 JWT 是否过期
        4. 注入到浏览器上下文
        5. 导航到目标页面，验证认证是否有效

        Args:
            page: Playwright 页面
            context: Playwright 浏览器上下文
            target_url: 目标 URL
            errors: 错误收集列表

        Returns:
            True 如果凭据有效并已成功注入；False 如果无凭据或凭据无效
        """
        from ....attack.auth import (
            parse_header_file,
            inject_auth,
            normalize_domain,
            find_credential_file,
        )

        target_domain = normalize_domain(target_url)
        if not target_domain:
            return False

        cred_file = find_credential_file(target_domain, self.CREDENTIALS_DIR)
        if not cred_file:
            logger.info("No cached credential found for domain: %s", target_domain)
            return False

        logger.info("Found cached credential: %s", cred_file)

        try:
            auth_profile = parse_header_file(cred_file)
        except Exception as e:
            logger.warning("Failed to parse credential file %s: %s", cred_file, str(e))
            return False

        if not auth_profile.has_auth():
            logger.warning("Credential file has no auth info: %s", cred_file)
            return False

        # 检查 JWT 是否过期
        if auth_profile.is_token_expired():
            logger.warning("Cached JWT token expired for domain: %s, will re-authenticate", target_domain)
            return False

        # 域名二次校验：确保凭据文件内的 Host 与目标域名一致
        cred_domain = normalize_domain(auth_profile.get_domain())
        if cred_domain and cred_domain != target_domain:
            logger.warning(
                "Credential domain mismatch: file has '%s', target is '%s' — refusing to use",
                cred_domain, target_domain,
            )
            return False

        # 注入凭据
        try:
            await inject_auth(context, page, auth_profile)
            logger.info("Cached credentials injected: %s", auth_profile.summary())
        except Exception as e:
            logger.warning("Credential injection failed: %s", str(e))
            return False

        # 导航到目标页面并验证认证有效性
        try:
            await page.goto(target_url, wait_until="networkidle", timeout=30000)
        except Exception as e:
            logger.warning("Navigation failed after credential injection: %s", str(e))
            return False

        if await self._verify_auth_valid(page, target_domain):
            logger.info("Cached credentials are VALID for domain: %s", target_domain)
            return True
        else:
            logger.warning("Cached credentials are INVALID (redirected to login), will re-authenticate")
            return False

    async def _verify_auth_valid(
        self,
        page: Any,
        target_domain: str,
    ) -> bool:
        """
        验证当前页面认证状态是否有效

        判定逻辑：如果页面 URL 仍在目标域名且未被重定向到登录页，则认证有效。

        Args:
            page: Playwright 页面
            target_domain: 目标域名

        Returns:
            True 如果认证有效；False 如果被重定向到登录页
        """
        await page.wait_for_timeout(2000)
        current_url = page.url.lower()

        # 如果不在目标域名，认证失败
        if target_domain.lower() not in current_url:
            return False

        # 检测是否被重定向到登录页
        login_indicators = [
            "/login", "/signin", "/account/login", "/auth",
            "#/login", "#/signin", "#login",
            "passport.", "/connect/authorize",
        ]
        for indicator in login_indicators:
            if indicator in current_url:
                logger.debug("Login page indicator detected: %s in %s", indicator, current_url)
                return False

        # 检测页面是否有登录表单（辅助判断）
        try:
            for selector in ("input[type='password']", "#password", "input[name='password']"):
                el = await page.query_selector(selector)
                if el and await el.is_visible():
                    logger.debug("Login form detected on page, auth may be invalid")
                    return False
        except Exception:
            pass

        return True

    async def _export_credentials(
        self,
        page: Any,
        context: Any,
        target_url: str,
    ) -> Optional[str]:
        """
        认证成功后自动导出凭据到 credentials/ 目录

        从浏览器上下文提取 Cookie + 页面 URL，格式化为 F12 风格的
        Request Headers 文本，保存为 credentials/{domain}.txt。

        Args:
            page: Playwright 页面（已认证状态）
            context: Playwright 浏览器上下文
            target_url: 目标 URL

        Returns:
            保存的凭据文件路径，或 None（失败时）
        """
        from ....attack.auth import normalize_domain

        target_domain = normalize_domain(target_url)
        if not target_domain:
            return None

        try:
            # 从浏览器上下文提取 Cookie
            cookies = await context.cookies()
            if not cookies:
                logger.debug("No cookies to export")
                return None

            # 过滤出目标域名的 Cookie
            domain_cookies = [
                c for c in cookies
                if target_domain in c.get("domain", "") or
                c.get("domain", "").lstrip(".") in target_domain
            ]
            if not domain_cookies:
                logger.debug("No cookies matching domain: %s", target_domain)
                return None

            # 构建 Cookie 字符串
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in domain_cookies)

            # 尝试提取 Authorization 头（从页面请求头中）
            # 注意：Playwright 无法直接读取已设置的 extra_http_headers，
            # 这里主要导出 Cookie，JWT 等需要用户手动从 F12 复制

            # 构建 F12 风格的 Request Headers 文本
            current_path = urlparse(page.url).path or "/"
            header_text = (
                f"GET {current_path} HTTP/1.1\n"
                f"Host: {target_domain}\n"
                f"Cookie: {cookie_str}\n"
            )

            # 确保目录存在
            os.makedirs(self.CREDENTIALS_DIR, exist_ok=True)

            # 保存文件（域名命名）
            cred_path = os.path.join(self.CREDENTIALS_DIR, f"{target_domain}.txt")
            with open(cred_path, "w", encoding="utf-8") as f:
                f.write(header_text)

            logger.info("Credentials exported to: %s (%d cookies)", cred_path, len(domain_cookies))
            print(f"\n  💾 凭据已自动导出到: {cred_path}")
            print(f"     下次侦察将自动复用此凭据，无需重新登录。")
            print(f"     如需更新，删除此文件或从 F12 重新复制 Headers。\n")

            return cred_path

        except Exception as e:
            logger.debug("Credential export failed: %s", str(e))
            return None

    async def _login_with_header_file(
        self,
        page: Any,
        context: Any,
        login_config: dict,
        errors: List[str],
    ) -> None:
        """使用 header_file 注入认证（复用 AuthProfile）"""
        header_file = login_config.get("header_file", "")
        if not header_file or not os.path.exists(header_file):
            errors.append(f"Header file not found: {header_file}")
            return

        try:
            from ....attack.auth import parse_header_file, inject_auth
            auth_profile = parse_header_file(header_file)
            await inject_auth(context, page, auth_profile)
            logger.info("Auth injected from header file: %s", auth_profile.summary())

            # 重新加载页面以使认证生效
            await page.reload(wait_until="networkidle")
            await page.wait_for_timeout(2000)

        except Exception as e:
            logger.error("Header file auth failed: %s", str(e))
            errors.append(f"Header file auth failed: {str(e)}")

    async def _login_manual(
        self,
        page: Any,
        login_config: dict,
        target_url: str,
        errors: List[str],
    ) -> None:
        """
        手动登录模式

        浏览器以非 headless 模式启动，用户手动完成登录后，
        在终端按 Enter 继续侦察流程。

        按 Enter 后，自动验证登录状态：
        1. 检查是否已落地到目标域名（非登录页）
        2. 检查 Cookie 数量变化（登录前后对比）
        3. 检查常见登录成功 DOM 指示器（用户名/头像/退出按钮等）
        4. 如果仍在登录页，警告用户但不阻塞（可能用户已完成部分操作）
        """
        timeout = login_config.get("manual_timeout", 120)
        logger.info("Manual login mode: waiting up to %ds for user to login", timeout)

        # ── 记录登录前的 Cookie 数量（用于后续对比） ──
        from ....attack.auth import normalize_domain
        target_domain = normalize_domain(target_url) if target_url else ""
        cookie_count_before = 0
        try:
            context = page.context
            cookie_count_before = len(await context.cookies())
        except Exception:
            pass

        await self._wait_for_human(
            "请在浏览器中完成登录，进入智能助手聊天界面",
            timeout=timeout,
        )

        # ── 登录成功验证（按 Enter 后） ──
        print("\n  🔍 验证登录状态...")

        # 等待页面稳定
        try:
            await page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass
        await page.wait_for_timeout(2000)

        current_url = page.url or ""
        url_lower = current_url.lower()

        # 检查 1: 是否仍在登录页
        login_page_indicators = [
            "/login", "/signin", "/account/login", "/auth",
            "#/login", "#/signin", "#login",
            "passport.", "/connect/authorize",
        ]
        is_on_login_page = any(ind in url_lower for ind in login_page_indicators)

        # 检查 2: Cookie 数量变化
        cookie_count_after = 0
        try:
            cookie_count_after = len(await page.context.cookies())
        except Exception:
            pass
        cookie_increased = cookie_count_after > cookie_count_before

        # 检查 3: 登录成功 DOM 指示器
        # 常见的登录后元素：用户名/昵称、头像、退出/登出按钮、个人中心链接等
        login_success_selectors = [
            # 通用登录成功指示器
            "[class*='logout']", "[class*='sign-out']", "[class*='login-out']",
            "[class*='user-name']", "[class*='username']", "[class*='nickname']",
            "[class*='user-info']", "[class*='user-avatar']", "[class*='avatar']",
            "[class*='account-info']", "[class*='profile']",
            # 京东特有
            "[class*='ttbar-login'] .link-login", ".nickname",
            "[class*='cw-icon']", "[class*='user-name-text']",
            # 通用退出/账户链接
            "a[href*='logout']", "a[href*='signout']",
            "a[href*='/account']", "a[href*='/profile']",
            "a[href*='/user/center']",
        ]
        login_success_dom_found = False
        for sel in login_success_selectors:
            try:
                el = await page.query_selector(sel)
                if el and await el.is_visible():
                    login_success_dom_found = True
                    logger.info("Login success indicator found: %s", sel)
                    break
            except Exception:
                continue

        # 检查 4: 是否在目标域名
        on_target_domain = bool(target_domain) and target_domain.lower() in url_lower

        # ── 综合判断登录状态 ──
        if is_on_login_page and not login_success_dom_found:
            # 仍在登录页且未检测到登录成功指示器
            print("  ⚠️  当前仍在登录页，登录可能未完成")
            print("     当前 URL: %s" % current_url[:80])
            print("     Cookie 变化: %d → %d" % (cookie_count_before, cookie_count_after))
            logger.warning(
                "Manual login: still on login page after Enter (url=%s, "
                "cookies=%d→%d)",
                current_url[:80], cookie_count_before, cookie_count_after,
            )
            # 不添加到 errors（用户可能有意按 Enter，不阻塞流程）
            # 但记录到 findings 供后续参考
            print("  ℹ️  将以当前状态继续侦察（可能捕获部分 API 流量）")
        elif login_success_dom_found or (cookie_increased and on_target_domain):
            # 检测到登录成功指示器 或 Cookie 增加且在目标域名
            print("  ✅ 登录成功")
            print("     当前 URL: %s" % current_url[:80])
            print("     Cookie 变化: %d → %d" % (cookie_count_before, cookie_count_after))
            if login_success_dom_found:
                print("     登录指示器: 已检测到")
            logger.info(
                "Manual login verified: url=%s, cookies=%d→%d, dom_indicator=%s",
                current_url[:80], cookie_count_before, cookie_count_after,
                login_success_dom_found,
            )
        elif cookie_increased:
            # Cookie 增加但不在目标域名（可能在中间页/SSO 回调）
            print("  ✅ 登录可能成功（Cookie 已增加）")
            print("     当前 URL: %s" % current_url[:80])
            print("     Cookie 变化: %d → %d" % (cookie_count_before, cookie_count_after))
            logger.info(
                "Manual login: cookies increased (%d→%d), url=%s",
                cookie_count_before, cookie_count_after, current_url[:80],
            )
            # 尝试等待落地到目标域名
            if target_domain and target_domain.lower() not in url_lower:
                print("  ⏳ 等待落地到目标域名 (%s)..." % target_domain)
                landed = await self._wait_for_landing(page, target_domain, timeout=30)
                if landed:
                    print("  ✅ 已落地到目标域名: %s" % page.url[:80])
                else:
                    print("  ⚠️  未落地到目标域名，以当前状态继续")
        else:
            # 无法确定登录状态
            print("  ❓ 无法确定登录状态")
            print("     当前 URL: %s" % current_url[:80])
            print("     Cookie 变化: %d → %d" % (cookie_count_before, cookie_count_after))
            logger.warning(
                "Manual login: status unclear (url=%s, cookies=%d→%d)",
                current_url[:80], cookie_count_before, cookie_count_after,
            )
            print("  ℹ️  将以当前状态继续侦察")

    # ── 人工干预与落地等待辅助方法 ──
    #
    # 设计原则：人工做人工的事（验证码/短信/OAuth 授权），代码做代码的事（跳转/导航）。
    # 任意需要人工完成的步骤 → _wait_for_human 提示并等 Enter；
    # 人工完成后 → _wait_for_landing 由代码接管，自动等待落地到目标域名。

    async def _detect_captcha(self, page: Any) -> bool:
        """
        检测页面是否出现验证码元素

        检测类型：
        - 滑窗拼图验证（slider, puzzle, drag）
        - 图形验证码（captcha img）
        - 行为验证（极验 geetest, 腾讯防水墙 tcaptcha）
        - 短信/邮箱验证码输入框

        Args:
            page: Playwright 页面

        Returns:
            True 如果检测到验证码元素
        """
        for selector in CAPTCHA_SELECTORS:
            try:
                element = await page.query_selector(selector)
                if element:
                    is_visible = await element.is_visible()
                    if is_visible:
                        logger.debug("Captcha detected: %s", selector)
                        return True
            except Exception:
                continue

        # 额外检测：iframe 内的验证码
        try:
            frames = page.frames
            for frame in frames:
                if frame == page.main_frame:
                    continue
                frame_url = frame.url.lower()
                if "captcha" in frame_url or "verify" in frame_url:
                    logger.debug("Captcha iframe detected: %s", frame_url)
                    return True
        except Exception:
            pass

        return False

    async def _wait_for_human(
        self,
        hint: str,
        timeout: int = 180,
    ) -> None:
        """
        人工干预等待点

        遇到需要人工完成的操作（滑窗拼图、短信验证码、OAuth 授权等）时，
        提示用户在浏览器中完成，按 Enter 后由代码接管后续流程。

        设计原则：人工做人工的事（验证码/授权），代码做代码的事（跳转/导航）。

        Args:
            hint: 提示信息（如"检测到滑窗验证码"、"请完成支付宝 OAuth 授权"）
            timeout: 非交互环境下的等待秒数
        """
        print("\n" + "=" * 60)
        print("  ⏸️  需要人工干预")
        print(f"  {hint}")
        print("  请在浏览器中完成上述操作，")
        print("  完成后回到此终端按 Enter，代码将接管后续流程...")
        print("=" * 60 + "\n")

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, input, "")
        except Exception:
            # 非交互环境，等待超时后继续
            await asyncio.sleep(timeout)

    async def _wait_for_landing(
        self,
        page: Any,
        target_domain: str,
        timeout: int = 60,
    ) -> bool:
        """
        等待落地到目标域名

        人工完成验证码/授权后，代码接管：轮询 URL 直到进入目标域名。
        自动处理 SSO/OIDC 回调跳转链。

        Args:
            page: Playwright 页面
            target_domain: 目标域名（如 student.syxy.ouchn.cn）
            timeout: 等待超时（秒）

        Returns:
            True 如果成功落地到目标域名
        """
        logger.info("Waiting for landing on domain: %s (timeout=%ds)", target_domain, timeout)

        elapsed = 0
        while elapsed < timeout:
            current_url = page.url
            url_lower = current_url.lower()

            # 检测是否仍在 OIDC 回调中间页（如 #/signin-oidc#access_token=...）
            # 此时虽然 URL 包含 target_domain，但 SPA 还在处理 token，不是最终落地
            is_oidc_callback = any(p in url_lower for p in OIDC_CALLBACK_WHITELIST)

            if target_domain in current_url and not is_oidc_callback:
                logger.info("Landed on target domain: %s", current_url)
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass
                await page.wait_for_timeout(2000)
                return True

            if is_oidc_callback:
                logger.debug("OIDC callback in progress, waiting for SPA to process token: %s", current_url)

            await page.wait_for_timeout(1000)
            elapsed += 1

        logger.warning("Landing wait timed out: current=%s, expected domain=%s",
                       page.url, target_domain)
        return False

    async def _login_with_oauth(
        self,
        page: Any,
        login_config: dict,
        errors: List[str],
    ) -> None:
        """
        第三方 OAuth 登录模式

        适用于通过支付宝/微信/QQ/GitHub 等第三方账户认证登录的场景。
        浏览器以非 headless 模式启动，用户手动完成 OAuth 登录流程，
        登录成功后回调返回目标页面，按 Enter 继续侦察。

        典型场景：
          - qianwen.com/chat 通过支付宝 OAuth 登录
          - 企业应用通过钉钉/企业微信 OAuth 登录
          - SaaS 应用通过 GitHub/Google OAuth 登录

        配置示例：
            login:
              mode: "oauth"
              oauth_provider: "alipay"          # alipay/wechat/qq/github/google/dingtalk
              oauth_button_selector: ""         # 可选：第三方登录按钮选择器（自动点击）
              redirect_url_pattern: "qianwen"   # 期望回调后 URL 包含的关键词
              manual_timeout: 180               # OAuth 登录超时（秒）
        """
        timeout = login_config.get("manual_timeout", 180)
        oauth_provider = login_config.get("oauth_provider", "unknown")
        oauth_button_sel = login_config.get("oauth_button_selector", "")
        redirect_pattern = login_config.get("redirect_url_pattern", "")

        logger.info("OAuth login mode: provider=%s, timeout=%ds", oauth_provider, timeout)

        provider_names = {
            "alipay": "支付宝",
            "wechat": "微信",
            "qq": "QQ",
            "github": "GitHub",
            "google": "Google",
            "dingtalk": "钉钉",
            "feishu": "飞书",
            "lark": "Lark",
        }
        provider_display = provider_names.get(oauth_provider, oauth_provider)

        # 可选：自动点击第三方登录按钮
        if oauth_button_sel:
            try:
                logger.info("Looking for OAuth login button: %s", oauth_button_sel)
                await page.wait_for_selector(oauth_button_sel, state="visible", timeout=10000)
                await page.click(oauth_button_sel)
                logger.info("Clicked OAuth login button")
                await page.wait_for_timeout(2000)
            except Exception as e:
                logger.warning("Failed to click OAuth button '%s': %s", oauth_button_sel, str(e))
                # 不作为错误，用户可以手动点击

        # 等待人工完成 OAuth 登录，按 Enter 后代码接管
        hint = f"请在浏览器中完成 {provider_display} OAuth 登录"
        if redirect_pattern:
            hint += f"（期望回调 URL 包含 '{redirect_pattern}'）"
        await self._wait_for_human(hint, timeout=timeout)

        # 可选：验证 URL 是否包含回调模式
        if redirect_pattern:
            current_url = page.url
            if redirect_pattern in current_url:
                logger.info("OAuth redirect verified: URL contains '%s'", redirect_pattern)
            else:
                logger.warning(
                    "OAuth redirect mismatch: expected '%s' in URL '%s'",
                    redirect_pattern, current_url,
                )

    async def _login_with_inline_cookies(
        self,
        page: Any,
        context: Any,
        login_config: dict,
        errors: List[str],
    ) -> None:
        """
        内联 Cookie 注入模式

        直接在 YAML 配置中内联 Cookie 字符串，无需外部文件。
        适用于从 F12 复制 Cookie 后直接粘贴到配置的场景。

        配置示例：
            login:
              mode: "cookies"
              cookie_string: "UM_distinctid=xxx; cna=yyy; tfstk=zzz; ..."
              # 可选：指定域名（默认从 connection.url 提取）
              domain: "www.qianwen.com"

        也支持结构化 Cookie 列表：
            login:
              mode: "cookies"
              cookies:
                - name: "UM_distinctid"
                  value: "xxx"
                - name: "cna"
                  value: "yyy"
        """
        from urllib.parse import urlparse

        cookie_string = login_config.get("cookie_string", "")
        cookies_list = login_config.get("cookies", [])

        # 从 connection.url 提取默认域名
        connection_url = login_config.get("url", "")
        default_domain = ""
        if connection_url:
            default_domain = urlparse(connection_url).netloc
        domain = login_config.get("domain", default_domain)

        if not cookie_string and not cookies_list:
            errors.append("Cookies login mode requires 'cookie_string' or 'cookies' in config")
            return

        try:
            cookies_to_add: List[Dict[str, str]] = []

            if cookies_list:
                # 结构化 Cookie 列表
                for ck in cookies_list:
                    if isinstance(ck, dict) and ck.get("name") and ck.get("value"):
                        cookie = {
                            "name": ck["name"],
                            "value": ck["value"],
                            "path": ck.get("path", "/"),
                        }
                        if ck.get("domain"):
                            cookie["domain"] = ck["domain"]
                        elif domain:
                            cookie["domain"] = domain if domain.startswith(".") else f".{domain}"
                        cookies_to_add.append(cookie)
            elif cookie_string:
                # Cookie 字符串解析
                from ....attack.auth.header_parser import _parse_cookies
                cookies_to_add = _parse_cookies(cookie_string, domain)

            if cookies_to_add:
                await context.add_cookies(cookies_to_add)
                logger.info("Injected %d cookies for domain: %s", len(cookies_to_add), domain)

                # 重新加载页面以使 Cookie 生效
                await page.reload(wait_until="networkidle")
                await page.wait_for_timeout(2000)
            else:
                errors.append("No valid cookies parsed from config")

        except Exception as e:
            logger.error("Inline cookies auth failed: %s", str(e))
            errors.append(f"Inline cookies auth failed: {str(e)}")

    async def _login_with_raw_headers(
        self,
        page: Any,
        context: Any,
        login_config: dict,
        errors: List[str],
    ) -> None:
        """
        原始 Headers 文本注入模式

        直接在 YAML 配置中内联从 F12 复制的完整 HTTP Request Headers 文本。
        无需保存为外部文件，适用于快速测试。

        配置示例：
            login:
              mode: "raw_headers"
              raw_text: |
                GET /chat HTTP/2
                Host: www.qianwen.com
                Cookie: UM_distinctid=xxx; cna=yyy; ...
                User-Agent: Mozilla/5.0 ...
        """
        raw_text = login_config.get("raw_text", "")

        if not raw_text:
            errors.append("raw_headers login mode requires 'raw_text' in config")
            return

        try:
            from ....attack.auth.header_parser import parse_header_text
            from ....attack.auth import inject_auth

            auth_profile = parse_header_text(raw_text)
            await inject_auth(context, page, auth_profile)
            logger.info("Auth injected from raw headers: %s", auth_profile.summary())

            # 重新加载页面以使认证生效
            await page.reload(wait_until="networkidle")
            await page.wait_for_timeout(2000)

        except Exception as e:
            logger.error("Raw headers auth failed: %s", str(e))
            errors.append(f"Raw headers auth failed: {str(e)}")
