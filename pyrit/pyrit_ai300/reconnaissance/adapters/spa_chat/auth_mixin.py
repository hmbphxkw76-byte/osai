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
        default_username_selectors = [
            "input[name='username']", "input[name='account']",
            "input[name='userName']", "#username", "#account",
            "input[type='text'][placeholder*='账号']",
            "input[type='text'][placeholder*='用户']",
            "input[type='text'][placeholder*='学号']",
            "input[type='text'][placeholder*='手机']",
            "input[type='text']",
        ]
        default_password_selectors = [
            "input[name='password']", "input[name='passwd']",
            "#password", "input[type='password']",
        ]
        default_submit_selectors = [
            "button[type='submit']", "input[type='submit']",
            "button.login-btn", ".submit-btn",
            "button:has-text('登录')", "button:has-text('Login')",
            "a:has-text('登录')", "button:has-text('Sign')",
        ]

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
            logger.info("Filling login form (selector list + type delay)...")

            # 填用户名（依次尝试选择器列表）
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
            if not submit_ok:
                print("  ⚠️ 未找到登录按钮，请手动点击登录")

            logger.info("Login form submitted")

            # 等待页面响应
            await page.wait_for_timeout(2000)

            # 检测是否出现验证码
            captcha_found = await self._detect_captcha(page)
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
          - 企业应用 → 钉钉/企业微信 SSO → 验证码 → 回调
          - SaaS 应用 → Okta/Auth0 SSO → MFA → 回调

        配置示例：
            login:
              mode: "sso"
              url: ""                           # 留空则从 connection.url 触发重定向
              username: "student001"
              password: "password123"
              sso_login_url: "https://passport.syxy.ouchn.cn/Account/Login"
              sso_domain: "passport.syxy.ouchn.cn"    # SSO 认证域名
              target_domain: "student.syxy.ouchn.cn"  # 目标应用域名（回调后检测）
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

        # SSO 配置
        sso_login_url = login_config.get("sso_login_url", "")
        sso_domain = login_config.get("sso_domain", "")
        target_domain = login_config.get("target_domain", "")

        # 从 target_url 提取目标域名
        if not target_domain and target_url:
            target_domain = urlparse(target_url).netloc

        # 登录表单选择器（支持配置覆盖，默认与 auto_spa_recon.py 一致的选择器列表）
        # 使用列表依次尝试，比逗号分隔的单选择器更稳健（避免 fill 选中错误元素）
        default_username_selectors = [
            "input[name='username']", "input[name='account']",
            "input[name='userName']", "#username", "#account",
            "input[type='text'][placeholder*='账号']",
            "input[type='text'][placeholder*='用户']",
            "input[type='text'][placeholder*='学号']",
            "input[type='text'][placeholder*='手机']",
            "input[type='text']",
        ]
        default_password_selectors = [
            "input[name='password']", "input[name='passwd']",
            "#password", "input[type='password']",
        ]
        default_submit_selectors = [
            "button[type='submit']", "input[type='submit']",
            "button.login-btn", ".submit-btn",
            "button:has-text('登录')", "button:has-text('Login')",
            "a:has-text('登录')", "button:has-text('Sign')",
        ]

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

        # 步骤 1：导航到 SSO 登录页
        # 如果配置了 sso_login_url，直接导航到该 URL
        # 否则导航到 target_url，让应用自动重定向到 SSO 登录页
        if sso_login_url:
            logger.info("Navigating to SSO login URL: %s", sso_login_url)
            await page.goto(sso_login_url, wait_until="networkidle")
        else:
            # 已经在 _execute_recon 中导航到 login_url 或 target_url
            # 等待重定向到 SSO 登录页
            logger.info("Waiting for SSO redirect from target page...")
            await page.wait_for_timeout(3000)

        current_url = page.url
        logger.info("Current URL after SSO redirect: %s", current_url)

        # 步骤 2：填写账号密码（如果配置了）
        # 使用选择器列表依次尝试 + page.type(delay=30) 逐字输入
        # （与 auto_spa_recon.py 一致，确保触发 Vue/React 前端校验）
        if username and password:
            form_filled = False
            try:
                logger.info("Filling SSO login form (selector list + type delay)...")

                # 填用户名（依次尝试选择器列表）
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

        # 步骤 3：检测验证码
        captcha_found = await self._detect_captcha(page)
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
        from ...orchestrators.auth import (
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
        from ...orchestrators.auth import (
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
        from ...orchestrators.auth import normalize_domain

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
            from ...orchestrators.auth import parse_header_file, inject_auth
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
        errors: List[str],
    ) -> None:
        """
        手动登录模式

        浏览器以非 headless 模式启动，用户手动完成登录后，
        在终端按 Enter 继续侦察流程。
        """
        timeout = login_config.get("manual_timeout", 120)
        logger.info("Manual login mode: waiting up to %ds for user to login", timeout)

        await self._wait_for_human(
            "请在浏览器中完成登录，进入智能助手聊天界面",
            timeout=timeout,
        )

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
                from ...orchestrators.auth.header_parser import _parse_cookies
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
            from ...orchestrators.auth.header_parser import parse_header_text
            from ...orchestrators.auth import inject_auth

            auth_profile = parse_header_text(raw_text)
            await inject_auth(context, page, auth_profile)
            logger.info("Auth injected from raw headers: %s", auth_profile.summary())

            # 重新加载页面以使认证生效
            await page.reload(wait_until="networkidle")
            await page.wait_for_timeout(2000)

        except Exception as e:
            logger.error("Raw headers auth failed: %s", str(e))
            errors.append(f"Raw headers auth failed: {str(e)}")
