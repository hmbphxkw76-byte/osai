# -*- coding: utf-8 -*-
"""
Login Waiter
============

人工登录等待器。

在检测到登录页后暂停侦察流程，等待用户完成：
  - 账号密码登录
  - 短信/图片验证码
  - 拼图/滑块验证
  - OTP / 二次认证
  - 扫码登录
  - SSO 跨域跳转回原页面

支持自动检测登录完成并接管后续流程，也支持用户按 Enter 键手动确认继续。
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from .text import truncate_error

logger = logging.getLogger(__name__)

DEFAULT_WAIT_RESULT = {
    "success": False,
    "reason": "",
    "waited_ms": 0,
    "login_resolved": False,
    "detection": {},
}

# 常见验证码/滑块/拼图容器选择器
CAPTCHA_SELECTORS = [
    "#captcha",
    ".captcha",
    ".slider",
    ".puzzle",
    ".geetest",
    ".nc-container",
    ".verify-code",
    ".verification-code",
    "[class*='captcha']",
    "[class*='slider']",
    "[class*='puzzle']",
    "[class*='geetest']",
    "[class*='nc-container']",
    "[id*='captcha']",
    "iframe[src*='captcha']",
    "iframe[src*='geetest']",
]


def _normalize_domain(url: str) -> str:
    """从 URL 提取域名（去掉协议、端口、路径）"""
    from urllib.parse import urlparse

    netloc = urlparse(url).netloc or url
    return netloc.split(":")[0].lower()


async def _has_visible_selector(page: Any, selectors: list) -> bool:
    """检查页面是否存在任一可见元素"""
    for selector in selectors:
        try:
            el = await page.query_selector(selector)
            if el and await el.is_visible():
                return True
        except Exception:
            continue
    return False


async def _check_enter_pressed() -> bool:
    """非阻塞检查用户是否按下了 Enter 键（仅 Windows）。"""
    try:
        import msvcrt

        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key in (b"\r", b"\n"):
                return True
    except Exception:
        pass
    return False


async def wait_for_manual_login(
    page: Any,
    detector: Any,
    timeout_ms: int = 300000,
    poll_interval_ms: int = 2000,
    require_enter: bool = True,
    target_url: str = "",
    captcha_selectors: Optional[List[str]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    等待人工完成登录流程，并在完成后自动接管。

    支持场景：
      - 账号密码登录
      - 短信/图片验证码
      - 拼图/滑块验证
      - OTP/二次认证
      - 扫码登录
      - 跨域登录后跳转回原页面（如 www.jd.com → passport.jd.com → www.jd.com）

    登录完成判定条件（满足任一即可）：
      1. 登录表单消失，且检测到聊天输入框
      2. 当前 URL 已回到 target_url 域名下
      3. URL 域从登录域跳转到其他非登录域，且检测到聊天输入框
      4. 用户按下 Enter 键继续（如果 require_enter=True）
      5. 等待超时

    Args:
        page: Playwright Page 对象
        detector: DOMDetector 实例
        timeout_ms: 最大等待时间（毫秒），默认 5 分钟
        poll_interval_ms: 轮询间隔（毫秒）
        require_enter: 是否在自动检测成功后仍要求用户按 Enter 确认
        target_url: 登录成功后应返回的目标 URL（用于跨域登录检测）
        captcha_selectors: 自定义验证码/滑块/拼图元素选择器，覆盖默认列表
        config: 全局配置，用于读取日志截断长度等参数

    Returns:
        {
            "success": bool,
            "reason": str,
            "waited_ms": int,
            "login_resolved": bool,
            "detection": dict,
        }
    """
    start_time = time.time()
    deadline = start_time + (timeout_ms / 1000.0)
    target_domain = _normalize_domain(target_url) if target_url else ""
    login_domain = _normalize_domain(page.url)
    active_captcha_selectors = captcha_selectors if captcha_selectors is not None else CAPTCHA_SELECTORS
    captcha_hint_printed = False

    print("\n" + "=" * 60)
    print("  🔐 检测到登录页")
    print("=" * 60)
    print("  请在当前浏览器窗口完成登录：")
    print("    - 如已自动填充账号密码，请人工点击登录按钮")
    print("    - 填写短信/图片验证码")
    print("    - 完成拼图/滑块验证")
    print("    - 输入 OTP / 二次认证码")
    print("    - 或完成扫码登录")
    if target_domain:
        print(f"  登录成功后会自动跳转回: {target_url}")
    if require_enter:
        print("=" * 60)
        print("  登录完成后，请回到此终端按 Enter 键继续侦察...")
    else:
        print("  系统将自动检测登录完成状态并继续侦察...")
    print("=" * 60 + "\n")

    while time.time() < deadline:
        elapsed_ms = int((time.time() - start_time) * 1000)

        try:
            # 刷新当前页面信息
            current_url = page.url
            current_domain = _normalize_domain(current_url)
            detection = await detector.detect_all()
            is_login = await detector.is_login_page()
            has_input = bool(detection.get("input_selector"))
        except Exception as exc:
            # 页面在登录过程中被关闭/重定向导致检测失败，安全地继续轮询
            logger.debug("Login wait detection failed (page may be closing): %s", truncate_error(str(exc), config))
            await asyncio.sleep(poll_interval_ms / 1000.0)
            continue

        # 验证码/滑块提示
        if not captcha_hint_printed and await _has_visible_selector(page, active_captcha_selectors):
            print("  🧩 检测到验证码/滑块/拼图元素，请人工完成后系统将自动继续...")
            captcha_hint_printed = True

        # 自动判定登录完成
        returned_to_target = bool(target_domain and current_domain == target_domain)
        left_login_domain = bool(login_domain and current_domain and current_domain != login_domain)

        login_completed = False
        reason = ""

        if returned_to_target:
            login_completed = True
            reason = "returned_to_target"
        elif left_login_domain and has_input:
            login_completed = True
            reason = "left_login_domain_with_input"
        elif not is_login and has_input:
            login_completed = True
            reason = "auto_detected"

        if login_completed:
            print(f"  ✅ 自动检测到登录完成（{reason}，耗时 {elapsed_ms // 1000} 秒）")
            if require_enter:
                input("  请按 Enter 键确认继续侦察...")
            return {
                "success": True,
                "reason": reason,
                "waited_ms": elapsed_ms,
                "login_resolved": True,
                "detection": detection,
            }

        # 用户按 Enter 提前继续
        if require_enter and await _check_enter_pressed():
            print(f"  ⏎ 用户手动确认继续（耗时 {elapsed_ms // 1000} 秒）")
            return {
                "success": True,
                "reason": "manual_confirmed",
                "waited_ms": elapsed_ms,
                "login_resolved": True,
                "detection": await detector.detect_all(),
            }

        await asyncio.sleep(poll_interval_ms / 1000.0)

    elapsed_ms = int((time.time() - start_time) * 1000)
    print(f"  ⏰ 等待登录超时（{elapsed_ms // 1000} 秒）")
    try:
        final_detection = await detector.detect_all()
    except Exception:
        final_detection = {}
    return {
        "success": False,
        "reason": "timeout",
        "waited_ms": elapsed_ms,
        "login_resolved": False,
        "detection": final_detection,
    }
