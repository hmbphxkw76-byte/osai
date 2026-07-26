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

支持自动检测登录完成（登录表单消失 + 聊天输入框出现），
也支持用户按 Enter 键手动确认继续。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)

DEFAULT_WAIT_RESULT = {
    "success": False,
    "reason": "",
    "waited_ms": 0,
    "login_resolved": False,
    "detection": {},
}


def _normalize_domain(url: str) -> str:
    """从 URL 提取域名（去掉协议、端口、路径）"""
    from urllib.parse import urlparse

    netloc = urlparse(url).netloc or url
    return netloc.split(":")[0].lower()


async def wait_for_manual_login(
    page: Any,
    detector: Any,
    timeout_ms: int = 300000,
    poll_interval_ms: int = 2000,
    require_enter: bool = True,
    target_url: str = "",
) -> Dict[str, Any]:
    """
    等待人工完成登录流程。

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
      3. 用户按下 Enter 键继续（如果 require_enter=True）
      4. 等待超时

    Args:
        page: Playwright Page 对象
        detector: DOMDetector 实例
        timeout_ms: 最大等待时间（毫秒），默认 5 分钟
        poll_interval_ms: 轮询间隔（毫秒）
        require_enter: 是否在自动检测成功后仍要求用户按 Enter 确认
        target_url: 登录成功后应返回的目标 URL（用于跨域登录检测）

    Returns:
        {
            "success": bool,
            "reason": str,
            "waited_ms": int,
            "login_resolved": bool,
            "detection": dict,
        }
    """
    import asyncio

    start_time = time.time()
    deadline = start_time + (timeout_ms / 1000.0)
    target_domain = _normalize_domain(target_url) if target_url else ""

    print("\n" + "=" * 60)
    print("  🔐 检测到登录页")
    print("=" * 60)
    print("  请在当前浏览器窗口完成登录：")
    print("    - 输入账号密码")
    print("    - 填写短信/图片验证码")
    print("    - 完成拼图/滑块验证")
    print("    - 输入 OTP / 二次认证码")
    print("    - 或完成扫码登录")
    if target_domain:
        print(f"  登录成功后会自动跳转回: {target_url}")
    print("=" * 60)
    if require_enter:
        print("  登录完成后，请回到此终端按 Enter 键继续侦察...")
    else:
        print("  系统将自动检测登录完成状态...")
    print("=" * 60 + "\n")

    while time.time() < deadline:
        elapsed_ms = int((time.time() - start_time) * 1000)

        # 自动检测登录是否完成
        is_login = await detector.is_login_page()
        detection = await detector.detect_all()
        has_input = bool(detection.get("input_selector"))
        current_domain = _normalize_domain(page.url)
        returned_to_target = bool(target_domain and current_domain == target_domain)

        if (not is_login and has_input) or returned_to_target:
            reason = "returned_to_target" if returned_to_target else "auto_detected"
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
        if require_enter:
            try:
                import msvcrt

                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key in (b"\r", b"\n"):
                        print(f"  ⏎ 用户手动确认继续（耗时 {elapsed_ms // 1000} 秒）")
                        return {
                            "success": True,
                            "reason": "manual_confirmed",
                            "waited_ms": elapsed_ms,
                            "login_resolved": True,
                            "detection": await detector.detect_all(),
                        }
            except Exception:
                pass

        await asyncio.sleep(poll_interval_ms / 1000.0)

    elapsed_ms = int((time.time() - start_time) * 1000)
    print(f"  ⏰ 等待登录超时（{elapsed_ms // 1000} 秒）")
    return {
        "success": False,
        "reason": "timeout",
        "waited_ms": elapsed_ms,
        "login_resolved": False,
        "detection": await detector.detect_all(),
    }
