"""登录页字段选择器 — 跨站适配

不同站点的登录页 DOM 结构不同。本模块提供：
  1. 内置常见选择器（用户名/密码/提交/OTP/验证码/滑窗/扫码）
  2. 按目标域名加载用户自定义选择器（config 或 selectors.yaml）

选择器以「先命中先得」的方式在 bootstrap 中使用。
"""

from __future__ import annotations

from typing import Any

# 内置默认选择器（按优先级排列，bootstrap 会依次尝试直到找到元素）
DEFAULT_SELECTORS: dict[str, list[str]] = {
    # 用户名输入框
    "username": [
        "input[name=username]", "input[name=user]", "input[name=email]",
        "input[type=email]", "input[autocomplete=username]",
        "#username", "#user", "#email", ".username input",
    ],
    # 密码输入框
    "password": [
        "input[type=password]",
        "input[name=password]", "#password", ".password input",
    ],
    # 提交按钮
    "submit": [
        "button[type=submit]", "input[type=submit]",
        "button.login", "button#login", "button:has-text('登录')",
        "button:has-text('Sign in')", "button:has-text('提交')",
    ],
    # OTP / 动态码输入框
    "otp": [
        "input[name=otp]", "input[name=code]", "input[name=totp]",
        "input[autocomplete=one-time-code]", "#otp", "#code",
        "input[inputmode=numeric][maxlength]",
    ],
    # 图形验证码图片
    "captcha_img": [
        "img[src*=captcha]", "img[src*=verify]", "img.captcha",
        "#captcha", ".captcha img",
    ],
    # 验证码输入框
    "captcha_input": [
        "input[name=captcha]", "input[name=verify]", "#captcha-input",
        "input[placeholder*=验证码]", "input[placeholder*=verify]",
    ],
    # 行为验证滑窗（滑块）
    "slider": [
        ".slider", ".captcha-slider", "#slider",
        "[class*=slider]", "[class*=verify]", ".geetest_slider",
    ],
    # 扫码登录（二维码）
    "scan_qr": [
        "img[src*=qrcode]", "img[src*=qr]", ".qrcode img", "#qrcode",
        "[class*=qrcode]",
    ],
}


def get_selectors(target_url: str, overrides: dict[str, Any] | None = None) -> dict[str, list[str]]:
    """获取某目标域的选择器列表

    合并顺序：内置默认 + 用户覆盖（overrides 可整体替换某字段的列表）

    :param target_url: 目标 URL（用于未来按域名定制，当前统一返回）
    :param overrides: 用户自定义选择器，形如
                      {"username": ["#myuser"], "submit": ["#mysubmit"]}
    :returns: 选择器字典，值为候选选择器列表
    """
    merged = {k: list(v) for k, v in DEFAULT_SELECTORS.items()}
    if overrides:
        for key, vals in overrides.items():
            if vals:
                merged[key] = list(vals)
    return merged
