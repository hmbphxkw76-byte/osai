# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""MFADetector: 二次认证 (MFA) 自动检测器。.

在认证页面加载后, 检测页面是否需要二次认证:
  1. OTP (一次性密码) — input[name*="code"], input[maxlength="6"]
  2. QR 扫码 — img[src*="qr"], canvas[class*="qr"]
  3. CAPTCHA (图片验证码) — img[src*="captcha"], div[id*="captcha"]
  4. 滑窗验证 — div[class*="slider"], div[class*="slide-to"]
  5. SMS 短信验证 — 页面文本含 "短信"/"SMS" + OTP 输入框

检测策略: DOM 选择器 + 页面文本关键词双路检测。

学术依据:
  - NIST SP 800-63B: 多因素认证分类 (知识因素 + 拥有因素 + 生物因素)
  - OWASP ASVS V2.4: 认证验证要求
  - PyRIT CopilotAuthenticator: page 交互模式

> **日期**: 2026-8-3
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.async_api import Page

logger = logging.getLogger(__name__)

# ── MFA 类型 → DOM 选择器映射 ──
_MFA_SELECTORS: dict[str, list[str]] = {
    "otp": [
        'input[name*="otp"]',
        'input[name*="code"]',
        'input[name*="verification"]',
        'input[id*="otp"]',
        'input[id*="code"]',
        'input[maxlength="6"]',
        'input[maxlength="4"]',
        'input[autocomplete="one-time-code"]',
    ],
    "qr_scan": [
        'img[src*="qr"]',
        'img[src*="QR"]',
        'canvas[class*="qr"]',
        'div[class*="qr-code"]',
        'div[class*="qrcode"]',
        'img[alt*="QR"]',
        'img[alt*="二维码"]',
    ],
    "captcha": [
        'img[src*="captcha"]',
        'img[src*="verify"]',
        'div[id*="captcha"]',
        'div[class*="captcha"]',
        'iframe[src*="captcha"]',
        'iframe[src*="recaptcha"]',
        'div[class*="g-recaptcha"]',
        'div[class*="h-captcha"]',
    ],
    "slider": [
        'div[class*="slider"]',
        'div[class*="slide-to"]',
        'div[class*="nc_iconfont"]',
        'div[class*="slide-verify"]',
        'span[class*="slider"]',
        'div[class*="drag"]',
    ],
}

# ── MFA 类型 → 页面文本关键词映射 ──
_MFA_TEXT_KEYWORDS: dict[str, list[str]] = {
    "otp": [
        "验证码", "动态密码", "OTP", "one-time", "verification code",
        "输入密码", "请输入验证", "二次验证", "两步验证",
    ],
    "qr_scan": [
        "扫码", "扫描", "scan", "QR", "二维码", "扫一扫",
    ],
    "captcha": [
        "图形验证", "图片验证", "captcha", "CAPTCHA", "请输入图中",
        "看不清", "点击刷新",
    ],
    "slider": [
        "滑动", "拖动", "slide", "drag", "滑块", "向右滑动",
    ],
    "sms": [
        "短信", "SMS", "手机", "phone", "手机号", "手机号码",
        "发送短信", "获取短信",
    ],
}


@dataclass
class MFADetectionResult:
    """MFA 检测结果。.

    Attributes:
        mfa_types: 检测到的 MFA 类型列表 (如 ["otp", "sms"])。
        selectors_matched: 每种 MFA 类型匹配到的选择器。
        text_keywords_matched: 每种 MFA 类型匹配到的文本关键词。
        detection_reason: 判别依据的人类可读描述。
        human_instructions: 生成的人工辅助指令列表。
    """

    mfa_types: list[str] = field(default_factory=list)
    selectors_matched: dict[str, list[str]] = field(default_factory=dict)
    text_keywords_matched: dict[str, list[str]] = field(default_factory=dict)
    detection_reason: str = ""
    human_instructions: list[str] = field(default_factory=list)

    @property
    def has_mfa(self) -> bool:
        """是否检测到 MFA。."""
        return len(self.mfa_types) > 0

    def __str__(self) -> str:
        """Return string representation."""
        lines = [
            "MFADetectionResult:",
            f"  mfa_types:     {self.mfa_types}",
            f"  has_mfa:       {self.has_mfa}",
            f"  reason:        {self.detection_reason}",
        ]
        if self.human_instructions:
            lines.append("  instructions:")
            for inst in self.human_instructions:
                lines.append(f"    • {inst}")
        return "\n".join(lines)


class MFADetector:
    """二次认证 (MFA) 自动检测器。.

    在认证页面加载后, 通过 DOM 选择器和页面文本关键词
    双路检测是否需要二次认证 (OTP/QR/CAPTCHA/滑窗/SMS)。

    用法::

        detector = MFADetector()
        result = await detector.detect(page)
        if result.has_mfa:
            logger.info("检测到 MFA: %s", result.mfa_types)
            for inst in result.human_instructions:
                logger.info(f"  • {inst}")
    """

    # MFA 类型 → 中文描述
    MFA_DESCRIPTIONS = {
        "otp": "OTP 验证码",
        "qr_scan": "扫码认证",
        "captcha": "图形验证码",
        "slider": "滑块验证",
        "sms": "短信验证码",
    }

    # MFA 类型 → 人工辅助指令
    MFA_INSTRUCTIONS = {
        "otp": "请在浏览器中输入 OTP / 验证码",
        "qr_scan": "请使用手机扫描浏览器中的二维码",
        "captcha": "请在浏览器中完成图形验证码",
        "slider": "请在浏览器中完成滑块拖动验证",
        "sms": "请在浏览器中输入收到的短信验证码",
    }

    async def detect(self, page: Page) -> MFADetectionResult:
        """检测页面是否需要二次认证。.

        双路检测:
          1. DOM 选择器: 遍历 MFA 选择器列表, 检查元素是否存在
          2. 页面文本: 获取页面文本内容, 检查关键词

        两路 OR 逻辑: 任一路检测到即认为该 MFA 类型存在。

        Args:
            page: Playwright Page 对象 (需已加载认证页面)。

        Returns:
            MFADetectionResult 检测结果。
        """
        result = MFADetectionResult()
        detected_types: set[str] = set()

        # 路径 1: DOM 选择器检测
        for mfa_type, selectors in _MFA_SELECTORS.items():
            matched_selectors: list[str] = []
            for selector in selectors:
                try:
                    element = await page.query_selector(selector)
                    if element:
                        matched_selectors.append(selector)
                        logger.debug(f"MFADetector: {mfa_type} selector matched: {selector}")
                except Exception:
                    continue

            if matched_selectors:
                detected_types.add(mfa_type)
                result.selectors_matched[mfa_type] = matched_selectors

        # 路径 2: 页面文本关键词检测
        page_text = ""
        try:
            page_text = await page.inner_text("body")
            page_text_lower = page_text.lower()
        except Exception as e:
            logger.debug(f"MFADetector: failed to get page text: {e}")
            page_text_lower = ""

        if page_text_lower:
            for mfa_type, keywords in _MFA_TEXT_KEYWORDS.items():
                matched_keywords: list[str] = []
                for keyword in keywords:
                    if keyword.lower() in page_text_lower:
                        matched_keywords.append(keyword)

                if matched_keywords:
                    detected_types.add(mfa_type)
                    result.text_keywords_matched[mfa_type] = matched_keywords

        # 构建结果
        result.mfa_types = sorted(detected_types)

        if result.has_mfa:
            # SMS 检测需要同时有 OTP 输入框和短信关键词
            if "sms" in result.mfa_types and "otp" not in result.mfa_types:
                # SMS 但没有 OTP 输入框, 可能只是提示文本, 降级为 OTP
                result.mfa_types.append("otp")
                result.mfa_types = sorted(set(result.mfa_types))

            # 生成人工辅助指令
            for mfa_type in result.mfa_types:
                instruction = self.MFA_INSTRUCTIONS.get(mfa_type, f"请完成 {mfa_type} 认证")
                result.human_instructions.append(instruction)

            result.detection_reason = (
                f"检测到 {len(result.mfa_types)} 种二次认证: "
                f"{', '.join(self.MFA_DESCRIPTIONS.get(t, t) for t in result.mfa_types)}"
            )
            logger.info(f"MFADetector: {result.detection_reason}")
        else:
            result.detection_reason = "未检测到二次认证 (MFA)"
            logger.info("MFADetector: no MFA detected")

        return result
