# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""MFADetector 单元测试。.

测试覆盖:
  1. MFADetector DOM 选择器检测 (mock Page)
  2. MFADetector 页面文本关键词检测
  3. MFADetector 无 MFA 场景
  4. MFADetector 多种 MFA 同时检测

> **日期**: 2026-8-3
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from web_redteam.auth.mfa_detector import MFADetector


class _MockPage:
    """Mock Playwright Page 对象。"""

    def __init__(
        self,
        selector_results: dict[str, bool] | None = None,
        page_text: str = "",
    ) -> None:
        """Initialize mock page.

        Args:
            selector_results: {selector: element_exists} 映射。
            page_text: 页面文本内容。
        """
        self._selector_results = selector_results or {}
        self._page_text = page_text

    async def query_selector(self, selector: str) -> object | None:
        """Mock query_selector。"""
        if self._selector_results.get(selector, False):
            return MagicMock()  # 返回非 None 表示元素存在
        return None

    async def inner_text(self, selector: str) -> str:
        """Mock inner_text。"""
        return self._page_text


class TestMFADetector:
    """MFADetector 测试。"""

    @pytest.mark.asyncio
    async def test_no_mfa(self) -> None:
        """无 MFA 场景。"""
        page = _MockPage(
            selector_results={},
            page_text="Welcome to the dashboard",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is False
        assert result.mfa_types == []

    @pytest.mark.asyncio
    async def test_otp_detected_by_selector(self) -> None:
        """通过 DOM 选择器检测 OTP。"""
        page = _MockPage(
            selector_results={
                'input[name*="code"]': True,
            },
            page_text="Login page",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is True
        assert "otp" in result.mfa_types

    @pytest.mark.asyncio
    async def test_otp_detected_by_text(self) -> None:
        """通过页面文本关键词检测 OTP。"""
        page = _MockPage(
            selector_results={},
            page_text="请输入验证码完成二次验证",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is True
        assert "otp" in result.mfa_types

    @pytest.mark.asyncio
    async def test_qr_scan_detected(self) -> None:
        """检测 QR 扫码。"""
        page = _MockPage(
            selector_results={
                'img[src*="qr"]': True,
            },
            page_text="请扫描二维码",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is True
        assert "qr_scan" in result.mfa_types

    @pytest.mark.asyncio
    async def test_captcha_detected(self) -> None:
        """检测图形验证码。"""
        page = _MockPage(
            selector_results={
                'div[class*="captcha"]': True,
            },
            page_text="请输入图形验证码",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is True
        assert "captcha" in result.mfa_types

    @pytest.mark.asyncio
    async def test_slider_detected(self) -> None:
        """检测滑块验证。"""
        page = _MockPage(
            selector_results={
                'div[class*="slider"]': True,
            },
            page_text="请向右滑动滑块",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is True
        assert "slider" in result.mfa_types

    @pytest.mark.asyncio
    async def test_sms_detected(self) -> None:
        """检测短信验证码。"""
        page = _MockPage(
            selector_results={
                'input[name*="code"]': True,
            },
            page_text="请输入手机收到的短信验证码",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is True
        assert "sms" in result.mfa_types or "otp" in result.mfa_types

    @pytest.mark.asyncio
    async def test_multiple_mfa_detected(self) -> None:
        """同时检测多种 MFA。"""
        page = _MockPage(
            selector_results={
                'input[name*="code"]': True,
                'img[src*="captcha"]': True,
            },
            page_text="请输入验证码和图形验证",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is True
        assert len(result.mfa_types) >= 2

    @pytest.mark.asyncio
    async def test_human_instructions_generated(self) -> None:
        """检测到 MFA 时生成人工辅助指令。"""
        page = _MockPage(
            selector_results={
                'input[name*="code"]': True,
            },
            page_text="验证码",
        )
        detector = MFADetector()
        result = await detector.detect(page)  # type: ignore[arg-type]

        assert result.has_mfa is True
        assert len(result.human_instructions) > 0
        assert any("验证码" in inst or "OTP" in inst for inst in result.human_instructions)
