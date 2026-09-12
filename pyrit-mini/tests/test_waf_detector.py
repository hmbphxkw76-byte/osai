# -*- coding: utf-8 -*-
"""tests/test_waf_detector.py — recon/waf_detector.py 单元测试（WAF/限流指纹）。"""

from __future__ import annotations

from recon.waf_detector import (
    parse_rate_limit_headers,
    waf_to_fingerprint_fields,
)


def test_parse_rate_limit_headers_x_ratelimit():
    """解析 X-RateLimit-* 标准头。"""
    headers = {
        "X-RateLimit-Limit": "100",
        "X-RateLimit-Remaining": "42",
        "X-RateLimit-Reset": "1700000000",
    }
    info = parse_rate_limit_headers(headers)
    assert info.limit == 100
    assert info.remaining == 42
    assert info.reset_seconds == 1700000000


def test_parse_rate_limit_headers_retry_after():
    """解析 Retry-After 回退。"""
    info = parse_rate_limit_headers({"Retry-After": "30"})
    assert info.retry_after_seconds == 30


def test_parse_rate_limit_headers_missing():
    """无相关头时返回空 RateLimitInfo（limited=False，IA-6：不抛异常）。"""
    info = parse_rate_limit_headers({})
    assert info.limited is False
    assert info.limit is None


def test_fingerprint_waf_detects_cloudflare():
    """Cloudflare 特征头被识别为 WAF 厂商。"""
    from recon.waf_detector import fingerprint_waf

    report = fingerprint_waf(
        headers={"Server": "cloudflare", "CF-Ray": "abc"},
        cookies={"__cf_bm": "x"},
        body="",
        status_code=403,
    )
    assert report.detected is True
    assert "cloudflare" in report.vendors


def test_fingerprint_waf_no_signal():
    """无 WAF 特征时 detected=False（IA-6：不误报）。"""
    from recon.waf_detector import fingerprint_waf

    report = fingerprint_waf(headers={"Server": "nginx"}, cookies={}, body="", status_code=200)
    assert report.detected is False
    assert report.vendors == []


def test_fingerprint_waf_block_status():
    """403 + 封锁语义页被标记为 blocked（拦截页信号）。"""
    from recon.waf_detector import fingerprint_waf

    report = fingerprint_waf(headers={}, cookies={}, body="Access Denied by the firewall", status_code=403)
    assert report.blocked is True


def test_waf_to_fingerprint_fields():
    """WAF 报告 → fingerprint 友好字段映射。"""
    from recon.waf_detector import fingerprint_waf

    report = fingerprint_waf(
        headers={"Server": "cloudflare"},
        cookies={},
        body="",
        status_code=403,
    )
    fields = waf_to_fingerprint_fields(report)
    assert fields["waf_detected"] is True
    assert fields["waf_vendors"] == report.vendors
    assert "rate_limit" in fields
    assert fields["rate_limit"]["limited"] is False
