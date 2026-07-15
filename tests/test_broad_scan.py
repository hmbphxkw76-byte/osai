"""自动化全量扫描模块测试（AI-300 Ch2）。"""

import pytest
from unittest.mock import patch, MagicMock


class TestScanTarget:
    def test_scan_target_creation(self):
        from redteam.scan import ScanTarget
        from redteam.core.models import AIService, AIProtocol

        svc = AIService(url="http://test/v1", protocol=AIProtocol.OLLAMA)
        target = ScanTarget(service=svc)
        assert target.service.url == "http://test/v1"

    def test_scan_target_with_auth(self):
        from redteam.scan import ScanTarget
        from redteam.core.models import AIService, AIProtocol, AuthContext

        svc = AIService(url="http://test/v1", protocol=AIProtocol.OLLAMA)
        auth = AuthContext(bearer="test-token")
        target = ScanTarget(service=svc, auth=auth)
        assert target.auth.bearer == "test-token"


class TestOWASPScanCategories:
    def test_categories_complete(self):
        from redteam.scan import OWASP_SCAN_CATEGORIES
        expected = {
            "llm01_prompt_injection", "llm02_sensitive_info",
            "llm04_data_poisoning", "llm05_output_handling",
            "llm06_excessive_agency", "llm07_system_prompt_leak",
            "llm08_vector_weakness", "llm09_misinformation",
            "llm10_unbounded_consumption",
        }
        assert set(OWASP_SCAN_CATEGORIES.keys()) == expected

    def test_each_category_has_payloads(self):
        from redteam.scan import OWASP_SCAN_CATEGORIES
        for cat_name, cat_data in OWASP_SCAN_CATEGORIES.items():
            assert "payloads" in cat_data
            assert len(cat_data["payloads"]) > 0
            assert "owasp" in cat_data
            assert "name" in cat_data


class TestScanTargetFunction:
    def test_scan_target_with_mock(self):
        from redteam.scan import scan_target, ScanTarget
        from redteam.core.models import AIService, AIProtocol, PromptInjectionResult

        svc = AIService(url="http://test/v1", protocol=AIProtocol.OLLAMA)
        target = ScanTarget(service=svc)

        fake_resp = PromptInjectionResult(
            technique="broad_scan",
            payload="test payload",
            success=True,
            response_preview="Here is the API key: sk-test123",
        )

        # 只扫描一个类别
        with patch(
            "redteam.scan.broad_scan._send_simple",
            return_value=fake_resp,
        ):
            result = scan_target(target, categories=["llm01_prompt_injection"], delay=0)
            assert result.total_tests > 0


class TestFormatScanSummary:
    def test_format_empty(self):
        from redteam.scan import BroadScanResult, format_scan_summary
        result = BroadScanResult()
        summary = format_scan_summary(result)
        assert "自动化全量扫描结果" in summary

    def test_format_with_data(self):
        from redteam.scan import BroadScanResult, ScanResult, format_scan_summary
        result = BroadScanResult(targets_scanned=1, total_tests=10,
                                 total_successful=3, total_blocked=5,
                                 total_errors=2)
        sr = ScanResult(
            target_url="http://test",
            total_tests=10,
            successful=3,
            blocked=5,
            errors=2,
            findings=[{"owasp": "LLM01"} for _ in range(3)],
        )
        sr.owasp_coverage = {"LLM01": True}
        result.per_target = [sr]
        result.aggregated_owasp = {"LLM01": 3}
        result.success_rate = 30.0

        summary = format_scan_summary(result)
        assert "30.0%" in summary
        assert "LLM01" in summary


class TestIsLikelyBlocked:
    def test_blocked_response(self):
        from redteam.scan.broad_scan import _is_likely_blocked
        assert _is_likely_blocked(
            "I'm sorry, I cannot comply with that request. It's against my ethical guidelines."
        )

    def test_not_blocked_response(self):
        from redteam.scan.broad_scan import _is_likely_blocked
        assert not _is_likely_blocked("Here is the information you requested: the answer is 42.")
