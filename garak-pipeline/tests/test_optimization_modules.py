"""P1/P2 优化模块测试 — 验证 defense_probe / cross_target / compliance_map"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ============================================================
# defense_probe 模块测试
# ============================================================
class TestDefenseProbe:
    """WAF/防御前置探测模块测试"""

    def test_waf_detection_cloudflare(self):
        """检测 Cloudflare WAF 指纹"""
        from pipeline.auth.defense_probe import _detect_waf

        resp = MagicMock()
        resp.headers = {"cf-ray": "abc123", "server": "cloudflare"}
        resp.text = "<html>normal</html>"
        waf = _detect_waf(resp)
        assert waf == "Cloudflare"

    def test_waf_detection_akamai(self):
        """检测 Akamai WAF 指纹"""
        from pipeline.auth.defense_probe import _detect_waf

        resp = MagicMock()
        resp.headers = {"x-akamai-transformed": "1"}
        resp.text = ""
        waf = _detect_waf(resp)
        assert waf == "Akamai"

    def test_waf_detection_none(self):
        """无 WAF 时返回 None"""
        from pipeline.auth.defense_probe import _detect_waf

        resp = MagicMock()
        resp.headers = {"content-type": "application/json"}
        resp.text = '{"status":"ok"}'
        waf = _detect_waf(resp)
        assert waf is None

    def test_captcha_detection(self):
        """CAPTCHA 检测"""
        from pipeline.auth.defense_probe import _detect_captcha

        resp = MagicMock()
        resp.text = '<div class="recaptcha">Please verify</div>'
        assert _detect_captcha(resp) is True

        resp.text = '{"message":"hello"}'
        assert _detect_captcha(resp) is False

    def test_security_headers(self):
        """安全响应头检测"""
        from pipeline.auth.defense_probe import _check_security_headers

        resp = MagicMock()
        resp.headers = {
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
        }
        result = _check_security_headers(resp)
        assert result["strict-transport-security"] is True
        assert result["x-frame-options"] is True
        assert result["content-security-policy"] is False

    def test_rate_limit_extraction(self):
        """速率限制头提取"""
        from pipeline.auth.defense_probe import _extract_rate_limits

        resp = MagicMock()
        resp.headers = {
            "x-ratelimit-limit-requests": "60",
            "retry-after": "30",
        }
        rl = _extract_rate_limits(resp)
        assert "x-ratelimit-limit-requests" in rl
        assert "retry-after" in rl

    def test_apply_defense_recommendations_waf(self):
        """WAF 检测后自动降速"""
        from pipeline.auth.defense_probe import apply_defense_recommendations

        target = {"endpoint": "http://example.com"}
        defense = {"waf_detected": True, "waf_type": "Cloudflare", "rate_limits": {}}
        execute_cfg = {
            "rate_limit": {"max_rpm": 60, "base_delay": 1.0, "jitter": False},
        }
        result = apply_defense_recommendations(target, defense, execute_cfg)
        assert result["rate_limit"]["max_rpm"] == 30  # 降一半
        assert result["rate_limit"]["base_delay"] == 2.0  # 加倍
        assert result["rate_limit"]["jitter"] is True  # 启用抖动

    def test_apply_defense_recommendations_rate_limit(self):
        """从响应头动态设置 RPM（取当前值与动态值的较小值）"""
        from pipeline.auth.defense_probe import apply_defense_recommendations

        target = {"endpoint": "http://example.com"}
        defense = {
            "waf_detected": False,
            "rate_limits": {"x-ratelimit-limit-requests": "100"},
        }
        # 当前 max_rpm=60 < 动态 80%×100=80 → 保持 60（不超出当前限制）
        execute_cfg = {"rate_limit": {"max_rpm": 60}}
        result = apply_defense_recommendations(target, defense, execute_cfg)
        assert result["rate_limit"]["max_rpm"] == 60  # min(60, 80)=60

        # 当前 max_rpm=120 > 动态 80%×100=80 → 降至 80
        execute_cfg2 = {"rate_limit": {"max_rpm": 120}}
        result2 = apply_defense_recommendations(target, defense, execute_cfg2)
        assert result2["rate_limit"]["max_rpm"] == 80  # min(120, 80)=80

    def test_probe_defenses_connection_error(self):
        """连接失败时返回空结果（不抛异常）"""
        from pipeline.auth.defense_probe import probe_defenses

        result = probe_defenses("http://nonexistent.invalid/", timeout=2)
        assert result["waf_detected"] is False
        assert result["latency_ms"] >= 0


# ============================================================
# cross_target 模块测试
# ============================================================
class TestCrossTarget:
    """跨目标关联分析模块测试"""

    def test_analyze_single_target(self):
        """单目标不触发关联分析"""
        from pipeline.cross_target import analyze_cross_target

        batch_summary = {
            "targets": [{"name": "t1", "status": "success", "endpoint": "http://a"}],
        }
        result = analyze_cross_target(batch_summary)
        assert result["analyzed"] is False

    def test_analyze_shared_endpoints(self):
        """检测共享 endpoint"""
        from pipeline.cross_target import analyze_cross_target

        batch_summary = {
            "targets": [
                {"name": "page1", "status": "success", "endpoint": "http://api/v1",
                 "model": "m", "analysis_path": ""},
                {"name": "page2", "status": "success", "endpoint": "http://api/v1",
                 "model": "m", "analysis_path": ""},
                {"name": "page3", "status": "success", "endpoint": "http://api2/v1",
                 "model": "m", "analysis_path": ""},
            ],
        }
        result = analyze_cross_target(batch_summary, artifacts_dir=tempfile.mkdtemp())
        assert result["analyzed"] is True
        shared = result["shared_endpoints"]
        assert "http://api/v1" in shared
        assert "page1" in shared["http://api/v1"]
        assert "page2" in shared["http://api/v1"]

    def test_analyze_fully_isolated(self):
        """完全隔离的风险域"""
        from pipeline.cross_target import analyze_cross_target

        batch_summary = {
            "targets": [
                {"name": "page1", "status": "success", "endpoint": "http://a",
                 "model": "m", "analysis_path": ""},
                {"name": "page2", "status": "success", "endpoint": "http://b",
                 "model": "m", "analysis_path": ""},
            ],
        }
        result = analyze_cross_target(batch_summary, artifacts_dir=tempfile.mkdtemp())
        assert result["risk_domains"]["isolation"] == "fully_isolated"


# ============================================================
# compliance_map 模块测试
# ============================================================
class TestComplianceMap:
    """合规框架映射模块测试"""

    def test_mapping_completeness(self):
        """OWASP LLM Top10 全 10 类都有合规映射"""
        from pipeline.compliance_map import OWASP_TO_COMPLIANCE

        assert len(OWASP_TO_COMPLIANCE) == 10
        for _cat, mappings in OWASP_TO_COMPLIANCE.items():
            assert "GDPR" in mappings
            assert "ISO27001" in mappings
            assert "NIST_AI_RMF" in mappings
            assert "EU_AI_ACT" in mappings

    def test_generate_compliance_report(self):
        """生成合规报告"""
        from pipeline.compliance_map import generate_compliance_report

        analysis = {
            "overall": {"defcon": 2, "worst_asr": 45.5},
            "target_model": "test-model",
            "owasp_llm": {
                "LLM01_Prompt_Injection": {"worst_asr": 45.5, "defcon": 2},
                "LLM06_Sensitive_Information_Disclosure": {"worst_asr": 10.0, "defcon": 3},
                "LLM09_Misinformation": {"worst_asr": 0, "defcon": 5},
            },
        }
        tmpdir = tempfile.mkdtemp()
        result = generate_compliance_report(analysis, "test_run", tmpdir)

        assert result["run_id"] == "test_run"
        assert result["overall_defcon"] == 2
        assert "GDPR" in result["compliance_checklist"]
        assert "ISO27001" in result["compliance_checklist"]
        gdpr = result["compliance_checklist"]["GDPR"]
        # LLM01 (defcon=2 → fail) and LLM06 (defcon=3 → warn) should be in findings
        assert gdpr["failed"] >= 1
        assert gdpr["warned"] >= 1
        # LLM09 (defcon=5, asr=0) should NOT be in findings
        finding_cats = [f["owasp_category"] for f in gdpr["findings"]]
        assert "LLM09_Misinformation" not in finding_cats
        assert Path(result["output_path"]).exists()

    def test_compliance_score(self):
        """合规评分计算"""
        from pipeline.compliance_map import generate_compliance_report

        analysis = {
            "overall": {"defcon": 5, "worst_asr": 0},
            "owasp_llm": {},
        }
        tmpdir = tempfile.mkdtemp()
        result = generate_compliance_report(analysis, "clean_run", tmpdir)
        for fw in result["compliance_checklist"].values():
            assert fw["compliance_score"] >= 0
