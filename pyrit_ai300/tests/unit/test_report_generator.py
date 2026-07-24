"""
报告生成器测试
==============

测试 OWASPMapper 的映射功能。

遵循开发规则 1.4.9 测试先行原则
"""

import pytest
from unittest.mock import MagicMock, patch

from src.reporting.report_generator import OWASPMapper
from src.core.models import OWASPFinding


# ============================================================
# OWASPMapper 测试
# ============================================================


class TestOWASPMapper:
    """测试 OWASP 映射器"""

    @pytest.fixture
    def mapper(self):
        """创建 OWASP 映射器实例"""
        return OWASPMapper()

    def test_attack_to_owasp_prompt_injection(self, mapper):
        """测试 prompt_injection 映射到 LLM01"""
        result = mapper.attack_to_owasp("prompt_injection")
        assert "LLM01" in result

    def test_attack_to_owasp_jailbreak(self, mapper):
        """测试 jailbreak 映射到 LLM01 和 LLM07"""
        result = mapper.attack_to_owasp("jailbreak")
        assert "LLM01" in result
        assert "LLM07" in result

    def test_attack_to_owasp_goal_hijack(self, mapper):
        """测试 goal_hijack 映射到 ASI01"""
        result = mapper.attack_to_owasp("goal_hijack")
        assert "ASI01" in result

    def test_attack_to_owasp_tool_misuse(self, mapper):
        """测试 tool_misuse 映射到 ASI02"""
        result = mapper.attack_to_owasp("tool_misuse")
        assert "ASI02" in result

    def test_attack_to_owasp_class_name_prompt_sending(self, mapper):
        """测试通过类名映射 PromptSendingAttack"""
        result = mapper.attack_to_owasp("PromptSendingAttack")
        assert "LLM01" in result

    def test_attack_to_owasp_class_name_xpia(self, mapper):
        """测试通过类名映射 XPIATestWorkflow"""
        result = mapper.attack_to_owasp("XPIATestWorkflow")
        assert len(result) > 0

    def test_attack_to_owasp_invalid_type(self, mapper):
        """测试无效攻击类型返回空列表"""
        result = mapper.attack_to_owasp("invalid_attack")
        assert result == []

    def test_get_owasp_details_llm(self, mapper):
        """测试获取 LLM OWASP 详情"""
        details = mapper.get_owasp_details("LLM01")
        assert details is not None
        assert details["name"] == "Prompt Injection"

    def test_get_owasp_details_asi(self, mapper):
        """测试获取 Agentic AI OWASP 详情"""
        details = mapper.get_owasp_details("ASI01")
        assert details is not None
        assert details["name"] == "Goal Hijacking"

    def test_get_owasp_details_invalid(self, mapper):
        """测试获取无效 OWASP ID 的详情"""
        details = mapper.get_owasp_details("INVALID")
        assert details is None

    def test_map_attacks_to_findings_with_llm(self, mapper):
        """测试映射 LLM 攻击结果到 OWASP Finding"""
        mock_result = MagicMock()
        mock_result.attack_type = "prompt_injection"

        findings = mapper.map_attacks_to_findings([mock_result])
        assert len(findings) > 0
        finding = findings[0]
        assert isinstance(finding, OWASPFinding)
        assert finding.owasp_framework == "llm"

    def test_map_attacks_to_findings_with_asi(self, mapper):
        """测试映射 Agentic AI 攻击结果到 OWASP Finding"""
        mock_result = MagicMock()
        mock_result.attack_type = "goal_hijack"

        findings = mapper.map_attacks_to_findings([mock_result])
        assert len(findings) > 0
        finding = findings[0]
        assert isinstance(finding, OWASPFinding)
        assert finding.owasp_framework == "agentic"

    def test_map_attacks_to_findings_mixed(self, mapper):
        """测试映射混合攻击结果"""
        mock_result1 = MagicMock()
        mock_result1.attack_type = "prompt_injection"

        mock_result2 = MagicMock()
        mock_result2.attack_type = "goal_hijack"

        findings = mapper.map_attacks_to_findings([mock_result1, mock_result2])
        assert len(findings) >= 2

        frameworks = {f.owasp_framework for f in findings}
        assert "llm" in frameworks
        assert "agentic" in frameworks

    def test_map_attacks_to_findings_empty(self, mapper):
        """测试空攻击结果列表"""
        findings = mapper.map_attacks_to_findings([])
        assert findings == []

    def test_attack_class_to_category_includes_agentic(self, mapper):
        """测试攻击类名映射包含 Agentic AI 相关攻击"""
        assert "ManyShotJailbreakAttack" in mapper.ATTACK_CLASS_TO_CATEGORY
        assert "SkeletonKeyAttack" in mapper.ATTACK_CLASS_TO_CATEGORY
        assert "RolePlayAttack" in mapper.ATTACK_CLASS_TO_CATEGORY
