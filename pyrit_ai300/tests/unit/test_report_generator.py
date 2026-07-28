"""
报告生成器测试
==============

测试 OWASPMapper 的映射功能。

遵循开发规则 1.4.9 测试先行原则
"""

import pytest
from unittest.mock import MagicMock

from src.reporting.report_generator import OWASPMapper
from src.core.models import OWASPFinding


# ============================================================
# 测试辅助函数
# ============================================================


def _make_mock_attack_result(attack_type: str, outcome: str = "success") -> MagicMock:
    """
    创建模拟的 AttackResult

    正确 mock get_attack_strategy_identifier() 和其他属性，
    使其行为与真实 AttackResult 一致。
    """
    mock = MagicMock()

    # get_attack_strategy_identifier 返回 None，使代码回退到 atomic_attack_identifier
    mock.get_attack_strategy_identifier.return_value = None

    # 设置 atomic_attack_identifier 为攻击类型字符串
    mock.atomic_attack_identifier = attack_type

    # 设置其他常用属性
    mock.objective = f"Test objective for {attack_type}"
    mock.conversation_id = f"conv-test-{attack_type}"
    mock.attack_result_id = f"ar-test-{attack_type}"
    mock.executed_turns = 1
    mock.execution_time_ms = 1000
    mock.outcome = MagicMock()
    mock.outcome.value = outcome
    mock.outcome_reason = ""
    mock.last_score = None
    mock.labels = {"attack_technique": attack_type}
    mock.metadata = {}
    mock.error_message = ""
    mock.timestamp = "2025-01-01T00:00:00"
    mock.related_conversations = []
    mock.error_type = ""
    mock.error_traceback = ""
    mock.retry_events = []
    mock.total_retries = 0
    mock.attribution_parent_id = None
    mock.attribution_data = None

    return mock


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
        mock_result = _make_mock_attack_result("prompt_injection")

        findings = mapper.map_attacks_to_findings([mock_result])
        assert len(findings) > 0
        finding = findings[0]
        assert isinstance(finding, OWASPFinding)
        assert finding.owasp_framework == "llm"

    def test_map_attacks_to_findings_with_asi(self, mapper):
        """测试映射 Agentic AI 攻击结果到 OWASP Finding"""
        mock_result = _make_mock_attack_result("goal_hijack")

        findings = mapper.map_attacks_to_findings([mock_result])
        assert len(findings) > 0
        finding = findings[0]
        assert isinstance(finding, OWASPFinding)
        assert finding.owasp_framework == "agentic"

    def test_map_attacks_to_findings_mixed(self, mapper):
        """测试映射混合攻击结果"""
        mock_result1 = _make_mock_attack_result("prompt_injection")
        mock_result2 = _make_mock_attack_result("goal_hijack")

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
        assert "BargeInAttack" in mapper.ATTACK_CLASS_TO_CATEGORY
        assert "ChunkedRequestAttack" in mapper.ATTACK_CLASS_TO_CATEGORY
        assert "XPIATestWorkflow" in mapper.ATTACK_CLASS_TO_CATEGORY
        # PyRIT 1.0.0: RolePlayAttack 已移除（改用 Converter + PromptSendingAttack）
        assert "RolePlayAttack" not in mapper.ATTACK_CLASS_TO_CATEGORY

    def test_build_coverage_matrix(self, mapper):
        """测试构建 OWASP 覆盖矩阵"""
        mock_result1 = _make_mock_attack_result("prompt_injection", outcome="success")
        mock_result2 = _make_mock_attack_result("goal_hijack", outcome="failure")

        matrix = mapper.build_coverage_matrix([mock_result1, mock_result2])

        # LLM01 应被覆盖
        assert "LLM01" in matrix
        assert matrix["LLM01"]["covered"] is True
        assert matrix["LLM01"]["attack_count"] >= 1

        # ASI01 应被覆盖
        assert "ASI01" in matrix
        assert matrix["ASI01"]["covered"] is True

        # 未覆盖的应该 marked as not covered
        assert matrix.get("LLM03", {}).get("covered") is False

    def test_map_attacks_to_findings_with_evidence_ids(self, mapper):
        """测试映射结果包含证据 ID（conversation_id）"""
        mock_result = _make_mock_attack_result("prompt_injection")

        findings = mapper.map_attacks_to_findings([mock_result])
        assert len(findings) > 0
        finding = findings[0]
        assert len(finding.evidence_ids) > 0
        assert "conv-test-prompt_injection" in finding.evidence_ids

    def test_map_attacks_to_findings_dynamic_confidence(self, mapper):
        """测试动态 confidence 计算"""
        # 成功的攻击应该有较高的 confidence
        mock_success = _make_mock_attack_result("prompt_injection", outcome="success")
        success_findings = mapper.map_attacks_to_findings([mock_success])
        assert len(success_findings) > 0
        success_confidence = success_findings[0].confidence
        assert success_confidence > 0

        # 失败的攻击应该有较低的 confidence
        mock_failure = _make_mock_attack_result("prompt_injection", outcome="failure")
        failure_findings = mapper.map_attacks_to_findings([mock_failure])
        assert len(failure_findings) > 0
        failure_confidence = failure_findings[0].confidence

        # 成功的 confidence 应该高于失败的
        assert success_confidence > failure_confidence
