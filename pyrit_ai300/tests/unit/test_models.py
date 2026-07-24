"""
数据模型测试
==============

测试 src.core.models 中的数据模型，特别是 OWASPFinding。

遵循开发规则 1.4.9 测试先行原则
"""

import pytest
from pydantic import ValidationError

from src.core.models import (
    OWASPFinding,
    AISystemType,
    AuthType,
    AuthStatus,
    ReconResult,
    AuthResult,
    StrategySelection,
    ReportResult,
    ReportSummary,
)


# ============================================================
# OWASPFinding 模型测试
# ============================================================


class TestOWASPFinding:
    """测试 OWASPFinding 数据模型"""

    def test_create_llm_finding(self):
        """测试创建 LLM 框架的 OWASP Finding"""
        finding = OWASPFinding(
            owasp_id="LLM01",
            owasp_name="Prompt Injection",
            owasp_framework="llm",
            severity="HIGH",
            cvss_score=8.5,
            attack_type="prompt_injection",
            description="测试描述",
            indicators=["指标1"],
            remediation=["修复1"],
            confidence=0.9,
        )
        assert finding.owasp_id == "LLM01"
        assert finding.owasp_framework == "llm"
        assert finding.severity == "HIGH"

    def test_create_asi_finding(self):
        """测试创建 Agentic AI 框架的 OWASP Finding"""
        finding = OWASPFinding(
            owasp_id="ASI01",
            owasp_name="Goal Hijacking",
            owasp_framework="agentic",
            severity="HIGH",
            cvss_score=8.0,
            attack_type="goal_hijack",
            description="测试描述",
            indicators=["指标1"],
            remediation=["修复1"],
            confidence=0.9,
        )
        assert finding.owasp_id == "ASI01"
        assert finding.owasp_framework == "agentic"

    def test_default_framework_is_llm(self):
        """测试默认框架为 llm"""
        finding = OWASPFinding(
            owasp_id="LLM01",
            owasp_name="Prompt Injection",
            severity="HIGH",
            cvss_score=8.5,
            attack_type="prompt_injection",
            description="测试",
            indicators=[],
            remediation=[],
            confidence=0.5,
        )
        assert finding.owasp_framework == "llm"

    def test_confidence_range_validation(self):
        """测试 confidence 值范围验证"""
        with pytest.raises(ValidationError):
            OWASPFinding(
                owasp_id="LLM01",
                owasp_name="Test",
                severity="HIGH",
                cvss_score=8.0,
                attack_type="test",
                description="test",
                indicators=[],
                remediation=[],
                confidence=1.5,  # 超出范围
            )

    def test_optional_fields_default_empty(self):
        """测试可选字段默认为空列表"""
        finding = OWASPFinding(
            owasp_id="LLM01",
            owasp_name="Test",
            severity="HIGH",
            cvss_score=8.0,
            attack_type="test",
            description="test",
            indicators=[],
            remediation=[],
            confidence=0.5,
        )
        assert finding.evidence_ids == []
        assert finding.mitre_techniques == []
        assert finding.kill_chain_phases == []


# ============================================================
# AISystemType 枚举测试
# ============================================================


class TestAISystemType:
    """测试 AISystemType 枚举"""

    def test_pyrit_attackable_types(self):
        """测试 PyRIT 可攻击的类型"""
        attackable = [AISystemType.LLM, AISystemType.MULTI_AGENT, AISystemType.MCP_SERVER, AISystemType.RAG]
        for t in attackable:
            assert t.is_pyrit_attackable() is True

    def test_non_pyrit_attackable_types(self):
        """测试非 PyRIT 可攻击的类型"""
        non_attackable = [AISystemType.EMBEDDINGS, AISystemType.INFRASTRUCTURE]
        for t in non_attackable:
            assert t.is_pyrit_attackable() is False
