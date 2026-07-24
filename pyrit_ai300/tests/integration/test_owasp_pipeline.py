"""
OWASP 映射管道集成测试
======================

测试从配置文件到 OWASP 映射结果的端到端流程。

遵循开发规则 1.4.9 测试先行原则
"""

import pytest
from unittest.mock import MagicMock

from src.core.config_loader import ConfigLoader
from src.reporting.report_generator import OWASPMapper
from src.core.models import OWASPFinding


# ============================================================
# OWASP 端到端映射集成测试
# ============================================================


class TestOWASPPipeline:
    """测试 OWASP 映射的端到端流程"""

    @pytest.fixture
    def config_loader(self):
        """创建配置加载器"""
        return ConfigLoader()

    @pytest.fixture
    def mapper(self):
        """创建 OWASP 映射器"""
        return OWASPMapper()

    def test_full_pipeline_llm_attack(self, config_loader, mapper):
        """测试完整的 LLM 攻击映射管道"""
        # 1. 加载配置
        llm_top_10 = config_loader.get_owasp_llm_top_10()
        assert len(llm_top_10) == 10

        # 2. 映射攻击类型
        owasp_ids = mapper.attack_to_owasp("prompt_injection")
        assert "LLM01" in owasp_ids

        # 3. 获取详情
        details = mapper.get_owasp_details("LLM01")
        assert details is not None
        assert details["version"] == "2025"

        # 4. 映射到 Finding
        mock_result = MagicMock()
        mock_result.attack_type = "prompt_injection"
        findings = mapper.map_attacks_to_findings([mock_result])

        assert len(findings) > 0
        finding = findings[0]
        assert isinstance(finding, OWASPFinding)
        assert finding.owasp_id == "LLM01"
        assert finding.owasp_framework == "llm"
        assert finding.owasp_name == "Prompt Injection"

    def test_full_pipeline_agentic_attack(self, config_loader, mapper):
        """测试完整的 Agentic AI 攻击映射管道"""
        # 1. 加载配置
        asi_top_10 = config_loader.get_owasp_asi_top_10()
        assert len(asi_top_10) == 10

        # 2. 映射攻击类型
        owasp_ids = mapper.attack_to_owasp("goal_hijack")
        assert "ASI01" in owasp_ids

        # 3. 获取详情
        details = mapper.get_owasp_details("ASI01")
        assert details is not None
        assert details["name"] == "Goal Hijacking"

        # 4. 映射到 Finding
        mock_result = MagicMock()
        mock_result.attack_type = "goal_hijack"
        findings = mapper.map_attacks_to_findings([mock_result])

        assert len(findings) > 0
        finding = findings[0]
        assert isinstance(finding, OWASPFinding)
        assert finding.owasp_id == "ASI01"
        assert finding.owasp_framework == "agentic"

    def test_all_llm_mappings_resolve(self, config_loader, mapper):
        """测试所有 LLM 攻击映射都能正确解析"""
        attack_to_owasp = config_loader.get_owasp_mapping()
        all_standards = config_loader.get_all_owasp_standards()

        for attack_type, owasp_ids in attack_to_owasp.items():
            for owasp_id in owasp_ids:
                # 每个 OWASP ID 都能找到详情
                details = all_standards.get(owasp_id)
                assert details is not None, (
                    f"攻击类型 '{attack_type}' 引用的 {owasp_id} 无详情"
                )
                # 每个 OWASP ID 都有名称
                assert "name" in details, f"{owasp_id} 缺少 name 字段"
                # 每个 OWASP ID 都有 severity
                assert "severity" in details, f"{owasp_id} 缺少 severity 字段"

    def test_dual_framework_findings(self, mapper):
        """测试同时生成 LLM 和 Agentic AI 的 Finding"""
        results = []
        for attack_type in ["prompt_injection", "goal_hijack", "tool_misuse"]:
            mock = MagicMock()
            mock.attack_type = attack_type
            results.append(mock)

        findings = mapper.map_attacks_to_findings(results)
        assert len(findings) >= 3

        llm_findings = [f for f in findings if f.owasp_framework == "llm"]
        agentic_findings = [f for f in findings if f.owasp_framework == "agentic"]

        assert len(llm_findings) > 0, "应有 LLM 框架的 finding"
        assert len(agentic_findings) > 0, "应有 Agentic AI 框架的 finding"

    def test_owasp_2025_compliance(self, config_loader):
        """测试 OWASP LLM Top 10 对齐 2025 版本"""
        llm_top_10 = config_loader.get_owasp_llm_top_10()

        # 验证 2025 版本的特定名称
        assert llm_top_10["LLM02"]["name"] == "Sensitive Information Disclosure"
        assert llm_top_10["LLM03"]["name"] == "Supply Chain"
        assert llm_top_10["LLM05"]["name"] == "Improper Output Handling"
        assert llm_top_10["LLM07"]["name"] == "System Prompt Leakage"
        assert llm_top_10["LLM08"]["name"] == "Vector and Embedding Weaknesses"
        assert llm_top_10["LLM09"]["name"] == "Misinformation"
        assert llm_top_10["LLM10"]["name"] == "Unbounded Consumption"

    def test_no_old_2023_names(self, config_loader):
        """测试不包含旧的 2023 版本名称"""
        llm_top_10 = config_loader.get_owasp_llm_top_10()
        old_names = {
            "Insecure Output Handling",
            "Training Data Poisoning",
            "Model Denial of Service",
            "Supply Chain Vulnerabilities",
            "Insecure Plugin Design",
            "Over-Reliance",
            "Model Theft",
        }
        for owasp_id, entry in llm_top_10.items():
            assert entry["name"] not in old_names, (
                f"{owasp_id} 仍使用旧的 2023 版本名称: {entry['name']}"
            )
