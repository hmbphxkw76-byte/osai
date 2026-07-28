"""
OWASP 映射测试
==============

测试 OWASP 安全标准映射的正确性，包括：
- OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10)
- OWASP Top 10 for Agentic AI (ASI01-ASI10)
- 攻击类型到 OWASP ID 的映射
- 配置文件加载和解析

遵循开发规则 1.4.9 测试先行原则
"""

import yaml
import pytest


# ============================================================
# 配置文件加载测试
# ============================================================


class TestOWASPMappingConfig:
    """测试 OWASP 映射配置文件的正确性"""

    @pytest.fixture
    def owasp_config(self):
        """加载 OWASP 映射配置文件（系统默认在 src/core/defaults/）"""
        from src.core.config_loader import ConfigLoader
        config_path = ConfigLoader().owasp_file
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_config_file_exists(self):
        """测试配置文件存在"""
        from src.core.config_loader import ConfigLoader
        config_path = ConfigLoader().owasp_file
        assert config_path.exists(), f"OWASP 映射配置文件不存在: {config_path}"

    def test_llm_top_10_has_10_entries(self, owasp_config):
        """测试 LLM Top 10 有 10 个条目"""
        llm_top_10 = owasp_config.get("owasp_llm_top_10", {})
        assert len(llm_top_10) == 10, f"LLM Top 10 应有 10 个条目，实际有 {len(llm_top_10)}"

    def test_asi_top_10_has_10_entries(self, owasp_config):
        """测试 Agentic AI Top 10 有 10 个条目"""
        asi_top_10 = owasp_config.get("owasp_asi_top_10", {})
        assert len(asi_top_10) == 10, f"Agentic AI Top 10 应有 10 个条目，实际有 {len(asi_top_10)}"

    def test_llm_top_10_ids_are_correct(self, owasp_config):
        """测试 LLM Top 10 的 ID 是 LLM01-LLM10"""
        llm_top_10 = owasp_config.get("owasp_llm_top_10", {})
        expected_ids = {f"LLM0{i}" for i in range(1, 10)} | {"LLM10"}
        actual_ids = set(llm_top_10.keys())
        assert actual_ids == expected_ids, f"LLM Top 10 ID 不匹配: 期望 {expected_ids}, 实际 {actual_ids}"

    def test_asi_top_10_ids_are_correct(self, owasp_config):
        """测试 Agentic AI Top 10 的 ID 是 ASI01-ASI10"""
        asi_top_10 = owasp_config.get("owasp_asi_top_10", {})
        expected_ids = {f"ASI0{i}" for i in range(1, 10)} | {"ASI10"}
        actual_ids = set(asi_top_10.keys())
        assert actual_ids == expected_ids, f"Agentic AI Top 10 ID 不匹配: 期望 {expected_ids}, 实际 {actual_ids}"

    def test_llm_top_10_names_are_2025_version(self, owasp_config):
        """测试 LLM Top 10 名称对齐 2025 版本"""
        llm_top_10 = owasp_config.get("owasp_llm_top_10", {})
        expected_names = {
            "LLM01": "Prompt Injection",
            "LLM02": "Sensitive Information Disclosure",
            "LLM03": "Supply Chain",
            "LLM04": "Data and Model Poisoning",
            "LLM05": "Improper Output Handling",
            "LLM06": "Excessive Agency",
            "LLM07": "System Prompt Leakage",
            "LLM08": "Vector and Embedding Weaknesses",
            "LLM09": "Misinformation",
            "LLM10": "Unbounded Consumption",
        }
        for owasp_id, expected_name in expected_names.items():
            actual_name = llm_top_10.get(owasp_id, {}).get("name", "")
            assert actual_name == expected_name, (
                f"{owasp_id} 名称不匹配: 期望 '{expected_name}', 实际 '{actual_name}'"
            )

    def test_asi_top_10_names_are_correct(self, owasp_config):
        """测试 Agentic AI Top 10 名称正确"""
        asi_top_10 = owasp_config.get("owasp_asi_top_10", {})
        expected_names = {
            "ASI01": "Goal Hijacking",
            "ASI02": "Tool Misuse",
            "ASI03": "Identity Abuse",
            "ASI04": "Supply Chain (Agentic)",
            "ASI05": "Code Execution",
            "ASI06": "Agentic Memory Attack",
            "ASI07": "Agent Communication",
            "ASI08": "Cascading Failures",
            "ASI09": "Trust Exploitation",
            "ASI10": "Rogue AI Agent",
        }
        for owasp_id, expected_name in expected_names.items():
            actual_name = asi_top_10.get(owasp_id, {}).get("name", "")
            assert actual_name == expected_name, (
                f"{owasp_id} 名称不匹配: 期望 '{expected_name}', 实际 '{actual_name}'"
            )

    def test_llm_top_10_not_using_old_2023_names(self, owasp_config):
        """测试 LLM Top 10 不包含旧的 2023 版本名称"""
        llm_top_10 = owasp_config.get("owasp_llm_top_10", {})
        old_names = [
            "Insecure Output Handling",
            "Training Data Poisoning",
            "Model Denial of Service",
            "Supply Chain Vulnerabilities",
            "Insecure Plugin Design",
            "Over-Reliance",
            "Model Theft",
        ]
        for entry in llm_top_10.values():
            assert entry.get("name", "") not in old_names, (
                f"发现旧的 2023 版本名称: {entry.get('name')}"
            )

    def test_llm_entries_have_version_field(self, owasp_config):
        """测试 LLM Top 10 每个条目都有 version 字段且值为 2025"""
        llm_top_10 = owasp_config.get("owasp_llm_top_10", {})
        for owasp_id, entry in llm_top_10.items():
            version = entry.get("version", "")
            assert version == "2025", (
                f"{owasp_id} 版本字段应为 '2025', 实际为 '{version}'"
            )

    def test_each_entry_has_required_fields(self, owasp_config):
        """测试每个 OWASP 条目都有必需字段"""
        required_fields = ["name", "severity", "cvss_base", "description"]
        for section in ["owasp_llm_top_10", "owasp_asi_top_10"]:
            standards = owasp_config.get(section, {})
            for owasp_id, entry in standards.items():
                for field in required_fields:
                    assert field in entry, (
                        f"{section}.{owasp_id} 缺少必需字段: {field}"
                    )

    def test_attack_to_owasp_mapping_exists(self, owasp_config):
        """测试攻击类型到 OWASP 的映射存在"""
        attack_to_owasp = owasp_config.get("attack_to_owasp", {})
        assert len(attack_to_owasp) > 0, "attack_to_owasp 映射为空"

    def test_attack_to_owasp_mappings_are_valid(self, owasp_config):
        """测试攻击类型到 OWASP 的映射引用有效的 OWASP ID"""
        attack_to_owasp = owasp_config.get("attack_to_owasp", {})
        llm_top_10 = owasp_config.get("owasp_llm_top_10", {})
        asi_top_10 = owasp_config.get("owasp_asi_top_10", {})
        all_valid_ids = set(llm_top_10.keys()) | set(asi_top_10.keys())

        for attack_type, owasp_ids in attack_to_owasp.items():
            for owasp_id in owasp_ids:
                assert owasp_id in all_valid_ids, (
                    f"攻击类型 '{attack_type}' 引用了无效的 OWASP ID: {owasp_id}"
                )

    def test_kill_chain_mapping_exists(self, owasp_config):
        """测试 Cyber Kill Chain 映射存在"""
        kill_chain = owasp_config.get("kill_chain_mapping", {})
        assert len(kill_chain) > 0, "kill_chain_mapping 为空"

    def test_kill_chain_has_all_phases(self, owasp_config):
        """测试 Cyber Kill Chain 包含所有阶段"""
        kill_chain = owasp_config.get("kill_chain_mapping", {})
        expected_phases = [
            "reconnaissance",
            "weaponization",
            "delivery",
            "exploitation",
            "installation",
            "command_and_control",
            "actions_on_objectives",
        ]
        for phase in expected_phases:
            assert phase in kill_chain, f"Kill Chain 缺少阶段: {phase}"
