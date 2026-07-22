# -*- coding: utf-8 -*-
"""
P3 测试：框架配置文件 + 风险分类 + 全量集成验证

验证：
1. config/attack/framework_config.yaml 配置文件格式正确
2. risk_category.py 风险分类功能完整
3. 配置 → 框架实例的端到端加载
4. 所有阶段（P0-P3）集成验证
"""

import pytest
import yaml
import json
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# 1. 框架配置文件验证
# ──────────────────────────────────────────────────────────────────────────────

class TestFrameworkConfigYaml:
    """验证 config/attack/framework_config.yaml 配置文件"""

    @pytest.fixture
    def config_path(self):
        return Path(__file__).parent.parent.parent / "config" / "attack" / "framework_config.yaml"

    def test_config_file_exists(self, config_path):
        assert config_path.exists()

    def test_config_has_framework(self, config_path):
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert "framework" in config
        assert config["framework"] == "owasp_llm_2025"

    def test_config_has_depth(self, config_path):
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert "depth" in config
        assert config["depth"] in ("quick", "standard", "deep")

    def test_config_has_report_section(self, config_path):
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert "report" in config
        assert "include_framework_info" in config["report"]
        assert "include_coverage_matrix" in config["report"]
        assert "include_remediation_roadmap" in config["report"]

    def test_config_has_deepteam_section(self, config_path):
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert "deepteam" in config
        assert "async_mode" in config["deepteam"]

    def test_config_has_profiles(self, config_path):
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert "profiles" in config
        profiles = config["profiles"]
        assert "llm_quick" in profiles
        assert "llm_standard" in profiles
        assert "agentic" in profiles

    def test_config_profiles_valid_frameworks(self, config_path):
        from pyrit_ai300.standards.framework_registry import list_frameworks
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        valid_ids = list_frameworks()
        for name, profile in config["profiles"].items():
            fw_id = profile.get("framework", "")
            assert fw_id in valid_ids, f"Profile {name} has invalid framework: {fw_id}"


# ──────────────────────────────────────────────────────────────────────────────
# 2. 风险分类功能验证
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskCategoriesComplete:
    """验证风险分类功能的完整性"""

    def test_all_owasp_ids_have_risk_category(self):
        """所有 OWASP ID 都映射到风险类别"""
        from pyrit_ai300.standards.owasp_2025 import get_all_owasp_ids
        from pyrit_ai300.standards.risk_category import get_risk_category
        for owasp_id in get_all_owasp_ids():
            cat = get_risk_category(owasp_id)
            assert cat is not None, f"{owasp_id} has no risk category"

    def test_risk_category_has_parent_chain(self):
        """子类别有父类别链"""
        from pyrit_ai300.standards.risk_category import RISK_CATEGORIES, get_top_level_categories
        top_ids = {c.category_id for c in get_top_level_categories()}
        for cat in RISK_CATEGORIES.values():
            if cat.parent:
                assert cat.parent in RISK_CATEGORIES, f"{cat.category_id} parent '{cat.parent}' not found"
                # 递归到顶级
                current = cat
                visited = set()
                while current.parent:
                    assert current.category_id not in visited, "Circular reference!"
                    visited.add(current.category_id)
                    current = RISK_CATEGORIES[current.parent]
                assert current.category_id in top_ids

    def test_top_level_categories_count(self):
        """顶级类别数量正确"""
        from pyrit_ai300.standards.risk_category import get_top_level_categories
        top = get_top_level_categories()
        assert len(top) >= 4  # responsible_ai, security, data_privacy, agentic_security


# ──────────────────────────────────────────────────────────────────────────────
# 3. 端到端配置加载验证
# ──────────────────────────────────────────────────────────────────────────────

class TestEndToEndConfigLoading:
    """验证从 YAML 配置到框架实例的端到端加载"""

    def test_load_framework_from_config(self):
        """从配置加载框架实例"""
        from pyrit_ai300.standards.framework_registry import select_framework_from_config
        config = {"framework": "owasp_llm_2025"}
        fw = select_framework_from_config(config)
        assert fw is not None
        assert fw.framework_id == "owasp_llm_2025"

    def test_load_framework_from_yaml_file(self):
        """从 YAML 文件加载框架配置"""
        from pyrit_ai300.standards.framework_registry import select_framework_from_config
        config_path = Path(__file__).parent.parent.parent / "config" / "attack" / "framework_config.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        fw = select_framework_from_config(config)
        assert fw is not None
        assert fw.framework_id == "owasp_llm_2025"

    def test_load_agentic_profile_from_yaml(self):
        """从 YAML profiles 加载 agentic 框架"""
        from pyrit_ai300.standards.framework_registry import select_framework_from_config
        config_path = Path(__file__).parent.parent.parent / "config" / "attack" / "framework_config.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        agentic_profile = config["profiles"]["agentic"]
        fw = select_framework_from_config(agentic_profile)
        assert fw is not None
        assert fw.framework_id == "owasp_asi_2026"


# ──────────────────────────────────────────────────────────────────────────────
# 4. 全量集成验证（P0-P3）
# ──────────────────────────────────────────────────────────────────────────────

class TestFullIntegration:
    """全量集成验证：P0-P3 所有组件协同工作"""

    def test_owasp_mapping_consistent_across_all_modules(self):
        """所有模块使用同一 OWASP 映射来源"""
        from pyrit_ai300.standards.owasp_2025 import (
            OWASP_LLM_2025, OWASP_ASI_2026, DEEPTEAM_TO_OWASP,
            GARAK_TO_OWASP, KEYWORD_TO_OWASP,
        )
        # 所有映射表的值都引用有效的 OWASP ID
        all_ids = set(OWASP_LLM_2025.keys()) | set(OWASP_ASI_2026.keys())
        for mapping in [DEEPTEAM_TO_OWASP, GARAK_TO_OWASP, KEYWORD_TO_OWASP]:
            for owasp_id in mapping.values():
                assert owasp_id in all_ids, f"Invalid OWASP ID: {owasp_id}"

    def test_framework_uses_owasp_mapping(self):
        """框架实现使用 OWASP 映射"""
        from pyrit_ai300.standards.owasp_llm_framework import OWASPLinearFramework2025
        from pyrit_ai300.standards.owasp_2025 import OWASP_LLM_2025
        fw = OWASPLinearFramework2025()
        for v in fw.get_vulnerabilities():
            assert v.vuln_id in OWASP_LLM_2025
            entry = OWASP_LLM_2025[v.vuln_id]
            assert v.title == entry.title

    def test_report_generator_uses_standards(self):
        """报告生成器使用标准模块"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        # 验证方法论节使用动态 OWASP 映射
        methodology = gen._methodology()
        assert "OWASP_LLM_2025" in repr(gen._methodology.__code__.co_consts) or "2025" in methodology
        # 验证覆盖矩阵使用 OWASP 标准模块
        matrix = gen._owasp_coverage_matrix()
        assert "LLM01" in matrix

    def test_risk_assessment_uses_standards(self):
        """风险评估使用标准模块"""
        from pyrit_ai300.reporting.risk_assessment import build_risk_assessment
        results = [
            {
                "module": "test",
                "owasp_mapping": "LLM01",
                "summary": {"total_payloads": 1, "successful_payloads": 1, "failed_payloads": 0},
                "findings": [
                    {"category": "prompt_injection", "severity": "critical", "owasp_mapping": "LLM01"}
                ],
            }
        ]
        assessment = build_risk_assessment(results, framework_id="owasp_llm_2025")
        assert assessment.findings[0].owasp_id == "LLM01"
        assert assessment.findings[0].owasp_title == "Prompt Injection"

    def test_framework_config_yaml_end_to_end(self):
        """框架配置文件端到端验证"""
        from pyrit_ai300.standards.framework_registry import select_framework_from_config
        config_path = Path(__file__).parent.parent.parent / "config" / "attack" / "framework_config.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

        # 加载默认框架
        fw = select_framework_from_config(config)
        assert fw is not None
        assert fw.framework_id == "owasp_llm_2025"
        assert len(fw.get_vulnerabilities()) == 10

        # 加载 agentic profile
        agentic = config["profiles"]["agentic"]
        fw2 = select_framework_from_config(agentic)
        assert fw2 is not None
        assert fw2.framework_id == "owasp_asi_2026"
        assert len(fw2.get_vulnerabilities()) == 10

    def test_deepteam_adapter_uses_standards_mapping(self):
        """DeepTeam 适配器使用标准映射"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import VULNERABILITY_OWASP_MAP
        from pyrit_ai300.standards.owasp_2025 import DEEPTEAM_TO_OWASP
        assert VULNERABILITY_OWASP_MAP is DEEPTEAM_TO_OWASP

    def test_taxonomy_uses_standards(self):
        """OwaspTaxonomy 使用标准映射"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy
        from pyrit_ai300.standards.owasp_2025 import DEEPTEAM_TO_OWASP, GARAK_TO_OWASP
        assert OwaspTaxonomy.DEEPTEAM_TO_OWASP is DEEPTEAM_TO_OWASP
        assert OwaspTaxonomy.GARAK_TO_OWASP is GARAK_TO_OWASP
