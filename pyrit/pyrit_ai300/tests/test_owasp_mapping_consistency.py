# -*- coding: utf-8 -*-
"""
P0 回归测试：OWASP 2025 映射一致性验证

验证项目中所有 OWASP 映射来源都从 standards/owasp_2025.py 导入，
确保不存在不一致的本地映射表。

覆盖范围：
1. standards/owasp_2025.py 权威模块自身完整性
2. owasp_taxonomy.py 正确导入
3. deepteam/adapter.py VULNERABILITY_OWASP_MAP 正确导入
4. report_generator.py 动态生成覆盖表
5. asi_mapping.yaml 注释对齐 2025
6. 跨模块映射一致性
"""

import pytest
import re
import yaml
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# 1. 权威模块 standards/owasp_2025.py 完整性
# ──────────────────────────────────────────────────────────────────────────────

class TestOwasp2025Authoritative:
    """验证权威映射模块的完整性"""

    def test_owasp_llm_2025_has_10_entries(self):
        """LLM 2025 必须有 10 个条目"""
        from pyrit_ai300.standards.owasp_2025 import OWASP_LLM_2025
        assert len(OWASP_LLM_2025) == 10

    def test_owasp_asi_2026_has_10_entries(self):
        """ASI 2026 必须有 10 个条目"""
        from pyrit_ai300.standards.owasp_2025 import OWASP_ASI_2026
        assert len(OWASP_ASI_2026) == 10

    def test_llm_ids_sequential(self):
        """LLM ID 必须从 LLM01 到 LLM10 连续"""
        from pyrit_ai300.standards.owasp_2025 import OWASP_LLM_2025
        expected = [f"LLM{i:02d}" for i in range(1, 11)]
        assert list(OWASP_LLM_2025.keys()) == expected

    def test_asi_ids_sequential(self):
        """ASI ID 必须从 ASI01 到 ASI10 连续"""
        from pyrit_ai300.standards.owasp_2025 import OWASP_ASI_2026
        expected = [f"ASI{i:02d}" for i in range(1, 11)]
        assert list(OWASP_ASI_2026.keys()) == expected

    def test_every_entry_has_required_fields(self):
        """每个条目必须有必填字段"""
        from pyrit_ai300.standards.owasp_2025 import OWASP_LLM_2025, OWASP_ASI_2026
        required = ["owasp_id", "display_name", "title", "description",
                    "category", "vulnerabilities", "attacks", "severity"]
        for entry in list(OWASP_LLM_2025.values()) + list(OWASP_ASI_2026.values()):
            for field in required:
                assert hasattr(entry, field), f"{entry.owasp_id} missing {field}"

    def test_severity_values_valid(self):
        """严重等级必须是有效值"""
        from pyrit_ai300.standards.owasp_2025 import OWASP_LLM_2025, OWASP_ASI_2026
        valid = {"critical", "high", "medium", "low"}
        for entry in list(OWASP_LLM_2025.values()) + list(OWASP_ASI_2026.values()):
            assert entry.severity in valid, \
                f"{entry.owasp_id} has invalid severity: {entry.severity}"

    def test_get_all_owasp_ids_returns_20(self):
        """get_all_owasp_ids 返回 20 个 ID"""
        from pyrit_ai300.standards.owasp_2025 import get_all_owasp_ids
        ids = get_all_owasp_ids()
        assert len(ids) == 20

    def test_get_owasp_entry_llm(self):
        """get_owasp_entry 正确返回 LLM 条目"""
        from pyrit_ai300.standards.owasp_2025 import get_owasp_entry
        entry = get_owasp_entry("LLM01")
        assert entry is not None
        assert entry.title == "Prompt Injection"

    def test_get_owasp_entry_asi(self):
        """get_owasp_entry 正确返回 ASI 条目"""
        from pyrit_ai300.standards.owasp_2025 import get_owasp_entry
        entry = get_owasp_entry("ASI01")
        assert entry is not None
        assert entry.title == "Agent Goal Hijack"

    def test_get_owasp_entry_case_insensitive(self):
        """get_owasp_entry 大小写不敏感"""
        from pyrit_ai300.standards.owasp_2025 import get_owasp_entry
        assert get_owasp_entry("llm01") is not None
        assert get_owasp_entry("asi01") is not None

    def test_get_owasp_entry_invalid(self):
        """get_owasp_entry 对无效 ID 返回 None"""
        from pyrit_ai300.standards.owasp_2025 import get_owasp_entry
        assert get_owasp_entry("LLM99") is None
        assert get_owasp_entry("INVALID") is None

    def test_normalize_category_deepteam(self):
        """normalize_category 正确映射 DeepTeam 类别"""
        from pyrit_ai300.standards.owasp_2025 import normalize_category
        assert normalize_category("prompt_injection", "deepteam") == "LLM01"
        assert normalize_category("pii_leakage", "deepteam") == "LLM02"
        assert normalize_category("bias", "deepteam") == "LLM04"

    def test_normalize_category_garak(self):
        """normalize_category 正确映射 Garak 类别"""
        from pyrit_ai300.standards.owasp_2025 import normalize_category
        assert normalize_category("promptinject", "garak") == "LLM01"
        assert normalize_category("dan", "garak") == "LLM01"

    def test_normalize_category_already_owasp_id(self):
        """normalize_category 对已是 OWASP ID 的输入直接返回"""
        from pyrit_ai300.standards.owasp_2025 import normalize_category
        assert normalize_category("LLM01") == "LLM01"
        assert normalize_category("ASI01") == "ASI01"

    def test_normalize_category_fallback_keyword(self):
        """normalize_category 兜底关键词匹配"""
        from pyrit_ai300.standards.owasp_2025 import normalize_category
        assert normalize_category("some_injection_attack") == "LLM01"
        assert normalize_category("bias_detection") == "LLM04"

    def test_normalize_category_no_match(self):
        """normalize_category 无匹配返回空字符串"""
        from pyrit_ai300.standards.owasp_2025 import normalize_category
        assert normalize_category("totally_unknown_category") == ""

    def test_resolve_conflict_single_finding(self):
        """resolve_conflict 单个发现不冲突"""
        from pyrit_ai300.standards.owasp_2025 import resolve_conflict
        findings = [{"tool": "garak", "severity": "high", "confidence": 0.8}]
        sev, conf, conflict = resolve_conflict(findings)
        assert sev == "high"
        assert conf == 0.8
        assert conflict is False

    def test_resolve_conflict_multi_tool_agreement(self):
        """resolve_conflict 多工具一致时提升置信度"""
        from pyrit_ai300.standards.owasp_2025 import resolve_conflict
        findings = [
            {"tool": "garak", "severity": "high", "confidence": 0.7},
            {"tool": "deepteam", "severity": "high", "confidence": 0.8},
        ]
        sev, conf, conflict = resolve_conflict(findings)
        assert sev == "high"
        assert conf > 0.8  # 置信度提升
        assert conflict is False

    def test_resolve_conflict_severity_conflict(self):
        """resolve_conflict 严重等级差异大时检测冲突"""
        from pyrit_ai300.standards.owasp_2025 import resolve_conflict
        findings = [
            {"tool": "garak", "severity": "critical", "confidence": 0.9},
            {"tool": "deepteam", "severity": "low", "confidence": 0.5},
        ]
        sev, conf, conflict = resolve_conflict(findings)
        assert sev == "critical"  # 取最高
        assert conflict is True

    def test_get_probe_family(self):
        """get_probe_family 返回正确的探针族"""
        from pyrit_ai300.standards.owasp_2025 import get_probe_family
        assert get_probe_family("LLM01") == "DIRECT_SINGLE"
        assert get_probe_family("LLM06") == "PROGRESSIVE"
        assert get_probe_family("ASI01") == "PROGRESSIVE"


# ──────────────────────────────────────────────────────────────────────────────
# 2. owasp_taxonomy.py 正确导入
# ──────────────────────────────────────────────────────────────────────────────

class TestOwaspTaxonomyImport:
    """验证 owasp_taxonomy.py 从权威来源导入"""

    def test_taxonomy_normalize_uses_standards(self):
        """OwaspTaxonomy.normalize 与 standards 模块一致"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy
        from pyrit_ai300.standards.owasp_2025 import normalize_category
        # 多个测试用例
        for cat, tool in [
            ("prompt_injection", "deepteam"),
            ("dan", "garak"),
            ("bias", "deepteam"),
            ("LLM01", ""),
        ]:
            assert OwaspTaxonomy.normalize(cat, tool) == normalize_category(cat, tool)

    def test_taxonomy_get_probe_family_uses_standards(self):
        """OwaspTaxonomy.get_probe_family 与 standards 模块一致"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy
        from pyrit_ai300.standards.owasp_2025 import get_probe_family
        for owasp_id in ["LLM01", "LLM06", "ASI01", "ASI10"]:
            assert OwaspTaxonomy.get_probe_family(owasp_id) == get_probe_family(owasp_id)

    def test_taxonomy_get_all_ids_uses_standards(self):
        """OwaspTaxonomy.get_all_owasp_ids 与 standards 模块一致"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy
        from pyrit_ai300.standards.owasp_2025 import get_all_owasp_ids
        assert OwaspTaxonomy.get_all_owasp_ids() == get_all_owasp_ids()

    def test_taxonomy_exposes_deepteam_map(self):
        """OwaspTaxonomy 暴露 DEEPTEAM_TO_OWASP 映射表"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy
        assert hasattr(OwaspTaxonomy, "DEEPTEAM_TO_OWASP")
        assert "prompt_injection" in OwaspTaxonomy.DEEPTEAM_TO_OWASP
        assert OwaspTaxonomy.DEEPTEAM_TO_OWASP["prompt_injection"] == "LLM01"

    def test_taxonomy_resolve_conflict_uses_standards(self):
        """OwaspTaxonomy.resolve_conflict 与 standards 模块一致"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy
        from pyrit_ai300.standards.owasp_2025 import resolve_conflict
        findings = [
            {"tool": "garak", "severity": "high", "confidence": 0.7},
            {"tool": "deepteam", "severity": "high", "confidence": 0.8},
        ]
        result_taxonomy = OwaspTaxonomy.resolve_conflict(findings)
        result_standards = resolve_conflict(findings)
        assert result_taxonomy == result_standards


# ──────────────────────────────────────────────────────────────────────────────
# 3. deepteam/adapter.py 映射表正确导入
# ──────────────────────────────────────────────────────────────────────────────

class TestDeepteamAdapterMapping:
    """验证 deepteam/adapter.py 从权威来源导入映射"""

    def test_vulnerability_owasp_map_imported(self):
        """VULNERABILITY_OWASP_MAP 从 standards 导入"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import (
            VULNERABILITY_OWASP_MAP,
        )
        from pyrit_ai300.standards.owasp_2025 import DEEPTEAM_TO_OWASP
        # 验证是同一对象
        assert VULNERABILITY_OWASP_MAP is DEEPTEAM_TO_OWASP

    def test_prompt_injection_maps_to_llm01(self):
        """prompt_injection 映射到 LLM01"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import (
            VULNERABILITY_OWASP_MAP,
        )
        assert VULNERABILITY_OWASP_MAP["prompt_injection"] == "LLM01"

    def test_pii_leakage_maps_to_llm02(self):
        """pii_leakage 映射到 LLM02（2025 版）"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import (
            VULNERABILITY_OWASP_MAP,
        )
        assert VULNERABILITY_OWASP_MAP["pii_leakage"] == "LLM02"

    def test_excessive_agency_maps_to_llm06(self):
        """excessive_agency 映射到 LLM06（2025 版，不是 LLM05）"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import (
            VULNERABILITY_OWASP_MAP,
        )
        assert VULNERABILITY_OWASP_MAP["excessive_agency"] == "LLM06"

    def test_system_prompt_maps_to_llm07(self):
        """system_prompt 映射到 LLM07（2025 版，不是 LLM06）"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import (
            VULNERABILITY_OWASP_MAP,
        )
        assert VULNERABILITY_OWASP_MAP["system_prompt"] == "LLM07"

    def test_attack_types_by_depth_has_3_levels(self):
        """ATTACK_TYPES_BY_DEPTH 有 quick/standard/deep 三个层级"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import (
            ATTACK_TYPES_BY_DEPTH,
        )
        assert "quick" in ATTACK_TYPES_BY_DEPTH
        assert "standard" in ATTACK_TYPES_BY_DEPTH
        assert "deep" in ATTACK_TYPES_BY_DEPTH

    def test_attack_methods_aligned_2025(self):
        """ATTACK_METHODS 包含 2025 版对齐的漏洞类型"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import ATTACK_METHODS
        vuln_names = {m["vulnerability"] for m in ATTACK_METHODS}
        # 验证 2025 版新增的漏洞类型
        assert "pii_leakage" in vuln_names        # LLM02
        assert "excessive_agency" in vuln_names   # LLM06
        assert "resource_exhaustion" in vuln_names  # LLM10
        assert "goal_theft" in vuln_names          # ASI01
        assert "memory_poison" in vuln_names       # ASI06

    def test_attack_methods_severity_critical_for_injection(self):
        """prompt_injection 严重等级为 critical（2025 版）"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import ATTACK_METHODS
        for m in ATTACK_METHODS:
            if m["vulnerability"] == "prompt_injection":
                assert m["severity"] == "critical"
                return
        pytest.fail("prompt_injection not found in ATTACK_METHODS")


# ──────────────────────────────────────────────────────────────────────────────
# 4. report_generator.py 动态生成覆盖表
# ──────────────────────────────────────────────────────────────────────────────

class TestReportGeneratorDynamicOwasp:
    """验证 report_generator.py 动态生成 OWASP 覆盖表"""

    def test_methodology_contains_2025_label(self):
        """_methodology() 包含 2025 标签"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        methodology = gen._methodology()
        assert "2025" in methodology
        assert "LLMs 2025" in methodology

    def test_methodology_contains_asi_2026(self):
        """_methodology() 包含 ASI 2026 覆盖表"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        methodology = gen._methodology()
        assert "Agentic Applications 2026" in methodology
        assert "ASI01" in methodology

    def test_methodology_contains_all_llm_ids(self):
        """_methodology() 包含所有 LLM01-LLM10"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        methodology = gen._methodology()
        for i in range(1, 11):
            assert f"LLM{i:02d}" in methodology, f"LLM{i:02d} not in methodology"

    def test_methodology_contains_all_asi_ids(self):
        """_methodology() 包含所有 ASI01-ASI10"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        methodology = gen._methodology()
        for i in range(1, 11):
            assert f"ASI{i:02d}" in methodology, f"ASI{i:02d} not in methodology"

    def test_methodology_not_using_old_2023_names(self):
        """_methodology() 不包含旧版 2023 名称"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        methodology = gen._methodology()
        # 2023 版的旧名称不应出现
        assert "Insecure Plugin Design" not in methodology
        assert "Model Theft" not in methodology  # 2025 版改为 Unbounded Consumption
        assert "Overreliance" not in methodology  # 2025 版改为 Misinformation

    def test_methodology_has_severity_column(self):
        """_methodology() 包含 Severity 列"""
        from pyrit_ai300.reporting.report_generator import ReportGenerator
        gen = ReportGenerator(results=[])
        methodology = gen._methodology()
        assert "Severity" in methodology
        assert "critical" in methodology


# ──────────────────────────────────────────────────────────────────────────────
# 5. asi_mapping.yaml 注释对齐 2025
# ──────────────────────────────────────────────────────────────────────────────

class TestAsiMappingYamlAlignment:
    """验证 asi_mapping.yaml 注释对齐 2025"""

    @pytest.fixture
    def yaml_path(self):
        return Path(__file__).parent.parent / "attack" / "asi_mapping.yaml"

    def test_yaml_file_exists(self, yaml_path):
        """asi_mapping.yaml 文件存在"""
        assert yaml_path.exists()

    def test_yaml_has_2025_reference(self, yaml_path):
        """YAML 注释中包含 2025 标准引用"""
        content = yaml_path.read_text(encoding="utf-8")
        assert "2025" in content
        assert "owasp_2025" in content

    def test_yaml_llm02_comment_correct(self, yaml_path):
        """LLM02 注释为 Sensitive Information Disclosure（2025 版）"""
        content = yaml_path.read_text(encoding="utf-8")
        assert "Sensitive Information Disclosure" in content

    def test_yaml_llm03_comment_correct(self, yaml_path):
        """LLM03 注释为 Supply Chain（2025 版，非 Training Data Poisoning）"""
        content = yaml_path.read_text(encoding="utf-8")
        assert "Supply Chain" in content
        assert "Training Data Poisoning" not in content

    def test_yaml_llm06_comment_correct(self, yaml_path):
        """LLM06 注释为 Excessive Agency（2025 版）"""
        content = yaml_path.read_text(encoding="utf-8")
        # LLM06 在 2025 版是 Excessive Agency
        assert "Excessive Agency" in content

    def test_yaml_llm07_comment_correct(self, yaml_path):
        """LLM07 注释为 System Prompt Leakage（2025 版）"""
        content = yaml_path.read_text(encoding="utf-8")
        assert "System Prompt Leakage" in content

    def test_yaml_no_old_2023_comments(self, yaml_path):
        """YAML 不包含旧版 2023 注释"""
        content = yaml_path.read_text(encoding="utf-8")
        # 2023 版的旧名称不应出现
        assert "Insecure Plugin Design" not in content
        assert "Model Theft" not in content


# ──────────────────────────────────────────────────────────────────────────────
# 6. 跨模块一致性
# ──────────────────────────────────────────────────────────────────────────────

class TestCrossModuleConsistency:
    """验证所有模块使用同一映射来源"""

    def test_deepteam_map_same_as_standards(self):
        """deepteam/adapter.py 的映射表与 standards 模块一致"""
        from pyrit_ai300.recon.adapters.deepteam.adapter import (
            VULNERABILITY_OWASP_MAP,
        )
        from pyrit_ai300.standards.owasp_2025 import DEEPTEAM_TO_OWASP
        assert VULNERABILITY_OWASP_MAP is DEEPTEAM_TO_OWASP

    def test_taxonomy_map_same_as_standards(self):
        """owasp_taxonomy.py 的映射表与 standards 模块一致"""
        from pyrit_ai300.recon.owasp_taxonomy import OwaspTaxonomy
        from pyrit_ai300.standards.owasp_2025 import DEEPTEAM_TO_OWASP
        assert OwaspTaxonomy.DEEPTEAM_TO_OWASP is DEEPTEAM_TO_OWASP

    def test_report_generator_imports_standards(self):
        """report_generator.py 导入 standards 模块"""
        from pyrit_ai300.reporting import report_generator
        assert hasattr(report_generator, "OWASP_LLM_2025")
        assert hasattr(report_generator, "OWASP_ASI_2026")

    def test_no_local_owasp_map_in_adapter(self):
        """deepteam/adapter.py 不包含本地 VULNERABILITY_OWASP_MAP 定义"""
        adapter_path = Path(__file__).parent.parent / "recon" / "adapters" / "deepteam" / "adapter.py"
        content = adapter_path.read_text(encoding="utf-8")
        # 不应该有本地字典定义（应该只有 import）
        assert "VULNERABILITY_OWASP_MAP = {" not in content
        assert "from ....standards.owasp_2025 import" in content

    def test_no_local_owasp_map_in_taxonomy(self):
        """owasp_taxonomy.py 不包含本地映射表定义"""
        taxonomy_path = Path(__file__).parent.parent / "recon" / "owasp_taxonomy.py"
        content = taxonomy_path.read_text(encoding="utf-8")
        # 不应该有本地字典定义（应该只有 import）
        assert "GARAK_TO_OWASP: Dict[str, str] = {" not in content
        assert "from ..standards.owasp_2025 import" in content
