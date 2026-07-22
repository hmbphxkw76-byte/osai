# -*- coding: utf-8 -*-
"""
P1 回归测试：框架抽象层验证

验证 AISafetyFramework 基类、OWASP LLM/ASI 框架实现、
框架注册表和风险类别的完整性和一致性。
"""

import pytest
import json


# ──────────────────────────────────────────────────────────────────────────────
# 1. AISafetyFramework 基类
# ──────────────────────────────────────────────────────────────────────────────

class TestFrameworkBase:
    """验证 AISafetyFramework 基类"""

    def test_framework_base_is_abstract(self):
        """AISafetyFramework 是抽象类，不能直接实例化"""
        from pyrit_ai300.standards.framework_base import AISafetyFramework
        with pytest.raises(TypeError):
            AISafetyFramework()

    def test_framework_vulnerability_is_frozen(self):
        """FrameworkVulnerability 是不可变数据类"""
        from pyrit_ai300.standards.framework_base import FrameworkVulnerability
        v = FrameworkVulnerability(
            vuln_id="TEST01",
            title="Test",
            description="Test desc",
        )
        assert v.vuln_id == "TEST01"
        # frozen dataclass 不可修改
        with pytest.raises(AttributeError):
            v.vuln_id = "CHANGED"

    def test_framework_attack_is_frozen(self):
        """FrameworkAttack 是不可变数据类"""
        from pyrit_ai300.standards.framework_base import FrameworkAttack
        a = FrameworkAttack(
            attack_id="test_attack",
            title="Test Attack",
            description="Test desc",
        )
        assert a.attack_id == "test_attack"
        with pytest.raises(AttributeError):
            a.attack_id = "changed"


# ──────────────────────────────────────────────────────────────────────────────
# 2. OWASP LLM 2025 框架实现
# ──────────────────────────────────────────────────────────────────────────────

class TestOWASPLinearFramework:
    """验证 OWASP Top 10 for LLMs 2025 框架实现"""

    @pytest.fixture
    def framework(self):
        from pyrit_ai300.standards.owasp_llm_framework import OWASPLinearFramework2025
        return OWASPLinearFramework2025()

    def test_framework_name(self, framework):
        assert framework.framework_name == "OWASP Top 10 for LLMs 2025"

    def test_framework_version(self, framework):
        assert framework.framework_version == "2025.1"

    def test_framework_id(self, framework):
        assert framework.framework_id == "owasp_llm_2025"

    def test_has_10_vulnerabilities(self, framework):
        vulns = framework.get_vulnerabilities()
        assert len(vulns) == 10

    def test_vulnerability_ids_sequential(self, framework):
        ids = framework.get_vulnerability_ids()
        assert ids == [f"LLM{i:02d}" for i in range(1, 11)]

    def test_vulnerability_has_remediation(self, framework):
        """每个漏洞都有修复建议"""
        for v in framework.get_vulnerabilities():
            assert v.remediation, f"{v.vuln_id} missing remediation"
            assert len(v.remediation) > 10

    def test_vulnerability_has_risk_category(self, framework):
        """每个漏洞都有风险类别"""
        for v in framework.get_vulnerabilities():
            assert v.risk_category, f"{v.vuln_id} missing risk_category"

    def test_get_vulnerability_by_id(self, framework):
        v = framework.get_vulnerability("LLM01")
        assert v is not None
        assert v.title == "Prompt Injection"

    def test_get_vulnerability_invalid_id(self, framework):
        assert framework.get_vulnerability("INVALID") is None

    def test_has_attacks(self, framework):
        attacks = framework.get_attacks()
        assert len(attacks) > 0

    def test_attack_has_vulnerability_reference(self, framework):
        """每个攻击方法都关联到漏洞 ID"""
        for a in framework.get_attacks():
            assert len(a.vulnerabilities) > 0

    def test_to_dict(self, framework):
        d = framework.to_dict()
        assert d["framework_id"] == "owasp_llm_2025"
        assert len(d["vulnerabilities"]) == 10
        assert "attacks" in d

    def test_repr(self, framework):
        assert "owasp_llm_2025" in repr(framework)

    def test_str(self, framework):
        assert "OWASP" in str(framework)

    def test_probe_family(self, framework):
        assert framework.get_probe_family("LLM01") == "DIRECT_SINGLE"


# ──────────────────────────────────────────────────────────────────────────────
# 3. OWASP ASI 2026 框架实现
# ──────────────────────────────────────────────────────────────────────────────

class TestOWASPAgenticFramework:
    """验证 OWASP Top 10 for Agentic Applications 2026 框架实现"""

    @pytest.fixture
    def framework(self):
        from pyrit_ai300.standards.owasp_asi_framework import OWASPAgenticFramework2026
        return OWASPAgenticFramework2026()

    def test_framework_name(self, framework):
        assert framework.framework_name == "OWASP Top 10 for Agentic Applications 2026"

    def test_framework_version(self, framework):
        assert framework.framework_version == "2026.1"

    def test_framework_id(self, framework):
        assert framework.framework_id == "owasp_asi_2026"

    def test_has_10_vulnerabilities(self, framework):
        vulns = framework.get_vulnerabilities()
        assert len(vulns) == 10

    def test_vulnerability_ids_sequential(self, framework):
        ids = framework.get_vulnerability_ids()
        assert ids == [f"ASI{i:02d}" for i in range(1, 11)]

    def test_vulnerability_has_remediation(self, framework):
        for v in framework.get_vulnerabilities():
            assert v.remediation, f"{v.vuln_id} missing remediation"

    def test_get_vulnerability_by_id(self, framework):
        v = framework.get_vulnerability("ASI01")
        assert v is not None
        assert v.title == "Agent Goal Hijack"

    def test_to_dict(self, framework):
        d = framework.to_dict()
        assert d["framework_id"] == "owasp_asi_2026"
        assert len(d["vulnerabilities"]) == 10


# ──────────────────────────────────────────────────────────────────────────────
# 4. 框架注册表
# ──────────────────────────────────────────────────────────────────────────────

class TestFrameworkRegistry:
    """验证框架注册表"""

    def test_list_frameworks(self):
        from pyrit_ai300.standards.framework_registry import list_frameworks
        ids = list_frameworks()
        assert "owasp_llm_2025" in ids
        assert "owasp_asi_2026" in ids

    def test_get_framework_llm(self):
        from pyrit_ai300.standards.framework_registry import get_framework
        fw = get_framework("owasp_llm_2025")
        assert fw is not None
        assert fw.framework_id == "owasp_llm_2025"

    def test_get_framework_asi(self):
        from pyrit_ai300.standards.framework_registry import get_framework
        fw = get_framework("owasp_asi_2026")
        assert fw is not None
        assert fw.framework_id == "owasp_asi_2026"

    def test_get_framework_invalid(self):
        from pyrit_ai300.standards.framework_registry import get_framework
        assert get_framework("invalid_id") is None

    def test_get_framework_caches_instance(self):
        """框架实例被缓存（同一 ID 返回同一实例）"""
        from pyrit_ai300.standards.framework_registry import get_framework
        fw1 = get_framework("owasp_llm_2025")
        fw2 = get_framework("owasp_llm_2025")
        assert fw1 is fw2

    def test_get_all_frameworks_info(self):
        from pyrit_ai300.standards.framework_registry import get_all_frameworks_info
        infos = get_all_frameworks_info()
        assert len(infos) >= 2
        ids = [i["framework_id"] for i in infos]
        assert "owasp_llm_2025" in ids
        assert "owasp_asi_2026" in ids

    def test_register_custom_framework(self):
        """注册自定义框架"""
        from pyrit_ai300.standards.framework_registry import (
            register_framework, get_framework,
        )
        from pyrit_ai300.standards.framework_base import (
            AISafetyFramework, FrameworkVulnerability, FrameworkAttack,
        )

        class CustomFramework(AISafetyFramework):
            @property
            def framework_name(self): return "Custom Test Framework"
            @property
            def framework_version(self): return "1.0.0"
            @property
            def framework_id(self): return "custom_test"
            def get_vulnerabilities(self):
                return [FrameworkVulnerability(vuln_id="C01", title="Custom", description="Test")]
            def get_attacks(self):
                return [FrameworkAttack(attack_id="c_attack", title="Custom Attack", description="Test")]

        register_framework("custom_test", CustomFramework)
        fw = get_framework("custom_test")
        assert fw is not None
        assert fw.framework_name == "Custom Test Framework"

    def test_select_framework_from_config_string(self):
        """从字符串配置选择框架"""
        from pyrit_ai300.standards.framework_registry import select_framework_from_config
        fw = select_framework_from_config({"framework": "owasp_llm_2025"})
        assert fw is not None
        assert fw.framework_id == "owasp_llm_2025"

    def test_select_framework_from_config_dict(self):
        """从字典配置选择框架"""
        from pyrit_ai300.standards.framework_registry import select_framework_from_config
        fw = select_framework_from_config({"framework": {"id": "owasp_asi_2026"}})
        assert fw is not None
        assert fw.framework_id == "owasp_asi_2026"

    def test_select_framework_from_config_missing(self):
        """配置中没有框架时返回 None"""
        from pyrit_ai300.standards.framework_registry import select_framework_from_config
        assert select_framework_from_config({}) is None

    def test_framework_to_json(self):
        from pyrit_ai300.standards.framework_registry import framework_to_json
        j = framework_to_json("owasp_llm_2025")
        data = json.loads(j)
        assert data["framework_id"] == "owasp_llm_2025"
        assert len(data["vulnerabilities"]) == 10

    def test_framework_to_yaml(self):
        from pyrit_ai300.standards.framework_registry import framework_to_yaml
        y = framework_to_yaml("owasp_llm_2025")
        assert "owasp_llm_2025" in y
        assert "vulnerabilities:" in y


# ──────────────────────────────────────────────────────────────────────────────
# 5. 风险类别
# ──────────────────────────────────────────────────────────────────────────────

class TestRiskCategory:
    """验证风险类别模型"""

    def test_risk_categories_not_empty(self):
        from pyrit_ai300.standards.risk_category import RISK_CATEGORIES
        assert len(RISK_CATEGORIES) > 0

    def test_has_top_level_categories(self):
        from pyrit_ai300.standards.risk_category import get_top_level_categories
        top = get_top_level_categories()
        assert len(top) >= 4  # responsible_ai, security, data_privacy, agentic_security
        names = [c.display_name for c in top]
        assert "Security" in names
        assert "Responsible AI" in names

    def test_owasp_to_risk_category_mapping(self):
        from pyrit_ai300.standards.risk_category import OWASP_TO_RISK_CATEGORY
        # LLM01 应该映射到 prompt_injection 类别
        assert "LLM01" in OWASP_TO_RISK_CATEGORY
        assert "ASI01" in OWASP_TO_RISK_CATEGORY

    def test_get_risk_category_for_llm01(self):
        from pyrit_ai300.standards.risk_category import get_risk_category
        cat = get_risk_category("LLM01")
        assert cat is not None
        assert "Prompt Injection" in cat.display_name or "prompt_injection" in cat.category_id

    def test_get_risk_category_for_asi01(self):
        from pyrit_ai300.standards.risk_category import get_risk_category
        cat = get_risk_category("ASI01")
        assert cat is not None
        assert "Agent Goal Hijack" in cat.display_name or "agent_goal_hijack" in cat.category_id

    def test_get_risk_category_invalid(self):
        from pyrit_ai300.standards.risk_category import get_risk_category
        assert get_risk_category("INVALID") is None

    def test_all_categories_have_owasp_ids(self):
        """每个子类别都关联到至少一个 OWASP ID"""
        from pyrit_ai300.standards.risk_category import RISK_CATEGORIES
        for cat in RISK_CATEGORIES.values():
            if cat.parent:  # 子类别必须有 OWASP ID
                assert len(cat.owasp_ids) > 0, f"{cat.category_id} has no OWASP IDs"


# ──────────────────────────────────────────────────────────────────────────────
# 6. 框架与权威映射的一致性
# ──────────────────────────────────────────────────────────────────────────────

class TestFrameworkMappingConsistency:
    """验证框架实现与权威映射一致"""

    def test_llm_framework_matches_owasp_2025(self):
        """LLM 框架的漏洞数量与 OWASP_LLM_2025 一致"""
        from pyrit_ai300.standards.owasp_llm_framework import OWASPLinearFramework2025
        from pyrit_ai300.standards.owasp_2025 import OWASP_LLM_2025
        fw = OWASPLinearFramework2025()
        assert len(fw.get_vulnerabilities()) == len(OWASP_LLM_2025)

    def test_asi_framework_matches_owasp_2026(self):
        """ASI 框架的漏洞数量与 OWASP_ASI_2026 一致"""
        from pyrit_ai300.standards.owasp_asi_framework import OWASPAgenticFramework2026
        from pyrit_ai300.standards.owasp_2025 import OWASP_ASI_2026
        fw = OWASPAgenticFramework2026()
        assert len(fw.get_vulnerabilities()) == len(OWASP_ASI_2026)

    def test_llm_framework_vuln_titles_match(self):
        """LLM 框架的漏洞标题与权威映射一致"""
        from pyrit_ai300.standards.owasp_llm_framework import OWASPLinearFramework2025
        from pyrit_ai300.standards.owasp_2025 import OWASP_LLM_2025
        fw = OWASPLinearFramework2025()
        for v in fw.get_vulnerabilities():
            entry = OWASP_LLM_2025.get(v.vuln_id)
            assert entry is not None
            assert v.title == entry.title

    def test_asi_framework_vuln_titles_match(self):
        """ASI 框架的漏洞标题与权威映射一致"""
        from pyrit_ai300.standards.owasp_asi_framework import OWASPAgenticFramework2026
        from pyrit_ai300.standards.owasp_2025 import OWASP_ASI_2026
        fw = OWASPAgenticFramework2026()
        for v in fw.get_vulnerabilities():
            entry = OWASP_ASI_2026.get(v.vuln_id)
            assert entry is not None
            assert v.title == entry.title
