"""P4-1: tests/test_custom_probes.py — 自定义探针测试覆盖

验证 6 个自定义探针模块的核心功能：
- _resolve_detectors 不再返回 always.Passthru（P0-1 修复）
- keyword 类型返回正确的语义检测器
- judge 类型返回 mitigation.MitigationBypass + judge.ModelAsJudge
- 探针 spec 结构完整性（prompts/detector_hints/tags/tier）
- register_custom_probes 注册成功
"""

import pytest

# 导入各自定义探针模块
from pipeline.custom_probes import (
    llm03_training_data,
    llm07_plugin_design,
    llm08_vector_embedding,
    asi07_inter_agent,
    asi08_cascading,
    mcp_abuse,
)


_MODULES = [
    llm03_training_data,
    llm07_plugin_design,
    llm08_vector_embedding,
    asi07_inter_agent,
    asi08_cascading,
    mcp_abuse,
]


class TestResolveDetectors:
    """P0-1: 验证 _resolve_detectors 不再返回 always.Passthru"""

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__.split(".")[-1])
    def test_judge_type_not_passthru(self, module):
        """judge 类型不应返回 always.Passthru"""
        hints = {"type": "judge"}
        primary, extended = module._resolve_detectors(hints, "LLM01")
        assert primary != "always.Passthru", f"{module.__name__}: primary_detector 仍为 always.Passthru"
        assert primary == "mitigation.MitigationBypass"

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__.split(".")[-1])
    def test_keyword_type_jailbreak(self, module):
        """keyword 类型 + LLM01/LLM07 → mitigation.MitigationBypass"""
        hints = {"type": "keyword"}
        primary, extended = module._resolve_detectors(hints, "LLM01")
        assert primary == "mitigation.MitigationBypass"
        assert extended == []

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__.split(".")[-1])
    def test_keyword_type_non_jailbreak(self, module):
        """keyword 类型 + 非 LLM01/07 → goodside.GoodsideDetector"""
        hints = {"type": "keyword"}
        primary, extended = module._resolve_detectors(hints, "LLM03")
        assert primary == "goodside.GoodsideDetector"
        assert extended == []

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__.split(".")[-1])
    def test_judge_type_extended_has_judge(self, module):
        """judge 类型 extended_detectors 应包含 judge.ModelAsJudge"""
        hints = {"type": "judge"}
        _, extended = module._resolve_detectors(hints, None)
        assert "judge.ModelAsJudge" in extended


class TestProbeSpecs:
    """验证探针 spec 结构完整性"""

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__.split(".")[-1])
    def test_specs_non_empty(self, module):
        """每个模块应有至少一个 spec"""
        # 获取 SPECS 常量
        spec_attr = None
        for attr in dir(module):
            if attr.endswith("_SPECS"):
                spec_attr = attr
                break
        assert spec_attr is not None, f"{module.__name__}: 未找到 *_SPECS 常量"
        specs = getattr(module, spec_attr)
        assert len(specs) > 0, f"{module.__name__}: SPECS 为空"

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__.split(".")[-1])
    def test_specs_have_required_fields(self, module):
        """每个 spec 应包含 name/owasp_llm/tier/prompts/detector_hints"""
        spec_attr = None
        for attr in dir(module):
            if attr.endswith("_SPECS"):
                spec_attr = attr
                break
        specs = getattr(module, spec_attr)
        for spec in specs:
            assert "name" in spec, f"spec 缺少 name: {spec}"
            assert "tier" in spec, f"spec 缺少 tier: {spec.get('name')}"
            assert "prompts" in spec, f"spec 缺少 prompts: {spec.get('name')}"
            assert "detector_hints" in spec, f"spec 缺少 detector_hints: {spec.get('name')}"
            assert len(spec["prompts"]) > 0, f"prompts 为空: {spec.get('name')}"

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__.split(".")[-1])
    def test_probe_classes_exist(self, module):
        """每个模块应定义至少一个 Probe 子类"""
        from garak.probes.base import Probe
        probe_classes = [
            obj for obj in vars(module).values()
            if isinstance(obj, type) and issubclass(obj, Probe) and obj is not Probe
        ]
        assert len(probe_classes) > 0, f"{module.__name__}: 未定义 Probe 子类"

    @pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__.split(".")[-1])
    def test_probe_primary_detector_not_passthru(self, module):
        """Probe 子类的 primary_detector 不应为 always.Passthru"""
        from garak.probes.base import Probe
        probe_classes = [
            obj for obj in vars(module).values()
            if isinstance(obj, type) and issubclass(obj, Probe) and obj is not Probe
        ]
        for cls in probe_classes:
            pd = getattr(cls, "primary_detector", None)
            assert pd is not None, f"{cls.__name__}: primary_detector 为 None"
            assert pd != "always.Passthru", f"{cls.__name__}: primary_detector 仍为 always.Passthru"


class TestRegisterCustomProbes:
    """验证 register_custom_probes 注册函数"""

    def test_register_no_exception(self):
        """register_custom_probes 应不抛异常"""
        from pipeline.custom_probes import register_custom_probes
        try:
            register_custom_probes()
        except Exception as e:
            pytest.fail(f"register_custom_probes 抛异常: {e}")
