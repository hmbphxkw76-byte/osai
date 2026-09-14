"""Tests for core.component_profile — 组件画像契约（BL-082④ 下沉后的回归守卫）。

该结构是 recon 输出 / arm·strike 消费的唯一交接契约，下沉到 `core/` 后由本文件
守住两点：① 序列化语义不变（to_dict/from_dict 可往返）；② `recon.orchestrator`
的 re-export 与 `core.component_profile` 是同一符号（防止再次分叉成两份定义）。
"""

from __future__ import annotations

from core.component_profile import ComponentProfile


class TestComponentProfileDefaults:
    def test_defaults_are_generic_and_empty(self) -> None:
        profile = ComponentProfile()
        assert profile.target_type == "generic"
        assert profile.capabilities == set()
        assert profile.attack_surface == {}
        assert profile.recommended_techniques == []
        assert profile.guardrail_indicators == {}


class TestComponentProfileSerialization:
    def test_to_dict_casts_capabilities_to_list(self) -> None:
        profile = ComponentProfile(target_type="mcp", capabilities={"tools/list", "tools/call"})
        payload = profile.to_dict()
        assert payload["target_type"] == "mcp"
        assert sorted(payload["capabilities"]) == ["tools/call", "tools/list"]

    def test_roundtrip_preserves_all_fields(self) -> None:
        original = ComponentProfile(
            target_type="a2a",
            capabilities={"agent_card"},
            attack_surface={"entry_points": ["prompt"]},
            recon_budget_consumed={"topology": 1.5},
            component_specific={"cards": 2},
            confidence_scores={"a2a": 0.8},
            recommended_techniques=["task_interception"],
            guardrail_indicators={"waf": False},
        )
        restored = ComponentProfile.from_dict(original.to_dict())
        assert restored == original
        assert restored.capabilities == {"agent_card"}

    def test_from_dict_tolerates_missing_keys(self) -> None:
        restored = ComponentProfile.from_dict({"target_type": "rag"})
        assert restored.target_type == "rag"
        assert restored.capabilities == set()
        assert restored.recommended_techniques == []


class TestReExportIdentity:
    def test_recon_orchestrator_reexports_same_symbol(self) -> None:
        """re-export 必须与 core 定义为同一对象（BL-082④ 防分叉）。"""
        from recon.orchestrator import ComponentProfile as ReExported

        assert ReExported is ComponentProfile
