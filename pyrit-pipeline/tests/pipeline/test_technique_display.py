# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_technique_display — 技术名/Converter链/数据集提取修复单元测试。

覆盖 Round 36 修复:
  - ProgressDashboard._extract_technique: 修正路径 (get_attack_strategy_identifier)
  - _extract_converter_chain_brief: 原生标识符路径 Converter 链提取
  - _extract_dataset_from_result: 数据集来源提取
  - AttackResultAnalyzer.extract_technique_name: class_name → 规范技术名映射
  - _extract_converter_names_from_result: 原生标识符路径优先

> **日期**: 2026-8-8
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from pipeline.analysis.attack_result_analyzer import AttackResultAnalyzer
from pipeline.analysis.technique_name_mapper import map_class_name_to_technique
from pipeline.reporting.output_manager import (
    ProgressDashboard,
    _extract_converter_chain_brief,
    _extract_dataset_from_result,
)
from pipeline.stages.stage_execute import _extract_converter_names_from_result

# ──────────────────────────────────────────────────────────────────
#  辅助类 — 模拟 PyRIT 原生 ComponentIdentifier 结构
# ──────────────────────────────────────────────────────────────────


class FakeIdentifier:
    """模拟 PyRIT ComponentIdentifier (内层 AttackIdentifier)."""

    def __init__(  # noqa: D107
        self,
        class_name: str = "ManyShotJailbreakAttack",
        children: dict | None = None,
        params: dict | None = None,
    ) -> None:
        self.class_name = class_name
        self.children = children or {}
        self.params = params or {}

    def get_child(self, key: str) -> Any:
        return self.children.get(key)

    @property
    def unique_name(self) -> str:
        return f"{self.class_name}::a1b2c3d4"


class FakeAttackResult:
    """模拟 PyRIT AttackResult."""

    def __init__(  # noqa: D107
        self,
        attack_identifier: FakeIdentifier | None = None,
        atomic_attack_identifier: FakeIdentifier | None = None,
        objective: str = "Test objective",
        metadata: dict | None = None,
        labels: dict | None = None,
    ) -> None:
        self._attack_identifier = attack_identifier
        self.atomic_attack_identifier = atomic_attack_identifier
        self.objective = objective
        self.metadata = metadata or {}
        self.labels = labels or {}

    def get_attack_strategy_identifier(self) -> FakeIdentifier | None:
        return self._attack_identifier


class FakeConverter:
    """模拟 PyRIT Converter 类实例."""


# ──────────────────────────────────────────────────────────────────
#  ProgressDashboard._extract_technique (修正后)
# ──────────────────────────────────────────────────────────────────


class TestExtractTechniqueFixed:
    """ProgressDashboard._extract_technique: 修正路径测试。."""

    def test_many_shot_via_get_attack_strategy_identifier(self) -> None:
        """路径 1: get_attack_strategy_identifier().class_name → map_class_name_to_technique → "many_shot"."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="ManyShotJailbreakAttack"),
        )
        result = ProgressDashboard._extract_technique(ar)
        assert result == "many_shot"

    def test_crescendo_via_get_attack_strategy_identifier(self) -> None:
        """路径 1: CrescendoAttack → "crescendo"."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="CrescendoAttack"),
        )
        result = ProgressDashboard._extract_technique(ar)
        assert result == "crescendo"

    def test_prompt_sending_via_get_attack_strategy_identifier(self) -> None:
        """路径 1: PromptSendingAttack → "prompt_sending"."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="PromptSendingAttack"),
        )
        result = ProgressDashboard._extract_technique(ar)
        assert result == "prompt_sending"

    def test_fallback_to_atomic_attack_identifier_drill_down(self) -> None:
        """路径 2: 无 get_attack_strategy_identifier → 向下钻取 atomic_attack_identifier."""
        # 构建嵌套结构: atomic_attack_identifier → children["attack_technique"] → children["attack"]
        inner_attack = FakeIdentifier(class_name="TAPAttack")
        technique_id = FakeIdentifier(class_name="AttackTechnique", children={"attack": inner_attack})
        outer_id = FakeIdentifier(class_name="AtomicAttack", children={"attack_technique": technique_id})

        ar = FakeAttackResult(attack_identifier=None, atomic_attack_identifier=outer_id)
        result = ProgressDashboard._extract_technique(ar)
        assert result == "tap"

    def test_fallback_to_metadata(self) -> None:
        """路径 3: 无 identifier → metadata.technique 回退."""
        ar = FakeAttackResult(
            attack_identifier=None,
            atomic_attack_identifier=None,
            metadata={"technique": "red_teaming"},
        )
        result = ProgressDashboard._extract_technique(ar)
        assert result == "red_teaming"

    def test_unknown_class_name_preserved(self) -> None:
        """无映射的 class_name → 保留原始 (不返回 "AtomicAttack")."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="SomeNewAttack"),
        )
        result = ProgressDashboard._extract_technique(ar)
        assert result == "SomeNewAttack"

    def test_atomic_attack_class_name_filtered(self) -> None:
        """class_name="AtomicAttack" → 不返回, 继续回退."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="AtomicAttack"),
            metadata={"technique": "pair"},
        )
        result = ProgressDashboard._extract_technique(ar)
        assert result == "pair"

    def test_exception_defensive(self) -> None:
        """get_attack_strategy_identifier 抛异常 → 防御性回退到 metadata."""

        class ExceptionAR(FakeAttackResult):
            """get_attack_strategy_identifier 抛异常的测试类."""

            def get_attack_strategy_identifier(self) -> None:
                raise RuntimeError("test")

        ar = ExceptionAR(metadata={"technique": "skeleton_key"})
        result = ProgressDashboard._extract_technique(ar)
        assert result == "skeleton_key"


# ──────────────────────────────────────────────────────────────────
#  _extract_converter_chain_brief
# ──────────────────────────────────────────────────────────────────


class TestExtractConverterChainBrief:
    """_extract_converter_chain_brief: 从原生标识符提取 Converter 链名。."""

    def test_with_converters(self) -> None:
        """有 request_converters → 返回 Converter 类名列表."""
        conv1 = FakeConverter()
        conv2 = FakeConverter()
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(
                class_name="ManyShotJailbreakAttack",
                children={"request_converters": [conv1, conv2]},
            ),
        )
        result = _extract_converter_chain_brief(ar)
        assert len(result) == 2
        assert "FakeConverter" in result[0]

    def test_no_converters(self) -> None:
        """无 request_converters → 返回空列表."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="PromptSendingAttack"),
        )
        result = _extract_converter_chain_brief(ar)
        assert result == []

    def test_no_identifier(self) -> None:
        """无 attack_strategy_identifier → 返回空列表."""
        ar = FakeAttackResult(attack_identifier=None)
        result = _extract_converter_chain_brief(ar)
        assert result == []

    def test_metadata_fallback(self) -> None:
        """无标识符 Converter → metadata 回退."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="PromptSendingAttack"),
            metadata={"converters": ["Base64Converter", "LeetConverter"]},
        )
        result = _extract_converter_chain_brief(ar)
        assert result == ["Base64Converter", "LeetConverter"]

    def test_exception_defensive(self) -> None:
        """异常 → 返回空列表."""
        ar = MagicMock()
        ar.get_attack_strategy_identifier.side_effect = RuntimeError("test")
        result = _extract_converter_chain_brief(ar)
        assert result == []


# ──────────────────────────────────────────────────────────────────
#  _extract_dataset_from_result
# ──────────────────────────────────────────────────────────────────


class TestExtractDatasetFromResult:
    """_extract_dataset_from_result: 从 AttackResult 提取数据集来源。."""

    def test_from_atomic_attack_identifier_params(self) -> None:
        """路径 1: atomic_attack_identifier.params.display_group → 返回."""
        outer_id = FakeIdentifier(class_name="AtomicAttack", params={"display_group": "owasp_llm01"})
        ar = FakeAttackResult(atomic_attack_identifier=outer_id)
        result = _extract_dataset_from_result(ar)
        assert result == "owasp_llm01"

    def test_from_metadata_dataset_name(self) -> None:
        """路径 2: metadata.dataset_name → 返回."""
        ar = FakeAttackResult(
            atomic_attack_identifier=None,
            metadata={"dataset_name": "jbb_behaviors"},
        )
        result = _extract_dataset_from_result(ar)
        assert result == "jbb_behaviors"

    def test_from_metadata_display_group(self) -> None:
        """路径 2: metadata.display_group → 返回."""
        ar = FakeAttackResult(
            atomic_attack_identifier=None,
            metadata={"display_group": "harmbench"},
        )
        result = _extract_dataset_from_result(ar)
        assert result == "harmbench"

    def test_no_data_returns_empty(self) -> None:
        """无任何数据 → 返回空字符串."""
        ar = FakeAttackResult(atomic_attack_identifier=None, metadata={})
        result = _extract_dataset_from_result(ar)
        assert result == ""


# ──────────────────────────────────────────────────────────────────
#  AttackResultAnalyzer.extract_technique_name (修正后)
# ──────────────────────────────────────────────────────────────────


class TestExtractTechniqueNameWithMapping:
    """AttackResultAnalyzer.extract_technique_name: class_name → 规范技术名映射。."""

    def test_many_shot_mapping(self) -> None:
        """ManyShotJailbreakAttack → "many_shot"."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="ManyShotJailbreakAttack"),
        )
        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "many_shot"

    def test_crescendo_mapping(self) -> None:
        """CrescendoAttack → "crescendo"."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="CrescendoAttack"),
        )
        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "crescendo"

    def test_unknown_class_preserved(self) -> None:
        """无映射的 class_name → 保留原始 (不返回 "AtomicAttack")."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="CustomAttack"),
        )
        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "CustomAttack"

    def test_no_identifier_returns_unknown(self) -> None:
        """无 identifier → "unknown"."""
        ar = FakeAttackResult(attack_identifier=None)
        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "unknown"

    def test_converter_variant_concatenation(self) -> None:
        """有 Converter 子节点 → 拼接变体名 (如 "many_shot+FakeConverter")."""
        conv = FakeConverter()
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(
                class_name="ManyShotJailbreakAttack",
                children={"request_converters": [conv]},
            ),
        )
        # extract_technique_name 会在 class_name 路径直接返回 "many_shot"
        # 不会走到 Converter 拼接 (因为 class_name 有映射)
        result = AttackResultAnalyzer.extract_technique_name(ar)
        assert result == "many_shot"


# ──────────────────────────────────────────────────────────────────
#  _extract_converter_names_from_result (修正后 — 路径 1 新增)
# ──────────────────────────────────────────────────────────────────


class TestExtractConverterNamesFromResultFixed:
    """_extract_converter_names_from_result: 原生标识符路径优先。."""

    def test_native_identifier_path(self) -> None:
        """路径 1: 原生标识符 → children["request_converters"] → Converter 类名."""
        conv1 = FakeConverter()
        conv2 = FakeConverter()
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(
                class_name="ManyShotJailbreakAttack",
                children={"request_converters": [conv1, conv2]},
            ),
        )
        result = _extract_converter_names_from_result(ar)
        assert len(result) == 2
        assert "FakeConverter" in result[0]

    def test_native_identifier_no_converters_falls_to_labels(self) -> None:
        """路径 1 无 Converter → 路径 2 labels 回退."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="PromptSendingAttack"),
            labels={"converter_1": "PersuasionConverter"},
        )
        result = _extract_converter_names_from_result(ar)
        assert "PersuasionConverter" in result

    def test_native_identifier_no_identifier_falls_to_metadata(self) -> None:
        """路径 1 无 identifier → 路径 3 metadata 回退."""
        ar = FakeAttackResult(
            attack_identifier=None,
            metadata={"converters": ["ROT13Converter", "UnicodeConverter"]},
        )
        result = _extract_converter_names_from_result(ar)
        assert result == ["ROT13Converter", "UnicodeConverter"]

    def test_all_paths_empty_returns_empty(self) -> None:
        """全部路径无数据 → 返回空列表."""
        ar = FakeAttackResult(
            attack_identifier=FakeIdentifier(class_name="PromptSendingAttack"),
            metadata={},
            labels={},
        )
        result = _extract_converter_names_from_result(ar)
        assert result == []


# ──────────────────────────────────────────────────────────────────
#  map_class_name_to_technique (回归测试)
# ──────────────────────────────────────────────────────────────────


class TestMapClassNameToTechnique:
    """map_class_name_to_technique: 类名 → 规范技术名映射回归测试。."""

    def test_many_shot(self) -> None:
        assert map_class_name_to_technique("ManyShotJailbreakAttack") == "many_shot"

    def test_crescendo(self) -> None:
        assert map_class_name_to_technique("CrescendoAttack") == "crescendo"

    def test_tap(self) -> None:
        assert map_class_name_to_technique("TAPAttack") == "tap"

    def test_prompt_sending(self) -> None:
        assert map_class_name_to_technique("PromptSendingAttack") == "prompt_sending"

    def test_unknown_returns_none(self) -> None:
        assert map_class_name_to_technique("NonExistentAttack") is None

    def test_atomic_attack_returns_unknown(self) -> None:
        assert map_class_name_to_technique("AtomicAttack") == "unknown"
