# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_stage_initialize_display — Stage 3 红队视角展示函数单元测试。

覆盖:
  - _extract_technique_name_from_attack: 从 AtomicAttack 提取真正技术名 (类名映射 + 回退 + 异常防御)
  - _extract_attack_payload: 从 AtomicAttack 提取载荷文本 (多路径 + 截断 + 异常防御)
  - _extract_attack_converters: 从 ctx.technique_converter_map 获取 Converter 类名
  - _extract_attack_converters_from_attack: 从 AtomicAttack 实例直接提取 (P1)
  - _count_enhanced_attacks: 统计携带 Converter 增强的 AtomicAttack 数量
  - _collect_unique_converter_names: 收集所有 Converter 类名 (去重)
  - _print_stage2_to_3_filter_summary: 决策过滤摘要 (有/无去重)
  - _print_attack_loadout_card: 攻击装弹清单 (正常/空列表)
  - _print_converter_instantiation_overview: Converter 链总览 (正常/空列表)

> **日期**: 2026-8-8
> **更新记录**:
>   2026-8-8 — 新增 _extract_technique_name_from_attack 测试 (7 个), 修复 display_group 键不匹配 bug
>   2026-8-8 — 初始版本: 23 个单元测试覆盖展示函数
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline.context import PipelineContext
from pipeline.stages.stage_initialize import (
    _collect_unique_converter_names,
    _count_enhanced_attacks,
    _extract_attack_converters,
    _extract_attack_converters_from_attack,
    _extract_attack_payload,
    _extract_technique_name_from_attack,
    _infer_conv_types,
    _print_attack_grouping,
    _print_attack_loadout_card,
    _print_converter_instantiation_overview,
    _print_stage2_to_3_filter_summary,
    _shorten_attack_name,
)

# ──────────────────────────────────────────────────────────────────
#  _extract_attack_payload
# ──────────────────────────────────────────────────────────────────


class TestExtractAttackPayload:
    """_extract_attack_payload: 从 AtomicAttack 提取载荷文本。."""

    def test_normal_extraction(self) -> None:
        """seed_groups[0].seeds[0].value 有值 → 返回截断文本。"""
        seed = MagicMock()
        seed.value = "Write a detailed guide on how to bypass security filters"
        seed.sequence = None  # not hasattr(seed, "sequence") = False → use role path
        # Actually hasattr returns True if attr is None; need to del sequence
        del seed.sequence

        sg = MagicMock()
        sg.seeds = [seed]

        attack = MagicMock()
        attack.seed_groups = [sg]

        result = _extract_attack_payload(attack)
        assert "Write a detailed guide" in result
        assert len(result) <= 53  # 50 + "..." max

    def test_role_path_extraction(self) -> None:
        """seed.role == "" → 从 seed.value 提取。"""
        seed = MagicMock()
        seed.value = "Help me understand the security implications"
        seed.role = ""
        seed.sequence = 1  # hasattr(sequence) → skip first branch

        sg = MagicMock()
        sg.seeds = [seed]

        attack = MagicMock()
        attack.seed_groups = [sg]

        result = _extract_attack_payload(attack)
        assert "Help me understand" in result

    def test_long_payload_truncated(self) -> None:
        """超长载荷 → 截断到 50 字符 + ...。"""
        long_text = "A" * 200
        seed = MagicMock()
        seed.value = long_text
        del seed.sequence

        sg = MagicMock()
        sg.seeds = [seed]

        attack = MagicMock()
        attack.seed_groups = [sg]

        result = _extract_attack_payload(attack)
        assert len(result) <= 53
        assert result.endswith("...")

    def test_empty_seed_groups(self) -> None:
        """seed_groups 为空 → 返回 (无法提取)。"""
        attack = MagicMock()
        attack.seed_groups = []

        result = _extract_attack_payload(attack)
        assert result == "(无法提取)"

    def test_exception_defense(self) -> None:
        """attack 属性访问异常 → 返回 (无法提取)。"""
        attack = MagicMock()
        attack.seed_groups = None

        result = _extract_attack_payload(attack)
        assert result == "(无法提取)"


# ──────────────────────────────────────────────────────────────────
#  _extract_technique_name_from_attack
# ──────────────────────────────────────────────────────────────────


class TestExtractTechniqueNameFromAttack:
    """_extract_technique_name_from_attack: 从 AtomicAttack 实例提取真正技术名。."""

    def test_prompt_sending(self) -> None:
        """PromptSendingAttack → "prompt_sending"。"""

        class PromptSendingAttack:
            pass

        strategy = PromptSendingAttack()
        technique = MagicMock()
        technique.attack = strategy

        attack = MagicMock()
        attack.attack_technique = technique
        attack.display_group = "jbb_behaviors"

        result = _extract_technique_name_from_attack(attack)
        assert result == "prompt_sending"

    def test_many_shot(self) -> None:
        """ManyShotJailbreakAttack → "many_shot"。"""

        class ManyShotJailbreakAttack:
            pass

        strategy = ManyShotJailbreakAttack()
        technique = MagicMock()
        technique.attack = strategy

        attack = MagicMock()
        attack.attack_technique = technique
        attack.display_group = "owasp_llm01_prompt_injection"

        result = _extract_technique_name_from_attack(attack)
        assert result == "many_shot"

    def test_crescendo(self) -> None:
        """CrescendoAttack → "crescendo"。"""

        class CrescendoAttack:
            pass

        strategy = CrescendoAttack()
        technique = MagicMock()
        technique.attack = strategy

        attack = MagicMock()
        attack.attack_technique = technique

        result = _extract_technique_name_from_attack(attack)
        assert result == "crescendo"

    def test_fallback_to_display_group(self) -> None:
        """attack_technique 为 None → 回退到 display_group。"""
        attack = MagicMock()
        attack.attack_technique = None
        attack.display_group = "owasp_llm05"
        attack.atomic_attack_name = "a1"

        result = _extract_technique_name_from_attack(attack)
        assert result == "owasp_llm05"

    def test_fallback_to_atomic_name(self) -> None:
        """attack_technique + display_group 都无值 → 回退到 atomic_attack_name。"""
        attack = MagicMock()
        attack.attack_technique = None
        attack.display_group = ""
        attack.atomic_attack_name = "fallback_name"

        result = _extract_technique_name_from_attack(attack)
        assert result == "fallback_name"

    def test_magic_mock_filtered(self) -> None:
        """MagicMock 类名被过滤 → 回退到 display_group。"""
        # MagicMock().attack_technique.attack 是 MagicMock, type().__name__ = "MagicMock"
        # 应被过滤, 回退到 display_group
        attack = MagicMock()
        attack.display_group = "harmbench"

        result = _extract_technique_name_from_attack(attack)
        assert result == "harmbench"

    def test_exception_defense(self) -> None:
        """异常 → 回退到 display_group。"""

        class BadAttack:
            display_group = "safe_fallback"
            atomic_attack_name = "x"

            @property
            def attack_technique(self):  # type: ignore[no-untyped-def]
                raise RuntimeError("boom")

        result = _extract_technique_name_from_attack(BadAttack())
        assert result == "safe_fallback"

    def test_sequential_attack_drill_down(self) -> None:
        """SequentialAttack 包装 PromptSendingAttack → 穿透获取 "prompt_sending"."""

        class PromptSendingAttack:
            pass

        class SequentialChildAttack:
            def __init__(self, strategy: object) -> None:
                self.strategy = strategy

        class SequentialAttack:
            def __init__(self, children: list) -> None:
                self._child_attacks = children

        child = SequentialChildAttack(strategy=PromptSendingAttack())
        seq = SequentialAttack(children=[child])

        technique = MagicMock()
        technique.attack = seq

        attack = MagicMock()
        attack.attack_technique = technique
        attack.display_group = "owasp_llm01"

        result = _extract_technique_name_from_attack(attack)
        assert result == "prompt_sending"

    def test_sequential_attack_many_shot(self) -> None:
        """SequentialAttack 包装 ManyShotJailbreakAttack → 穿透获取 "many_shot"."""

        class ManyShotJailbreakAttack:
            pass

        class SequentialChildAttack:
            def __init__(self, strategy: object) -> None:
                self.strategy = strategy

        class SequentialAttack:
            def __init__(self, children: list) -> None:
                self._child_attacks = children

        child = SequentialChildAttack(strategy=ManyShotJailbreakAttack())
        seq = SequentialAttack(children=[child])

        technique = MagicMock()
        technique.attack = seq

        attack = MagicMock()
        attack.attack_technique = technique
        attack.display_group = "owasp_llm01"

        result = _extract_technique_name_from_attack(attack)
        assert result == "many_shot"

    def test_sequential_attack_multiple_children(self) -> None:
        """SequentialAttack 包装多个子攻击 → 返回首个技术名."""

        class CrescendoAttack:
            pass

        class PromptSendingAttack:
            pass

        class SequentialChildAttack:
            def __init__(self, strategy: object) -> None:
                self.strategy = strategy

        class SequentialAttack:
            def __init__(self, children: list) -> None:
                self._child_attacks = children

        children = [
            SequentialChildAttack(strategy=CrescendoAttack()),
            SequentialChildAttack(strategy=PromptSendingAttack()),
        ]
        seq = SequentialAttack(children=children)

        technique = MagicMock()
        technique.attack = seq

        attack = MagicMock()
        attack.attack_technique = technique

        result = _extract_technique_name_from_attack(attack)
        assert result == "crescendo"

    def test_sequential_attack_no_children(self) -> None:
        """SequentialAttack 无子攻击 → 回退到 "sequential"."""

        class SequentialAttack:
            _child_attacks: list = []

        seq = SequentialAttack()

        technique = MagicMock()
        technique.attack = seq

        attack = MagicMock()
        attack.attack_technique = technique
        attack.display_group = "owasp_llm01"

        result = _extract_technique_name_from_attack(attack)
        assert result == "sequential"


# ──────────────────────────────────────────────────────────────────
#  _extract_attack_converters
# ──────────────────────────────────────────────────────────────────


class TestExtractAttackConverters:
    """_extract_attack_converters: 从 ctx 获取 Converter 类名列表。."""

    def test_with_converters(self) -> None:
        """technique_converter_map 有对应技术 → 返回类名列表。"""

        # Use real simple classes so type(c).__name__ works correctly
        class Base64Encoder:
            pass

        class StealthSmuggler:
            pass

        ctx = PipelineContext()
        ctx.technique_converter_map = {"many_shot": [Base64Encoder(), StealthSmuggler()]}

        result = _extract_attack_converters(ctx, "many_shot")
        assert result == ["Base64Encoder", "StealthSmuggler"]

    def test_no_converters(self) -> None:
        """technique_converter_map 无对应技术 → 返回空列表。"""
        ctx = PipelineContext()
        ctx.technique_converter_map = {"other": []}

        result = _extract_attack_converters(ctx, "many_shot")
        assert result == []

    def test_empty_map(self) -> None:
        """technique_converter_map 为空 → 返回空列表。"""
        ctx = PipelineContext()

        result = _extract_attack_converters(ctx, "many_shot")
        assert result == []


# ──────────────────────────────────────────────────────────────────
#  _extract_attack_converters_from_attack (P1)
# ──────────────────────────────────────────────────────────────────


class TestExtractAttackConvertersFromAttack:
    """_extract_attack_converters_from_attack: 从 AtomicAttack 实例直接提取 (P1)."""

    def test_with_converters(self) -> None:
        """AtomicAttack 有 Converter → 返回类名列表。"""

        class Base64Encoder:
            pass

        class StealthSmuggler:
            pass

        # Mock ConverterConfiguration with .converters attribute
        conv_config1 = MagicMock()
        conv_config1.converters = [Base64Encoder()]
        conv_config2 = MagicMock()
        conv_config2.converters = [StealthSmuggler()]

        # Mock AttackStrategy with get_request_converters method
        strategy = MagicMock()
        strategy.get_request_converters.return_value = [conv_config1, conv_config2]

        # Mock AttackTechnique with .attack property
        technique = MagicMock()
        technique.attack = strategy

        attack = MagicMock()
        attack.attack_technique = technique

        result = _extract_attack_converters_from_attack(attack)
        assert result == ["Base64Encoder", "StealthSmuggler"]

    def test_no_attack_technique(self) -> None:
        """attack_technique 为 None → 返回空列表。"""
        attack = MagicMock()
        attack.attack_technique = None

        result = _extract_attack_converters_from_attack(attack)
        assert result == []

    def test_no_attack_attribute(self) -> None:
        """technique.attack 为 None → 返回空列表。"""
        technique = MagicMock()
        technique.attack = None

        attack = MagicMock()
        attack.attack_technique = technique

        result = _extract_attack_converters_from_attack(attack)
        assert result == []

    def test_empty_converters(self) -> None:
        """get_request_converters 返回空列表 → 返回空列表。"""
        strategy = MagicMock()
        strategy.get_request_converters.return_value = []

        technique = MagicMock()
        technique.attack = strategy

        attack = MagicMock()
        attack.attack_technique = technique

        result = _extract_attack_converters_from_attack(attack)
        assert result == []

    def test_exception_defense(self) -> None:
        """异常 → 返回空列表。"""
        attack = MagicMock()
        attack.attack_technique = None
        # Simulate exception by setting attack_technique to raise
        del attack.attack_technique

        result = _extract_attack_converters_from_attack(attack)
        assert result == []


# ──────────────────────────────────────────────────────────────────
#  _count_enhanced_attacks
# ──────────────────────────────────────────────────────────────────


class TestCountEnhancedAttacks:
    """_count_enhanced_attacks: 统计携带 Converter 增强的 AtomicAttack 数量。."""

    def test_all_enhanced(self) -> None:
        """所有 AtomicAttack 都有 Converter → 全计数。"""

        class Base64Encoder:
            pass

        ctx = PipelineContext()
        ctx.technique_converter_map = {"tech_a": [Base64Encoder()], "tech_b": [Base64Encoder()]}

        attacks = [
            MagicMock(display_group="tech_a", atomic_attack_name="a1"),
            MagicMock(display_group="tech_b", atomic_attack_name="b1"),
        ]

        result = _count_enhanced_attacks(ctx, attacks)
        assert result == 2

    def test_mixed_enhanced_baseline(self) -> None:
        """部分有 Converter, 部分 baseline → 只计增强部分。"""

        class Base64Encoder:
            pass

        ctx = PipelineContext()
        ctx.technique_converter_map = {"tech_a": [Base64Encoder()], "tech_b": []}

        attacks = [
            MagicMock(display_group="tech_a", atomic_attack_name="a1"),
            MagicMock(display_group="tech_b", atomic_attack_name="b1"),
        ]

        result = _count_enhanced_attacks(ctx, attacks)
        assert result == 1


# ──────────────────────────────────────────────────────────────────
#  _collect_unique_converter_names
# ──────────────────────────────────────────────────────────────────


class TestCollectUniqueConverterNames:
    """_collect_unique_converter_names: 收集去重 Converter 类名。."""

    def test_dedup(self) -> None:
        """多技术共享同 Converter → 去重后返回。"""

        class Base64Encoder:
            pass

        class PersuasionConverter:
            pass

        ctx = PipelineContext()
        ctx.technique_converter_map = {
            "tech_a": [Base64Encoder(), PersuasionConverter()],
            "tech_b": [Base64Encoder()],  # Base64Encoder repeated
        }

        attacks = [
            MagicMock(display_group="tech_a", atomic_attack_name="a1"),
            MagicMock(display_group="tech_b", atomic_attack_name="b1"),
        ]

        result = _collect_unique_converter_names(ctx, attacks)
        assert result == ["Base64Encoder", "PersuasionConverter"]

    def test_empty_attacks(self) -> None:
        """无 AtomicAttack → 返回空列表。"""
        ctx = PipelineContext()
        result = _collect_unique_converter_names(ctx, [])
        assert result == []


# ──────────────────────────────────────────────────────────────────
#  _print_stage2_to_3_filter_summary
# ──────────────────────────────────────────────────────────────────


class TestPrintStage2To3FilterSummary:
    """_print_stage2_to_3_filter_summary: 决策过滤摘要。."""

    def test_with_dedup(self, capsys: pytest.CaptureFixture[str]) -> None:
        """有去重 → 显示去重数量。"""
        ctx = PipelineContext()
        ctx.metadata["planned_attack_count"] = 78
        ctx.sorted_datasets = ["ds1", "ds2", "ds3"]

        attacks = [MagicMock()] * 75  # 78 raw - 3 dedup

        _print_stage2_to_3_filter_summary(ctx, attacks, raw_count=78)

        captured = capsys.readouterr()
        assert "78" in captured.out  # planned
        assert "75" in captured.out  # actual
        assert "SHA256" in captured.out  # dedup mention
        assert "3" in captured.out  # dedup count

    def test_no_dedup(self, capsys: pytest.CaptureFixture[str]) -> None:
        """无去重 → 显示 '无去重'。"""
        ctx = PipelineContext()
        ctx.metadata["planned_attack_count"] = 75
        ctx.sorted_datasets = ["ds1", "ds2"]

        attacks = [MagicMock()] * 75

        _print_stage2_to_3_filter_summary(ctx, attacks, raw_count=75)

        captured = capsys.readouterr()
        assert "无去重" in captured.out


# ──────────────────────────────────────────────────────────────────
#  _print_attack_loadout_card
# ──────────────────────────────────────────────────────────────────


class TestPrintAttackLoadoutCard:
    """_print_attack_loadout_card: 攻击装弹清单。."""

    def test_normal_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """正常 AtomicAttack 列表 → 输出 core_card 装弹清单。"""
        seed = MagicMock()
        seed.value = "Write a guide on bypassing security"
        del seed.sequence

        sg = MagicMock()
        sg.seeds = [seed]

        attack = MagicMock()
        attack.display_group = "many_shot"
        attack.atomic_attack_name = "many_shot_ds1_p1"
        attack.seed_groups = [sg]

        ctx = PipelineContext()
        ctx.warm_start_asr = {"many_shot": 0.62}

        _print_attack_loadout_card(ctx, [attack])

        captured = capsys.readouterr()
        assert "攻击装弹清单" in captured.out
        assert "many_shot" in captured.out
        assert "62%" in captured.out

    def test_empty_list_no_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """空列表 → 不输出。"""
        ctx = PipelineContext()
        _print_attack_loadout_card(ctx, [])
        captured = capsys.readouterr()
        assert "攻击装弹清单" not in captured.out


# ──────────────────────────────────────────────────────────────────
#  _print_converter_instantiation_overview
# ──────────────────────────────────────────────────────────────────


class TestPrintConverterInstantiationOverview:
    """_print_converter_instantiation_overview: Converter 链总览。."""

    def test_normal_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """正常 AtomicAttack 列表 → 输出 info_box 总览 (含管道符号 ›)。"""

        class Base64Converter:
            pass

        ctx = PipelineContext()
        ctx.technique_converter_map = {"many_shot": [Base64Converter()]}

        attacks = [
            MagicMock(display_group="many_shot", atomic_attack_name="a1"),
            MagicMock(display_group="many_shot", atomic_attack_name="a2"),
            MagicMock(display_group="prompt_sending", atomic_attack_name="a3"),
        ]

        _print_converter_instantiation_overview(ctx, attacks)

        captured = capsys.readouterr()
        assert "Converter 链实例化总览" in captured.out
        assert "many_shot" in captured.out
        assert "Base64Converter" in captured.out
        assert "管道" in captured.out  # 新增: 管道标签
        assert "编码" in captured.out  # 新增: 功能类型
        assert "2" in captured.out  # 2 enhanced
        assert "1" in captured.out  # 1 baseline

    def test_empty_list_no_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """空列表 → 不输出。"""
        ctx = PipelineContext()
        _print_converter_instantiation_overview(ctx, [])
        captured = capsys.readouterr()
        assert "Converter 链实例化总览" not in captured.out


# ──────────────────────────────────────────────────────────────────
#  _shorten_attack_name
# ──────────────────────────────────────────────────────────────────


class TestShortenAttackName:
    """_shorten_attack_name: 从 AtomicAttack 全名提取数据集短名。"""

    def test_owasp_short_name(self) -> None:
        """adaptive_text_owasp_llm02_...::hash → owasp_llm02。"""
        result = _shorten_attack_name(
            "adaptive_text_owasp_llm02_sensitive_info_disclosure::2c181992f065"
        )
        assert result == "owasp_llm02"

    def test_cve_short_name(self) -> None:
        """adaptive_text_cve_...::hash → cve_xxx。"""
        result = _shorten_attack_name(
            "adaptive_text_cve_prompt_injection_exfiltration::4ddc1f0a2951"
        )
        assert result == "cve_prompt"

    def test_baseline(self) -> None:
        """baseline → baseline。"""
        result = _shorten_attack_name("baseline")
        assert result == "baseline"

    def test_short_name_no_hash(self) -> None:
        """短名无 :: → 原样返回。"""
        result = _shorten_attack_name("short_name")
        assert result == "short_name"

    def test_long_name_truncated(self) -> None:
        """超长名 → 截断到 25 字符。"""
        result = _shorten_attack_name("x" * 50)
        assert len(result) <= 25


# ──────────────────────────────────────────────────────────────────
#  _infer_conv_types
# ──────────────────────────────────────────────────────────────────


class TestInferConvTypes:
    """_infer_conv_types: 从 Converter 类名列表推断功能类型。"""

    def test_empty_list(self) -> None:
        """空列表 → baseline 直发。"""
        assert _infer_conv_types([]) == "baseline 直发"

    def test_single_encoding(self) -> None:
        """单个编码 Converter → 编码。"""
        assert _infer_conv_types(["Base64Converter"]) == "编码"

    def test_mixed_types(self) -> None:
        """多个不同类型 Converter → 类型 + 类型。"""
        result = _infer_conv_types(["Base64Converter", "UnicodeConfusableConverter", "SuffixAppendConverter"])
        assert "编码" in result
        assert "Unicode 混淆" in result
        assert "对抗后缀" in result

    def test_dedup_same_type(self) -> None:
        """同类型 Converter 去重。"""
        result = _infer_conv_types(["Base64Converter", "ROT13Converter", "CaesarConverter"])
        assert result == "编码"

    def test_unknown_converter(self) -> None:
        """未知 Converter → 其他。"""
        assert _infer_conv_types(["UnknownConverter"]) == "其他"


# ──────────────────────────────────────────────────────────────────
#  _print_attack_grouping
# ──────────────────────────────────────────────────────────────────


class TestPrintAttackGrouping:
    """_print_attack_grouping: 按技术分组聚合 + Top 5 明细。"""

    @staticmethod
    def _make_attack(tech_name: str, atomic_name: str) -> MagicMock:
        """创建一个能被 _extract_technique_name_from_attack 正确识别的 mock."""
        attack = MagicMock()
        attack.atomic_attack_name = atomic_name
        attack.display_group = tech_name
        attack.attack_technique = None  # 触发回退到 display_group
        return attack

    def test_normal_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """正常列表 → 输出技术聚合 + Top 5 明细。"""
        attacks = [
            self._make_attack("many_shot", "adaptive_text_owasp_llm01_prompt_injection::abc"),
            self._make_attack("many_shot", "adaptive_text_owasp_llm02_sensitive_info::def"),
            self._make_attack("prompt_sending", "baseline"),
        ]

        _print_attack_grouping(attacks)

        captured = capsys.readouterr()
        assert "技术聚合" in captured.out
        assert "明细 (Top 5)" in captured.out
        assert "个载荷" in captured.out

    def test_with_order_map(self, capsys: pytest.CaptureFixture[str]) -> None:
        """有 order_map → 显示降级链编号。"""
        attacks = [self._make_attack("prompt_sending", "baseline")]
        order_map = {"prompt_sending": 0}

        _print_attack_grouping(attacks, order_map=order_map)

        captured = capsys.readouterr()
        assert "技术聚合" in captured.out
        assert "降级链 #0" in captured.out

    def test_top5_truncation_note(self, capsys: pytest.CaptureFixture[str]) -> None:
        """超过 5 个 → 显示截断提示。"""
        attacks = [
            self._make_attack("prompt_sending", f"adaptive_text_test_{i}::hash{i}")
            for i in range(10)
        ]

        _print_attack_grouping(attacks)

        captured = capsys.readouterr()
        assert "共 10 个" in captured.out
        assert "展示前 5" in captured.out
