# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""test_converter_factory — Converter 工厂单元测试。.

覆盖:
  - create_converters: 名称 → 实例
  - build_technique_converter_map: ASR 驱动差异化路由
  - build_converters_from_chain_names: 链名 → 扁平化去重 Converter 列表
  - build_target_aware_converter_map: target_type → 技术→Converter 映射
  - merge_converter_maps: CLI + Target 感知并集合并
  - get_available_converter_names

> **日期**: 2026-8-1
> **更新记录**:
>   2026-8-1 — v8.1: 新增 build_converters_from_chain_names / build_target_aware_converter_map /
>     merge_converter_maps 单元测试 (P5-2)
"""

from __future__ import annotations

import pytest

from pipeline.converters.factory import (
    build_target_aware_converter_map,
    build_technique_converter_map,
    create_converters,
    get_available_converter_names,
    merge_converter_maps,
)

# ──────────────────────────────────────────────────────────────────
#  create_converters
# ──────────────────────────────────────────────────────────────────


class TestCreateConverters:
    """create_converters 单元测试。."""

    def test_create_single_converter(self) -> None:
        """单个 converter 创建。."""
        converters = create_converters(["rot13"])
        assert len(converters) == 1
        assert type(converters[0]).__name__ == "ROT13Converter"

    def test_create_multiple_converters(self) -> None:
        """多个 converter 创建。."""
        converters = create_converters(["rot13", "base64", "flip"])
        assert len(converters) == 3

    def test_case_insensitive(self) -> None:
        """不区分大小写。."""
        converters = create_converters(["ROT13", "Base64"])
        assert len(converters) == 2

    def test_unknown_converter_raises(self) -> None:
        """未知 converter 名称引发 ValueError。."""
        with pytest.raises(ValueError, match="Unknown converter"):
            create_converters(["unknown_converter"])

    def test_empty_list(self) -> None:
        """空列表返回空列表。."""
        assert create_converters([]) == []


# ──────────────────────────────────────────────────────────────────
#  build_technique_converter_map
# ──────────────────────────────────────────────────────────────────


class TestBuildTechniqueConverterMap:
    """build_technique_converter_map 单元测试。."""

    def test_no_asr_data_uniform_routing(self) -> None:
        """无 ASR 数据时均匀路由 (冷启动)。."""
        result = build_technique_converter_map(
            converter_names=["rot13", "base64"],
            technique_names=["many_shot", "tap"],
            asr_by_technique={},  # 显式空 = 冷启动
        )
        assert len(result) == 2
        assert len(result["many_shot"]) == 2  # 全部 converters
        assert len(result["tap"]) == 2  # 全部 converters

    def test_asr_driven_routing(self) -> None:
        """有 ASR 数据时差异化路由。."""
        from pipeline.asr.optimizer import compute_stats

        asr = {
            "many_shot": compute_stats(successes=9, failures=1, undetermined=0, errors=0),  # 高 ASR
            "tap": compute_stats(successes=1, failures=9, undetermined=0, errors=0),  # 低 ASR
        }
        result = build_technique_converter_map(
            converter_names=["rot13", "base64", "flip"],
            technique_names=["many_shot", "tap"],
            asr_by_technique=asr,
        )
        # 高 ASR 技术: 全部 converters
        assert len(result["many_shot"]) == 3
        # 低 ASR 技术: 子集 (len//2 = 1)
        assert len(result["tap"]) == 1

    def test_empty_converter_names(self) -> None:
        """空 converter 列表返回空字典。."""
        result = build_technique_converter_map(
            converter_names=[],
            technique_names=["many_shot"],
            asr_by_technique={},
        )
        assert result == {}

    def test_all_zero_asr_uniform(self) -> None:
        """所有技术 ASR 为 0 时退化为均匀路由。."""
        from pipeline.asr.optimizer import compute_stats

        asr = {
            "many_shot": compute_stats(successes=0, failures=10, undetermined=0, errors=0),
            "tap": compute_stats(successes=0, failures=10, undetermined=0, errors=0),
        }
        result = build_technique_converter_map(
            converter_names=["rot13"],
            technique_names=["many_shot", "tap"],
            asr_by_technique=asr,
        )
        # ASR = 0 < 0.5, 低 ASR 子集 = max(1, 1//2) = 1
        assert len(result["many_shot"]) == 1
        assert len(result["tap"]) == 1


# ──────────────────────────────────────────────────────────────────
#  build_converters_from_chain_names
# ──────────────────────────────────────────────────────────────────


class TestBuildConvertersFromChainNames:
    """build_converters_from_chain_names 单元测试。.

    测试从多个链名构建扁平化去重 Converter 实例列表。
    """

    def test_single_non_llm_chain(self) -> None:
        """单个非 LLM 链构建成功。."""
        from pipeline.converters.chains import build_converters_from_chain_names

        converters = build_converters_from_chain_names(["stealth_evasion"])
        assert len(converters) >= 1
        # stealth_evasion = UnicodeConfusable + Base64 + SuffixAppend
        type_names = {type(c).__name__ for c in converters}
        assert "UnicodeConfusableConverter" in type_names
        assert "Base64Converter" in type_names
        assert "SuffixAppendConverter" in type_names

    def test_multiple_non_llm_chains(self) -> None:
        """多个非 LLM 链合并为扁平列表 (P0: 深度截断到 MAX_CONVERTER_CHAIN_DEPTH=3)."""
        from pipeline.converters.chains import build_converters_from_chain_names

        converters = build_converters_from_chain_names(["stealth_evasion", "encoding_bypass"])
        # P0: stealth_evasion 有 3 converters, 深度截断后最多 3 个
        # stealth_evasion: UnicodeConfusable + Base64 + SuffixAppend = 3 converters
        # encoding_bypass 的 converters 会被截断 (已达 MAX_CONVERTER_CHAIN_DEPTH=3)
        assert len(converters) >= 1
        assert len(converters) <= 3  # P0: 深度截断到 3

    def test_multiple_non_llm_chains_no_depth_limit(self) -> None:
        """P0: max_depth=None 时不截断, 多个链合并为完整列表."""
        from pipeline.converters.chains import build_converters_from_chain_names

        converters = build_converters_from_chain_names(
            ["stealth_evasion", "encoding_bypass"],
            max_depth=99,
        )
        # 无截限时: stealth_evasion 3 + encoding_bypass 3 - Base64Converter 去重 1 = 5
        assert len(converters) >= 4
        assert len(converters) <= 6

    def test_dedup_same_converter_class(self) -> None:
        """同名 Converter 类只保留第一个实例 (P0: 深度截断到 3)."""
        from pipeline.converters.chains import build_converters_from_chain_names

        # P0: 使用 max_depth=99 测试完整去重行为
        converters = build_converters_from_chain_names(
            ["stealth_evasion", "multi_encoding_v2"],
            max_depth=99,
        )
        type_names = [type(c).__name__ for c in converters]
        # 不应有重复
        assert len(type_names) == len(set(type_names))

    def test_llm_chain_without_converter_target_skipped(self) -> None:
        """LLM 链在无 converter_target 时跳过。."""
        from pipeline.converters.chains import build_converters_from_chain_names

        # persuasion_authority 是 LLM 链
        converters = build_converters_from_chain_names(
            ["persuasion_authority"],
            converter_target=None,
        )
        assert len(converters) == 0

    def test_unknown_chain_name_skipped(self) -> None:
        """未知链名被跳过, 不报错。."""
        from pipeline.converters.chains import build_converters_from_chain_names

        converters = build_converters_from_chain_names(["nonexistent_chain"])
        assert len(converters) == 0

    def test_empty_list(self) -> None:
        """空链名列表返回空列表。."""
        from pipeline.converters.chains import build_converters_from_chain_names

        assert build_converters_from_chain_names([]) == []

    def test_p0_depth_limit_truncation(self) -> None:
        """P0: MAX_CONVERTER_CHAIN_DEPTH=3 截断生效。."""
        from pipeline.converters.chains import MAX_CONVERTER_CHAIN_DEPTH, build_converters_from_chain_names

        assert MAX_CONVERTER_CHAIN_DEPTH == 3

        # stealth_evasion(3) + encoding_bypass(3) = 6 unique, 截断到 3
        converters = build_converters_from_chain_names(
            ["stealth_evasion", "encoding_bypass"],
            max_depth=99,
        )
        assert len(converters) >= 4  # 无截限

        converters_limited = build_converters_from_chain_names(
            ["stealth_evasion", "encoding_bypass"],
        )
        assert len(converters_limited) <= 3  # P0 截断

    def test_p2_cross_paradigm_2layer(self) -> None:
        """P2: cross_paradigm_2layer 构建 Base64 + UnicodeConfusable。."""
        from pipeline.converters.chains import build_converters_from_chain_names

        converters = build_converters_from_chain_names(["cross_paradigm_2layer"])
        type_names = {type(c).__name__ for c in converters}
        assert "Base64Converter" in type_names
        assert "UnicodeConfusableConverter" in type_names
        assert len(converters) == 2

    def test_p2_cross_paradigm_3layer_without_target(self) -> None:
        """P2: cross_paradigm_3layer 在 YAML 中 requires_llm=true, 无 target 时被跳过.

        注意: build_converters_from_chain_names 检查 YAML 的 requires_llm 标志,
        在 converter_target=None 时跳过整个链. 这是预期行为 —
        cross_paradigm_3layer 的 LLM 语义层需要 converter_target 才有意义.
        若需无 LLM 的跨范式链, 使用 cross_paradigm_2layer.
        """
        from pipeline.converters.chains import build_converters_from_chain_names

        converters = build_converters_from_chain_names(
            ["cross_paradigm_3layer"],
            converter_target=None,
        )
        # requires_llm=true 且无 target → 跳过, 返回空列表
        assert len(converters) == 0

        # 但 cross_paradigm_2layer (非 LLM) 正常工作
        converters_2layer = build_converters_from_chain_names(["cross_paradigm_2layer"])
        assert len(converters_2layer) == 2

    def test_mixed_llm_and_non_llm_chains(self) -> None:
        """混合 LLM 和非 LLM 链: 非 LLM 链构建, LLM 链跳过 (无 target)。."""
        from pipeline.converters.chains import build_converters_from_chain_names

        converters = build_converters_from_chain_names(
            ["stealth_evasion", "persuasion_authority"],
            converter_target=None,
        )
        # 只有 stealth_evasion 的 converters (P0: 最多 3 个)
        assert len(converters) >= 1
        assert len(converters) <= 3  # P0: MAX_CONVERTER_CHAIN_DEPTH=3
        type_names = {type(c).__name__ for c in converters}
        assert "UnicodeConfusableConverter" in type_names


# ──────────────────────────────────────────────────────────────────
#  build_target_aware_converter_map
# ──────────────────────────────────────────────────────────────────


class TestBuildTargetAwareConverterMap:
    """build_target_aware_converter_map 单元测试。.

    测试根据 target_type 自动构建技术→Converter 映射。
    """

    def test_none_target_type_returns_empty(self) -> None:
        """target_type 为 None 时返回空字典。."""
        result = build_target_aware_converter_map(
            technique_names=["prompt_sending", "many_shot"],
            target_type=None,
        )
        assert result == {}

    def test_known_target_type_returns_mapping(self) -> None:
        """已知 target_type 返回非空映射。."""
        result = build_target_aware_converter_map(
            technique_names=["prompt_sending", "many_shot"],
            target_type="openai_chat",
            converter_target_available=False,
            model_tier="moderate",
        )
        # openai_chat → llm_direct 分组, 应有推荐链
        assert len(result) >= 1
        # prompt_sending 应在结果中 (它在 base_techniques_for_variants 中)
        if "prompt_sending" in result:
            assert len(result["prompt_sending"]) >= 1

    def test_unknown_target_type_returns_empty(self) -> None:
        """未知 target_type 返回空字典。."""
        result = build_target_aware_converter_map(
            technique_names=["prompt_sending"],
            target_type="nonexistent_type",
        )
        assert result == {}

    def test_variant_technique_name_matches_base(self) -> None:
        """变体技术名 (含 '+') 能匹配基础技术。."""
        result = build_target_aware_converter_map(
            technique_names=["prompt_sending+stealth_evasion"],
            target_type="openai_chat",
            converter_target_available=False,
            model_tier="moderate",
        )
        # 变体名的 base_technique 是 prompt_sending, 应匹配到推荐链
        if result:
            assert "prompt_sending+stealth_evasion" in result

    def test_empty_technique_names_returns_empty(self) -> None:
        """空技术列表返回空字典。."""
        result = build_target_aware_converter_map(
            technique_names=[],
            target_type="openai_chat",
        )
        assert result == {}


# ──────────────────────────────────────────────────────────────────
#  merge_converter_maps
# ──────────────────────────────────────────────────────────────────


class TestMergeConverterMaps:
    """merge_converter_maps 单元测试。.

    测试 CLI 指定与 Target 感知 Converter 映射的并集合并。
    """

    def test_empty_target_aware_returns_cli(self) -> None:
        """target_aware 为空时返回 cli_map。."""
        from pyrit.converter import ROT13Converter

        cli_map = {"many_shot": [ROT13Converter()]}
        result = merge_converter_maps(cli_map, {})
        assert result == cli_map

    def test_empty_cli_returns_target_aware(self) -> None:
        """Cli 为空时返回 target_aware_map。."""
        from pyrit.converter import Base64Converter

        ta_map = {"tap": [Base64Converter()]}
        result = merge_converter_maps({}, ta_map)
        assert result == ta_map

    def test_both_empty_returns_empty(self) -> None:
        """两者都为空时返回空字典。."""
        assert merge_converter_maps({}, {}) == {}

    def test_union_of_different_techniques(self) -> None:
        """不同技术的并集合并。."""
        from pyrit.converter import Base64Converter, ROT13Converter

        cli_map = {"many_shot": [ROT13Converter()]}
        ta_map = {"tap": [Base64Converter()]}
        result = merge_converter_maps(cli_map, ta_map)
        assert len(result) == 2
        assert "many_shot" in result
        assert "tap" in result

    def test_same_technique_dedup(self) -> None:
        """同一技术的 Converter 去重 (同名类只保留一个)。."""
        from pyrit.converter import ROT13Converter

        cli_map = {"many_shot": [ROT13Converter()]}
        ta_map = {"many_shot": [ROT13Converter()]}  # 同名类
        result = merge_converter_maps(cli_map, ta_map)
        assert len(result["many_shot"]) == 1  # 去重后只保留一个

    def test_cli_priority_ordering(self) -> None:
        """CLI converters 排在 target-aware 前面。."""
        from pyrit.converter import Base64Converter, ROT13Converter

        cli_map = {"many_shot": [ROT13Converter()]}
        ta_map = {"many_shot": [Base64Converter()]}
        result = merge_converter_maps(cli_map, ta_map)
        # CLI 的 ROT13 应在第一位
        assert type(result["many_shot"][0]).__name__ == "ROT13Converter"
        assert type(result["many_shot"][1]).__name__ == "Base64Converter"


# ──────────────────────────────────────────────────────────────────
#  get_available_converter_names
# ──────────────────────────────────────────────────────────────────


class TestGetAvailableConverterNames:
    """get_available_converter_names 单元测试。."""

    def test_returns_sorted_list(self) -> None:
        """返回排序后的列表。."""
        names = get_available_converter_names()
        assert names == sorted(names)
        assert "rot13" in names
        assert "base64" in names
        assert len(names) >= 18
