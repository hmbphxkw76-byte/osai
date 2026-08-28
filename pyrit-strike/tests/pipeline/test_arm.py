"""Arm 模块测试 — converter_chains, seed_ranker, technique_picker, autodan_generator。

覆盖:
    - Converter 链构建 (encoding, stealth, persuasion, l5_optimal, build_converter_map)
    - 种子加载 + ASR 排序 + 语言自适应
    - 攻击技术选择 (auto, single, multi, 指定)
    - AutoDAN 种子生成
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# converter_chains: _conv 惰性导入
# ═══════════════════════════════════════════════════════


class TestConvImport:
    """测试 _conv 惰性导入."""

    def test_conv_returns_class(self):
        from pipeline.arm.converter_chains import _conv

        cls = _conv("Base64Converter")
        assert cls is not None
        assert hasattr(cls, "__name__")

    def test_conv_invalid_name_raises(self):
        from pipeline.arm.converter_chains import _conv

        with pytest.raises(AttributeError, match="not found"):
            _conv("NonExistentConverter")


# ═══════════════════════════════════════════════════════
# converter_chains: 各链构建函数
# ═══════════════════════════════════════════════════════


class TestEncodingBypass:
    """测试 encoding_bypass."""

    def test_returns_3_converters(self):
        from pipeline.arm.converter_chains import encoding_bypass

        converters = encoding_bypass()
        assert len(converters) == 3
        type_names = [type(c).__name__ for c in converters]
        assert "Base64Converter" in type_names
        assert "ROT13Converter" in type_names
        assert "CaesarConverter" in type_names


class TestStealthEvasion:
    """测试 stealth_evasion."""

    def test_returns_unicode_substitution(self):
        from pipeline.arm.converter_chains import stealth_evasion

        converters = stealth_evasion()
        assert len(converters) >= 1
        type_names = [type(c).__name__ for c in converters]
        assert "UnicodeSubstitutionConverter" in type_names


class TestPersuasion:
    """测试 persuasion."""

    def test_no_converter_target_returns_empty(self):
        from pipeline.arm.converter_chains import persuasion

        assert persuasion(converter_target=None) == []

    def test_with_mock_target(self):
        from pipeline.arm.converter_chains import persuasion

        mock = MagicMock()
        converters = persuasion(converter_target=mock)
        # 可能因为构造参数不对而失败, 但不应抛异常
        assert isinstance(converters, list)


class TestFormatInjection:
    """测试 format_injection."""

    def test_returns_ascii_art(self):
        from pipeline.arm.converter_chains import format_injection

        converters = format_injection()
        assert len(converters) == 1
        assert type(converters[0]).__name__ == "AsciiArtConverter"


class TestMultiEncoding:
    """测试 multi_encoding."""

    def test_returns_4_converters(self):
        from pipeline.arm.converter_chains import multi_encoding

        converters = multi_encoding()
        assert len(converters) == 4


class TestDecomposition:
    """测试 decomposition."""

    def test_no_converter_target_returns_empty(self):
        from pipeline.arm.converter_chains import decomposition

        assert decomposition(converter_target=None) == []

    def test_with_mock_target(self):
        from pipeline.arm.converter_chains import decomposition

        mock = MagicMock()
        converters = decomposition(converter_target=mock)
        assert isinstance(converters, list)


class TestVariation:
    """测试 variation."""

    def test_no_converter_target_returns_empty(self):
        from pipeline.arm.converter_chains import variation

        assert variation(converter_target=None) == []

    def test_with_mock_target(self):
        from pipeline.arm.converter_chains import variation

        mock = MagicMock()
        converters = variation(converter_target=mock)
        assert isinstance(converters, list)


class TestFlip:
    """测试 flip."""

    def test_returns_flip_converter(self):
        from pipeline.arm.converter_chains import flip

        converters = flip()
        assert len(converters) == 1
        assert type(converters[0]).__name__ == "FlipConverter"


class TestSmoothllmBypass:
    """测试 smoothllm_bypass."""

    def test_returns_converters(self):
        from pipeline.arm.converter_chains import smoothllm_bypass

        converters = smoothllm_bypass()
        assert len(converters) >= 1


# ═══════════════════════════════════════════════════════
# converter_chains: l5_optimal
# ═══════════════════════════════════════════════════════


class TestL5Optimal:
    """测试 l5_optimal converter 链构建."""

    def test_without_converter_target(self):
        """无 converter_target 时仍返回非 LLM converter."""
        from pipeline.arm.converter_chains import l5_optimal

        converters = l5_optimal(converter_target=None)
        assert len(converters) >= 3
        type_names = [type(c).__name__ for c in converters]
        assert "Base64Converter" in type_names
        assert "ROT13Converter" in type_names

    def test_with_mock_converter_target(self):
        """有 converter_target 时返回更多路径."""
        from pipeline.arm.converter_chains import l5_optimal

        mock_target = MagicMock()
        converters = l5_optimal(converter_target=mock_target)
        assert len(converters) >= 3

    def test_chain_builders_mapping(self):
        """CHAIN_BUILDERS 包含所有链名."""
        from pipeline.arm.converter_chains import CHAIN_BUILDERS

        expected_keys = {
            "encoding", "stealth", "persuasion", "format",
            "multi_encoding", "decomposition", "variation",
            "flip", "smoothllm_bypass", "l5_optimal",
        }
        assert expected_keys.issubset(CHAIN_BUILDERS.keys())


# ═══════════════════════════════════════════════════════
# converter_chains: build_converter_map
# ═══════════════════════════════════════════════════════


class TestBuildConverterMap:
    """测试 build_converter_map."""

    def test_empty_techniques_returns_empty(self):
        from pipeline.arm.converter_chains import build_converter_map

        result = build_converter_map([], ["encoding"])
        assert result == {}

    def test_empty_chain_names_returns_empty(self):
        from pipeline.arm.converter_chains import build_converter_map

        result = build_converter_map(["prompt_sending"], [])
        assert result == {}

    def test_unknown_chain_name_skipped(self):
        from pipeline.arm.converter_chains import build_converter_map

        result = build_converter_map(["prompt_sending"], ["nonexistent_chain"])
        assert result == {}

    def test_encoding_chain_built(self):
        from pipeline.arm.converter_chains import build_converter_map

        result = build_converter_map(["prompt_sending"], ["encoding"])
        assert "prompt_sending" in result
        assert len(result["prompt_sending"]) == 3

    def test_multiple_techniques_and_chains(self):
        from pipeline.arm.converter_chains import build_converter_map

        result = build_converter_map(
            ["prompt_sending", "many_shot"],
            ["encoding", "stealth"],
        )
        assert "prompt_sending" in result
        assert "many_shot" in result

    def test_l5_optimal_without_target(self):
        from pipeline.arm.converter_chains import build_converter_map

        result = build_converter_map(["prompt_sending"], ["l5_optimal"], converter_target=None)
        # l5_optimal without target returns only non-LLM converters
        if "prompt_sending" in result:
            assert len(result["prompt_sending"]) >= 3


# ═══════════════════════════════════════════════════════
# seed_ranker: 种子加载
# ═══════════════════════════════════════════════════════


class TestLoadSeeds:
    """测试 load_seeds."""

    def test_load_real_seeds(self):
        """从真实种子文件加载."""
        req_path = _PROJECT_ROOT / "data" / "seeds" / "elite_jailbreaks.prompt"
        if not req_path.exists():
            pytest.skip("Seed file not found")

        from pipeline.arm.seed_ranker import load_seeds

        seeds = load_seeds("elite_jailbreaks", max_seeds=5)
        assert len(seeds) > 0
        assert len(seeds) <= 5

    def test_nonexistent_seed_file_raises(self):
        from pipeline.arm.seed_ranker import load_seeds

        with pytest.raises(FileNotFoundError):
            load_seeds("nonexistent_seed_file", max_seeds=5)

    def test_comma_separated_seeds(self):
        """逗号分隔的多种子文件."""
        path = _PROJECT_ROOT / "data" / "seeds" / "elite_jailbreaks.prompt"
        if not path.exists():
            pytest.skip("Seed file not found")

        from pipeline.arm.seed_ranker import load_seeds

        seeds = load_seeds("elite_jailbreaks,elite_jailbreaks", max_seeds=3)
        assert len(seeds) > 0


# ═══════════════════════════════════════════════════════
# seed_ranker: 语言筛选
# ═══════════════════════════════════════════════════════


class TestFilterByLanguage:
    """测试 _filter_by_language."""

    def test_zh_language_filter(self):
        from pipeline.arm.seed_ranker import _filter_by_language

        seeds = [
            {"value": "seed1", "metadata": {"language": "zh"}},
            {"value": "seed2", "metadata": {"language": "en"}},
            {"value": "seed3", "metadata": {"language": "zh"}},
        ]
        result = _filter_by_language(seeds, "zh")
        # Should include mostly zh seeds
        zh_count = sum(1 for s in result if s.get("metadata", {}).get("language") == "zh")
        assert zh_count > 0

    def test_no_matching_language_returns_all(self):
        from pipeline.arm.seed_ranker import _filter_by_language

        seeds = [
            {"value": "seed1", "metadata": {"language": "en"}},
            {"value": "seed2", "metadata": {"language": "en"}},
        ]
        result = _filter_by_language(seeds, "zh")
        # No zh seeds, should return all
        assert len(result) == 2

    def test_empty_seeds(self):
        from pipeline.arm.seed_ranker import _filter_by_language

        assert _filter_by_language([], "zh") == []


# ═══════════════════════════════════════════════════════
# seed_ranker: ASR 历史更新
# ═══════════════════════════════════════════════════════


class TestUpdateAsrHistory:
    """测试 update_asr_history 种子级 ASR 更新."""

    def test_update_with_seed_asr(self, tmp_path, monkeypatch):
        from pipeline.arm import seed_ranker, seed_ranking

        asr_path = tmp_path / "asr_history.json"
        monkeypatch.setattr(seed_ranker, "_ASR_HISTORY_PATH", asr_path)
        monkeypatch.setattr(seed_ranker, "_SEEDS_DIR", tmp_path)
        monkeypatch.setattr(seed_ranking, "_ASR_HISTORY_PATH", asr_path)
        monkeypatch.setattr(seed_ranking, "_SEEDS_DIR", tmp_path)

        seed_ranker.update_asr_history(
            {"prompt_sending": 30.0},
            seed_asr={"test objective": 50.0},
            seed_attempts={"test objective": 3},
        )

        data = json.loads(
            asr_path.read_text(encoding="utf-8")
        )
        assert "seed_asr" in data
        assert "test objective" in data["seed_asr"]
        assert data["seed_asr"]["test objective"] == 50.0
        assert data["seed_attempts"]["test objective"] == 3

    def test_ema_merge_seed_asr(self, tmp_path, monkeypatch):
        from pipeline.arm import seed_ranker, seed_ranking

        asr_path = tmp_path / "asr_history.json"
        monkeypatch.setattr(seed_ranker, "_ASR_HISTORY_PATH", asr_path)
        monkeypatch.setattr(seed_ranker, "_SEEDS_DIR", tmp_path)
        monkeypatch.setattr(seed_ranking, "_ASR_HISTORY_PATH", asr_path)
        monkeypatch.setattr(seed_ranking, "_SEEDS_DIR", tmp_path)

        # First update
        seed_ranker.update_asr_history(
            {"prompt_sending": 30.0},
            seed_asr={"seed1": 100.0},
            seed_attempts={"seed1": 1},
        )

        # Second update (EMA: 0.3 * 50 + 0.7 * 100 = 85)
        seed_ranker.update_asr_history(
            {"prompt_sending": 40.0},
            seed_asr={"seed1": 50.0},
            seed_attempts={"seed1": 1},
        )

        data = json.loads(
            asr_path.read_text(encoding="utf-8")
        )
        assert data["seed_asr"]["seed1"] == 85.0
        assert data["seed_attempts"]["seed1"] == 2

    def test_update_without_seed_asr(self, tmp_path, monkeypatch):
        from pipeline.arm import seed_ranker, seed_ranking

        asr_path = tmp_path / "asr_history.json"
        monkeypatch.setattr(seed_ranker, "_ASR_HISTORY_PATH", asr_path)
        monkeypatch.setattr(seed_ranker, "_SEEDS_DIR", tmp_path)
        monkeypatch.setattr(seed_ranking, "_ASR_HISTORY_PATH", asr_path)
        monkeypatch.setattr(seed_ranking, "_SEEDS_DIR", tmp_path)

        seed_ranker.update_asr_history({"prompt_sending": 50.0})
        data = json.loads(
            asr_path.read_text(encoding="utf-8")
        )
        assert data["asr"]["prompt_sending"] == 50.0


# ═══════════════════════════════════════════════════════
# technique_picker: 技术选择
# ═══════════════════════════════════════════════════════


class TestSelectTechniques:
    """测试 select_techniques."""

    def test_auto_with_adversarial(self):
        from pipeline.arm.technique_picker import select_techniques

        techniques = select_techniques("auto", has_adversarial=True)
        assert "prompt_sending" in techniques
        assert "crescendo_simulated" in techniques
        assert "tap" in techniques

    def test_auto_without_adversarial(self):
        from pipeline.arm.technique_picker import select_techniques

        techniques = select_techniques("auto", has_adversarial=False)
        assert "prompt_sending" in techniques
        # Multi-turn techniques should not be present
        assert "tap" not in techniques
        assert "pair" not in techniques

    def test_single_mode(self):
        from pipeline.arm.technique_picker import select_techniques

        techniques = select_techniques("single")
        assert "prompt_sending" in techniques
        assert "crescendo_simulated" not in techniques

    def test_multi_mode(self):
        from pipeline.arm.technique_picker import select_techniques

        techniques = select_techniques("multi")
        assert "crescendo_simulated" in techniques
        assert "tap" in techniques
        assert "prompt_sending" not in techniques

    def test_specific_techniques(self):
        from pipeline.arm.technique_picker import select_techniques

        techniques = select_techniques("prompt_sending,tap")
        assert techniques == ["prompt_sending", "tap"]


class TestIsMultiTurnTechnique:
    """测试 is_multi_turn_technique."""

    def test_crescendo_is_multi_turn(self):
        from pipeline.arm.technique_picker import is_multi_turn_technique

        assert is_multi_turn_technique("crescendo_simulated") is True

    def test_tap_is_multi_turn(self):
        from pipeline.arm.technique_picker import is_multi_turn_technique

        assert is_multi_turn_technique("tap") is True

    def test_prompt_sending_not_multi_turn(self):
        from pipeline.arm.technique_picker import is_multi_turn_technique

        assert is_multi_turn_technique("prompt_sending") is False


class TestFilterByAdversarial:
    """测试 filter_by_adversarial."""

    def test_with_adversarial_keeps_all(self):
        from pipeline.arm.technique_picker import filter_by_adversarial

        techniques = ["prompt_sending", "tap", "pair"]
        result = filter_by_adversarial(techniques, has_adversarial=True)
        assert result == techniques

    def test_without_adversarial_removes_multi_turn(self):
        from pipeline.arm.technique_picker import filter_by_adversarial

        techniques = ["prompt_sending", "tap", "pair", "many_shot"]
        result = filter_by_adversarial(techniques, has_adversarial=False)
        assert "prompt_sending" in result
        assert "many_shot" in result
        assert "tap" not in result
        assert "pair" not in result


# ═══════════════════════════════════════════════════════
# autodan_generator: 种子生成
# ═══════════════════════════════════════════════════════


class TestAutoDanGenerator:
    """测试 autodan_generator."""

    def test_clean_generated_variant(self):
        from pipeline.arm.autodan_generator import _clean_generated_variant

        content = "Rewritten request: This is the actual jailbreak content here."
        result = _clean_generated_variant(content, "original objective")
        assert "[System Override]" in result
        assert "skeleton-key mode" in result
        assert "This is the actual jailbreak content here." in result

    def test_clean_academic_prefix(self):
        from pipeline.arm.autodan_generator import _clean_generated_variant

        content = "Academic framing: The academic content here."
        result = _clean_generated_variant(content, "objective")
        assert "[System Override]" in result
        assert "The academic content here." in result

    def test_get_autodan_seed_groups(self):
        from pipeline.arm.autodan_generator import get_autodan_seed_groups

        objectives = ["test objective 1", "test objective 2"]
        mock_target = MagicMock()
        groups = get_autodan_seed_groups(objectives, mock_target, n_variants_per_objective=2)
        assert len(groups) == 4  # 2 objectives * 2 variants
        # Each group should have at least one seed
        for group in groups:
            assert hasattr(group, "seeds")
            assert len(group.seeds) >= 1

    def test_autodan_strategies_count(self):
        from pipeline.arm.autodan_generator import _AUTODAN_STRATEGIES

        assert len(_AUTODAN_STRATEGIES) >= 5

    def test_roles_count(self):
        from pipeline.arm.autodan_generator import _ROLES

        assert len(_ROLES) >= 5

    def test_scenarios_count(self):
        from pipeline.arm.autodan_generator import _SCENARIOS

        assert len(_SCENARIOS) >= 5
