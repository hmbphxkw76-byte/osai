"""converter_selector 独立单元测试 — 转换器选择、签名、优先级、裁剪.

覆盖:
    - _converter_signature: 各类型 converter 签名生成
    - _get_candidate_converters: 去重、裁剪、优先级排序
    - _get_owasp_converter_priorities: OWASP 自适应优先级
    - _build_converter_config: 转换器配置构建
    - _prune_low_asr_converters: 低 ASR 裁剪
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ═══════════════════════════════════════════════════════
# _converter_signature
# ═══════════════════════════════════════════════════════


class TestConverterSignature:
    """测试 _converter_signature 函数."""

    def test_plain_converter_returns_type_name(self):
        from pipeline.strike.converter_selector import _converter_signature

        converter = MagicMock()
        converter.__class__.__name__ = "Base64Converter"
        # MagicMock doesn't trigger PersuasionConverter/ToneConverter branches
        result = _converter_signature(converter)
        assert result == "Base64Converter"

    def test_persuasion_converter_with_technique(self):
        from pipeline.strike.converter_selector import _converter_signature

        converter = MagicMock()
        converter.__class__.__name__ = "PersuasionConverter"
        technique = MagicMock()
        technique.value = "authority_endorsement"
        converter._persuasion_technique = technique

        result = _converter_signature(converter)
        assert result == "PersuasionConverter:authority_endorsement"

    def test_persuasion_converter_without_technique(self):
        from pipeline.strike.converter_selector import _converter_signature

        converter = MagicMock()
        converter.__class__.__name__ = "PersuasionConverter"
        converter._persuasion_technique = None

        result = _converter_signature(converter)
        assert result == "PersuasionConverter"

    def test_tone_converter_with_tone(self):
        from pipeline.strike.converter_selector import _converter_signature

        converter = MagicMock()
        converter.__class__.__name__ = "ToneConverter"
        tone = MagicMock()
        tone.value = "academic"
        converter._tone = tone

        result = _converter_signature(converter)
        assert result == "ToneConverter:academic"

    def test_rot13_converter(self):
        from pipeline.strike.converter_selector import _converter_signature

        converter = MagicMock()
        converter.__class__.__name__ = "ROT13Converter"
        converter._persuasion_technique = None
        converter._tone = None

        result = _converter_signature(converter)
        assert result == "ROT13Converter"


# ═══════════════════════════════════════════════════════
# _get_candidate_converters
# ═══════════════════════════════════════════════════════


class TestGetCandidateConverters:
    """测试 _get_candidate_converters 函数."""

    def test_empty_converter_map_returns_empty(self):
        from pipeline.strike.converter_selector import _get_candidate_converters

        ctx = MagicMock()
        ctx.converter_map = {}
        result = _get_candidate_converters(ctx)
        assert result == []

    def test_dedup_same_signature(self):
        from pipeline.strike.converter_selector import _get_candidate_converters

        c1 = MagicMock()
        c1.__class__.__name__ = "ROT13Converter"
        c1._persuasion_technique = None
        c1._tone = None

        c2 = MagicMock()
        c2.__class__.__name__ = "ROT13Converter"
        c2._persuasion_technique = None
        c2._tone = None

        ctx = MagicMock()
        ctx.converter_map = {"encoding": [c1, c2]}
        ctx.seeds = {}
        ctx._obj_metadata_map = {}

        result = _get_candidate_converters(ctx)
        # Should deduplicate to 1
        assert len(result) <= 1

    def test_max_10_candidates(self):
        """L5 v36: 验证返回的候选列表不超过 10 个 (v36 扩展自 7)."""
        from pipeline.strike.converter_selector import _get_candidate_converters

        converters = []
        for name in [
            "DecompositionConverter", "ROT13Converter", "Base64Converter",
            "VariationConverter", "UnicodeSubstitutionConverter",
            "RandomTranslationConverter", "TranslationConverter",
            "RandomCapitalLettersConverter", "CaesarConverter",
            "SelectiveTextConverter", "CodeChameleonConverter",
            "PolicyPuppetryConverter", "SearchReplaceConverter",
        ]:
            c = MagicMock()
            c.__class__.__name__ = name
            c._persuasion_technique = None
            c._tone = None
            c._selection_strategy = None
            c._pattern = None
            c._encrypt_type = None
            c._sub_converter = None
            converters.append(c)

        ctx = MagicMock()
        ctx.converter_map = {"chain": converters}
        ctx.seeds = {}
        ctx._obj_metadata_map = {}

        result = _get_candidate_converters(ctx)
        assert len(result) <= 10


# ═══════════════════════════════════════════════════════
# _get_owasp_converter_priorities
# ═══════════════════════════════════════════════════════


class TestGetOwaspConverterPriorities:
    """测试 _get_owasp_converter_priorities 函数."""

    def test_no_seeds_returns_empty(self):
        from pipeline.strike.converter_selector import _get_owasp_converter_priorities

        ctx = MagicMock()
        ctx.seeds = {}
        ctx._obj_metadata_map = {}
        result = _get_owasp_converter_priorities(ctx)
        assert result == []

    def test_no_metadata_map_returns_empty(self):
        from pipeline.strike.converter_selector import _get_owasp_converter_priorities

        ctx = MagicMock()
        ctx.seeds = {"elite_jailbreaks": []}
        ctx._obj_metadata_map = {}
        result = _get_owasp_converter_priorities(ctx)
        assert result == []
