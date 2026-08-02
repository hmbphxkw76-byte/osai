# -*- coding: utf-8 -*-
"""修复3个skipped集成测试: SimpleNamespace替换MagicMock + lambda替换side_effect列表"""

path = "tests/integration/test_pipeline_e2e.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix 0: 添加 SimpleNamespace import
content = content.replace(
    "from pathlib import Path\nfrom unittest.mock import MagicMock, patch",
    "from pathlib import Path\nfrom types import SimpleNamespace\nfrom unittest.mock import MagicMock, patch",
)

# Fix 1: 移除 converter routing skip + 修复 side_effect
content = content.replace(
    '    @pytest.mark.skip(reason="MagicMock与内部排序交互问题, 需真实数据验证")\n    def test_build_technique_converter_map_gradient',
    '    def test_build_technique_converter_map_gradient',
)
content = content.replace(
    '        # Mock converters\n        converter_names = ["base64", "rot13", "morse", "binary", "caesar"]\n\n        # Mock _tech_asr_score to return different ASR values\n        with patch("pipeline.converters.factory._tech_asr_score") as mock_score:\n            mock_score.side_effect = [0.8, 0.3, 0.1]  # high, medium, low ASR (floats)\n\n            result = build_technique_converter_map(\n                converter_names=converter_names,\n                technique_names=["tech_high", "tech_mid", "tech_low"],\n            )\n\n        # High ASR tech → all converters\n        assert len(result["tech_high"]) == 5\n        # Low ASR tech → fewer converters (gradient)\n        assert len(result["tech_low"]) >= 1\n        assert len(result["tech_low"]) <= 5',
    '        converter_names = ["base64", "rot13", "morse", "binary", "caesar"]\n\n        # 使用 lambda 避免 side_effect 耗尽 (sorted 可能多次调用)\n        asr_map = {"tech_high": 0.8, "tech_mid": 0.3, "tech_low": 0.1}\n        with patch("pipeline.converters.factory._tech_asr_score") as mock_score:\n            mock_score.side_effect = lambda tech: asr_map.get(tech, 0.5)\n\n            result = build_technique_converter_map(\n                converter_names=converter_names,\n                technique_names=list(asr_map.keys()),\n            )\n\n        # High ASR tech → all converters\n        assert len(result["tech_high"]) == 5\n        # Low ASR tech → fewer converters (gradient)\n        assert len(result["tech_low"]) >= 1\n        assert len(result["tech_low"]) < 5',
)

# Fix 2: 移除 evidence chain skip + SimpleNamespace 替换
content = content.replace(
    '    @pytest.mark.skip(reason="MagicMock class_name 深度属性链问题, 需真实 AttackResult")\n    def test_collect_evidence_from_results',
    '    def test_collect_evidence_from_results',
)
content = content.replace(
    '        _strategy_id = MagicMock()\n        _strategy_id.class_name = "many_shot"',
    '        _strategy_id = SimpleNamespace(name=None, class_name="many_shot")',
)
content = content.replace(
    '        _strategy_id2 = MagicMock()\n        _strategy_id2.class_name = "tap"',
    '        _strategy_id2 = SimpleNamespace(name=None, class_name="tap")',
)

# Fix 3: 移除 web_redteam evidence skip + SimpleNamespace 替换
content = content.replace(
    '    @pytest.mark.skip(reason="MagicMock class_name 深度属性链问题, 需真实 AttackResult")\n    def test_collect_web_redteam_evidence_with_results',
    '    def test_collect_web_redteam_evidence_with_results',
)
content = content.replace(
    '        _sid1 = MagicMock()\n        _sid1.class_name = "prompt_sending"',
    '        _sid1 = SimpleNamespace(name=None, class_name="prompt_sending")',
)
content = content.replace(
    '        _sid2 = MagicMock()\n        _sid2.class_name = "crescendo"',
    '        _sid2 = SimpleNamespace(name=None, class_name="crescendo")',
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("[OK] 3 skipped tests fixed: SimpleNamespace + lambda")
